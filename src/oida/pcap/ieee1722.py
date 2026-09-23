"""
IEEE 1722 AVTP (Audio Video Transport Protocol) Passive Listener.

Passively monitors IEEE 1722 / AVTP traffic (Time-Sensitive Networking,
Audio Video Bridging, automotive Ethernet) to identify:
- AVTP talkers (stream sources) and the subtypes they transport
- Stream IDs (the 64-bit AVB stream identifier) and sequence numbers
- Media format per subtype (AAF audio, CVF video, CRF clock reference)

AVTP runs directly over Ethernet (ethertype 0x22F0) or UDP (17220).  Stream
subtypes are one-way (talker -> listener); control subtypes (ADP/AECP/ACMP,
MAAP) manage stream reservations.

tshark fields used:
- ieee1722.subtype          : AVTP subtype (0x00 61883 .. 0x82 NTSCF)
- ieee1722.svfield          : stream-id valid flag
- <subtype>.stream_id       : 64-bit stream id (aaf/crf/cvf/... layer)
- <subtype>.seqnum          : sequence number
- <subtype>.avtp_timestamp  : presentation timestamp

Reference: IEEE 1722-2016; packet-ieee1722.c (Wireshark).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# AVTP subtype -> (name, kind).  kind "stream" = media data (talker->listener),
# "control" = AVDECC/stream-reservation management.
AVTP_SUBTYPE = {
    "0x00": ("61883/IIDC", "stream"),
    "0x01": ("MMA Streams", "stream"),
    "0x02": ("AAF (Audio)", "stream"),
    "0x03": ("CVF (Compressed Video)", "stream"),
    "0x04": ("CRF (Clock Reference)", "stream"),
    "0x05": ("TSCF", "stream"),
    "0x06": ("SVF (SDI Video)", "stream"),
    "0x07": ("RVF (Raw Video)", "stream"),
    "0x6e": ("AEF-Continuous", "stream"),
    "0x6f": ("VSF", "stream"),
    "0x7f": ("Experimental", "stream"),
    "0x82": ("NTSCF", "stream"),
    # Control subtypes -- names verbatim from `tshark -G values |
    # grep ieee1722.subtype` (IEEE 1722-2016 Table 6).  0xec was previously a
    # duplicate "MAAP" entry (MAAP is 0xfe) and 0xee was labeled
    # "Media Clock (EF)", so signed/encrypted AVB control traffic was reported
    # as benign address-reservation / clock traffic; 0xed was missing.
    "0xec": ("ECC Signed Control Format", "control"),
    "0xed": ("ECC Encrypted Control Format", "control"),
    "0xee": ("AES Encrypted Format Discrete", "control"),
    "0xfa": ("AVDECC Discovery Protocol", "control"),
    "0xfb": ("AVDECC Enumeration and Control Protocol", "control"),
    "0xfc": ("AVDECC Connection Management Protocol", "control"),
    "0xfe": ("MAAP", "control"),
    "0xff": ("Experimental Format Control", "control"),
}

# Subtype layer names to probe for stream_id / seqnum / timestamp.
_SUBTYPE_LAYERS = ("aaf", "cvf", "crf", "iec61883", "tscf", "ntscf", "acf")


class IEEE1722PassiveListener(PySharkListenerBase):
    """Passive IEEE 1722 / AVTP traffic listener (PyShark-based).

    Monitors AVTP traffic to:
    - Identify talkers and the AVTP subtypes/streams present
    - Track stream IDs and their media formats
    - Distinguish media streams from AVDECC control traffic

    Data stored in device.ieee1722_passive_data:
        {
            "role": "talker",
            "subtypes": ["AAF (Audio)", "CRF (Clock Reference)"],
            "stream_ids": ["0x0011223344556677"],
            "protocol": "IEEE 1722/AVTP",
        }
    """

    PROTOCOL_NAME = "ieee1722"
    DISPLAY_FILTER = "ieee1722"
    REQUIRED_LAYERS = ("ieee1722",)
    SERVER_PORTS = (17220,)
    PROTOCOL_COLUMNS = ("subtype", "kind", "stream_id", "seqnum")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # talker mac/ip -> {subtypes, stream_ids}
        self.talkers: Dict[str, Dict[str, Any]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        return [
            d.get("subtype_name", "?"),
            d.get("kind", "?"),
            d.get("stream_id", "-") or "-",
            d.get("seqnum", "-") or "-",
        ]

    def process_packet(self, packet) -> None:
        """Process an IEEE 1722 / AVTP packet."""
        if not hasattr(packet, "ieee1722"):
            return

        avtp = packet.ieee1722
        subtype_raw = self.get_field(avtp, "subtype", None)
        if subtype_raw is None:
            self.logger.debug("IEEE1722: missing subtype")
            return
        subtype = self._norm_hex(subtype_raw)
        subtype_name, kind = AVTP_SUBTYPE.get(subtype, (f"Unknown ({subtype})", "stream"))

        # AVTP is L2 media transport; IPs may be absent for raw-Ethernet
        # streams.  Fall back to MAC endpoints for identity.
        src_ip, dst_ip = self.get_ip_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        src_key = src_ip or src_mac or ""
        if not src_key:
            return

        flow_id = self.get_flow_id(packet)

        # Pull stream_id / seqnum / timestamp from whichever subtype layer is
        # present.
        stream_id = ""
        seqnum = ""
        timestamp = ""
        for lyr_name in _SUBTYPE_LAYERS:
            if hasattr(packet, lyr_name):
                lyr = getattr(packet, lyr_name)
                stream_id = str(self.get_field(lyr, "stream_id", "") or "")
                seqnum = str(self.get_field(lyr, "seqnum", "") or "")
                timestamp = str(self.get_field(lyr, "avtp_timestamp", "") or "")
                if stream_id or seqnum:
                    break

        details: Dict[str, Any] = {
            "subtype": subtype,
            "subtype_name": subtype_name,
            "kind": kind,
            "stream_id": stream_id,
            "seqnum": seqnum,
            "timestamp": timestamp,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }

        now = datetime.now().isoformat()
        summary = f"AVTP {subtype_name} {src_key}"
        if stream_id:
            summary += f" stream={stream_id}"

        # Streams are talker->listener (publish); record as response/publish.
        self._record_interaction(
            now,
            src_ip or src_mac,
            dst_ip or dst_mac,
            "response" if kind == "stream" else "request",
            f"AVTP {subtype_name}",
            details,
            summary,
            flow_id=flow_id,
            stream_id=self.get_stream_id(packet),
        )

        self._track_talker(src_key, subtype_name, stream_id)

        # Register the talker.  Use IP when present, else the MAC-derived key.
        if src_ip and is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"ieee1722-talker:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type="AVTP Talker",
                manufacturer=vendor if vendor and vendor != "Unknown" else "",
                data_attr="ieee1722_passive_data",
                protocol_data=self._talker_data(src_key),
            )
        elif src_mac:
            # L2-only stream: create a MAC-addressed device with no IP.
            self._ensure_device(
                f"ieee1722-talker:{src_mac}",
                "",
                mac=src_mac,
                device_type="AVTP Talker",
                data_attr="ieee1722_passive_data",
                protocol_data=self._talker_data(src_key),
            )

    # ------------------------------------------------------------------
    def _track_talker(self, key: str, subtype_name: str, stream_id: str) -> None:
        info = self.talkers.setdefault(key, {"subtypes": set(), "stream_ids": set()})
        info["subtypes"].add(subtype_name)
        if stream_id:
            info["stream_ids"].add(stream_id)

    def _talker_data(self, key: str) -> Dict[str, Any]:
        info = self.talkers.get(key, {})
        return {
            "role": "talker",
            "subtypes": sorted(info.get("subtypes", set())),
            "stream_ids": sorted(info.get("stream_ids", set())),
            "protocol": "IEEE 1722/AVTP",
        }

    @staticmethod
    def _norm_hex(raw: Any) -> str:
        s = str(raw).strip().lower()
        if s.startswith("0x"):
            return s
        try:
            return f"0x{int(s):02x}"
        except (ValueError, TypeError):
            return s

    def harvest(self) -> Dict[str, Any]:
        """Add an AVTP stream inventory table to the base alerts."""
        result = super().harvest() or {}
        tables = result.setdefault("tables", [])
        if self.talkers:
            rows = []
            for key, info in sorted(self.talkers.items()):
                rows.append(
                    [
                        key,
                        ", ".join(sorted(info["subtypes"])) or "-",
                        ", ".join(sorted(info["stream_ids"])) or "-",
                    ]
                )
            tables.append(
                {
                    "title": "AVTP Talkers / Streams",
                    "headers": ["Talker", "Subtypes", "Stream IDs"],
                    "rows": rows,
                }
            )
        return result if (result.get("tables") or result.get("alerts")) else {}
