"""
DDS / RTPS (Real-Time Publish-Subscribe) Passive Listener (PyShark-based).

Passively monitors the RTPS wire protocol -- the interoperability transport
under OMG DDS (Data Distribution Service) used by robotics/ROS 2, defense,
and modern industrial data buses -- to identify:
- DDS participants (by GUID prefix) and the domains they belong to
- Vendor / protocol version of each participant
- Discovery vs. user-data traffic and source locators

RTPS is connectionless (typically UDP multicast + unicast).  Every message
carries a GUID prefix identifying the sending participant and a domain id.

tshark fields used (rtps layer):
- rtps.magic            : "RTPS" signature
- rtps.domain_id        : DDS domain id
- rtps.guidPrefix / rtps.guidPrefix.src : participant GUID prefix
- rtps.hostId / rtps.appId : legacy identity components
- rtps.info_src.ip      : source locator address
- rtps.version / rtps.vendorId : protocol version / vendor

Reference: OMG DDS-RTPS 2.x; packet-rtps.c (Wireshark).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# RTPS vendor IDs (OMG-assigned; subset).
RTPS_VENDORS = {
    "0x0101": "RTI Connext",
    "0x0102": "ADLINK OpenSplice",
    "0x0103": "OCI OpenDDS",
    "0x0104": "MilSOFT",
    "0x0105": "Kongsberg InterCOM",
    "0x0106": "TwinOaks CoreDX",
    "0x0107": "Lakota",
    "0x0108": "ICOTeam",
    "0x0109": "ETRI",
    "0x010a": "RTI Connext (micro)",
    "0x010b": "ADLINK Cyclone/Vortex",
    "0x010f": "eProsima Fast DDS",
    "0x0110": "eclipse Cyclone DDS",
    "0x0120": "Gurum DDS",
}


class RTPSPassiveListener(PySharkListenerBase):
    """Passive DDS/RTPS traffic listener (PyShark-based).

    Monitors RTPS traffic to:
    - Enumerate DDS participants (GUID prefixes) and their domains
    - Identify the DDS vendor/version in use
    - Map the discovery topology of a DDS databus

    Data stored in device.rtps_passive_data:
        {
            "role": "participant",
            "guid_prefixes": ["00:00:00:00:00:01:09:01:..."],
            "domains": ["60"],
            "vendor": "RTI Connext",
            "protocol": "DDS/RTPS",
        }
    """

    PROTOCOL_NAME = "rtps"
    DISPLAY_FILTER = "rtps"
    REQUIRED_LAYERS = ("rtps",)
    # RTPS default discovery ports are computed from the domain id; there is no
    # single canonical port, so direction stays participant-symmetric.
    PROTOCOL_COLUMNS = ("domain", "guid_prefix", "vendor", "src_locator")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # ip -> {guid_prefixes, domains, vendor}
        self.participants: Dict[str, Dict[str, Any]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        return [
            d.get("domain_id", "-") or "-",
            d.get("guid_prefix", "-") or "-",
            d.get("vendor_name", d.get("vendor_id", "-")) or "-",
            d.get("src_locator", "-") or "-",
        ]

    def process_packet(self, packet) -> None:
        """Process an RTPS packet."""
        if not hasattr(packet, "rtps"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        rtps = packet.rtps
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)

        domain_id = str(self.get_field(rtps, "domain_id", "") or "")
        guid_prefix = str(
            self.get_field_any(rtps, "guidPrefix_src", "guidPrefix", default="") or ""
        )
        host_id = str(self.get_field(rtps, "hostId", "") or "")
        app_id = str(self.get_field(rtps, "appId", "") or "")
        src_locator = str(self.get_field_any(rtps, "info_src_ip", default="") or "")
        vendor_id = self._norm_hex(
            self.get_field_any(rtps, "vendorId", "vendor_id", "sm_vendorId", default="")
        )
        version = str(self.get_field_any(rtps, "version", "protocolVersion", default="") or "")
        vendor_name = RTPS_VENDORS.get(vendor_id, "")

        details: Dict[str, Any] = {
            "domain_id": domain_id,
            "guid_prefix": guid_prefix,
            "host_id": host_id,
            "app_id": app_id,
            "src_locator": src_locator,
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "version": version,
        }

        now = datetime.now().isoformat()
        summary = f"RTPS domain={domain_id or '?'} {src_ip}"
        if guid_prefix:
            summary += f" guid={guid_prefix[:23]}"
        if vendor_name:
            summary += f" vendor={vendor_name}"

        # RTPS is peer-to-peer publish/subscribe; record as participant traffic.
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"RTPS domain={domain_id or '?'}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        self._track_participant(src_ip, guid_prefix, domain_id, vendor_name or vendor_id)

        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"rtps-participant:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type="DDS Participant",
                manufacturer=vendor_name or (vendor if vendor and vendor != "Unknown" else ""),
                data_attr="rtps_passive_data",
                protocol_data=self._participant_data(src_ip),
            )

    # ------------------------------------------------------------------
    def _track_participant(self, ip: str, guid_prefix: str, domain_id: str, vendor: str) -> None:
        info = self.participants.setdefault(
            ip, {"guid_prefixes": set(), "domains": set(), "vendor": ""}
        )
        if guid_prefix:
            info["guid_prefixes"].add(guid_prefix)
        if domain_id:
            info["domains"].add(domain_id)
        if vendor:
            info["vendor"] = vendor

    def _participant_data(self, ip: str) -> Dict[str, Any]:
        info = self.participants.get(ip, {})
        return {
            "role": "participant",
            "guid_prefixes": sorted(info.get("guid_prefixes", set())),
            "domains": sorted(info.get("domains", set())),
            "vendor": info.get("vendor", ""),
            "protocol": "DDS/RTPS",
        }

    @staticmethod
    def _norm_hex(raw: Any) -> str:
        s = str(raw).strip().lower()
        if not s:
            return ""
        if s.startswith("0x"):
            return s
        try:
            return f"0x{int(s):04x}"
        except (ValueError, TypeError):
            return s

    def harvest(self) -> Dict[str, Any]:
        """Add a DDS participant inventory table to the base alerts."""
        result = super().harvest() or {}
        tables = result.setdefault("tables", [])
        if self.participants:
            rows = []
            for ip, info in sorted(self.participants.items()):
                rows.append(
                    [
                        ip,
                        ", ".join(sorted(info["domains"])) or "-",
                        info.get("vendor", "-") or "-",
                        str(len(info["guid_prefixes"])),
                    ]
                )
            tables.append(
                {
                    "title": "DDS/RTPS Participants",
                    "headers": ["IP", "Domains", "Vendor", "GUID Count"],
                    "rows": rows,
                }
            )
        return result if (result.get("tables") or result.get("alerts")) else {}
