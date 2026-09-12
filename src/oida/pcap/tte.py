"""
TTEthernet (TTE, SAE AS6802) Passive Listener (PyShark-based).

Passively monitors TTEthernet traffic -- time-triggered deterministic
Ethernet used in rail, energy, aerospace and industrial backbones -- to
identify:
- Critical-traffic virtual links (VLs) and the end systems using them
- Protocol Control Frames (PCF) from the compression/sync master
- Integration-cycle / membership state and transparent-clock values

TTEthernet runs directly over Ethernet (ethertype 0x891D).  Two frame
classes are seen: time-triggered / rate-constrained *critical traffic*
(carries a Critical Traffic ID) and *Protocol Control Frames* that drive
clock synchronisation.

tshark fields used:
- tte.cf            : critical-traffic marker / CT field
- tte.ctid          : Critical Traffic ID (virtual link)
- tte_pcf.type      : PCF type (0=coldstart, integration, ...)
- tte_pcf.mn        : membership new / integration cycle
- tte_pcf.tc        : transparent clock
- tte_pcf.sp / tte_pcf.sd : sync priority / domain

Reference: SAE AS6802; packet-tte.c / packet-tte-pcf.c (Wireshark).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor, normalize_mac

# PCF type codes (SAE AS6802).
TTE_PCF_TYPE = {
    "0x00": "Integration Frame",
    "0x02": "Coldstart Frame",
    "0x04": "Coldstart Ack Frame",
    "0": "Integration Frame",
    "2": "Coldstart Frame",
    "4": "Coldstart Ack Frame",
}


class TTEPassiveListener(PySharkListenerBase):
    """Passive TTEthernet traffic listener (PyShark-based).

    Monitors TTEthernet traffic to:
    - Enumerate critical-traffic virtual links (Critical Traffic IDs)
    - Identify the sync master via Protocol Control Frames
    - Map end systems (by MAC) participating in time-triggered traffic

    Data stored in device.tte_passive_data:
        {
            "role": "end_system" | "sync_master",
            "critical_traffic_ids": ["0xffff"],
            "pcf_types": ["Coldstart Frame"],
            "protocol": "TTEthernet",
        }
    """

    PROTOCOL_NAME = "tte"
    DISPLAY_FILTER = "tte || tte_pcf"
    REQUIRED_LAYERS = ("tte", "tte_pcf")
    PROTOCOL_COLUMNS = ("frame_type", "ct_id", "pcf_type", "int_cycle")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # mac -> {role, ctids, pcf_types}
        self.stations: Dict[str, Dict[str, Any]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        return [
            d.get("frame_type", "?"),
            d.get("ct_id", "-") or "-",
            d.get("pcf_type_name", "-") or "-",
            d.get("integration_cycle", "-") or "-",
        ]

    def process_packet(self, packet) -> None:
        """Process a TTEthernet frame (critical traffic or PCF)."""
        has_tte = hasattr(packet, "tte")
        has_pcf = hasattr(packet, "tte_pcf")
        if not (has_tte or has_pcf):
            return

        # TTEthernet is L2; identity is the MAC address.  tshark nests the
        # eth.src/eth.dst fields *inside* the tte layer (no standalone eth
        # layer for an ethertype-0x891D handoff), so get_mac_info() misses
        # them -- read them from the tte/tte_pcf layer directly.
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            src_mac, dst_mac = self._tte_macs(packet)
        if not src_mac:
            return
        flow_id = self.get_flow_id(packet)

        ct_id = ""
        cf = ""
        if has_tte:
            cf = str(self.get_field(packet.tte, "cf", "") or "")
            ct_id = str(self.get_field(packet.tte, "ctid", "") or "")

        pcf_type = ""
        pcf_type_name = ""
        integration_cycle = ""
        transparent_clock = ""
        if has_pcf:
            pcf = packet.tte_pcf
            pcf_type = str(self.get_field(pcf, "type", "") or "")
            pcf_type_name = TTE_PCF_TYPE.get(
                self._norm_hex(pcf_type), TTE_PCF_TYPE.get(pcf_type, pcf_type)
            )
            integration_cycle = str(self.get_field(pcf, "mn", "") or "")
            transparent_clock = str(self.get_field(pcf, "tc", "") or "")

        if has_pcf:
            frame_type = "PCF"
            role = "sync_master"
            operation = f"TTE PCF {pcf_type_name}".strip()
        else:
            frame_type = "Critical Traffic"
            role = "end_system"
            operation = f"TTE CT vl={ct_id}"

        details: Dict[str, Any] = {
            "frame_type": frame_type,
            "ct_id": ct_id,
            "cf": cf,
            "pcf_type": pcf_type,
            "pcf_type_name": pcf_type_name,
            "integration_cycle": integration_cycle,
            "transparent_clock": transparent_clock,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }

        now = datetime.now().isoformat()
        summary = f"{operation} {src_mac} -> {dst_mac}"

        self._record_interaction(
            now,
            src_mac,
            dst_mac,
            "response",
            operation,
            details,
            summary,
            flow_id=flow_id,
            stream_id=self.get_stream_id(packet),
        )

        self._track_station(src_mac, role, ct_id, pcf_type_name)

        # L2-only device keyed by MAC (no IP for TTEthernet).
        vendor = lookup_mac_vendor(src_mac) if src_mac else ""
        self._ensure_device(
            f"tte-{role}:{src_mac}",
            "",
            mac=src_mac,
            device_type=f"TTE {'Sync Master' if role == 'sync_master' else 'End System'}",
            manufacturer=vendor if vendor and vendor != "Unknown" else "",
            data_attr="tte_passive_data",
            protocol_data=self._station_data(src_mac),
        )

    @staticmethod
    def _tte_macs(packet) -> tuple:
        """Extract (src_mac, dst_mac) from the eth fields nested in the tte layer.

        For an ethertype-0x891D handoff tshark places ``eth.src`` / ``eth.dst``
        under the ``tte`` (or ``tte_pcf``) layer rather than a standalone ``eth``
        layer, so they must be read from that layer's raw field dict.
        """
        for lyr_name in ("tte", "tte_pcf"):
            if not hasattr(packet, lyr_name):
                continue
            try:
                fd = object.__getattribute__(getattr(packet, lyr_name), "_fields_dict")
            except AttributeError:
                fd = None
            if not isinstance(fd, dict):
                continue
            src = fd.get("eth_eth_src")
            dst = fd.get("eth_eth_dst")
            if isinstance(src, list):
                src = src[0] if src else None
            if isinstance(dst, list):
                dst = dst[0] if dst else None
            if src:
                return (
                    normalize_mac(str(src)),
                    normalize_mac(str(dst)) if dst else "",
                )
        return "", ""

    # ------------------------------------------------------------------
    def _track_station(self, mac: str, role: str, ct_id: str, pcf_type_name: str) -> None:
        info = self.stations.setdefault(mac, {"role": role, "ctids": set(), "pcf_types": set()})
        # A station sending PCFs is the sync master -- that role wins.
        if role == "sync_master":
            info["role"] = "sync_master"
        if ct_id:
            info["ctids"].add(ct_id)
        if pcf_type_name:
            info["pcf_types"].add(pcf_type_name)

    def _station_data(self, mac: str) -> Dict[str, Any]:
        info = self.stations.get(mac, {})
        return {
            "role": info.get("role", ""),
            "critical_traffic_ids": sorted(info.get("ctids", set())),
            "pcf_types": sorted(info.get("pcf_types", set())),
            "protocol": "TTEthernet",
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
        """Add a TTE station/VL inventory table to the base alerts."""
        result = super().harvest() or {}
        tables = result.setdefault("tables", [])
        if self.stations:
            rows = []
            for mac, info in sorted(self.stations.items()):
                rows.append(
                    [
                        mac,
                        info.get("role", "-"),
                        ", ".join(sorted(info["ctids"])) or "-",
                        ", ".join(sorted(info["pcf_types"])) or "-",
                    ]
                )
            tables.append(
                {
                    "title": "TTEthernet Stations",
                    "headers": ["MAC", "Role", "Critical Traffic IDs", "PCF Types"],
                    "rows": rows,
                }
            )
        return result if (result.get("tables") or result.get("alerts")) else {}
