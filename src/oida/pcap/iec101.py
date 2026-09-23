"""
IEC 60870-5-101 Passive Listener (PyShark-based).

Passively monitors IEC 101 serial telecontrol traffic (often tunneled over
TCP in modern deployments) to identify:
- Controlling stations (SCADA/master) and controlled stations (RTU/slave)
- Link addresses and data link layer function codes
- ASDU type IDs, cause of transmission, common addresses, IOAs
- Measurement values (single/double point, measured values, counters)
- Control commands and their parameters
- Quality flags (IV, NT, SB, BL, OV)

IEC 101 is the serial sibling of IEC 104.  Both share the same ASDU layer
(iec60870_asdu) but differ at the link layer: IEC 101 uses FT1.2 framing
with link addresses, while IEC 104 uses TCP with APCI framing.

tshark fields used:
- iec60870_101.linkaddr: Data link address (FT_UINT16)
- iec60870_101.ctrl_prm: Primary message flag (FT_UINT8)
- iec60870_101.ctrl_fcb: Frame count bit (FT_UINT8)
- iec60870_101.ctrl_fcv: Frame count bit valid (FT_UINT8)
- iec60870_101.ctrl_dfc: Data flow control (FT_UINT8)
- iec60870_101.ctrl_func_pri_to_sec: Function code, primary to secondary (FT_UINT8)
- iec60870_101.ctrl_func_sec_to_pri: Function code, secondary to primary (FT_UINT8)
- iec60870_101.header: Frame format byte (FT_UINT8)
- iec60870_101.length: Frame length (FT_UINT8)
- iec60870_asdu.*: Shared ASDU layer fields (same as IEC 104)

References:
- IEC 60870-5-101:2003 Telecontrol companion standard
- IEC 60870-5-5:2000 Basic application functions
- Wireshark dissector: packet-iec104.c (handles both 101 and 104)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

from ._iec_common import (
    CONTROL_TYPE_IDS,
    COT_NAMES,
    LINK_FUNC_PRI_TO_SEC,
    LINK_FUNC_SEC_TO_PRI,
    TYPE_IDS,
    IecAsduValueMixin,
)


@dataclass
class IEC101Session:
    """Track IEC 101 session statistics."""

    controlling_ip: str  # SCADA/master
    controlled_ip: str  # RTU/slave
    link_addresses: Set[int] = field(default_factory=set)
    common_addresses: Set[int] = field(default_factory=set)
    type_ids: Set[int] = field(default_factory=set)
    ioa_seen: Set[int] = field(default_factory=set)
    control_count: int = 0
    monitor_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class IEC101PassiveListener(IecAsduValueMixin, PySharkListenerBase):
    """Passive IEC 60870-5-101 traffic listener (PyShark-based).

    Monitors IEC 101 telecontrol traffic (serial protocol, commonly tunneled
    over TCP) without sending packets to:
    - Identify controlling stations (SCADA) and controlled stations (RTU)
    - Track link addresses and data link layer functions
    - Track common addresses (ASDU addresses) and type IDs
    - Extract actual data values per IOA (measurements, commands, setpoints)
    - Report quality flags (IV, NT, SB, BL, OV)
    - Detect control commands in the command direction

    Usage:
        listener = IEC101PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "iec101"
    DISPLAY_FILTER = "iec60870_101"
    REQUIRED_LAYERS = ("iec60870_101",)
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "link_addr",
        "type_id",
        "cot",
        "common_addr",
        "ioa",
        "value",
        "quality",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], IEC101Session] = {}

    def process_packet(self, packet) -> None:
        """Process IEC 101 packet using PyShark."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not hasattr(packet, "iec60870_101"):
            return

        iec101_layer = packet.iec60870_101

        # Extract link address
        link_addr_raw = self.get_field(iec101_layer, "linkaddr", None)
        link_addr = self._parse_int(link_addr_raw, 0)

        # Determine direction from PRM (Primary Message) bit
        # PRM=1: primary station sending (master -> slave)
        # PRM=0: secondary station sending (slave -> master)
        prm_raw = self.get_field(iec101_layer, "ctrl_prm", None)
        is_primary = self._parse_int(prm_raw, 0) == 1

        if is_primary:
            # Master sending to slave
            controlling_ip = src_ip
            controlled_ip = dst_ip
            controlling_mac = src_mac
            controlled_mac = dst_mac
        else:
            # Slave responding to master
            controlling_ip = dst_ip
            controlled_ip = src_ip
            controlling_mac = dst_mac
            controlled_mac = src_mac

        session = self._ensure_session(controlling_ip, controlled_ip)
        session.link_addresses.add(link_addr)

        # Extract link layer function code
        func_pri_raw = self.get_field(iec101_layer, "ctrl_func_pri_to_sec", None)
        func_sec_raw = self.get_field(iec101_layer, "ctrl_func_sec_to_pri", None)

        # Check frame format to determine variable-length vs fixed-length
        header_raw = self.get_field(iec101_layer, "header", None)
        # EK mode (oida pcap -r) hands over a bare DECIMAL int for this BASE_HEX
        # field (229, not "0xe5"); base=16 turned 229 into 553 and 16 into 22, so
        # the 0xE5 single-char-ACK test below could never fire.  _parse_int still
        # auto-detects the "0x" prefix XML mode produces.
        header_val = self._parse_int(header_raw, 0)

        # Process ASDU if present (variable-length frames with user data)
        if hasattr(packet, "iec60870_asdu"):
            self._process_asdu(packet, session, src_ip, dst_ip, flow_id, link_addr, is_primary)
        else:
            # Link-layer only frame (fixed-length or no ASDU)
            self._process_link_frame(
                packet,
                src_ip,
                dst_ip,
                flow_id,
                link_addr,
                is_primary,
                func_pri_raw,
                func_sec_raw,
                header_val,
            )

        # Update devices
        self._update_devices(controlling_ip, controlling_mac, controlled_ip, controlled_mac)

    def _ensure_session(self, controlling_ip: str, controlled_ip: str) -> IEC101Session:
        """Ensure session exists and return it."""
        session_key = (controlling_ip, controlled_ip)
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = IEC101Session(
                controlling_ip=controlling_ip,
                controlled_ip=controlled_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        return session

    def _process_link_frame(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        is_primary: bool,
        func_pri_raw,
        func_sec_raw,
        header_val: int,
    ) -> None:
        """Process link-layer only frame (no ASDU)."""
        if is_primary and func_pri_raw is not None:
            func_code = self._parse_int(func_pri_raw, -1)
            func_name = LINK_FUNC_PRI_TO_SEC.get(func_code, f"PRI Func {func_code}")
            direction = "request"
        elif not is_primary and func_sec_raw is not None:
            func_code = self._parse_int(func_sec_raw, -1)
            func_name = LINK_FUNC_SEC_TO_PRI.get(func_code, f"SEC Func {func_code}")
            direction = "response"
        else:
            func_code = -1
            func_name = "Unknown Link Func"
            direction = "request" if is_primary else "response"

        operation = "Single Char ACK (E5h)" if header_val == 0xE5 else f"Link: {func_name}"

        self._record_link_frame(
            packet,
            src_ip,
            dst_ip,
            flow_id,
            link_addr,
            is_primary,
            func_code,
            func_name,
            direction,
            operation,
        )

    def _process_asdu(
        self,
        packet,
        session: IEC101Session,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        is_primary: bool,
    ) -> None:
        """Process ASDU layer (shared with IEC 104)."""
        asdu_layer = packet.iec60870_asdu

        type_id_raw = self.get_field(asdu_layer, "typeid", None)
        if not type_id_raw:
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request" if is_primary else "response",
                "ASDU (malformed)",
                {"link_addr": link_addr, "malformed": True},
                f"Malformed ASDU link_addr={link_addr}",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        parsed = self._parse_asdu_core(session, asdu_layer)
        if parsed is None:
            self.logger.debug(
                "IEC101 unparseable ASDU typeid %r link_addr=%s", type_id_raw, link_addr
            )
            now = datetime.now().isoformat()
            _sp, _dp = self.get_port_info(packet)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request" if is_primary else "response",
                "ASDU (malformed)",
                {"link_addr": link_addr, "malformed": True, "typeid_raw": str(type_id_raw)},
                f"Malformed ASDU typeid={type_id_raw} link_addr={link_addr}",
                flow_id=flow_id,
                src_port=_sp,
                dst_port=_dp,
                stream_id=self.get_stream_id(packet),
            )
            return

        type_id = parsed["type_id"]
        type_name = parsed["type_name"]
        common_addr = parsed["common_address"]
        cause_tx = parsed["cause_of_transmission"]
        cot_name = parsed["cot_name"]
        rw = parsed["rw"]
        is_negative = parsed["negative"]
        is_control = parsed["is_control"]
        is_error_cot = parsed["is_error_cot"]
        ioa_list = parsed["ioa_list"]
        values = parsed["values"]
        quality_list = parsed["quality"]

        direction = "request" if is_control else "response"

        details: Dict[str, Any] = {
            "type_id": type_id,
            "type_name": type_name,
            "link_addr": link_addr,
            "common_address": common_addr,
            "cause_of_transmission": cause_tx,
            "cot_name": cot_name,
            "rw": rw,
            "negative": is_negative,
        }
        if ioa_list:
            details["ioa"] = ioa_list[0] if len(ioa_list) == 1 else ioa_list
        if values:
            details["values"] = values
        if quality_list:
            details["quality"] = quality_list

        summary = self._build_asdu_summary(
            type_id,
            type_name,
            ioa_list,
            common_addr,
            is_control,
            values,
            cot_name=cot_name,
            is_error=is_error_cot,
            link_addr=link_addr,
        )

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            type_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        type_id = d.get("type_id", "")
        type_name = d.get("type_name", "")
        common_addr = d.get("common_address", "")
        link_addr = d.get("link_addr", "")

        # Format IOA column
        ioa = d.get("ioa", "")
        if isinstance(ioa, list):
            if len(ioa) == 1:
                ioa_str = str(ioa[0])
            elif len(ioa) <= 5:
                ioa_str = " | ".join(str(a) for a in ioa)
            elif len(ioa) > 1:
                ioa_str = f"{ioa[0]}-{ioa[-1]}"
            else:
                ioa_str = ""
        else:
            ioa_str = str(ioa) if ioa != "" else ""

        # Type ID column
        type_str = f"{type_id} ({type_name})" if type_id else ""

        # COT column
        cot_name = d.get("cot_name", "")
        if not cot_name:
            cot_raw = d.get("cause_of_transmission", 0)
            if cot_raw:
                cot_name = COT_NAMES.get(cot_raw, str(cot_raw))

        # Value column
        values = d.get("values", [])
        if isinstance(values, list) and values:
            val_str = " | ".join(values)
        else:
            val_str = ""

        # Quality column
        quality = d.get("quality", [])
        if isinstance(quality, list) and quality:
            active = [q for q in quality if q]
            qual_str = ";".join(active) if active else ""
        else:
            qual_str = ""

        rw = d.get("rw", "")

        return [
            rw,
            ix.operation,
            link_addr if link_addr else "",
            type_str,
            cot_name,
            common_addr if common_addr else "",
            ioa_str,
            val_str,
            qual_str,
        ]

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        controlling_ip: str,
        controlling_mac: str,
        controlled_ip: str,
        controlled_mac: str,
    ) -> None:
        """Update device entries."""
        session_key = (controlling_ip, controlled_ip)
        session = self.sessions.get(session_key)
        if not session:
            return

        # Controlled station (RTU)
        if is_valid_discovered_ip(controlled_ip):
            controlled_vendor = lookup_mac_vendor(controlled_mac) if controlled_mac else ""
            key = f"iec101-controlled:{controlled_ip}"
            device, is_new = self._ensure_device(
                key,
                controlled_ip,
                mac=controlled_mac,
                manufacturer=controlled_vendor if controlled_vendor else "",
                device_type="IEC 101 Controlled Station (RTU)",
            )
            device.protocol_data = self._build_data("controlled_station", session)
            if is_new:
                self.logger.debug(
                    f"IEC101: RTU {controlled_ip} LA={list(session.link_addresses)} "
                    f"CA={list(session.common_addresses)}"
                )

        # Controlling station (SCADA)
        if is_valid_discovered_ip(controlling_ip):
            controlling_vendor = lookup_mac_vendor(controlling_mac) if controlling_mac else ""
            key = f"iec101-controlling:{controlling_ip}"
            device, is_new = self._ensure_device(
                key,
                controlling_ip,
                mac=controlling_mac,
                manufacturer=controlling_vendor,
                device_type="IEC 101 Controlling Station (SCADA)",
            )
            device.protocol_data = self._build_data("controlling_station", session)

    def _build_data(self, role: str, session: IEC101Session) -> Dict[str, Any]:
        """Build protocol_data dict."""
        return {
            "role": role,
            "link_addresses": sorted(list(session.link_addresses)),
            "common_addresses": sorted(list(session.common_addresses)),
            "type_ids_seen": sorted(list(session.type_ids)),
            "type_names": [TYPE_IDS.get(t, f"Type{t}") for t in sorted(session.type_ids)],
            "ioa_ranges": self._merge_ioa_ranges(session.ioa_seen),
            "control_commands": session.control_count,
            "monitor_messages": session.monitor_count,
            "protocol": "IEC101/Serial",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

    def _merge_ioa_ranges(self, ioas: Set[int]) -> List[Tuple[int, int]]:
        """Merge IOAs into ranges."""
        if not ioas:
            return []
        sorted_ioas = sorted(ioas)
        ranges = []
        start = end = sorted_ioas[0]
        for ioa in sorted_ioas[1:]:
            if ioa <= end + 10:
                end = ioa
            else:
                ranges.append((start, end))
                start = end = ioa
        ranges.append((start, end))
        return ranges

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed IEC 101 sessions."""
        return [
            {
                "controlling": session.controlling_ip,
                "controlled": session.controlled_ip,
                "link_addresses": sorted(list(session.link_addresses)),
                "common_addresses": sorted(list(session.common_addresses)),
                "type_ids": sorted(list(session.type_ids)),
                "control_count": session.control_count,
                "monitor_count": session.monitor_count,
            }
            for session in self.sessions.values()
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with control operations."""
        return [
            {
                "controlling": session.controlling_ip,
                "controlled": session.controlled_ip,
                "control_count": session.control_count,
                "control_types": [
                    TYPE_IDS.get(t, f"Type{t}") for t in session.type_ids if t in CONTROL_TYPE_IDS
                ],
            }
            for session in self.sessions.values()
            if session.control_count > 0
        ]
