"""
IEC 60870-5-103 Passive Listener (PyShark-based).

Passively monitors IEC 103 protection equipment companion standard traffic
(commonly tunneled over TCP in modern deployments) to identify:
- Protection relays by link address and ASDU common address
- ASDU type IDs (monitoring and control direction)
- Function types identifying protection functions (distance, overcurrent, etc.)
- Information numbers within each function type
- Cause of transmission for event classification
- General commands and disturbance data transfers
- Time synchronization operations

IEC 103 is used in substations for communication between protection relays
and bay controllers/substation automation systems.  It uses FT1.2 link layer
framing (same as IEC 101) with its own ASDU structure.

tshark fields used:
- iec60870_5_103.linkaddr: Data link address (FT_UINT8)
- iec60870_5_103.ctrl_prm: Primary message flag (FT_UINT8)
- iec60870_5_103.ctrl_func_pri_to_sec: Function code, primary to secondary (FT_UINT8)
- iec60870_5_103.ctrl_func_sec_to_pri: Function code, secondary to primary (FT_UINT8)
- iec60870_5_103.asdu_typeid_ctrl: ASDU type ID, control direction (FT_UINT8)
- iec60870_5_103.asdu_typeid_mon: ASDU type ID, monitor direction (FT_UINT8)
- iec60870_5_103.asdu_address: ASDU common address (FT_UINT8)
- iec60870_5_103.func_type: Function type (FT_UINT8)
- iec60870_5_103.info_num: Information number (FT_UINT8)
- iec60870_5_103.cot_ctrl: Cause of transmission, control direction (FT_UINT8)
- iec60870_5_103.cot_mon: Cause of transmission, monitor direction (FT_UINT8)
- iec60870_5_103.dpi: Double point information (FT_UINT8)
- iec60870_5_103.dco: Double command type (FT_UINT8)
- iec60870_5_103.col: Compatibility level (FT_UINT8)
- iec60870_5_103.rii: Return information identifier (FT_UINT8)
- iec60870_5_103.scn: Scan number (FT_UINT8)
- iec60870_5_103.sin: Supplementary information (FT_UINT8)
- iec60870_5_103.mfg: Manufacturer identity (FT_STRING)
- iec60870_5_103.mfg_sw: Manufacturer software identification (FT_UINT32)
- iec60870_5_103.header: Frame format byte (FT_UINT8)

References:
- IEC 60870-5-103:1997 Companion standard for informative interface of
  protection equipment
- Wireshark dissector: packet-iec104.c (handles 101, 103, and 104)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# IEC 103 ASDU Type IDs -- Monitor Direction
ASDU_TYPE_MON = {
    1: "Time-tagged message",
    2: "Time-tagged message with relative time",
    4: "Time-tagged measurands with relative time",
    5: "Identification",
    6: "Time synchronization",
    8: "General interrogation termination",
    9: "Measurands II",
    10: "Generic data",
    11: "Generic identification",
    23: "List of recorded disturbances",
    26: "Ready for transmission of disturbance data",
    27: "Ready for transmission of a channel",
    28: "Ready for transmission of tags",
    29: "Transmission of tags",
    30: "Transmission of disturbance values",
    31: "End of transmission",
}

# IEC 103 ASDU Type IDs -- Control Direction
ASDU_TYPE_CTRL = {
    6: "Time synchronization",
    7: "General interrogation",
    10: "Generic data",
    20: "General command",
    21: "Generic command",
    24: "Order for disturbance data transmission",
    25: "Acknowledgement for disturbance data transmission",
}

# IEC 103 Function Types (protection function identifiers)
FUNCTION_TYPES = {
    0: "Not Used",
    128: "Distance Protection",
    160: "Overcurrent Protection",
    176: "Transformer Differential Protection",
    192: "Line Differential Protection",
    224: "Generic Function",
    254: "Global Function Type",
    255: "All Functions (Broadcast)",
}

# Additional function type ranges for display
_FUNC_TYPE_RANGES = [
    (128, 159, "Distance Protection"),
    (160, 175, "Overcurrent Protection"),
    (176, 191, "Transformer Differential Protection"),
    (192, 207, "Line Differential Protection"),
    (208, 223, "Reserved"),
    (224, 239, "Generic Function"),
    (240, 253, "Vendor-Specific"),
]

# IEC 103 Cause of Transmission -- Monitor Direction
COT_MON = {
    1: "Spontaneous",
    2: "Cyclic",
    3: "Reset frame count bit",
    4: "Reset communication link",
    5: "Start/restart",
    6: "Power on",
    7: "Test mode",
    8: "Time synchronized",
    9: "General interrogation",
    10: "Termination of general interrogation",
    11: "Local operation",
    12: "Remote operation",
    20: "Positive acknowledgement of command",
    21: "Negative acknowledgement of command",
    31: "Transmission of disturbance data",
    40: "Positive acknowledgement of generic write command",
    41: "Negative acknowledgement of generic write command",
    44: "Valid data response",
}

# IEC 103 Cause of Transmission -- Control Direction
COT_CTRL = {
    8: "Time synchronization",
    9: "General interrogation",
    20: "General command",
    31: "Transmission of disturbance data",
    40: "Generic write command",
    42: "Generic read command",
}

# Security-relevant ASDU type IDs (control direction commands)
_CONTROL_TYPE_IDS = {6, 7, 10, 20, 21, 24, 25}

# IEC 103 link layer function codes (primary -> secondary)
LINK_FUNC_PRI_TO_SEC = {
    0: "Reset Remote Link",
    1: "Reset User Process",
    2: "Test Function for Link",
    3: "User Data (Confirmed)",
    4: "User Data (No Reply)",
    8: "Expected Response Specifies Access Demand",
    9: "Request Status of Link",
    10: "Request User Data Class 1",
    11: "Request User Data Class 2",
}

# IEC 103 link layer function codes (secondary -> primary)
LINK_FUNC_SEC_TO_PRI = {
    0: "ACK (positive)",
    1: "NACK (link busy)",
    8: "User Data",
    9: "No Data Available (NACK)",
    11: "Status of Link / Access Demand",
    14: "Link Not Functioning",
    15: "Link Not Implemented",
}

# Double point information values
_DPI_VALUES = {0: "INTERMEDIATE", 1: "OFF", 2: "ON", 3: "INDETERMINATE"}

# Double command values
_DCO_VALUES = {0: "NOT_PERMITTED", 1: "OFF", 2: "ON", 3: "NOT_PERMITTED"}


def _get_function_type_name(func_type: int) -> str:
    """Resolve function type to a human-readable name."""
    if func_type in FUNCTION_TYPES:
        return FUNCTION_TYPES[func_type]
    for lo, hi, name in _FUNC_TYPE_RANGES:
        if lo <= func_type <= hi:
            return name
    if func_type < 128:
        return f"Application Func {func_type}"
    return f"Func {func_type}"


@dataclass
class IEC103Session:
    """Track IEC 103 session statistics."""

    controlling_ip: str  # Bay controller / substation automation
    controlled_ip: str  # Protection relay
    link_addresses: Set[int] = field(default_factory=set)
    asdu_addresses: Set[int] = field(default_factory=set)
    type_ids_mon: Set[int] = field(default_factory=set)
    type_ids_ctrl: Set[int] = field(default_factory=set)
    function_types: Set[int] = field(default_factory=set)
    control_count: int = 0
    monitor_count: int = 0
    manufacturer: str = ""
    manufacturer_sw: str = ""
    first_seen: str = ""
    last_seen: str = ""


class IEC103PassiveListener(PySharkListenerBase):
    """Passive IEC 60870-5-103 traffic listener (PyShark-based).

    Monitors IEC 103 protection equipment companion standard traffic
    without sending packets to:
    - Identify protection relays and bay controllers
    - Track function types (distance, overcurrent, transformer differential)
    - Monitor ASDU types and cause of transmission
    - Detect general commands, time synchronization, disturbance data transfers
    - Track manufacturer identification and compatibility levels

    Usage:
        listener = IEC103PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "iec103"
    DISPLAY_FILTER = "iec60870_5_103"
    REQUIRED_LAYERS = ("iec60870_5_103",)
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "link_addr",
        "asdu_type",
        "func_type",
        "info_num",
        "cot",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], IEC103Session] = {}

    def process_packet(self, packet) -> None:
        """Process IEC 103 packet using PyShark."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not hasattr(packet, "iec60870_5_103"):
            return

        iec103_layer = packet.iec60870_5_103

        # Extract link address
        link_addr_raw = self.get_field(iec103_layer, "linkaddr", None)
        link_addr = self._parse_int(link_addr_raw, 0)

        # Determine direction from PRM (Primary Message) bit
        prm_raw = self.get_field(iec103_layer, "ctrl_prm", None)
        is_primary = self._parse_int(prm_raw, 0) == 1

        if is_primary:
            controlling_ip = src_ip
            controlled_ip = dst_ip
            controlling_mac = src_mac
            controlled_mac = dst_mac
        else:
            controlling_ip = dst_ip
            controlled_ip = src_ip
            controlling_mac = dst_mac
            controlled_mac = src_mac

        session = self._ensure_session(controlling_ip, controlled_ip)
        session.link_addresses.add(link_addr)

        # Try to extract ASDU type IDs (separate fields for control and monitor)
        type_id_ctrl_raw = self.get_field(iec103_layer, "asdu_typeid_ctrl", None)
        type_id_mon_raw = self.get_field(iec103_layer, "asdu_typeid_mon", None)

        # Extract common fields
        asdu_addr_raw = self.get_field(iec103_layer, "asdu_address", None)
        asdu_addr = self._parse_int(asdu_addr_raw, 0)
        if asdu_addr:
            session.asdu_addresses.add(asdu_addr)

        func_type_raw = self.get_field(iec103_layer, "func_type", None)
        func_type = self._parse_int(func_type_raw, default=None)
        if func_type is not None:
            session.function_types.add(func_type)

        info_num_raw = self.get_field(iec103_layer, "info_num", None)
        info_num = self._parse_int(info_num_raw, default=None)

        if type_id_ctrl_raw is not None:
            self._process_control_asdu(
                packet,
                session,
                iec103_layer,
                src_ip,
                dst_ip,
                flow_id,
                link_addr,
                asdu_addr,
                func_type,
                info_num,
                type_id_ctrl_raw,
            )
        elif type_id_mon_raw is not None:
            self._process_monitor_asdu(
                packet,
                session,
                iec103_layer,
                src_ip,
                dst_ip,
                flow_id,
                link_addr,
                asdu_addr,
                func_type,
                info_num,
                type_id_mon_raw,
            )
        else:
            # Link-layer only frame (no ASDU)
            self._process_link_frame(
                packet,
                src_ip,
                dst_ip,
                flow_id,
                link_addr,
                is_primary,
            )

        self._update_devices(controlling_ip, controlling_mac, controlled_ip, controlled_mac)

    def _ensure_session(self, controlling_ip: str, controlled_ip: str) -> IEC103Session:
        """Ensure session exists and return it."""
        session_key = (controlling_ip, controlled_ip)
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = IEC103Session(
                controlling_ip=controlling_ip,
                controlled_ip=controlled_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        return session

    def _process_control_asdu(
        self,
        packet,
        session: IEC103Session,
        iec103_layer,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        asdu_addr: int,
        func_type: Optional[int],
        info_num: Optional[int],
        type_id_raw: Any,
    ) -> None:
        """Process control direction ASDU."""
        type_id = self._parse_int(type_id_raw, 0, base=16)
        session.type_ids_ctrl.add(type_id)
        session.control_count += 1

        type_name = ASDU_TYPE_CTRL.get(type_id, f"Ctrl Type {type_id}")

        # COT for control direction
        cot_raw = self.get_field(iec103_layer, "cot_ctrl", None)
        cot = self._parse_int(cot_raw, 0, base=16)
        cot_name = COT_CTRL.get(cot, str(cot))

        # Extract additional details based on type
        detail_str = ""
        extra: Dict[str, Any] = {}

        if type_id == 6:
            # Time synchronization
            detail_str = "Time sync command"
        elif type_id == 7:
            # General interrogation
            scan_raw = self.get_field(iec103_layer, "scn", None)
            scan_num = self._parse_int(scan_raw, default=None)
            if scan_num is not None:
                detail_str = f"GI scan={scan_num}"
                extra["scan_number"] = scan_num
            else:
                detail_str = "General interrogation"
        elif type_id == 20:
            # General command
            dco_raw = self.get_field(iec103_layer, "dco", None)
            dco = self._parse_int(dco_raw, default=None)
            rii_raw = self.get_field(iec103_layer, "rii", None)
            rii = self._parse_int(rii_raw, default=None)
            if dco is not None:
                dco_name = _DCO_VALUES.get(dco, str(dco))
                detail_str = f"GC DCO={dco_name}"
                extra["dco"] = dco
                extra["dco_name"] = dco_name
            else:
                detail_str = "General command"
            if rii is not None:
                extra["rii"] = rii
        elif type_id == 24:
            # Order for disturbance data transmission
            detail_str = "Disturbance data order"
        elif type_id == 25:
            # Acknowledgement for disturbance data
            detail_str = "Disturbance data ACK"

        # Determine rw classification
        if type_id in (20, 21):
            rw = "write"
        elif type_id == 7:
            rw = "read"
        elif type_id == 6:
            rw = "control"
        elif type_id in (24, 25):
            rw = "control"
        else:
            rw = "write"

        func_name = _get_function_type_name(func_type) if func_type is not None else ""

        details: Dict[str, Any] = {
            "type_id": type_id,
            "type_name": type_name,
            "direction_type": "control",
            "link_addr": link_addr,
            "asdu_addr": asdu_addr,
            "cot": cot,
            "cot_name": cot_name,
            "rw": rw,
            "detail_str": detail_str,
        }
        if func_type is not None:
            details["func_type"] = func_type
            details["func_type_name"] = func_name
        if info_num is not None:
            details["info_num"] = info_num
        details.update(extra)

        func_str = f" {func_name}" if func_name else ""
        info_str = f" IN={info_num}" if info_num is not None else ""
        summary = (
            f"CMD {type_name} LA={link_addr} CA={asdu_addr}{func_str}{info_str} COT={cot_name}"
        )
        if detail_str:
            summary += f" [{detail_str}]"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            type_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _process_monitor_asdu(
        self,
        packet,
        session: IEC103Session,
        iec103_layer,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        asdu_addr: int,
        func_type: Optional[int],
        info_num: Optional[int],
        type_id_raw: Any,
    ) -> None:
        """Process monitor direction ASDU."""
        type_id = self._parse_int(type_id_raw, 0, base=16)
        session.type_ids_mon.add(type_id)
        session.monitor_count += 1

        type_name = ASDU_TYPE_MON.get(type_id, f"Mon Type {type_id}")

        # COT for monitor direction
        cot_raw = self.get_field(iec103_layer, "cot_mon", None)
        cot = self._parse_int(cot_raw, 0, base=16)
        cot_name = COT_MON.get(cot, str(cot))

        detail_str = ""
        extra: Dict[str, Any] = {}

        if type_id == 1:
            # Time-tagged message (event)
            dpi_raw = self.get_field(iec103_layer, "dpi", None)
            dpi = self._parse_int(dpi_raw, default=None)
            if dpi is not None:
                dpi_name = _DPI_VALUES.get(dpi, str(dpi))
                detail_str = f"DPI={dpi_name}"
                extra["dpi"] = dpi
                extra["dpi_name"] = dpi_name
        elif type_id == 2:
            # Time-tagged message with relative time
            dpi_raw = self.get_field(iec103_layer, "dpi", None)
            dpi = self._parse_int(dpi_raw, default=None)
            sin_raw = self.get_field(iec103_layer, "sin", None)
            sin = self._parse_int(sin_raw, default=None)
            if dpi is not None:
                dpi_name = _DPI_VALUES.get(dpi, str(dpi))
                detail_str = f"DPI={dpi_name}"
                extra["dpi"] = dpi
            if sin is not None:
                extra["supplementary_info"] = sin
        elif type_id == 5:
            # Identification
            mfg_raw = self.get_field(iec103_layer, "mfg", None)
            mfg_sw_raw = self.get_field(iec103_layer, "mfg_sw", None)
            col_raw = self.get_field(iec103_layer, "col", None)
            if mfg_raw:
                detail_str = f"MFG={mfg_raw}"
                extra["manufacturer"] = str(mfg_raw)
                session.manufacturer = str(mfg_raw)
            if mfg_sw_raw:
                extra["manufacturer_sw"] = str(mfg_sw_raw)
                session.manufacturer_sw = str(mfg_sw_raw)
                if detail_str:
                    detail_str += f" SW={mfg_sw_raw}"
            if col_raw:
                extra["compatibility_level"] = self._parse_int(col_raw, 0)
        elif type_id == 6:
            # Time synchronization response
            detail_str = "Time sync response"
        elif type_id == 8:
            # General interrogation termination
            detail_str = "GI termination"
        elif type_id in (23, 26, 27, 28, 29, 30, 31):
            # Disturbance data transfer types
            dist_names = {
                23: "Disturbance list",
                26: "Ready for disturbance data",
                27: "Ready for channel",
                28: "Ready for tags",
                29: "Tag transmission",
                30: "Disturbance values",
                31: "End of transmission",
            }
            detail_str = dist_names.get(type_id, "")

        # Classify rw (monitor direction is always "read")
        rw = "read"

        func_name = _get_function_type_name(func_type) if func_type is not None else ""

        details: Dict[str, Any] = {
            "type_id": type_id,
            "type_name": type_name,
            "direction_type": "monitor",
            "link_addr": link_addr,
            "asdu_addr": asdu_addr,
            "cot": cot,
            "cot_name": cot_name,
            "rw": rw,
            "detail_str": detail_str,
        }
        if func_type is not None:
            details["func_type"] = func_type
            details["func_type_name"] = func_name
        if info_num is not None:
            details["info_num"] = info_num
        details.update(extra)

        func_str = f" {func_name}" if func_name else ""
        info_str = f" IN={info_num}" if info_num is not None else ""
        summary = (
            f"MON {type_name} LA={link_addr} CA={asdu_addr}{func_str}{info_str} COT={cot_name}"
        )
        if detail_str:
            summary += f" [{detail_str}]"

        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            type_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    def _process_link_frame(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        is_primary: bool,
    ) -> None:
        """Process link-layer only frame (no ASDU type IDs found)."""
        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)

        iec103_layer = packet.iec60870_5_103

        if is_primary:
            func_raw = self.get_field(iec103_layer, "ctrl_func_pri_to_sec", None)
            func_code = self._parse_int(func_raw, -1)
            func_name = LINK_FUNC_PRI_TO_SEC.get(func_code, f"PRI Func {func_code}")
            direction = "request"
        else:
            func_raw = self.get_field(iec103_layer, "ctrl_func_sec_to_pri", None)
            func_code = self._parse_int(func_raw, -1)
            func_name = LINK_FUNC_SEC_TO_PRI.get(func_code, f"SEC Func {func_code}")
            direction = "response"

        operation = f"Link: {func_name}"

        details: Dict[str, Any] = {
            "link_addr": link_addr,
            "frame_type": "link",
            "is_primary": is_primary,
            "rw": "",
        }
        if func_code >= 0:
            details["link_func_code"] = func_code
            details["link_func_name"] = func_name

        summary = f"Link {func_name} addr={link_addr}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        rw = d.get("rw", "")
        link_addr = d.get("link_addr", "")

        type_id = d.get("type_id", "")
        type_name = d.get("type_name", "")
        type_str = f"{type_id} ({type_name})" if type_id else ""

        func_type = d.get("func_type")
        func_name = d.get("func_type_name", "")
        func_str = f"{func_type} ({func_name})" if func_type is not None else ""

        info_num = d.get("info_num")
        info_str = str(info_num) if info_num is not None else ""

        cot_name = d.get("cot_name", "")

        detail_str = d.get("detail_str", "")

        return [
            rw,
            ix.operation,
            link_addr if link_addr else "",
            type_str,
            func_str,
            info_str,
            cot_name,
            detail_str,
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

        # Controlled device (protection relay)
        if is_valid_discovered_ip(controlled_ip):
            controlled_vendor = lookup_mac_vendor(controlled_mac) if controlled_mac else ""
            key = f"iec103-relay:{controlled_ip}"
            device, is_new = self._ensure_device(
                key,
                controlled_ip,
                mac=controlled_mac,
                manufacturer=controlled_vendor if controlled_vendor else "",
                device_type="IEC 103 Protection Relay",
            )
            device.protocol_data = self._build_data("protection_relay", session)
            if is_new:
                self.logger.debug(
                    f"IEC103: Relay {controlled_ip} LA={list(session.link_addresses)} "
                    f"CA={list(session.asdu_addresses)}"
                )

        # Controlling device (bay controller / SA system)
        if is_valid_discovered_ip(controlling_ip):
            controlling_vendor = lookup_mac_vendor(controlling_mac) if controlling_mac else ""
            key = f"iec103-controller:{controlling_ip}"
            device, is_new = self._ensure_device(
                key,
                controlling_ip,
                mac=controlling_mac,
                manufacturer=controlling_vendor,
                device_type="IEC 103 Bay Controller",
            )
            device.protocol_data = self._build_data("bay_controller", session)

    def _build_data(self, role: str, session: IEC103Session) -> Dict[str, Any]:
        """Build protocol_data dict."""
        all_type_ids = sorted(session.type_ids_mon | session.type_ids_ctrl)
        func_names = [_get_function_type_name(ft) for ft in sorted(session.function_types)]
        data: Dict[str, Any] = {
            "role": role,
            "link_addresses": sorted(list(session.link_addresses)),
            "asdu_addresses": sorted(list(session.asdu_addresses)),
            "type_ids_monitor": sorted(list(session.type_ids_mon)),
            "type_ids_control": sorted(list(session.type_ids_ctrl)),
            "type_ids_all": all_type_ids,
            "function_types": sorted(list(session.function_types)),
            "function_type_names": func_names,
            "control_commands": session.control_count,
            "monitor_messages": session.monitor_count,
            "protocol": "IEC103/Serial",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }
        if session.manufacturer:
            data["manufacturer"] = session.manufacturer
        if session.manufacturer_sw:
            data["manufacturer_sw"] = session.manufacturer_sw
        return data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed IEC 103 sessions."""
        return [
            {
                "controlling": s.controlling_ip,
                "controlled": s.controlled_ip,
                "link_addresses": sorted(list(s.link_addresses)),
                "asdu_addresses": sorted(list(s.asdu_addresses)),
                "function_types": sorted(list(s.function_types)),
                "type_ids_mon": sorted(list(s.type_ids_mon)),
                "type_ids_ctrl": sorted(list(s.type_ids_ctrl)),
                "control_count": s.control_count,
                "monitor_count": s.monitor_count,
            }
            for s in self.sessions.values()
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with control operations."""
        return [
            {
                "controlling": s.controlling_ip,
                "controlled": s.controlled_ip,
                "control_count": s.control_count,
                "control_types": [
                    ASDU_TYPE_CTRL.get(t, f"Ctrl Type {t}")
                    for t in s.type_ids_ctrl
                    if t in _CONTROL_TYPE_IDS
                ],
            }
            for s in self.sessions.values()
            if s.control_count > 0
        ]
