"""
DNP3 Passive Listener for SCADA traffic analysis (ICS).

Passively captures DNP3 (Distributed Network Protocol 3) traffic to extract:
- Application layer function codes (read, write, direct operate, select-before-operate)
- Data object types (binary input/output, analog input/output, counters)
- Object group and variation
- Control operations (commanded state, trip/close)
- Data link layer function codes and addresses
- Application sequence numbers and internal indications
- File transfer operations (name, status, authentication)

DNP3 is widely used in electric utilities and water/wastewater for
SCADA master-outstation communication, typically on TCP port 20000.

tshark fields used:
- dnp3.al.func: Application layer function code (FT_UINT8)
- dnp3.al.obj: Object header (group:variation as FT_UINT16)
- dnp3.al.iin: Internal indications (FT_UINT16)
- dnp3.al.seq: Application layer sequence number (FT_UINT8)
- dnp3.al.ctrlstatus: Control relay output block status (FT_UINT8)
- dnp3.dst: Destination address (FT_UINT16)
- dnp3.src: Source address (FT_UINT16)
- dnp3.addr: Address field (FT_UINT16)
- dnp3.al.range.start: Object start index (FT_UINT8)
- dnp3.al.range.stop: Object stop index (FT_UINT8)
- dnp3.al.range.quantity: Object quantity (FT_UINT8)
- dnp3.al.bocs: Binary output commanded state (FT_BOOLEAN)
- dnp3.ctl.op: Control code operation type (FT_UINT8)
- dnp3.ctl.trip: Control code trip/close (FT_UINT8)
- dnp3.ctl.prifunc: Data link primary function code (FT_UINT8)
- dnp3.ctl.secfunc: Data link secondary function code (FT_UINT8)
- dnp3.al.file.auth: File authentication key (FT_UINT32)
- dnp3.al.file.reqID: File request ID (FT_UINT16)
- dnp3.al.file.status: File operation status (FT_UINT8)
- dnp3.al.file_name: File name (FT_STRING)

References:
- IEEE 1815 (DNP3) standard
- Wireshark dissector: packet-dnp.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

import logging

logger = logging.getLogger(__name__)


# DNP3 application layer function codes
DNP3_FUNCTIONS = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "Direct Operate",
    0x06: "Direct Operate No Ack",
    0x07: "Immediate Freeze",
    0x08: "Immediate Freeze No Ack",
    0x09: "Freeze and Clear",
    0x0A: "Freeze and Clear No Ack",
    0x0B: "Freeze at Time",
    0x0C: "Freeze at Time No Ack",
    0x0D: "Cold Restart",
    0x0E: "Warm Restart",
    0x0F: "Initialize Data",
    0x10: "Initialize Application",
    0x11: "Start Application",
    0x12: "Stop Application",
    0x13: "Save Configuration",
    0x14: "Enable Unsolicited",
    0x15: "Disable Unsolicited",
    0x16: "Assign Class",
    0x17: "Delay Measurement",
    0x18: "Record Current Time",
    0x19: "Open File",
    0x1A: "Close File",
    0x1B: "Delete File",
    0x1C: "Get File Info",
    0x1D: "Authenticate File",
    0x1E: "Abort File",
    0x81: "Response",
    0x82: "Unsolicited Response",
}

# DNP3 object groups
DNP3_GROUPS = {
    1: "Binary Input",
    2: "Binary Input Event",
    3: "Double-bit Binary Input",
    4: "Double-bit Binary Input Event",
    10: "Binary Output",
    11: "Binary Output Event",
    12: "Binary Output Command (CROB)",
    20: "Counter",
    21: "Frozen Counter",
    22: "Counter Event",
    23: "Frozen Counter Event",
    30: "Analog Input",
    31: "Frozen Analog Input",
    32: "Analog Input Event",
    33: "Frozen Analog Input Event",
    40: "Analog Output Status",
    41: "Analog Output Command",
    42: "Analog Output Event",
    50: "Time and Date",
    51: "Time and Date CTO",
    52: "Time Delay",
    60: "Class Data",
    70: "File Identification",
    80: "Internal Indications",
    110: "Octet String",
    111: "Octet String Event",
    120: "Authentication",
}

# DNP3 data link layer primary function codes
DNP3_DL_PRIMARY_FUNCTIONS = {
    0: "Reset Link",
    1: "Reset User Process",
    2: "Test Link",
    3: "User Data (Confirmed)",
    4: "Unconfirmed User Data",
    9: "Request Link Status",
}

# DNP3 data link layer secondary function codes
DNP3_DL_SECONDARY_FUNCTIONS = {
    0: "ACK",
    1: "NACK",
    11: "Link Status",
    15: "Not Supported",
}

# DNP3 file operation status codes
DNP3_FILE_STATUS = {
    0: "Success",
    1: "Permission Denied",
    2: "Invalid Mode",
    3: "File Not Found",
    4: "File Locked",
    5: "Not Opened",
    6: "Handle Expired",
    7: "Buffer Overrun",
    8: "Fatal Error",
    9: "Block Sequence Error",
    16: "Undefined",
}

# DNP3 CROB control status codes
DNP3_CTRL_STATUS = {
    0: "Success",
    1: "Timeout",
    2: "No Select",
    3: "Format Error",
    4: "Not Supported",
    5: "Already Active",
    6: "Hardware Error",
    7: "Local",
    8: "Too Many Objs",
    9: "Not Authorized",
    10: "Automation Inhibit",
    11: "Processing Limited",
    12: "Out of Range",
    126: "Non-Participating",
    127: "Undefined",
}

# Write/control function codes (security-relevant)
DNP3_WRITE_FUNCTIONS = {
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,  # Write, Select, Operate, Direct Operate
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,  # Freeze variants
    0x0D,
    0x0E,  # Cold/Warm Restart
    0x0F,
    0x10,
    0x11,
    0x12,  # Initialize, Start, Stop Application
    0x13,  # Save Config
    0x14,
    0x15,  # Enable/Disable Unsolicited
    0x16,  # Assign Class
    0x19,
    0x1A,
    0x1B,  # Open/Close/Delete File
    0x1D,
    0x1E,  # Authenticate/Abort File
}

# IIN bit definitions (Internal Indications, 2 bytes)
# IIN1 (first byte)
_IIN1_BROADCAST = 0x01
_IIN1_CLASS1 = 0x02
_IIN1_CLASS2 = 0x04
_IIN1_CLASS3 = 0x08
_IIN1_NEED_TIME = 0x10
_IIN1_LOCAL_CTRL = 0x20
_IIN1_DEVICE_TROUBLE = 0x40
_IIN1_DEVICE_RESTART = 0x80

# IIN2 (second byte) — error-class bits
_IIN2_NO_FUNC_CODE = 0x01
_IIN2_OBJECT_UNKNOWN = 0x02
_IIN2_PARAM_ERROR = 0x04
_IIN2_EVENT_OVERFLOW = 0x08
_IIN2_ALREADY_EXECUTING = 0x10
_IIN2_CONFIG_CORRUPT = 0x20

_IIN_FLAGS = [
    (0, _IIN1_BROADCAST, "BROADCAST"),
    (0, _IIN1_CLASS1, "CLASS1"),
    (0, _IIN1_CLASS2, "CLASS2"),
    (0, _IIN1_CLASS3, "CLASS3"),
    (0, _IIN1_NEED_TIME, "NEED_TIME"),
    (0, _IIN1_LOCAL_CTRL, "LOCAL_CTRL"),
    (0, _IIN1_DEVICE_TROUBLE, "TROUBLE"),
    (0, _IIN1_DEVICE_RESTART, "RESTART"),
    (1, _IIN2_NO_FUNC_CODE, "NO_FUNC"),
    (1, _IIN2_OBJECT_UNKNOWN, "OBJ_UNKNOWN"),
    (1, _IIN2_PARAM_ERROR, "PARAM_ERR"),
    (1, _IIN2_EVENT_OVERFLOW, "EVT_OVERFLOW"),
    (1, _IIN2_ALREADY_EXECUTING, "ALREADY_EXEC"),
    (1, _IIN2_CONFIG_CORRUPT, "CONFIG_CORRUPT"),
]

# IIN2 bits that indicate error-class conditions
_IIN2_ERROR_BITS = (
    _IIN2_NO_FUNC_CODE | _IIN2_OBJECT_UNKNOWN | _IIN2_PARAM_ERROR | _IIN2_CONFIG_CORRUPT
)


def _decode_iin(iin_value: int) -> str:
    """Decode IIN 16-bit value into human-readable flags."""
    iin1 = iin_value & 0xFF
    iin2 = (iin_value >> 8) & 0xFF
    flags = []
    for byte_idx, mask, name in _IIN_FLAGS:
        byte_val = iin1 if byte_idx == 0 else iin2
        if byte_val & mask:
            flags.append(name)
    return ",".join(flags) if flags else ""


@dataclass
class DNP3Session:
    """Track DNP3 session statistics."""

    controlling_ip: str  # Master/SCADA
    controlled_ip: str  # Outstation/RTU
    function_codes: Set[int] = field(default_factory=set)
    object_groups: Set[int] = field(default_factory=set)
    control_count: int = 0
    monitor_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class DNP3PassiveListener(PySharkListenerBase):
    """Passive DNP3 traffic listener for SCADA interaction analysis.

    Captures DNP3 protocol traffic to extract:
    - Function codes (read, write, operate, select-before-operate)
    - Object types and point ranges
    - Control operations (binary output commands)
    - Restart and configuration operations
    """

    PROTOCOL_NAME = "dnp3"
    DISPLAY_FILTER = "dnp3"
    REQUIRED_LAYERS = ("dnp3",)
    PROTOCOL_COLUMNS = ("src_addr", "dst_addr", "function", "object", "points", "data", "iin")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], DNP3Session] = {}
        # Cache: (src_ip, dst_ip) -> is_response, learned from FIR fragments
        # so continuation/FIN fragments can determine direction correctly.
        self._frag_direction_cache: Dict[Tuple[str, str], bool] = {}

    def process_packet(self, packet) -> None:
        """Process DNP3 packet and extract interactions."""
        if not hasattr(packet, "dnp3"):
            return

        dnp3 = packet.dnp3
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get MAC addresses for vendor lookup
        src_mac, dst_mac = self.get_mac_info(packet)

        now = datetime.now().isoformat()

        # Extract DNP3 addresses (use dnp3_ prefix to avoid audit _IGNORE filter)
        dnp3_src = 0
        dnp3_dst = 0
        src_raw = self.get_field(dnp3, "dnp3_src", None)
        if src_raw is None:
            src_raw = self.get_field(dnp3, "src", None)
        dst_raw = self.get_field(dnp3, "dnp3_dst", None)
        if dst_raw is None:
            dst_raw = self.get_field(dnp3, "dst", None)
        if src_raw:
            try:
                dnp3_src = int(src_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get dnp3_src: {e}")
        if dst_raw:
            try:
                dnp3_dst = int(dst_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get dnp3_dst: {e}")

        # Extract generic address field (list of [dst, src] in EK mode)
        addr_raw = self.get_field(dnp3, "dnp3_addr", None)
        if addr_raw is None:
            addr_raw = self.get_field(dnp3, "addr", None)

        # Extract data link layer primary function code
        prifunc_raw = self.get_field(dnp3, "ctl_prifunc", None)
        prifunc = None
        if prifunc_raw is not None:
            try:
                prifunc = int(prifunc_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get prifunc: {e}")

        # Extract data link layer secondary function code
        secfunc_raw = self.get_field(dnp3, "ctl_secfunc", None)
        secfunc = None
        if secfunc_raw is not None:
            try:
                secfunc = int(secfunc_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get secfunc: {e}")

        # Extract application layer function code
        func_raw = self.get_field(dnp3, "al_func", None)
        if func_raw is None:
            func_raw = self.get_field(dnp3, "al.func", None)
        func_code = None
        if func_raw is not None:
            try:
                func_code = int(func_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get func_code: {e}")

        if func_code is None:
            # No application layer -- handle link-layer-only frames and
            # transport fragments so every packet produces an interaction.
            self._process_non_app_packet(
                packet,
                dnp3,
                src_ip,
                dst_ip,
                flow_id,
                dnp3_src,
                dnp3_dst,
                prifunc,
                secfunc,
                src_mac,
                dst_mac,
                now,
                addr_raw,
            )
            return

        func_name = DNP3_FUNCTIONS.get(func_code, f"Func 0x{func_code:02x}")
        is_response = func_code in (0x81, 0x82)

        # Confirm (0x00) can be sent by either master or outstation.
        # Use session history to determine if the sender is already known
        # as an outstation (response side) or master (request side).
        if func_code == 0x00:
            # If we've seen this IP pair as (master, outstation) before,
            # the sender is the outstation confirming.
            if (dst_ip, src_ip) in self.sessions:
                is_response = True
            elif (src_ip, dst_ip) in self.sessions:
                is_response = False
            # Else: no existing session -> use DNP3 address heuristic
            elif dnp3_src > 0 and dnp3_dst > 0 and dnp3_src != dnp3_dst:
                is_response = dnp3_src > dnp3_dst

        direction = "response" if is_response else "request"

        # Extract application sequence number
        al_seq_raw = self.get_field(dnp3, "al_seq", None)
        al_seq = None
        if al_seq_raw is not None:
            try:
                al_seq = int(al_seq_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get al_seq: {e}")

        # Extract object group/variation
        obj_raw = self.get_field(dnp3, "al_obj", None)
        if obj_raw is None:
            obj_raw = self.get_field(dnp3, "al.obj", None)

        group = 0
        variation = 0
        if obj_raw is not None:
            try:
                obj_val = (
                    int(obj_raw, 16)
                    if isinstance(obj_raw, str) and obj_raw.startswith("0x")
                    else int(obj_raw)
                )
                group = (obj_val >> 8) & 0xFF
                variation = obj_val & 0xFF
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get obj_val: {e}")

        group_name = DNP3_GROUPS.get(group, f"Group {group}")

        # Extract point range
        start_idx = self._parse_int_field(dnp3, "al_range_start", "al.range.start")
        stop_idx = self._parse_int_field(dnp3, "al_range_stop", "al.range.stop")
        quantity = self._parse_int_field(dnp3, "al_range_quantity", "al.range.quantity")

        # Extract Internal Indications (IIN) from responses -- security-relevant
        iin_raw = self._parse_int_field(dnp3, "al_iin", "al.iin")

        # Extract CROB control status
        ctrlstatus_raw = self.get_field(dnp3, "al_ctrlstatus", None)
        ctrlstatus = None
        if ctrlstatus_raw is not None:
            try:
                ctrlstatus = int(ctrlstatus_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get ctrlstatus: {e}")

        # Extract control-specific fields
        commanded_state = self.get_field(dnp3, "al_bocs", None)
        if commanded_state is None:
            commanded_state = self.get_field(dnp3, "al.bocs", None)
        ctl_op_raw = self.get_field(dnp3, "ctl_op", None)
        ctl_op = None
        if ctl_op_raw is not None:
            try:
                ctl_op = int(ctl_op_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get ctl_op: {e}")
        ctl_trip_raw = self.get_field(dnp3, "ctl_trip", None)
        ctl_trip = None
        if ctl_trip_raw is not None:
            try:
                ctl_trip = int(ctl_trip_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get ctl_trip: {e}")

        # Extract file operation fields
        file_name = self.get_field(dnp3, "al_file_name", None)
        file_auth_raw = self.get_field(dnp3, "al_file_auth", None)
        file_auth = None
        if file_auth_raw is not None:
            try:
                file_auth = int(file_auth_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get file_auth: {e}")
        file_reqid_raw = self.get_field(dnp3, "al_file_reqID", None)
        file_reqid = None
        if file_reqid_raw is not None:
            try:
                file_reqid = int(file_reqid_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get file_reqid: {e}")
        file_status_raw = self.get_field(dnp3, "al_file_status", None)
        file_status = None
        if file_status_raw is not None:
            try:
                file_status = int(file_status_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get file_status: {e}")

        # Extract data values from response/unsolicited data or command payloads
        values = self._extract_point_values(dnp3, group)

        # Build details
        details: Dict[str, Any] = {
            "function_code": func_code,
            "function_name": func_name,
            "dnp3_src": dnp3_src,
            "dnp3_dst": dnp3_dst,
        }

        # Data link layer fields
        if prifunc is not None:
            details["dl_prifunc"] = prifunc
            details["dl_prifunc_name"] = DNP3_DL_PRIMARY_FUNCTIONS.get(
                prifunc, f"DL Func {prifunc}"
            )
        if secfunc is not None:
            details["dl_secfunc"] = secfunc
            details["dl_secfunc_name"] = DNP3_DL_SECONDARY_FUNCTIONS.get(
                secfunc, f"DL Sec Func {secfunc}"
            )

        # Application layer sequence number
        if al_seq is not None:
            details["al_seq"] = al_seq

        if group:
            details["group"] = group
            details["variation"] = variation
            details["group_name"] = group_name

        if start_idx is not None:
            details["start_index"] = start_idx
        if stop_idx is not None:
            details["stop_index"] = stop_idx
        if quantity is not None:
            details["quantity"] = quantity
        if iin_raw is not None:
            details["iin"] = iin_raw
        if ctrlstatus is not None:
            details["ctrl_status"] = ctrlstatus
            details["ctrl_status_name"] = DNP3_CTRL_STATUS.get(ctrlstatus, f"Status {ctrlstatus}")
        if commanded_state is not None:
            details["commanded_state"] = str(commanded_state)
        if ctl_op is not None:
            details["control_operation"] = ctl_op
        if ctl_trip is not None:
            details["control_trip"] = ctl_trip

        # File operation fields
        if file_name is not None:
            details["file_name"] = str(file_name)
        if file_auth is not None:
            details["file_auth"] = file_auth
        if file_reqid is not None:
            details["file_reqid"] = file_reqid
        if file_status is not None:
            details["file_status"] = file_status
            details["file_status_name"] = DNP3_FILE_STATUS.get(file_status, f"Status {file_status}")

        if values:
            details["values"] = values

        # CRC integrity status (data-link header + data chunks)
        details.update(self._crc_status_info(dnp3))

        # Classify rw based on function code and IIN error bits
        if is_response and iin_raw is not None:
            iin2 = (iin_raw >> 8) & 0xFF
            if iin2 & _IIN2_ERROR_BITS:
                details["rw"] = "error"
        if "rw" not in details and not is_response:
            if func_code in DNP3_WRITE_FUNCTIONS:
                details["rw"] = "write"
            elif func_code == 0x01:
                details["rw"] = "read"

        # Build summary
        summary = self._build_summary(
            func_name,
            func_code,
            group,
            group_name,
            variation,
            start_idx,
            stop_idx,
            quantity,
            commanded_state,
        )

        src_port, dst_port = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            func_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update devices
        self._update_devices(
            src_ip,
            dst_ip,
            dnp3_src,
            dnp3_dst,
            is_response,
            func_code=func_code,
            group=group,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    # ------------------------------------------------------------------
    # Non-application-layer packet handling
    # ------------------------------------------------------------------

    def _process_non_app_packet(
        self,
        packet,
        dnp3,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        dnp3_src: int,
        dnp3_dst: int,
        prifunc: Optional[int],
        secfunc: Optional[int],
        src_mac: str,
        dst_mac: str,
        now: str,
        addr_raw: Any = None,
    ) -> None:
        """Handle packets without an application-layer function code.

        Two categories:
        1. **Link-layer control frames**: Reset Link, Request Link Status,
           ACK, NACK, Link Status, Not Supported.  No transport header.
        2. **Transport-layer fragments**: Data link carries user data
           (prifunc=3 or 4) but the application layer is split across
           multiple transport segments.  Only the final segment (or
           single-segment messages) gets ``al.func`` from tshark.
        """
        # Determine if this is a transport fragment vs link-only
        tr_fir_raw = self.get_field(dnp3, "tr_fir", None)
        tr_fin_raw = self.get_field(dnp3, "tr_fin", None)
        has_transport = tr_fir_raw is not None

        if has_transport:
            self._process_transport_fragment(
                packet,
                dnp3,
                src_ip,
                dst_ip,
                flow_id,
                dnp3_src,
                dnp3_dst,
                prifunc,
                secfunc,
                src_mac,
                dst_mac,
                now,
                tr_fir_raw,
                tr_fin_raw,
            )
        else:
            self._process_link_control(
                packet,
                dnp3,
                src_ip,
                dst_ip,
                flow_id,
                dnp3_src,
                dnp3_dst,
                prifunc,
                secfunc,
                src_mac,
                dst_mac,
                now,
            )

    def _process_link_control(
        self,
        packet,
        dnp3,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        dnp3_src: int,
        dnp3_dst: int,
        prifunc: Optional[int],
        secfunc: Optional[int],
        src_mac: str,
        dst_mac: str,
        now: str,
    ) -> None:
        """Record an interaction for a link-layer-only control frame."""
        # Determine direction from PRM bit: PRM=1 means primary (master -> outstation)
        ctl_prm_raw = self.get_field(dnp3, "ctl_prm", None)
        is_primary = self._parse_bool(ctl_prm_raw)

        if prifunc is not None:
            func_name = DNP3_DL_PRIMARY_FUNCTIONS.get(prifunc, f"DL Func {prifunc}")
            operation = f"DL: {func_name}"
            direction = "request" if is_primary else "response"
        elif secfunc is not None:
            func_name = DNP3_DL_SECONDARY_FUNCTIONS.get(secfunc, f"DL Sec {secfunc}")
            operation = f"DL: {func_name}"
            direction = "response"  # secondary functions are always responses
        else:
            operation = "DL: Unknown"
            direction = "request"
            self.logger.debug(f"DNP3 link frame with no prifunc/secfunc from {src_ip} -> {dst_ip}")

        details: Dict[str, Any] = {
            "dnp3_src": dnp3_src,
            "dnp3_dst": dnp3_dst,
            "layer": "link",
        }
        if prifunc is not None:
            details["dl_prifunc"] = prifunc
            details["dl_prifunc_name"] = DNP3_DL_PRIMARY_FUNCTIONS.get(
                prifunc, f"DL Func {prifunc}"
            )
        if secfunc is not None:
            details["dl_secfunc"] = secfunc
            details["dl_secfunc_name"] = DNP3_DL_SECONDARY_FUNCTIONS.get(
                secfunc, f"DL Sec Func {secfunc}"
            )
        details.update(self._crc_status_info(dnp3))

        summary = f"{operation} addr {dnp3_src}->{dnp3_dst}"

        src_port, dst_port = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update devices -- link-layer frames reveal roles:
        # secfunc is set -> sender is secondary station (outstation responding)
        # prifunc is set -> sender is primary station (but could be master or outstation)
        # For link-control frames, secfunc is a reliable indicator of outstation.
        is_response = secfunc is not None
        self._update_devices(
            src_ip,
            dst_ip,
            dnp3_src,
            dnp3_dst,
            is_response,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    def _process_transport_fragment(
        self,
        packet,
        dnp3,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        dnp3_src: int,
        dnp3_dst: int,
        prifunc: Optional[int],
        secfunc: Optional[int],
        src_mac: str,
        dst_mac: str,
        now: str,
        tr_fir_raw: Any,
        tr_fin_raw: Any,
    ) -> None:
        """Record an interaction for a transport-layer fragment without app layer.

        For first fragments (FIR=1), we can peek at ``al_frag_data`` to
        extract the application function code from the raw reassembly buffer.
        For continuation fragments (FIR=0), we record them as transport
        continuation frames.
        """
        is_fir = self._parse_bool(tr_fir_raw)
        is_fin = self._parse_bool(tr_fin_raw)

        tr_seq_raw = self.get_field(dnp3, "tr_seq", None)
        tr_seq = None
        if tr_seq_raw is not None:
            try:
                tr_seq = int(tr_seq_raw)
            except (ValueError, TypeError):
                tr_seq = None

        # Determine direction from PRM bit
        ctl_prm_raw = self.get_field(dnp3, "ctl_prm", None)
        is_primary = self._parse_bool(ctl_prm_raw)

        # Try to extract function code from raw fragment data on FIR segments.
        # Use getattr directly -- get_field() converts bytes to hex strings.
        peeked_func_code = None
        peeked_func_name = None
        if is_fir:
            try:
                al_frag_data = getattr(dnp3, "al_frag_data", None)
            except Exception:
                al_frag_data = None
            if al_frag_data is not None:
                fc_byte = self._peek_func_code_from_frag(al_frag_data)
                if fc_byte is not None:
                    peeked_func_code = fc_byte
                    peeked_func_name = DNP3_FUNCTIONS.get(
                        peeked_func_code, f"Func 0x{peeked_func_code:02x}"
                    )

        # Build operation name
        if is_fir and peeked_func_name:
            operation = f"Transport Fragment (FIR): {peeked_func_name}"
            frag_label = "FIR"
        elif is_fir:
            operation = "Transport Fragment (FIR)"
            frag_label = "FIR"
        elif is_fin:
            operation = "Transport Fragment (FIN)"
            frag_label = "FIN"
        else:
            operation = "Transport Fragment"
            frag_label = "MID"

        # Determine direction: for responses (func >= 0x81), the sender is
        # the outstation; for requests, the sender is the master.
        # Cache the direction from FIR fragments so MID/FIN fragments
        # (which lack a function code) use the correct direction.
        flow_key = (src_ip, dst_ip)
        if peeked_func_code is not None:
            is_response = peeked_func_code >= 0x81
            direction = "response" if is_response else "request"
            # Cache for subsequent fragments in this direction
            self._frag_direction_cache[flow_key] = is_response
        elif flow_key in self._frag_direction_cache:
            # Use cached direction from the FIR fragment
            is_response = self._frag_direction_cache[flow_key]
            direction = "response" if is_response else "request"
        else:
            # Last resort: use DNP3 address heuristic -- the higher address
            # is typically the outstation (e.g. 100 vs 1), so if the sender's
            # DNP3 address > destination's, the sender is the outstation.
            if dnp3_src > 0 and dnp3_dst > 0 and dnp3_src != dnp3_dst:
                is_response = dnp3_src > dnp3_dst
            else:
                is_response = not is_primary
            direction = "response" if is_response else "request"

        details: Dict[str, Any] = {
            "dnp3_src": dnp3_src,
            "dnp3_dst": dnp3_dst,
            "layer": "transport",
            "frag_type": frag_label,
        }
        if tr_seq is not None:
            details["tr_seq"] = tr_seq
        if prifunc is not None:
            details["dl_prifunc"] = prifunc
            details["dl_prifunc_name"] = DNP3_DL_PRIMARY_FUNCTIONS.get(
                prifunc, f"DL Func {prifunc}"
            )
        if secfunc is not None:
            details["dl_secfunc"] = secfunc
            details["dl_secfunc_name"] = DNP3_DL_SECONDARY_FUNCTIONS.get(
                secfunc, f"DL Sec Func {secfunc}"
            )
        if peeked_func_code is not None:
            details["function_code"] = peeked_func_code
            details["function_name"] = peeked_func_name
        details.update(self._crc_status_info(dnp3))

        seq_str = f" seq={tr_seq}" if tr_seq is not None else ""
        func_str = f" {peeked_func_name}" if peeked_func_name else ""
        summary = f"Transport {frag_label}{func_str} addr {dnp3_src}->{dnp3_dst}{seq_str}"

        src_port, dst_port = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update devices -- pass peeked func_code for session tracking
        self._update_devices(
            src_ip,
            dst_ip,
            dnp3_src,
            dnp3_dst,
            is_response,
            func_code=peeked_func_code if peeked_func_code is not None else 0,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    @staticmethod
    def _peek_func_code_from_frag(al_frag_data: Any) -> Optional[int]:
        """Extract the application function code from raw fragment data.

        ``al_frag_data`` may be raw ``bytes`` (EK mode) or a colon-hex
        string (``"87:81:14:00:..."``) depending on the pyshark mode and
        the base-class ``get_field()`` normalization.  We need byte index 1
        (the function code; byte 0 is the application control byte).
        """
        if isinstance(al_frag_data, bytes) and len(al_frag_data) >= 2:
            return al_frag_data[1]
        if isinstance(al_frag_data, str) and ":" in al_frag_data:
            parts = al_frag_data.split(":")
            if len(parts) >= 2:
                try:
                    return int(parts[1], 16)
                except (ValueError, TypeError) as e:
                    logger.debug(f"Return value computation failed: {e}")
        return None

    def _crc_status_info(self, dnp3) -> Dict[str, Any]:
        """Extract DNP3 CRC validation status (header + data chunks).

        tshark validates each DNP3 block CRC and exposes the result as
        ``dnp.hdr.CRC.status`` (data-link header CRC) and
        ``dnp.data_chunk.CRC.status`` (per-data-chunk CRC).  Status values:
        ``1`` = Good, ``2`` = Bad, ``0`` = not present/unverified.  A bad CRC
        on passively observed traffic is a genuine integrity anomaly
        (corruption, truncation, or a malformed/injected frame), so we
        surface ``crc_bad`` for downstream alerting.

        Returns a dict suitable for ``details.update()``; empty if no CRC
        status fields are present.
        """
        info: Dict[str, Any] = {}
        bad = False
        hdr_raw = self.get_field(dnp3, "dnp_hdr_CRC_status", None)
        chunk_raw = self.get_field(dnp3, "dnp_data_chunk_CRC_status", None)
        for raw, key in ((hdr_raw, "hdr_crc_status"), (chunk_raw, "data_chunk_crc_status")):
            if raw is None:
                continue
            statuses = [s.strip() for s in str(raw).split(",") if s.strip()]
            if not statuses:
                continue
            info[key] = ",".join(statuses)
            # Status 2 = Bad CRC per tshark PROTO_CHECKSUM_E_BAD
            if any(s == "2" for s in statuses):
                bad = True
        if bad:
            info["crc_bad"] = True
        return info

    def _extract_point_values(self, dnp3, group: int) -> List[str]:
        """Extract data point values from DNP3 application layer.

        Tries analog (int/float/double), binary (bit), counter, and
        analog output fields based on the object group.

        Returns list of value strings, or [] if no values found.
        """
        vals: List[str] = []

        # Analog input values (groups 30, 32, etc.)
        if group in (30, 31, 32, 33, 34, 35, 36, 37):
            vals = self._get_multi_values(dnp3, "al_ana_int", "al.ana.int")
            if not vals:
                vals = self._get_multi_values(dnp3, "al_ana_float", "al.ana.float")
            if not vals:
                vals = self._get_multi_values(dnp3, "al_ana_double", "al.ana.double")

        # Analog output values (groups 40, 41, 42)
        elif group in (40, 41, 42):
            vals = self._get_multi_values(dnp3, "al_anaout_int", "al.anaout.int")
            if not vals:
                vals = self._get_multi_values(dnp3, "al_anaout_float", "al.anaout.float")
            if not vals:
                vals = self._get_multi_values(dnp3, "al_anaout_double", "al.anaout.double")

        # Double-bit binary (groups 3, 4) — must be checked before single-bit
        elif group in (3, 4):
            vals = self._get_multi_values(dnp3, "al_2bit", "al.2bit")

        # Binary input values (groups 1, 2, 10, 11)
        elif group in (1, 2, 10, 11):
            # dnp3.al.bit (single-bit) or dnp3.al.biq.b7 (point value in quality)
            vals = self._get_multi_values(dnp3, "al_bit", "al.bit")
            if not vals:
                vals = self._get_multi_values(dnp3, "al_biq_b7", "al.biq.b7")
            # Map True/False to ON/OFF for readability
            vals = [
                ("ON" if v in ("True", "1") else "OFF" if v in ("False", "0") else v) for v in vals
            ]

        # Counter values (groups 20, 21, 22, 23)
        elif group in (20, 21, 22, 23):
            vals = self._get_multi_values(dnp3, "al_cnt", "al.cnt")

        # Binary output command (group 12) -- commanded state
        elif group == 12:
            vals = self._get_multi_values(dnp3, "al_bocs", "al.bocs")
            vals = [
                ("ON" if v in ("True", "1") else "OFF" if v in ("False", "0") else v) for v in vals
            ]

        # If no group-specific extraction, try all value fields as fallback
        if not vals:
            for field_pair in [
                ("al_ana_int", "al.ana.int"),
                ("al_ana_float", "al.ana.float"),
                ("al_bit", "al.bit"),
                ("al_cnt", "al.cnt"),
                ("al_biq_b7", "al.biq.b7"),
            ]:
                vals = self._get_multi_values(dnp3, *field_pair)
                if vals:
                    break

        return vals

    def _get_multi_values(self, layer, *field_names) -> List[str]:
        """Try to extract multiple values from a DNP3 field.

        Handles PyShark multi-value fields (all_fields) and comma-separated.
        """
        for name in field_names:
            raw = self.get_field(layer, name, None)
            if raw is None:
                continue
            result: List[str] = []
            # Try all_fields for multi-value support
            try:
                for f in getattr(layer, name).all_fields:
                    result.append(str(f.show))
            except Exception:
                # Fallback: comma-separated or single value
                for part in str(raw).split(","):
                    part = part.strip()
                    if part:
                        result.append(part)
            if result:
                return result
        return []

    def _parse_int_field(self, layer, *field_names) -> Optional[int]:
        """Try to parse an integer from multiple possible field names."""
        for name in field_names:
            raw = self.get_field(layer, name, None)
            if raw is not None:
                try:
                    return int(raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Return value computation failed: {e}")
        return None

    @staticmethod
    def _build_summary(
        func_name: str,
        func_code: int,
        group: int,
        group_name: str,
        variation: int,
        start_idx: Optional[int],
        stop_idx: Optional[int],
        quantity: Optional[int],
        commanded_state: Optional[str],
    ) -> str:
        """Build human-readable summary."""
        parts = [func_name]

        if group:
            parts.append(f"{group_name} (g{group}v{variation})")

        if start_idx is not None and stop_idx is not None:
            parts.append(f"points {start_idx}-{stop_idx}")
        elif start_idx is not None and quantity is not None:
            parts.append(f"point {start_idx} qty={quantity}")
        elif quantity is not None:
            parts.append(f"qty={quantity}")

        if commanded_state is not None:
            state = "ON" if str(commanded_state) in ("1", "True", "true") else "OFF"
            parts.append(f"= {state}")

        return " ".join(parts)

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        dnp3_src: int,
        dnp3_dst: int,
        is_response: bool,
        func_code: int = 0,
        group: int = 0,
        src_mac: str = "",
        dst_mac: str = "",
    ) -> None:
        """Update device entries and session tracking."""
        if is_response:
            master_ip, outstation_ip = dst_ip, src_ip
            master_mac, outstation_mac = dst_mac, src_mac
        else:
            master_ip, outstation_ip = src_ip, dst_ip
            master_mac, outstation_mac = src_mac, dst_mac

        # Update session tracking
        session_key = (master_ip, outstation_ip)
        now = datetime.now().isoformat()
        if session_key not in self.sessions:
            self.sessions[session_key] = DNP3Session(
                controlling_ip=master_ip,
                controlled_ip=outstation_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[session_key]
        session.last_seen = now
        if func_code:
            session.function_codes.add(func_code)
        if group:
            session.object_groups.add(group)
        if func_code in DNP3_WRITE_FUNCTIONS:
            session.control_count += 1
        elif func_code and func_code not in (0x81, 0x82):
            session.monitor_count += 1

        if is_valid_discovered_ip(outstation_ip):
            out_vendor = lookup_mac_vendor(outstation_mac) if outstation_mac else ""
            out_key = f"dnp3-outstation:{outstation_ip}"
            device, is_new = self._ensure_device(
                out_key,
                outstation_ip,
                mac=outstation_mac,
                name=f"DNP3 Outstation ({outstation_ip})",
                manufacturer=out_vendor if out_vendor else "",
                device_type="DNP3 Outstation (RTU/IED)",
            )
            # Enrich on every packet (not just new)
            device.dnp3_passive_data = {
                "role": "outstation",
                "protocol": "DNP3/TCP",
                "function_codes": sorted(session.function_codes),
                "object_groups": sorted(session.object_groups),
            }

        if is_valid_discovered_ip(master_ip):
            master_vendor = lookup_mac_vendor(master_mac) if master_mac else ""
            master_key = f"dnp3-master:{master_ip}"
            device, is_new = self._ensure_device(
                master_key,
                master_ip,
                mac=master_mac,
                name=f"DNP3 Master ({master_ip})",
                manufacturer=master_vendor if master_vendor else "",
                device_type="DNP3 Master (SCADA)",
            )
            # Enrich on every packet (same as outstation)
            device.dnp3_passive_data = {
                "role": "master",
                "protocol": "DNP3/TCP",
                "targets": sorted(
                    {
                        s.controlled_ip
                        for s in self.sessions.values()
                        if s.controlling_ip == master_ip
                    }
                ),
            }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        func_name = d.get("function_name", "")
        group = d.get("group", "")
        group_name = d.get("group_name", "")
        variation = d.get("variation", "")
        obj_str = f"{group_name} (g{group}v{variation})" if group else ""

        start = d.get("start_index")
        stop = d.get("stop_index")
        qty = d.get("quantity")
        if start is not None and stop is not None:
            point_str = f"{start}-{stop}"
        elif start is not None and qty is not None:
            point_str = f"{start} (qty={qty})"
        elif qty is not None:
            point_str = f"qty={qty}"
        else:
            point_str = ""

        # Data column: point values or commanded state
        # Use " | " separator to avoid breaking CSV column parsing
        values = d.get("values", [])
        if isinstance(values, list) and values:
            data_str = " | ".join(values)
        elif d.get("commanded_state") is not None:
            state = d["commanded_state"]
            data_str = "ON" if state in ("1", "True", "true") else "OFF"
        else:
            data_str = ""

        # Decode IIN flags for display
        iin_val = d.get("iin")
        iin_str = _decode_iin(iin_val) if iin_val is not None else ""

        return [
            d.get("dnp3_src", ""),
            d.get("dnp3_dst", ""),
            func_name,
            obj_str,
            point_str,
            data_str,
            iin_str,
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed DNP3 sessions."""
        return [
            {
                "controlling": s.controlling_ip,
                "controlled": s.controlled_ip,
                "function_codes": sorted(s.function_codes),
                "object_groups": sorted(s.object_groups),
                "control_count": s.control_count,
                "monitor_count": s.monitor_count,
            }
            for s in self.sessions.values()
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with control/write operations."""
        return [
            {
                "controlling": s.controlling_ip,
                "controlled": s.controlled_ip,
                "control_count": s.control_count,
                "control_functions": [
                    DNP3_FUNCTIONS.get(fc, f"Func 0x{fc:02x}")
                    for fc in s.function_codes
                    if fc in DNP3_WRITE_FUNCTIONS
                ],
            }
            for s in self.sessions.values()
            if s.control_count > 0
        ]
