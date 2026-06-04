"""
HART-IP Passive Listener (PyShark-based).

Passively monitors HART-IP traffic to identify:
- HART field devices (transmitters, actuators) and host applications
- HART command codes in use (universal, common practice, device-specific)
- Process variable readings (PV, SV, TV, QV)
- Write operations (polling address changes, range/damping writes)
- Device identity (manufacturer, device type, device ID)
- Device status and health indicators

HART-IP carries standard HART (Highway Addressable Remote Transducer) commands
over IP (UDP/TCP port 5094). HART is the most widely used protocol for smart
field instruments in process industries.

HART-IP header (8 bytes):
- Version (1) + Message Type (1) + Message ID (1) + Status (1)
- Sequence Number (2) + Byte Count (2)

Message types: 0=Request, 1=Response, 2=Publish, 15=NAK

The pass-through (PT) payload carries a standard HART frame:
- Delimiter (1) + Address (1 or 5) + Command (1) + Length (1)
- [Response Code (1) + Device Status (1)] (responses only)
- Data (variable) + Checksum (1)

Security: HART-IP has **no encryption or authentication** by default.
All commands and process data travel in cleartext.

tshark fields used:
- hart_ip.message_type: Message type (0=req, 1=rsp, 2=publish)
- hart_ip.message_id: Message ID (0=session init, 1=session close,
  2=keep alive, 3=pass through)
- hart_ip.status: HART-IP status byte
- hart_ip.transaction_id: Sequence number
- hart_ip.pt.command: HART command number
- hart_ip.pt.short_addr: Short (polling) address 0-63
- hart_ip.pt.long_address: Long (unique) address bytes
- hart_ip.pt.response_code: Response code (0=success)
- hart_ip.pt.device_status: Device status byte
- hart_ip.pt.delimiter.address_type: 0=short, 1=long address
- hart_ip.pt.rsp.*: Decoded response fields per command

References:
- IEC 62591 (WirelessHART), HART Communication Foundation
- Wireshark dissector: packet-hartip.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# ---------------------------------------------------------------------------
# HART command code dictionary
# ---------------------------------------------------------------------------

# Universal commands (0-30): supported by all HART devices
HART_UNIVERSAL_COMMANDS = {
    0: "Read Unique Identifier",
    1: "Read Primary Variable",
    2: "Read Loop Current and Percent of Range",
    3: "Read Dynamic Variables and Loop Current",
    6: "Write Polling Address",
    7: "Read Loop Configuration",
    8: "Read Dynamic Variable Classifications",
    9: "Read Device Variables with Status",
    11: "Read Unique Identifier Associated with Tag",
    12: "Read Message",
    13: "Read Tag, Descriptor, Date",
    14: "Read Primary Variable Transducer Information",
    15: "Read Device Information",
    16: "Read Final Assembly Number",
    17: "Write Message",
    18: "Write Tag, Descriptor, Date",
    19: "Write Final Assembly Number",
    20: "Read Long Tag",
    21: "Read Unique Identifier Associated with Long Tag",
    22: "Write Long Tag",
}

# Common practice commands (33-126)
HART_COMMON_COMMANDS = {
    33: "Read Device Variables",
    34: "Write Primary Variable Damping Value",
    35: "Write Primary Variable Range Values",
    36: "Set Primary Variable Upper Range Value",
    37: "Set Primary Variable Lower Range Value",
    38: "Reset Configuration Changed Flag",
    40: "Enter/Exit Fixed Current Mode",
    41: "Perform Self-Test",
    42: "Perform Device Reset",
    43: "Set Primary Variable Zero",
    44: "Write Primary Variable Units",
    45: "Trim Loop Current Zero",
    46: "Trim Loop Current Gain",
    47: "Write Primary Variable Transfer Function",
    48: "Read Additional Device Status",
    49: "Write Primary Variable Transducer Serial Number",
    50: "Read Dynamic Variable Assignments",
    51: "Write Dynamic Variable Assignments",
    52: "Set Device Variable Zero",
    53: "Write Device Variable Units",
    54: "Read Device Variable Information",
    59: "Write Number of Response Preambles",
    76: "Read Lock Device State",
    77: "Write Lock Device State",
    78: "Read Aggregated Command",
    79: "Write Aggregated Command",
    80: "Read Device Variable Trim Points",
    81: "Read Device Variable Trim Guidelines",
    82: "Write Device Variable Trim Point",
    83: "Reset Device Variable Trim",
    84: "Read Sub-Device Identity Summary",
    85: "Read I/O Channel Statistics",
    86: "Read Sub-Device Statistics",
    87: "Write I/O System Master Mode",
    88: "Write I/O System Retry Count",
    89: "Set Real-Time Clock",
    90: "Read Real-Time Clock",
    91: "Read Trend Configuration",
    92: "Write Trend Configuration",
    93: "Read Trend",
    94: "Read I/O System Client Side Communication Statistics",
    95: "Read Device Communications Statistics",
    96: "Read Synchronous Action",
    97: "Configure Synchronous Action",
    98: "Read Command Action",
    99: "Configure Command Action",
    100: "Write Primary Variable Alarm Code",
    101: "Write Primary Variable Transfer Function Code",
    102: "Read Sub-Device to Burst Message Map",
    103: "Write Burst Period",
    104: "Write Burst Trigger",
    105: "Read Burst Mode Configuration",
    106: "Flush Delayed Responses",
    107: "Write Burst Device Variables",
    108: "Write Burst Mode Command Number",
    109: "Burst Mode Control",
    110: "Read Burst Mode Data Update Period",
    111: "Read Burst Mode Maximum Update Period",
    112: "Read Burst Mode Trigger Configuration",
    113: "Read Burst Mode Command List",
    114: "Read Event Notification Configuration",
    115: "Write Event Notification Configuration",
    116: "Write Event Notification Timing",
    117: "Read Event Notification Timing",
    118: "Event Notification Control",
    119: "Open Session",
    120: "Close Session",
}

# Merge all known commands
HART_COMMANDS: Dict[int, str] = {}
HART_COMMANDS.update(HART_UNIVERSAL_COMMANDS)
HART_COMMANDS.update(HART_COMMON_COMMANDS)

# Write commands (operations that modify device configuration)
WRITE_COMMANDS: Set[int] = {
    6,  # Write Polling Address
    17,  # Write Message
    18,  # Write Tag, Descriptor, Date
    19,  # Write Final Assembly Number
    22,  # Write Long Tag
    34,  # Write PV Damping Value
    35,  # Write PV Range Values
    36,  # Set PV Upper Range Value
    37,  # Set PV Lower Range Value
    38,  # Reset Configuration Changed Flag
    40,  # Enter/Exit Fixed Current Mode
    42,  # Perform Device Reset
    43,  # Set PV Zero
    44,  # Write PV Units
    45,  # Trim Loop Current Zero
    46,  # Trim Loop Current Gain
    47,  # Write PV Transfer Function
    49,  # Write PV Transducer Serial Number
    51,  # Write Dynamic Variable Assignments
    52,  # Set Device Variable Zero
    53,  # Write Device Variable Units
    59,  # Write Number of Response Preambles
    77,  # Write Lock Device State
    79,  # Write Aggregated Command
    82,  # Write Device Variable Trim Point
    83,  # Reset Device Variable Trim
    87,  # Write I/O System Master Mode
    88,  # Write I/O System Retry Count
    89,  # Set Real-Time Clock
    92,  # Write Trend Configuration
    97,  # Configure Synchronous Action
    99,  # Configure Command Action
    100,  # Write PV Alarm Code
    101,  # Write PV Transfer Function Code
    103,  # Write Burst Period
    104,  # Write Burst Trigger
    107,  # Write Burst Device Variables
    108,  # Write Burst Mode Command Number
    109,  # Burst Mode Control
    115,  # Write Event Notification Configuration
    116,  # Write Event Notification Timing
    118,  # Event Notification Control
}

# HART-IP message types
MSG_TYPE_REQUEST = 0
MSG_TYPE_RESPONSE = 1
MSG_TYPE_PUBLISH = 2
MSG_TYPE_NAK = 15

MSG_TYPE_NAMES = {
    MSG_TYPE_REQUEST: "Request",
    MSG_TYPE_RESPONSE: "Response",
    MSG_TYPE_PUBLISH: "Publish",
    MSG_TYPE_NAK: "NAK",
}

# HART-IP message IDs
MSG_ID_SESSION_INIT = 0
MSG_ID_SESSION_CLOSE = 1
MSG_ID_KEEP_ALIVE = 2
MSG_ID_PASS_THROUGH = 3

MSG_ID_NAMES = {
    MSG_ID_SESSION_INIT: "Session Init",
    MSG_ID_SESSION_CLOSE: "Session Close",
    MSG_ID_KEEP_ALIVE: "Keep Alive",
    MSG_ID_PASS_THROUGH: "Pass Through",
}

# Device status bit flags (hart_ip.pt.device_status)
DEVICE_STATUS_FLAGS = {
    0x80: "Device Malfunction",
    0x40: "Configuration Changed",
    0x20: "Cold Start",
    0x10: "More Status Available",
    0x08: "Loop Current Fixed",
    0x04: "Loop Current Saturated",
    0x02: "Non-PV Out of Limits",
    0x01: "PV Out of Limits",
}

# Response codes
RESPONSE_CODES = {
    0: "Success",
    1: "Undefined",
    2: "Invalid Selection",
    3: "Passed Parameter Too Large",
    4: "Passed Parameter Too Small",
    5: "Too Few Data Bytes Received",
    6: "Device-Specific Command Error",
    7: "In Write Protect Mode",
    8: "Update Failure",
    9: "Invalid Date Code",
    10: "Invalid Units Code",
    11: "Invalid Range Code",
    14: "Busy",
    16: "Access Restricted",
    28: "Invalid Range",
    29: "Invalid Extension",
    32: "Device Busy",
    64: "Command Not Implemented",
}


@dataclass
class HARTIPSession:
    """Track HART-IP session statistics between a host and field device."""

    host_ip: str
    device_ip: str
    commands_seen: Set[int] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    publish_count: int = 0
    short_addresses: Set[int] = field(default_factory=set)
    device_ids: Set[str] = field(default_factory=set)
    device_types: Set[str] = field(default_factory=set)
    manufacturers: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    status_flags_seen: Set[int] = field(default_factory=set)
    error_responses: int = 0
    first_seen: str = ""
    last_seen: str = ""


class HARTIPPassiveListener(PySharkListenerBase):
    """Passive HART-IP traffic listener (PyShark-based).

    Monitors HART-IP traffic without sending packets to:
    - Identify HART field devices and host applications
    - Track HART commands in use (universal, common practice, device-specific)
    - Extract process variable values (PV, SV, TV, QV)
    - Detect write operations (configuration changes, trim, calibration)
    - Capture device identity (tag, descriptor, manufacturer, device ID)
    - Monitor device status and health flags
    - Flag security concerns (no encryption, cleartext commands)

    Usage:
        listener = HARTIPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for session in listener.sessions.values():
            print(f"{session.host_ip} -> {session.device_ip}")
            print(f"  Commands: {session.commands_seen}")
            print(f"  Writes: {session.write_count}")
    """

    PROTOCOL_NAME = "hartip"
    DISPLAY_FILTER = "hart_ip"
    REQUIRED_LAYERS = ("hart_ip",)
    PROTOCOL_COLUMNS = (
        "rw",
        "command",
        "device_addr",
        "status",
        "data",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], HARTIPSession] = {}

    def should_process_packet(self, packet) -> bool:
        """Accept packets with hart_ip layer or ICMP-embedded HART-IP."""
        if super().should_process_packet(packet):
            return True
        # ICMP Port Unreachable may quote the original UDP/HART-IP payload;
        # tshark's display filter matches these so we must handle them.
        if hasattr(packet, "icmp"):
            try:
                fd = object.__getattribute__(packet.icmp, "_fields_dict")
                if isinstance(fd, dict) and "hart_ip" in fd:
                    return True
            except (AttributeError, TypeError) as e:
                self.logger.debug(
                    f"HART-IP: ICMP _fields_dict access for embedded payload check failed: {e}"
                )
        return False

    def process_packet(self, packet) -> None:
        """Process a HART-IP packet using PyShark dissection."""
        if not hasattr(packet, "hart_ip"):
            # HART-IP may be embedded inside ICMP (port unreachable quoting
            # the original UDP/HART-IP payload).  tshark's display filter
            # matches these, so we must record an interaction.
            if hasattr(packet, "icmp"):
                self._process_icmp_embedded(packet)
            return

        hart_layer = packet.hart_ip

        # Get IP and port info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)

        # Extract HART-IP header fields
        msg_type = self._parse_int(self.get_field(hart_layer, "message_type"))
        msg_id = self._parse_int(self.get_field(hart_layer, "message_id"))
        status = self._parse_int(self.get_field(hart_layer, "status"))
        version = self._parse_int(self.get_field(hart_layer, "version"))
        transaction_id = self._parse_int(self.get_field(hart_layer, "transaction_id"))

        # Determine direction: request goes to port 5094, response comes from it
        if dst_port == 5094:
            host_ip, device_ip = src_ip, dst_ip
            host_mac, device_mac = src_mac, dst_mac
            is_request = True
        elif msg_type == MSG_TYPE_REQUEST:
            host_ip, device_ip = src_ip, dst_ip
            host_mac, device_mac = src_mac, dst_mac
            is_request = True
        elif msg_type in (MSG_TYPE_RESPONSE, MSG_TYPE_PUBLISH):
            host_ip, device_ip = dst_ip, src_ip
            host_mac, device_mac = dst_mac, src_mac
            is_request = False
        else:
            host_ip, device_ip = src_ip, dst_ip
            host_mac, device_mac = src_mac, dst_mac
            is_request = True

        # Handle non-pass-through messages (session init/close, keep alive)
        if msg_id != MSG_ID_PASS_THROUGH:
            self._process_session_message(
                packet,
                hart_layer,
                msg_type,
                msg_id,
                status,
                host_ip,
                device_ip,
                host_mac,
                device_mac,
                is_request,
                flow_id,
                version=version,
                transaction_id=transaction_id,
            )
            return

        # Pass-through: extract HART command frame fields
        command = self._parse_int(self.get_field(hart_layer, "pt_command"))
        if command is None:
            return

        # Device address
        short_addr = self._parse_int(self.get_field(hart_layer, "pt_short_addr"))
        long_addr = self.get_field(hart_layer, "pt_long_address")
        addr_type = self._parse_int(self.get_field(hart_layer, "pt_delimiter_address_type"))

        # Build address display string
        if addr_type == 1 and long_addr:
            addr_str = str(long_addr)
        elif short_addr is not None:
            addr_str = str(short_addr)
        else:
            addr_str = ""

        # Response fields (only present in responses)
        response_code = self._parse_int(self.get_field(hart_layer, "pt_response_code"))
        device_status_raw = self._parse_int(self.get_field(hart_layer, "pt_device_status"), base=16)

        # Classify read/write
        is_write = command in WRITE_COMMANDS
        # Device-specific commands (128-253) are conservatively classified as write
        if 128 <= command <= 253 and command not in HART_COMMANDS:
            is_write = True
        rw = "write" if is_write else "read"

        # Update session
        session = self._ensure_session(host_ip, device_ip)
        session.commands_seen.add(command)
        if short_addr is not None:
            session.short_addresses.add(short_addr)

        if msg_type == MSG_TYPE_PUBLISH:
            session.publish_count += 1
        elif is_write and is_request:
            session.write_count += 1
        elif not is_write and is_request:
            session.read_count += 1

        # Track response errors
        if response_code is not None and response_code != 0:
            session.error_responses += 1

        # Track device status flags
        if device_status_raw is not None and device_status_raw != 0:
            session.status_flags_seen.add(device_status_raw)

        # Extract data values from response payload
        data_str = ""
        if not is_request or msg_type == MSG_TYPE_PUBLISH:
            data_str = self._extract_response_data(hart_layer, command)

        # Extract device identity from responses to universal commands
        if not is_request:
            self._extract_device_identity(hart_layer, command, session)

        # Build status display string
        status_parts: List[str] = []
        if response_code is not None:
            rc_name = RESPONSE_CODES.get(response_code, "")
            if response_code == 0:
                status_parts.append("OK")
            elif rc_name:
                status_parts.append(f"Err:{rc_name}")
            else:
                status_parts.append(f"Err:{response_code}")

        if device_status_raw is not None and device_status_raw != 0:
            flags = self._decode_device_status(device_status_raw)
            if flags:
                status_parts.append(flags)

        status_str = " ".join(status_parts)

        # Record interaction
        now = datetime.now().isoformat()
        cmd_name = HART_COMMANDS.get(command, f"Cmd {command}")
        if msg_type == MSG_TYPE_PUBLISH:
            direction = "response"
        else:
            direction = "request" if is_request else "response"

        details: Dict[str, Any] = {
            "command": command,
            "command_name": cmd_name,
            "rw": rw,
            "device_addr": addr_str,
            "status_str": status_str,
            "data_str": data_str,
        }
        if version is not None:
            details["version"] = version
        if transaction_id is not None:
            details["transaction_id"] = transaction_id
        if msg_type == MSG_TYPE_PUBLISH:
            details["publish"] = True
        if response_code is not None:
            details["response_code"] = response_code
        if device_status_raw is not None:
            details["device_status"] = device_status_raw

        # Pass-through frame checksum (HART frame integrity byte)
        pt_checksum = self._parse_int(self.get_field(hart_layer, "pt_checksum"), default=None, base=16)
        if pt_checksum is not None:
            details["pt_checksum"] = pt_checksum

        # Embedded command fields (present in both requests and responses)
        poll_addr_top = self.get_field(hart_layer, "pt_rsp_poll_address")
        if poll_addr_top is not None:
            details["poll_address"] = str(poll_addr_top)
        cmd_number_top = self.get_field(hart_layer, "pt_rsp_command_number")
        if cmd_number_top is not None:
            details["command_number"] = str(cmd_number_top)

        summary = self._build_summary(
            command,
            cmd_name,
            addr_str,
            is_request,
            msg_type,
            data_str,
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            cmd_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update device entries
        self._update_devices(host_ip, host_mac, device_ip, device_mac)

    # ------------------------------------------------------------------
    # Session management messages (init, close, keep alive)
    # ------------------------------------------------------------------

    def _process_session_message(
        self,
        packet,
        hart_layer,
        msg_type: Optional[int],
        msg_id: Optional[int],
        status: Optional[int],
        host_ip: str,
        device_ip: str,
        host_mac: str,
        device_mac: str,
        is_request: bool,
        flow_id: str,
        version: Optional[int] = None,
        transaction_id: Optional[int] = None,
    ) -> None:
        """Process non-pass-through HART-IP messages (session init/close/keepalive)."""
        src_port, dst_port = self.get_port_info(packet)
        self._ensure_session(host_ip, device_ip)

        msg_id_name = MSG_ID_NAMES.get(msg_id or 0, f"MsgID {msg_id}")
        direction = "request" if is_request else "response"

        # Extract session init details
        data_str = ""
        if msg_id == MSG_ID_SESSION_INIT:
            master_type = self._parse_int(self.get_field(hart_layer, "session_init_master_type"))
            inactivity = self._parse_int(
                self.get_field(hart_layer, "session_init_inactivity_close_timer")
            )
            parts: List[str] = []
            if master_type is not None:
                parts.append(f"host_type={master_type}")
            if inactivity is not None:
                parts.append(f"timeout={inactivity}ms")
            data_str = " ".join(parts)

        now = datetime.now().isoformat()
        details: Dict[str, Any] = {
            "command": -1,
            "command_name": msg_id_name,
            "rw": "read",
            "device_addr": "",
            "status_str": "",
            "data_str": data_str,
        }
        if version is not None:
            details["version"] = version
        if transaction_id is not None:
            details["transaction_id"] = transaction_id

        self._record_interaction(
            now,
            host_ip if is_request else device_ip,
            device_ip if is_request else host_ip,
            direction,
            msg_id_name,
            details,
            msg_id_name,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        self._update_devices(host_ip, host_mac, device_ip, device_mac)

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def _ensure_session(self, host_ip: str, device_ip: str) -> HARTIPSession:
        """Get or create session for this host/device pair."""
        key = (host_ip, device_ip)
        now = datetime.now().isoformat()
        if key not in self.sessions:
            self.sessions[key] = HARTIPSession(
                host_ip=host_ip,
                device_ip=device_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[key]
        session.last_seen = now
        return session

    # Slot-based device variable status field names (cmd 9, 33 responses).
    # Defined explicitly so the audit tool can detect them.
    _SLOT_VAR_STATUS_FIELDS = (
        "pt_rsp_slot0_device_var_status",
        "pt_rsp_slot1_device_var_status",
        "pt_rsp_slot2_device_var_status",
        "pt_rsp_slot3_device_var_status",
        "pt_rsp_slot4_device_var_status",
        "pt_rsp_slot5_device_var_status",
        "pt_rsp_slot6_device_var_status",
        "pt_rsp_slot7_device_var_status",
    )

    # Standardized status field names (cmd 48 response).
    _STANDARDIZED_STATUS_FIELDS = (
        "pt_rsp_standardized_status_0",
        "pt_rsp_standardized_status_1",
        "pt_rsp_standardized_status_2",
        "pt_rsp_standardized_status_3",
    )

    # ------------------------------------------------------------------
    # Value extraction from HART response payloads
    # ------------------------------------------------------------------

    def _extract_response_data(self, hart_layer, command: int) -> str:
        """Extract human-readable data from HART response fields.

        Uses tshark's decoded hart_ip.pt.rsp.* fields when available.
        """
        parts: List[str] = []

        if command == 0:
            # Read Unique Identifier response
            dev_type = self.get_field(hart_layer, "pt_rsp_expanded_device_type")
            dev_rev = self.get_field(hart_layer, "pt_rsp_device_rev")
            sw_rev = self.get_field(hart_layer, "pt_rsp_software_rev")
            dev_id = self.get_field(hart_layer, "pt_rsp_device_id")
            mfr_id = self.get_field(hart_layer, "pt_rsp_manufacturer_Id")
            dev_vars = self.get_field(hart_layer, "pt_rsp_device_variables")
            if dev_type is not None:
                parts.append(f"type=0x{int(dev_type):04x}")
            if mfr_id is not None:
                parts.append(f"mfr={mfr_id}")
            if dev_id is not None:
                parts.append(f"id={dev_id}")
            if dev_rev is not None:
                parts.append(f"rev={dev_rev}")
            if sw_rev is not None:
                parts.append(f"sw={sw_rev}")
            if dev_vars is not None:
                parts.append(f"vars={dev_vars}")

        elif command == 1:
            # Read Primary Variable
            pv_units = self.get_field(hart_layer, "pt_rsp_pv_units")
            pv = self.get_field(hart_layer, "pt_rsp_pv")
            if pv is not None:
                parts.append(f"PV={self._format_float(pv)}")
            if pv_units is not None:
                parts.append(f"units={pv_units}")

        elif command == 2:
            # Read Loop Current and Percent of Range
            current = self.get_field(hart_layer, "pt_rsp_pv_loop_current")
            percent = self.get_field(hart_layer, "pt_rsp_pv_percent_range")
            if current is not None:
                parts.append(f"current={self._format_float(current)}mA")
            if percent is not None:
                parts.append(f"range={self._format_float(percent)}%")

        elif command == 3:
            # Read Dynamic Variables and Loop Current
            current = self.get_field(hart_layer, "pt_rsp_pv_loop_current")
            pv = self.get_field(hart_layer, "pt_rsp_pv")
            sv = self.get_field(hart_layer, "pt_rsp_sv")
            tv = self.get_field(hart_layer, "pt_rsp_tv")
            qv = self.get_field(hart_layer, "pt_rsp_qv")
            if current is not None:
                parts.append(f"I={self._format_float(current)}mA")
            if pv is not None:
                parts.append(f"PV={self._format_float(pv)}")
            if sv is not None:
                parts.append(f"SV={self._format_float(sv)}")
            if tv is not None:
                parts.append(f"TV={self._format_float(tv)}")
            if qv is not None:
                parts.append(f"QV={self._format_float(qv)}")

        elif command == 9:
            # Read Device Variables with Status (slot-based)
            dev_vars = self.get_field(hart_layer, "pt_rsp_device_variables")
            if dev_vars is not None:
                parts.append(f"vars={dev_vars}")
            for slot, status_field in enumerate(self._SLOT_VAR_STATUS_FIELDS):
                val = self.get_field(hart_layer, f"pt_rsp_slot{slot}_device_var_value")
                if val is not None:
                    status_val = self.get_field(hart_layer, status_field)
                    val_str = f"slot{slot}={self._format_float(val)}"
                    if status_val is not None:
                        val_str += f"(st={status_val})"
                    parts.append(val_str)

        elif command == 13:
            # Read Tag, Descriptor, Date
            tag = self.get_field(hart_layer, "pt_rsp_tag")
            desc = self.get_field(hart_layer, "pt_rsp_descriptor")
            if tag is not None:
                tag_clean = str(tag).strip()
                if tag_clean:
                    parts.append(f"tag={tag_clean}")
            if desc is not None:
                desc_clean = str(desc).strip()
                if desc_clean:
                    parts.append(f"desc={desc_clean}")

        elif command == 15:
            # Read Device Information
            pv_class = self.get_field(hart_layer, "pt_rsp_primary_variable_classification")
            if pv_class is not None:
                parts.append(f"pv_class=0x{int(pv_class):02x}")

        elif command == 16:
            # Read Final Assembly Number
            fan = self.get_field(hart_layer, "pt_rsp_final_assembly_number")
            if fan is not None:
                parts.append(f"FAN={fan}")

        elif command == 20:
            # Read Long Tag
            tag = self.get_field(hart_layer, "pt_rsp_tag")
            if tag is not None:
                tag_clean = str(tag).strip()
                if tag_clean:
                    parts.append(f"tag={tag_clean}")

        elif command == 33:
            # Read Device Variables (slot-based, same as cmd 9)
            dev_vars = self.get_field(hart_layer, "pt_rsp_device_variables")
            if dev_vars is not None:
                parts.append(f"vars={dev_vars}")
            for slot, status_field in enumerate(self._SLOT_VAR_STATUS_FIELDS):
                val = self.get_field(hart_layer, f"pt_rsp_slot{slot}_device_var_value")
                if val is not None:
                    status_val = self.get_field(hart_layer, status_field)
                    val_str = f"slot{slot}={self._format_float(val)}"
                    if status_val is not None:
                        val_str += f"(st={status_val})"
                    parts.append(val_str)

        elif command == 48:
            # Read Additional Device Status
            ext_status = self.get_field(hart_layer, "pt_rsp_ext_device_status")
            op_mode = self.get_field(hart_layer, "pt_rsp_device_op_mode")
            dev_sp_status = self.get_field(hart_layer, "pt_rsp_device_sp_status")
            if ext_status is not None:
                parts.append(f"ext_status=0x{int(ext_status):02x}")
            if op_mode is not None:
                parts.append(f"mode={op_mode}")
            if dev_sp_status is not None:
                parts.append(f"sp_status={dev_sp_status}")
            # Standardized status bytes (cmd 48 response)
            for i, ss_field in enumerate(self._STANDARDIZED_STATUS_FIELDS):
                ss = self.get_field(hart_layer, ss_field)
                if ss is not None:
                    parts.append(f"std_status_{i}=0x{int(ss):02x}")

        # Embedded command fields (aggregated/multi-command responses)
        poll_addr = self.get_field(hart_layer, "pt_rsp_poll_address")
        if poll_addr is not None:
            parts.append(f"poll_addr={poll_addr}")
        cmd_number = self.get_field(hart_layer, "pt_rsp_command_number")
        if cmd_number is not None:
            parts.append(f"cmd_num={cmd_number}")

        # Fallback: if no decoded fields, show raw payload if present
        if not parts:
            payload = self.get_field(hart_layer, "pt_payload")
            if payload is not None:
                payload_str = str(payload).replace(":", "")
                if payload_str:
                    parts.append(payload_str)

        return " ".join(parts)

    def _extract_device_identity(self, hart_layer, command: int, session: HARTIPSession) -> None:
        """Extract device identity fields from universal command responses."""
        if command == 0:
            # Read Unique Identifier
            dev_id = self.get_field(hart_layer, "pt_rsp_device_id")
            dev_type = self.get_field(hart_layer, "pt_rsp_expanded_device_type")
            mfr_id = self.get_field(hart_layer, "pt_rsp_manufacturer_Id")
            if dev_id is not None:
                session.device_ids.add(str(dev_id))
            if dev_type is not None:
                session.device_types.add(str(dev_type))
            if mfr_id is not None:
                session.manufacturers.add(str(mfr_id))

        elif command in (13, 20):
            # Read Tag / Long Tag
            tag = self.get_field(hart_layer, "pt_rsp_tag")
            if tag is not None:
                tag_clean = str(tag).strip()
                if tag_clean:
                    session.tags.add(tag_clean)

    # ------------------------------------------------------------------
    # Device status decoding
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_device_status(status: int) -> str:
        """Decode device status byte into flag abbreviations."""
        flags: List[str] = []
        for bit, name in DEVICE_STATUS_FLAGS.items():
            if status & bit:
                # Abbreviate for compact display
                abbrev = name.split()[0]
                flags.append(abbrev)
        return " | ".join(flags)

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        command = d.get("command", "")
        cmd_name = d.get("command_name", "")
        rw = d.get("rw", "")
        addr = d.get("device_addr", "")
        status_str = d.get("status_str", "")
        data_str = d.get("data_str", "")

        # Command column: "CMD# Name"
        if command == -1:
            cmd_str = cmd_name
        elif cmd_name:
            cmd_str = f"{command} {cmd_name}"
        else:
            cmd_str = str(command)

        return [
            rw,
            cmd_str,
            addr,
            status_str,
            data_str,
        ]

    # ------------------------------------------------------------------
    # Summary builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        command: int,
        cmd_name: str,
        addr_str: str,
        is_request: bool,
        msg_type: Optional[int],
        data_str: str,
    ) -> str:
        """Build one-line human-readable interaction summary."""
        prefix = "REQ" if is_request else "RSP"
        if msg_type == MSG_TYPE_PUBLISH:
            prefix = "PUB"

        addr_part = f" addr={addr_str}" if addr_str else ""
        data_part = f" {data_str}" if data_str else ""

        return f"{prefix} Cmd{command} {cmd_name}{addr_part}{data_part}"

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        host_ip: str,
        host_mac: str,
        device_ip: str,
        device_mac: str,
    ) -> None:
        """Update device entries for host and field device."""
        session_key = (host_ip, device_ip)
        session = self.sessions.get(session_key)
        if not session:
            return

        # Field device
        if is_valid_discovered_ip(device_ip):
            device_vendor = lookup_mac_vendor(device_mac) if device_mac else ""
            key = f"hartip-device:{device_ip}"

            tag_str = ", ".join(sorted(session.tags)) if session.tags else ""
            device_name = tag_str if tag_str else ""

            device, is_new = self._ensure_device(
                key,
                device_ip,
                mac=device_mac,
                name=device_name,
                device_type="HART Field Device",
                manufacturer=device_vendor if device_vendor else "",
            )
            device.hartip_passive_data = self._build_device_data("field_device", session)
            if is_new:
                self.logger.debug(
                    f"HART-IP: Field device {device_ip} cmds={sorted(session.commands_seen)}"
                )

        # Host application
        if is_valid_discovered_ip(host_ip):
            host_vendor = lookup_mac_vendor(host_mac) if host_mac else ""
            key = f"hartip-host:{host_ip}"

            device, is_new = self._ensure_device(
                key,
                host_ip,
                mac=host_mac,
                device_type="HART-IP Host (HMI/DCS)",
                manufacturer=host_vendor if host_vendor else "",
            )
            device.hartip_passive_data = self._build_device_data("host", session)

    def _build_device_data(self, role: str, session: HARTIPSession) -> Dict[str, Any]:
        """Build hartip_passive_data dict from session."""
        return {
            "role": role,
            "commands_seen": sorted(session.commands_seen),
            "command_names": [
                HART_COMMANDS.get(c, f"Cmd {c}") for c in sorted(session.commands_seen)
            ],
            "read_operations": session.read_count,
            "write_operations": session.write_count,
            "publish_count": session.publish_count,
            "short_addresses": sorted(session.short_addresses),
            "device_ids": sorted(session.device_ids),
            "device_types": sorted(session.device_types),
            "manufacturers": sorted(session.manufacturers),
            "tags": sorted(session.tags),
            "error_responses": session.error_responses,
            "status_flags_seen": sorted(session.status_flags_seen),
            "protocol": "HART-IP",
            "security": "No encryption (cleartext)",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

    # ------------------------------------------------------------------
    # Harvest: sessions and write alerts
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed HART-IP sessions."""
        return [
            {
                "client": s.host_ip,
                "server": s.device_ip,
                "commands": sorted(s.commands_seen),
                "read_count": s.read_count,
                "write_count": s.write_count,
                "publish_count": s.publish_count,
                "short_addresses": sorted(s.short_addresses),
                "tags": sorted(s.tags),
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            }
            for s in self.sessions.values()
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations (configuration changes)."""
        return [
            {
                "client": s.host_ip,
                "server": s.device_ip,
                "write_count": s.write_count,
                "write_commands": [c for c in s.commands_seen if c in WRITE_COMMANDS],
            }
            for s in self.sessions.values()
            if s.write_count > 0
        ]

    def harvest(self) -> Dict[str, Any]:
        """Suppress WRITE alerts (writes visible in operations table)."""
        result = super().harvest()
        if result and result.get("alerts"):
            result["alerts"] = [a for a in result["alerts"] if a.get("category") != "write_alert"]
        return result

    # ------------------------------------------------------------------
    # ICMP-embedded HART-IP (port unreachable quoting original payload)
    # ------------------------------------------------------------------

    def _process_icmp_embedded(self, packet) -> None:
        """Record an interaction for HART-IP data embedded in an ICMP error.

        When an ICMP Port Unreachable quotes the original HART-IP UDP payload,
        tshark's display filter matches but PyShark stores the decoded hart_ip
        as a nested dict inside the icmp layer (EK mode), not as a top-level
        layer attribute.
        """
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Try to extract basic HART-IP fields from the ICMP layer's nested dict
        msg_id_str = ""
        try:
            icmp_layer = packet.icmp
            fd = object.__getattribute__(icmp_layer, "_fields_dict")
            if isinstance(fd, dict):
                hart_dict = fd.get("hart_ip")
                if isinstance(hart_dict, dict):
                    mi = hart_dict.get("hart_ip_hart_ip_message_id", "")
                    msg_id_str = MSG_ID_NAMES.get(int(mi) if mi else -1, str(mi))
        except Exception as e:
            self.logger.debug(f"Failed to get icmp_layer: {e}")

        icmp_type = self.get_field(packet.icmp, "type", "?")
        icmp_code = self.get_field(packet.icmp, "code", "?")

        now = datetime.now().isoformat()
        src_port, dst_port = self.get_port_info(packet)
        summary = f"ICMP {icmp_type}/{icmp_code} (embedded HART-IP)"
        if msg_id_str:
            summary += f" {msg_id_str}"

        details: Dict[str, Any] = {
            "command": -1,
            "command_name": "ICMP Error",
            "rw": "read",
            "device_addr": "",
            "status_str": f"ICMP type={icmp_type} code={icmp_code}",
            "data_str": msg_id_str,
            "icmp_embedded": True,
        }
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "ICMP Error (HART-IP)",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
