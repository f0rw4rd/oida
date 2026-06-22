"""
OMRON FINS Passive Listener for PLC traffic analysis (ICS).

Passively captures OMRON FINS protocol traffic to extract:
- Access passwords from FINS commands
- Memory area read/write (CIO, WR, HR, DM, EM areas)
- PLC mode changes (run/program/monitor)
- CPU unit status reads
- Error log operations

OMRON FINS (Factory Interface Network Service) is used by Omron PLCs
for communication between HMI/SCADA and controllers.
FINS runs over both UDP and TCP on port 9600.

tshark fields used:
- omron.command: FINS command code (FT_UINT16)
- omron.icf.dtb: Data Type bit (0=command, 1=response)
- omron.sid: Service ID for session correlation (FT_UINT8)
- omron.memory.area.read: Memory area code (FT_UINT8)
- omron.memory.address: Beginning address (FT_UINT16)
- omron.memory.address.bits: Bit offset within address (FT_UINT8)
- omron.memory.numitems: Number of items (FT_UINT16)
- omron.mode_code: Mode code for mode change (FT_UINT8)
- omron.password: Password field (FT_STRING, 4 bytes ASCII)
- omron.response.code: Response/error code (FT_UINT16)
- omron.controller.model: Controller model string
- omron.controller.version: Controller version string
- omron.unit_address: Destination CPU unit address (FT_UINT8)
- omron.network_address: FINS network address (FT_UINT8)
- omron.model_number: PLC model number string (FT_STRING)
- omron.status: CPU operating status (FT_UINT8)
- omron.pc_status: PC status byte (FT_UINT8)
- omron.program_number: PLC program number (FT_UINT16)
- omron.area_data.program_area_size: Program area size (FT_UINT16)
- omron.file_data.filename: Filename for file operations (FT_STRING)
- omron.fatal_error_data: Fatal error summary word (FT_UINT16)
- omron.error_reset_fals_no: Error reset FAL number (FT_UINT16)
- omron.error_message: Error message string (FT_STRING)
- omron.node_error_count: Node error counter (FT_UINT8)
- omron.cyclic_operation: Cyclic operation status (FT_UINT8)
- omron.cyclic_trans_status: Cyclic transfer status (FT_UINT8)
- omron.cyclic_error_status: Cyclic error status (FT_UINT8)
- omron.tcp.command: FINS/TCP command type (FT_UINT32)
- omron.tcp.error_code: FINS/TCP error code (FT_UINT32)
- omron.tcp.client_node_address: FINS/TCP client node address (FT_UINT32)
- omron.tcp.server_node_address: FINS/TCP server node address (FT_UINT32)

References:
- OMRON FINS Communication Protocol
- Wireshark dissector: packet-omron-fins.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# FINS command codes
FINS_COMMANDS = {
    0x0101: "Memory Area Read",
    0x0102: "Memory Area Write",
    0x0103: "Memory Area Fill",
    0x0104: "Multiple Memory Area Read",
    0x0201: "Parameter Area Read",
    0x0202: "Parameter Area Write",
    0x0203: "Parameter Area Clear",
    0x0301: "Program Area Read",
    0x0302: "Program Area Write",
    0x0303: "Program Area Clear",
    0x0401: "Run",
    0x0402: "Stop",
    0x0501: "CPU Unit Data Read",
    0x0502: "Connection Data Read",
    0x0601: "CPU Unit Status Read",
    0x0602: "Cycle Time Read",
    0x0620: "Clock Read",
    0x0621: "Clock Write",
    0x0701: "Message Read",
    0x0702: "Message Clear",
    0x0801: "Access Right Acquire",
    0x0802: "Access Right Release",
    0x0920: "Error Clear",
    0x0921: "Error Log Read",
    0x0922: "Error Log Clear",
    0x2101: "File Name Read",
    0x2102: "Single File Read",
    0x2103: "Single File Write",
    0x2104: "Memory Card Format",
    0x2105: "File Delete",
    0x2201: "Volume Label Create/Delete",
    0x2301: "File Copy",
    0x2302: "File Name Change",
    0x2303: "File Data Check",
    0x2304: "Memory Area File Transfer",
    0x2305: "Parameter Area File Transfer",
    0x2306: "Program Area File Transfer",
}

# FINS memory area codes
FINS_MEMORY_AREAS = {
    0x00: "CIO",  # CIO Area (bit)
    0x80: "CIO",  # CIO Area (word)
    0x01: "WR",  # Work Area (bit)
    0x81: "WR",  # Work Area (word)
    0x02: "HR",  # Holding Area (bit)
    0x82: "HR/DM",  # Holding Area (word) / Data Memory (word) - overlapping area code
    0x03: "AR",  # Auxiliary Area (bit)
    0x83: "AR",  # Auxiliary Area (word)
    0x20: "TIM",  # Timer (completion flag)
    0xA0: "TIM",  # Timer (PV)
    0x09: "EM0",  # Extended Memory bank 0 (bit)
    0x98: "EM0",  # Extended Memory bank 0 (word)
    0x06: "DM",  # Data Memory (bit)
}

# FINS mode codes
FINS_MODES = {
    0x00: "Program",
    0x01: "Debug",
    0x02: "Monitor",
    0x04: "Run",
}

# Write/control commands (security-relevant)
FINS_WRITE_COMMANDS = {
    0x0102,
    0x0103,
    0x0202,
    0x0203,
    0x0302,
    0x0303,
    0x0401,
    0x0402,  # Run, Stop
    0x0621,  # Clock Write
    0x0702,  # Message Clear
    0x0920,
    0x0922,  # Error Clear, Error Log Clear
    0x2103,
    0x2104,
    0x2105,  # File Write, Format, Delete
}

# FINS/TCP command codes (omron.tcp.command)
FINS_TCP_COMMANDS = {
    0: "Node Address Data Send",
    1: "Node Address Data Receive",
    2: "FINS Frame Send",
    3: "FINS Frame Receive",
    6: "Connection Confirmation",
}

# Fatal error flag field tokens (omron.fatal.*) from CPU Unit Status Read.
_FINS_FATAL_ERROR_FIELDS = (
    "fatal_fals_error",
    "fatal_sfc_error",
    "fatal_program_error",
    "fatal_io_setting_error",
    "fatal_cpu_bus_error",
    "fatal_duplication_error",
    "fatal_io_bus_error",
    "fatal_memory_error",
    "fatal_watch_dog_timer_error",
)

# Non-fatal error flag field tokens (omron.non_fatal.*).
_FINS_NON_FATAL_ERROR_FIELDS = (
    "non_fatal_cpu_bus_unit_setting_error",
    "non_fatal_batter_error",
    "non_fatal_sysmac_bus_error",
    "non_fatal_sysmac_bus2_error",
    "non_fatal_cpu_bus_unit_error",
    "non_fatal_io_verification_error",
    "non_fatal_sfc_error",
    "non_fatal_indirect_dm_error",
    "non_fatal_jmp_error",
    "non_fatal_fal_error",
)

# Map field token -> human-readable condition name for active-flag reporting.
_FINS_ERROR_FIELD_NAMES = {
    "fatal_fals_error": "FALS",
    "fatal_sfc_error": "SFC",
    "fatal_program_error": "Program",
    "fatal_io_setting_error": "I/O Setting",
    "fatal_cpu_bus_error": "CPU Bus",
    "fatal_duplication_error": "Duplication",
    "fatal_io_bus_error": "I/O Bus",
    "fatal_memory_error": "Memory",
    "fatal_watch_dog_timer_error": "Watchdog Timer",
    "non_fatal_cpu_bus_unit_setting_error": "CPU Bus Unit Setting",
    "non_fatal_batter_error": "Battery",
    "non_fatal_sysmac_bus_error": "SYSMAC Bus",
    "non_fatal_sysmac_bus2_error": "SYSMAC Bus 2",
    "non_fatal_cpu_bus_unit_error": "CPU Bus Unit",
    "non_fatal_io_verification_error": "I/O Verification",
    "non_fatal_sfc_error": "SFC",
    "non_fatal_indirect_dm_error": "Indirect DM",
    "non_fatal_jmp_error": "JMP",
    "non_fatal_fal_error": "FAL",
}

# CPU status codes (omron.status)
FINS_CPU_STATUS = {
    0x00: "Stop",
    0x01: "Run",
    0x02: "CPU Error",
    0x04: "Run (Forced Status ON)",
    0x80: "Standby",
}


@dataclass
class FINSCredential:
    """Extracted FINS password."""

    password: str
    credential_type: str = "plaintext"
    plc_ip: str = ""
    client_ip: str = ""
    timestamp: str = ""

    @property
    def server_ip(self) -> str:
        """Canonical scanner field alias for plc_ip."""
        return self.plc_ip

    @property
    def username(self) -> str:
        """Canonical scanner field -- FINS uses password-only auth."""
        return self.password

    @property
    def auth_method(self) -> str:
        """Canonical scanner field."""
        return "FINS-Access-Password"


class FINSPassiveListener(PySharkListenerBase):
    """Passive OMRON FINS traffic listener for interaction analysis.

    Captures OMRON FINS protocol traffic to extract:
    - Access passwords
    - Memory area read/write operations
    - PLC mode changes (run/program/monitor)
    - CPU status reads, error log operations
    """

    PROTOCOL_NAME = "fins"
    DISPLAY_FILTER = "omron"
    REQUIRED_LAYERS = ("omron",)
    PROTOCOL_COLUMNS = ("command", "memory_area", "address", "count", "data")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[FINSCredential] = []

    def process_packet(self, packet) -> None:
        """Process FINS packet and extract interactions + passwords."""
        if not hasattr(packet, "omron"):
            return

        omron = packet.omron
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)

        # Get MAC addresses for vendor lookup
        src_mac, dst_mac = self.get_mac_info(packet)

        now = datetime.now().isoformat()

        # -- FINS/TCP header fields (present in TCP-encapsulated FINS) --
        tcp_cmd_raw = self.get_field(omron, "tcp_command", None)
        if tcp_cmd_raw is None:
            tcp_cmd_raw = self.get_field(omron, "tcp.command", None)
        tcp_cmd = self._parse_int(tcp_cmd_raw, -1)

        tcp_error_raw = self.get_field(omron, "tcp_error_code", None)
        if tcp_error_raw is None:
            tcp_error_raw = self.get_field(omron, "tcp.error_code", None)
        tcp_error = self._parse_int(tcp_error_raw, -1)

        tcp_client_node_raw = self.get_field(omron, "tcp_client_node_address", None)
        if tcp_client_node_raw is None:
            tcp_client_node_raw = self.get_field(omron, "tcp.client_node_address", None)
        tcp_client_node = self._parse_int(tcp_client_node_raw, -1)

        tcp_server_node_raw = self.get_field(omron, "tcp_server_node_address", None)
        if tcp_server_node_raw is None:
            tcp_server_node_raw = self.get_field(omron, "tcp.server_node_address", None)
        tcp_server_node = self._parse_int(tcp_server_node_raw, -1)

        # Determine if command or response via ICF data type bit
        dtb_raw = self.get_field(omron, "icf_dtb", None)
        if dtb_raw is None:
            dtb_raw = self.get_field(omron, "icf.dtb", None)
        is_response = False
        if dtb_raw is not None:
            try:
                is_response = int(dtb_raw) == 1
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get is_response: {e}")

        direction = "response" if is_response else "request"

        # Extract command code
        cmd_raw = self.get_field(omron, "command", None)
        cmd_code = self._parse_int(cmd_raw)

        if cmd_code == 0:
            # Still try password extraction even without command code
            self._extract_password(omron, src_ip, dst_ip)
            # Record FINS/TCP-only frames (node address negotiation)
            if tcp_cmd >= 0:
                tcp_cmd_name = FINS_TCP_COMMANDS.get(tcp_cmd, f"TCP Cmd {tcp_cmd}")
                tcp_details: Dict[str, Any] = {
                    "tcp_command": tcp_cmd,
                    "tcp_command_name": tcp_cmd_name,
                }
                if tcp_error >= 0:
                    tcp_details["tcp_error_code"] = tcp_error
                if tcp_client_node >= 0:
                    tcp_details["tcp_client_node"] = tcp_client_node
                if tcp_server_node >= 0:
                    tcp_details["tcp_server_node"] = tcp_server_node
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    direction,
                    tcp_cmd_name,
                    tcp_details,
                    tcp_cmd_name,
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                if not is_response:
                    self._update_devices(src_ip, dst_ip, src_mac, dst_mac)
                else:
                    self._update_devices(dst_ip, src_ip, dst_mac, src_mac)
            return

        cmd_name = FINS_COMMANDS.get(cmd_code, f"Cmd 0x{cmd_code:04x}")

        # Extract response code for error detection
        resp_code_raw = self.get_field(omron, "response_code", None)
        if resp_code_raw is None:
            resp_code_raw = self.get_field(omron, "response.code", None)
        resp_code = self._parse_int(resp_code_raw)

        details: Dict[str, Any] = {
            "command_code": cmd_code,
            "command_name": cmd_name,
        }
        if resp_code:
            details["response_code"] = resp_code

        # -- Common FINS header fields --
        sid = self._parse_int(self.get_field(omron, "sid", None), -1)
        if sid >= 0:
            details["sid"] = sid

        unit_addr = self._parse_int(self.get_field(omron, "unit_address", None), -1)
        if unit_addr >= 0:
            details["unit_address"] = unit_addr

        net_addr = self._parse_int(self.get_field(omron, "network_address", None), -1)
        if net_addr >= 0:
            details["network_address"] = net_addr

        # FINS/TCP fields on FINS command frames
        if tcp_cmd >= 0:
            details["tcp_command"] = tcp_cmd
        if tcp_error >= 0:
            details["tcp_error_code"] = tcp_error
        if tcp_client_node >= 0:
            details["tcp_client_node"] = tcp_client_node
        if tcp_server_node >= 0:
            details["tcp_server_node"] = tcp_server_node

        # Memory area read/write
        if cmd_code in (0x0101, 0x0102, 0x0103, 0x0104):
            self._process_memory_op(omron, cmd_code, cmd_name, details, is_response)

        # PLC Run/Stop
        elif cmd_code in (0x0401, 0x0402):
            mode_raw = self.get_field(omron, "mode_code", None)
            if mode_raw:
                try:
                    mode = int(mode_raw)
                    details["mode"] = FINS_MODES.get(mode, f"Mode {mode}")
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"FINS: PLC mode_code int parse failed: {e}")

        # CPU Unit Data Read / Connection Data Read / Status Read
        elif cmd_code in (0x0501, 0x0502, 0x0601):
            self._process_cpu_status(omron, details, is_response, src_ip, dst_ip)

        # Error Log Read / Error Clear
        elif cmd_code in (0x0920, 0x0921, 0x0922):
            self._process_error_log(omron, details)

        # -- Fields that tshark only populates on relevant commands --
        # Extract program_number and program_area_size if present
        prog_num = self._parse_int(self.get_field(omron, "program_number", None), -1)
        if prog_num >= 0:
            details["program_number"] = prog_num
        prog_area_size = self._parse_int(
            self.get_field(omron, "area_data_program_area_size", None), -1
        )
        if prog_area_size < 0:
            prog_area_size = self._parse_int(
                self.get_field(omron, "area_data.program_area_size", None), -1
            )
        if prog_area_size >= 0:
            details["program_area_size"] = prog_area_size

        # Extract filename if present (file operations span 0x21xx-0x23xx)
        filename = str(self.get_field(omron, "file_data_filename", "") or "").strip()
        if not filename:
            filename = str(self.get_field(omron, "file_data.filename", "") or "").strip()
        if filename:
            details["filename"] = filename

        # Build summary
        summary = self._build_summary(cmd_code, cmd_name, details, is_response)
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
            stream_id=stream_id,
        )

        # Extract password
        self._extract_password(omron, src_ip, dst_ip)

        # Update devices
        if not is_response:
            self._update_devices(src_ip, dst_ip, src_mac, dst_mac)
        else:
            self._update_devices(dst_ip, src_ip, dst_mac, src_mac)

    def _process_memory_op(
        self,
        omron,
        cmd_code: int,
        cmd_name: str,
        details: Dict[str, Any],
        is_response: bool = False,
    ) -> None:
        """Extract memory area details for read/write commands."""
        area_raw = self.get_field(omron, "memory_area_read", None)
        if area_raw is None:
            area_raw = self.get_field(omron, "memory.area.read", None)
        addr_raw = self.get_field(omron, "memory_address", None)
        if addr_raw is None:
            addr_raw = self.get_field(omron, "memory.address", None)
        num_raw = self.get_field(omron, "memory_numitems", None)
        if num_raw is None:
            num_raw = self.get_field(omron, "memory.numitems", None)

        area_code = 0
        if area_raw:
            try:
                if isinstance(area_raw, str) and area_raw.startswith("0x"):
                    area_code = int(area_raw, 16)
                else:
                    area_code = int(area_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"FINS: failed to parse memory area code: {e}")

        area_name = FINS_MEMORY_AREAS.get(area_code, f"Area 0x{area_code:02x}")
        details["memory_area"] = area_name
        details["area_code"] = area_code

        address = 0
        if addr_raw:
            try:
                if isinstance(addr_raw, str) and addr_raw.startswith("0x"):
                    address = int(addr_raw, 16)
                else:
                    address = int(addr_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"FINS: failed to parse memory address: {e}")
        details["address"] = address

        num_items = 1
        if num_raw:
            try:
                num_items = int(num_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get num_items: {e}")
        details["num_items"] = num_items

        # Bit offset within address
        bits_raw = self.get_field(omron, "memory_address_bits", None)
        if bits_raw is None:
            bits_raw = self.get_field(omron, "memory.address.bits", None)
        addr_bits = self._parse_int(bits_raw, -1)
        if addr_bits >= 0:
            details["address_bits"] = addr_bits

        # Extract data payload:
        #   Read response  (cmd 0x0101, is_response=True) -> omron.response.data
        #   Write request  (cmd 0x0102, is_response=False) -> omron.command.data
        # Skip data extraction on error responses (non-zero response_code)
        data_str = ""
        if is_response and cmd_code == 0x0101 and not details.get("response_code"):
            raw = self.get_field(omron, "response_data", None)
            if raw is None:
                raw = self.get_field(omron, "response.data", None)
            if raw is not None:
                data_str = str(raw).strip()
        elif not is_response and cmd_code in (0x0102, 0x0103):
            raw = self.get_field(omron, "command_data", None)
            if raw is None:
                raw = self.get_field(omron, "command.data", None)
            if raw is not None:
                data_str = str(raw).strip()
        if data_str:
            details["data"] = data_str

    def _process_cpu_status(
        self,
        omron,
        details: Dict[str, Any],
        is_response: bool,
        src_ip: str,
        dst_ip: str,
    ) -> None:
        """Extract CPU unit data / status read fields (0x0501, 0x0601 responses)."""
        model = str(self.get_field(omron, "controller_model", "") or "").strip()
        if not model:
            model = str(self.get_field(omron, "controller.model", "") or "").strip()
        version = str(self.get_field(omron, "controller_version", "") or "").strip()
        if not version:
            version = str(self.get_field(omron, "controller.version", "") or "").strip()
        if model:
            details["model"] = model
        if version:
            details["version"] = version

        # model_number (different from controller.model -- PLC model string)
        model_num = str(self.get_field(omron, "model_number", "") or "").strip()
        if model_num:
            details["model_number"] = model_num

        # CPU operating status
        status = self._parse_int(self.get_field(omron, "status", None), -1)
        if status >= 0:
            details["cpu_status"] = FINS_CPU_STATUS.get(status, f"Status 0x{status:02x}")
            details["cpu_status_code"] = status

        # PC status byte
        pc_status = self._parse_int(self.get_field(omron, "pc_status", None), -1)
        if pc_status >= 0:
            details["pc_status"] = pc_status

        # PC status sub-bits (high bit + reserved bits) and rack number.
        pc_status_hi = self._parse_int(self.get_field(omron, "pc_status_hi", None), -1)
        if pc_status_hi >= 0:
            details["pc_status_hi"] = pc_status_hi
        pc_status_r1 = self._parse_int(self.get_field(omron, "pc_status_r1", None), -1)
        if pc_status_r1 >= 0:
            details["pc_status_r1"] = pc_status_r1
        pc_status_r2 = self._parse_int(self.get_field(omron, "pc_status_r2", None), -1)
        if pc_status_r2 >= 0:
            details["pc_status_r2"] = pc_status_r2
        rack_num = self._parse_int(self.get_field(omron, "pcp_status_rack_num", None), -1)
        if rack_num >= 0:
            details["rack_num"] = rack_num

        # Fatal / non-fatal error breakdown (CPU Unit Status Read response).
        # Each is a per-condition flag; collect the active ones into a list
        # so a fault on the PLC is surfaced as named conditions.
        fatal_errors = self._collect_active_flags(omron, _FINS_FATAL_ERROR_FIELDS)
        if fatal_errors:
            details["fatal_errors"] = fatal_errors
        non_fatal_errors = self._collect_active_flags(omron, _FINS_NON_FATAL_ERROR_FIELDS)
        if non_fatal_errors:
            details["non_fatal_errors"] = non_fatal_errors

        # Program number
        prog_num = self._parse_int(self.get_field(omron, "program_number", None), -1)
        if prog_num >= 0:
            details["program_number"] = prog_num

        # Program area size
        prog_area_size = self._parse_int(
            self.get_field(omron, "area_data_program_area_size", None), -1
        )
        if prog_area_size < 0:
            prog_area_size = self._parse_int(
                self.get_field(omron, "area_data.program_area_size", None), -1
            )
        if prog_area_size >= 0:
            details["program_area_size"] = prog_area_size

        # Error data fields (from CPU Unit Status Read response)
        fatal_error = self._parse_int(self.get_field(omron, "fatal_error_data", None), -1)
        if fatal_error >= 0:
            details["fatal_error_data"] = fatal_error

        error_msg = str(self.get_field(omron, "error_message", "") or "").strip()
        if error_msg:
            details["error_message"] = error_msg

        fals_no = self._parse_int(self.get_field(omron, "error_reset_fals_no", None), -1)
        if fals_no >= 0:
            details["error_reset_fals_no"] = fals_no

        # Cyclic/network status
        cyclic_op = self._parse_int(self.get_field(omron, "cyclic_operation", None), -1)
        if cyclic_op >= 0:
            details["cyclic_operation"] = cyclic_op

        cyclic_trans = self._parse_int(self.get_field(omron, "cyclic_trans_status", None), -1)
        if cyclic_trans >= 0:
            details["cyclic_trans_status"] = cyclic_trans

        cyclic_err = self._parse_int(self.get_field(omron, "cyclic_error_status", None), -1)
        if cyclic_err >= 0:
            details["cyclic_error_status"] = cyclic_err

        node_err = self._parse_int(self.get_field(omron, "node_error_count", None), -1)
        if node_err >= 0:
            details["node_error_count"] = node_err

        # Store model info on device for fingerprinting (response only)
        if is_response and (model or model_num):
            plc_ip = src_ip  # response comes from the PLC
            plc_key = f"fins-plc:{plc_ip}"
            if plc_key in self.discovered_devices:
                pdata = getattr(self.discovered_devices[plc_key], "fins_passive_data", {}) or {}
                if model:
                    pdata["controller_model"] = model
                if model_num:
                    pdata["model_number"] = model_num
                if version:
                    pdata["controller_version"] = version
                self.discovered_devices[plc_key].fins_passive_data = pdata

    def _process_error_log(self, omron, details: Dict[str, Any]) -> None:
        """Extract error log fields (0x0920, 0x0921, 0x0922)."""
        fals_no = self._parse_int(self.get_field(omron, "error_reset_fals_no", None), -1)
        if fals_no >= 0:
            details["error_reset_fals_no"] = fals_no

        error_msg = str(self.get_field(omron, "error_message", "") or "").strip()
        if error_msg:
            details["error_message"] = error_msg

    def _collect_active_flags(self, omron, field_tokens: Tuple[str, ...]) -> List[str]:
        """Return the human-readable names of error flags that are set.

        ``field_tokens`` is a tuple of pyshark field tokens. A field counts
        as active when its dissected value parses to a non-zero integer; its
        condition name comes from ``_FINS_ERROR_FIELD_NAMES``.
        """
        active: List[str] = []
        for field_token in field_tokens:
            val = self._parse_int(self.get_field(omron, field_token, None), -1)
            if val > 0:
                active.append(_FINS_ERROR_FIELD_NAMES.get(field_token, field_token))
        return active

    @staticmethod
    def _build_summary(
        cmd_code: int,
        cmd_name: str,
        details: Dict[str, Any],
        is_response: bool,
    ) -> str:
        """Build human-readable interaction summary."""
        if is_response:
            resp_code = details.get("response_code", 0)
            if resp_code:
                return f"{cmd_name} response (error 0x{resp_code:04x})"
            return f"{cmd_name} response"

        if cmd_code in (0x0101, 0x0102, 0x0103, 0x0104):
            area = details.get("memory_area", "?")
            addr = details.get("address", 0)
            num = details.get("num_items", 1)
            if num > 1:
                return f"{cmd_name} {area}{addr}-{area}{addr + num - 1}"
            return f"{cmd_name} {area}{addr}"

        if cmd_code in (0x0401, 0x0402):
            mode = details.get("mode", "")
            if mode:
                return f"{cmd_name} ({mode})"

        if cmd_code in (0x0501, 0x0601):
            model = details.get("model", "") or details.get("model_number", "")
            status = details.get("cpu_status", "")
            parts = [cmd_name]
            if model:
                parts.append(model)
            if status:
                parts.append(f"[{status}]")
            return ": ".join(parts) if len(parts) > 1 else cmd_name

        filename = details.get("filename", "")
        if filename:
            return f"{cmd_name}: {filename}"

        prog_num = details.get("program_number")
        if prog_num is not None and cmd_code in range(0x0301, 0x0310):
            return f"{cmd_name} (program #{prog_num})"

        return cmd_name

    def _extract_password(self, omron, src_ip: str, dst_ip: str) -> None:
        """Extract password from FINS packet."""
        password = str(self.get_field(omron, "password", "") or "").strip()
        if not password:
            return

        if not self._is_duplicate(password, src_ip, dst_ip):
            cred = FINSCredential(
                password=password,
                credential_type="plaintext",
                plc_ip=dst_ip,
                client_ip=src_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)
            self._update_devices(src_ip, dst_ip)
            self.logger.info(f"FINS: password={password} from {src_ip} to {dst_ip}")

    def _is_duplicate(self, password: str, client_ip: str, plc_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if cred.password == password and cred.client_ip == client_ip and cred.plc_ip == plc_ip:
                return True
        return False

    def _update_devices(
        self, client_ip: str, plc_ip: str, client_mac: str = "", plc_mac: str = ""
    ) -> None:
        """Update device entries."""
        if is_valid_discovered_ip(plc_ip):
            plc_vendor = lookup_mac_vendor(plc_mac) if plc_mac else ""
            plc_key = f"fins-plc:{plc_ip}"
            device, is_new = self._ensure_device(
                plc_key,
                plc_ip,
                mac=plc_mac,
                name=f"OMRON PLC ({plc_ip})",
                manufacturer=plc_vendor or "OMRON",
                device_type="PLC",
            )
            if is_new:
                device.fins_passive_data = {
                    "role": "plc",
                    "protocol": "FINS/UDP",
                }

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            client_key = f"fins-client:{client_ip}"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                name=f"FINS Client ({client_ip})",
                manufacturer=client_vendor if client_vendor else "",
                device_type="Engineering Workstation",
            )
            if is_new:
                device.fins_passive_data = {
                    "role": "client",
                    "protocol": "FINS/UDP",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        memory_area = d.get("memory_area", "")
        address = d.get("address", "")
        num_items = d.get("num_items", "")
        data = d.get("data", "")
        return [
            ix.operation,
            memory_area,
            address if address else "",
            num_items if num_items else "",
            data,
        ]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "FINS",
                "credential_type": cred.credential_type,
                "username": cred.password,  # canonical key for harvest() builder
                "auth_method": "FINS-Access-Password",
                "server_ip": cred.plc_ip,  # canonical key for harvest() builder
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get interactions that are write/control operations."""
        writes: Dict[Tuple[str, str], int] = {}
        for ix in self.interactions:
            if ix.direction == "request":
                cmd = ix.details.get("command_code", 0)
                if cmd in FINS_WRITE_COMMANDS:
                    pair = (ix.src_ip, ix.dst_ip)
                    writes[pair] = writes.get(pair, 0) + 1
        return [
            {"client": client, "server": plc, "write_count": count}
            for (client, plc), count in writes.items()
            if count > 0
        ]
