"""DNP3 Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Optimization Phases:
- Phase 1: Quick FC sweep (all function codes once) ~30 sec
- Phase 2: High-crash tests (overflow, buffer attacks) ~3 min
- Phase 3: CVE-targeted operations (control, file, auth) ~3 min
- Phase 4: Boundary attacks ~3 min
- Phase 5: Everything else (reads, diagnostics, etc.)

CVE Patterns Targeted:
- CVE-2020-10611: Type confusion in DNP3 Data Sets (Triangle MicroWorks)
- CVE-2020-10615: Stack buffer overflow via length field (Triangle MicroWorks)
- CVE-2013-2821/2822: Malformed packets causing restart (NovaTech Orion)
- CVE-2013-2791: Malformed DNP3 packets from outstation (MatrikonOPC)
"""

from typing import List

from boofuzz import Block, Byte, Bytes, Checksum, DWord, Group, Request, Static, Word
from crc import Calculator, Crc16

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.connections import TCPSocketConnection
from oida.fuzz.monitors import SocketHealthMonitor
from oida.fuzz.primitives.dynamic import SmartString, StringContext


class DNP3FunctionCodes:
    """DNP3 Application Layer function codes"""

    # Request function codes
    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    FREEZE = 0x07
    FREEZE_CLEAR = 0x08
    FREEZE_AT_TIME = 0x09
    FREEZE_AT_TIME_NR = 0x0A
    COLD_RESTART = 0x0D
    WARM_RESTART = 0x0E
    INITIALIZE_DATA = 0x0F
    INITIALIZE_APPLICATION = 0x10
    START_APPLICATION = 0x11
    STOP_APPLICATION = 0x12
    SAVE_CONFIGURATION = 0x13
    ENABLE_UNSOLICITED = 0x14
    DISABLE_UNSOLICITED = 0x15
    ASSIGN_CLASS = 0x16
    DELAY_MEASUREMENT = 0x17
    RECORD_CURRENT_TIME = 0x18
    OPEN_FILE = 0x19
    CLOSE_FILE = 0x1A
    DELETE_FILE = 0x1B
    GET_FILE_INFO = 0x1C
    AUTHENTICATE_FILE = 0x1D
    ABORT_FILE = 0x1E
    AUTHENTICATE_REQUEST = 0x20
    AUTHENTICATE_ERROR = 0x21

    # Response function codes
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82
    AUTHENTICATE_RESPONSE = 0x83


class DNP3ObjectGroups:
    """DNP3 object group constants"""

    # Binary Input
    BINARY_INPUT = 0x01
    BINARY_INPUT_EVENT = 0x02
    # Binary Output
    BINARY_OUTPUT = 0x0A
    BINARY_OUTPUT_EVENT = 0x0B
    CONTROL_RELAY_OUTPUT_BLOCK = 0x0C
    # Counter
    COUNTER = 0x14
    FROZEN_COUNTER = 0x15
    COUNTER_EVENT = 0x16
    # Analog Input
    ANALOG_INPUT = 0x1E
    ANALOG_INPUT_EVENT = 0x20
    # Analog Output
    ANALOG_OUTPUT = 0x28
    ANALOG_OUTPUT_BLOCK = 0x29
    # Time
    TIME_AND_DATE = 0x32
    # Class Data
    CLASS_DATA = 0x3C
    # File Control
    FILE_CONTROL = 0x46
    # Device Attributes
    DEVICE_ATTRIBUTES = 0x00
    # Data Set
    DATA_SET = 0x55
    # Octet String
    OCTET_STRING = 0x6E
    # Virtual Terminal
    VIRTUAL_TERMINAL = 0x70
    # Authentication
    AUTHENTICATION = 0x78
    SECURE_AUTHENTICATION = 0x79


class DNP3Fuzzer(BaseFuzzer):
    """DNP3 protocol fuzzer targeting SCADA system vulnerabilities"""

    PROTOCOL_OPTIONS = {
        "source_address": {
            "type": int,
            "default": 2,
            "description": "DNP3 source address / master address (0-65519)",
            "example": "2",
        },
        "dest_address": {
            "type": int,
            "default": 1,
            "description": "DNP3 destination address / outstation address (0-65519)",
            "example": "1",
        },
        "enable_write": {
            "type": bool,
            "default": False,
            "description": "Enable write/control operations (risky for production devices)",
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable authentication fuzzing",
        },
        "enable_control": {
            "type": bool,
            "default": False,
            "description": "Enable control command fuzzing (requires enable_write)",
        },
        "enable_file": {
            "type": bool,
            "default": False,
            "description": "Enable file transfer fuzzing (requires enable_write)",
        },
        "dnp3_username": {
            "type": str,
            "default": "admin",
            "description": "DNP3 SAv5 username for authentication fuzzing",
            "example": "admin",
        },
        "dnp3_auth_key": {
            "type": str,
            "default": "",
            "description": "DNP3 SAv5 authentication key (hex string)",
            "example": "0123456789ABCDEF",
        },
    }

    def __init__(self, config=None, connection_factory=None, command_runner=None):
        self.source_address = config.get_option("source_address", 2) if config else 2
        self.dest_address = config.get_option("dest_address", 1) if config else 1
        self.enable_write = config.get_option("enable_write", False) if config else False
        self.enable_auth = config.get_option("enable_auth", False) if config else False
        # Control and file ops require enable_write as a master gate
        self.enable_control = self.enable_write and (
            config.get_option("enable_control", False) if config else False
        )
        self.enable_file = self.enable_write and (
            config.get_option("enable_file", False) if config else False
        )
        self.dnp3_username = config.get_option("dnp3_username", "admin") if config else "admin"
        self.dnp3_auth_key = config.get_option("dnp3_auth_key", "") if config else ""
        super().__init__(config, connection_factory)
        # Log after super().__init__ so self.log is available
        self.log.debug(
            f"[DNP3-Fuzz] Initializing: src={self.source_address}, dest={self.dest_address}"
        )
        self.log.debug(
            f"[DNP3-Fuzz] Options: write={self.enable_write}, auth={self.enable_auth}, "
            f"control={self.enable_control}, file={self.enable_file}"
        )
        if self.dnp3_username != "admin" or self.dnp3_auth_key:
            self.log.debug(
                f"[DNP3-Fuzz] Auth config: username={self.dnp3_username}, key_len={len(self.dnp3_auth_key)}"
            )

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Request groups optimized for breadth-first coverage:
        - DNP3_Baseline: Quick FC sweep (all FCs once) + baseline read
        - DNP3_Overflow: Length overflow and buffer attack tests (CVE-2020-10615)
        - DNP3_Control: Control operations (Direct Operate, Select, Operate)
        - DNP3_File: File operations (CVE-2020-10611 target)
        - DNP3_Auth: Authentication fuzzing
        - DNP3_Boundary: Address and object count boundary testing
        - DNP3_Read: Standard read operations
        - DNP3_Malformed: Malformed packet testing
        """
        # Note: classmethod - no self.log available, use print for debugging if needed
        return [
            # Baseline (includes Quick_FC_Coverage for fast breadth)
            RequestInfo(
                "DNP3_Baseline",
                "Quick FC sweep (all FCs once) + baseline read",
                "baseline",
            ),
            # High-crash tests (prioritized early)
            RequestInfo(
                "DNP3_Overflow",
                "Length overflow and data link layer attacks (CVE-2020-10615)",
                "protocol",
            ),
            RequestInfo("DNP3_Combined", "Combined overflow/mismatch attacks", "boundary"),
            # CVE-targeted operations
            RequestInfo(
                "DNP3_Control",
                "Control operations: Direct Operate, Select, Operate (CVE targets)",
                "write",
            ),
            RequestInfo(
                "DNP3_File",
                "File operations: Open, Delete, Get Info (CVE-2020-10611)",
                "write",
            ),
            RequestInfo("DNP3_Auth", "Authentication fuzzing", "write"),
            # Boundary testing
            RequestInfo(
                "DNP3_Boundary",
                "Address, object count, qualifier boundary testing",
                "boundary",
            ),
            # Read operations (safe)
            RequestInfo(
                "DNP3_Read",
                "Read operations: Binary, Analog, Counter, Class, Events",
                "read",
            ),
            RequestInfo(
                "DNP3_System",
                "System operations: Restart, Unsolicited, Time, Freeze",
                "read",
            ),
            # Malformed packets
            RequestInfo(
                "DNP3_Malformed",
                "Malformed packets: Invalid FC, addresses, data",
                "special",
            ),
            # Object group/variation sweep (cve_patterns.json#dnp3-object-group-sweep)
            RequestInfo(
                "DNP3_Object_Sweep",
                "Iterate object Group (1-89) x Variation (0-16) against READ FC",
                "protocol",
            ),
            # Master-emulation IIN fuzzing (cve_patterns.json#dnp3-iin-flags-master)
            RequestInfo(
                "DNP3_IIN_Master",
                "Master-emulation Response with fuzzed 16-bit IIN flags field",
                "protocol",
            ),
            # Static invalid DL block CRC (cve_patterns.json#dnp3-dl-crc-bypass)
            RequestInfo(
                "DNP3_DL_Bad_CRC",
                "Data link header CRC replaced with static invalid bytes (validation path)",
                "protocol",
            ),
        ]

    def setup_custom_monitors(self) -> List:
        """Setup DNP3-specific monitors"""
        port = self.config.target_port or 20000
        self.log.debug(
            f"[DNP3-Fuzz] Setting up SocketHealthMonitor: {self.config.target_ip}:{port}"
        )
        self.log.debug("[DNP3-Fuzz] Monitor params: retry_count=3, timeout=2, failure_threshold=2")
        return [
            SocketHealthMonitor(
                host=self.config.target_ip,
                port=port,
                retry_count=3,
                timeout=2,
                failure_threshold=2,
            )
        ]

    def _create_socket(self):
        """Create TCP socket for DNP3 communication"""
        self.log.debug(
            f"[DNP3-Fuzz] Creating TCP socket: {self.config.target_ip}:{self.config.target_port}"
        )
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            **self._timeout_overrides(),
        )

    # DNP3 CRC-16 calculator (poly=0x3D65, init=0x0000, xorout=0xFFFF)
    _crc_calculator = Calculator(Crc16.DNP)

    def _log_capabilities(self) -> None:
        """Log DNP3 fuzzer capabilities."""
        self.log.debug(
            "[DNP3-Fuzz] Capabilities: control={}, file={}, auth={}".format(
                self.enable_control, self.enable_file, self.enable_auth
            )
        )

    def _dnp3_crc16(self, data):
        """Calculate DNP3 CRC-16 checksum.

        Returns 2-byte CRC in little-endian format.
        """
        if isinstance(data, (list, tuple)):
            data = bytes(data)
        elif not isinstance(data, bytes):
            data = bytes(data)

        crc = self._crc_calculator.checksum(data)
        # Only log in verbose debug mode to avoid flooding
        # self.log.debug(f"[DNP3-Fuzz] CRC16: data_len={len(data)}, crc=0x{crc:04x}")
        return crc.to_bytes(2, byteorder="little")

    def _define_protocol(self) -> None:
        """Define DNP3 protocol structure with optimized test ordering.

        Optimization Strategy (Breadth-First + Early Crash Detection):
        ===============================================================
        Phase 1: Quick FC Sweep (~30 sec)
            - Touch ALL 30+ function codes once with minimal params
            - Goal: Maximum feature coverage in minimum time

        Phase 2: High-Crash Tests (~3 min)
            - Length field overflow attacks (CVE-2020-10615 pattern)
            - Data link layer malformation
            - Buffer overflow triggers
            - Object count overflow

        Phase 3: CVE-Targeted Operations (~3 min)
            - Control operations (Direct Operate, Select, Operate)
            - File operations (CVE-2020-10611 target)
            - Authentication fuzzing

        Phase 4: Boundary Attacks (~3 min)
            - Address boundaries (0x0000, 0xFFFF)
            - Object count boundaries
            - Qualifier variations

        Phase 5: Remaining Tests
            - Standard read operations
            - System operations (restart, time sync)
            - Event reads

        DNP3 Data Link Layer format:
        - Start bytes: 0x05 0x64 (fixed, not CRC'd)
        - Length: 1 byte (number of bytes following the length field, not counting CRCs)
        - Control: 1 byte
        - Destination: 2 bytes (little-endian)
        - Source: 2 bytes (little-endian)
        - Header CRC: 2 bytes (covers length, control, dest, src)
        - User data blocks with CRC every 16 bytes
        """
        self.log.debug("[DNP3-Fuzz] Entering _define_protocol()")
        self.log.debug("[DNP3-Fuzz] Optimization strategy: Breadth-First + Early Crash Detection")

        # Server expects: outstation_address=1 as dest, master_address=2 as src
        dest_addr = self.dest_address  # Default 1 (outstation)
        src_addr = self.source_address  # Default 2 (master)
        self.log.debug(f"[DNP3-Fuzz] Addressing: dest={dest_addr}, src={src_addr}")

        # Helper function to create complete DNP3 frame with proper CRCs
        def create_dnp3_request(name, app_layer_children, control=0x44, user_data_len=None):
            """
            Create a complete DNP3 request with proper link, transport and app layers.

            Args:
                name: Request name suffix
                app_layer_children: Tuple of boofuzz primitives for application layer
                control: Link layer control byte (default 0x44 = unconfirmed user data)
                user_data_len: Number of user data bytes (transport + app layer)
                              If None, calculated as 1 + number of app_layer_children

            The structure is:
            - Start bytes: 0x05 0x64
            - Link header block (for CRC calculation): length, ctrl, dest, src
            - Header CRC (covers link header only)
            - User data block (transport + app): for CRC calculation
            - User data CRC

            DNP3 Length field = 5 (ctrl + dest + src) + user_data_bytes
            Note: Length does NOT include the CRCs, only the user octets.
            """
            self.log.debug(
                f"[DNP3-Fuzz] Creating request: {name}, children={len(app_layer_children)}"
            )
            # Calculate user data length if not provided
            # Each Byte primitive in app_layer_children is 1 byte
            if user_data_len is None:
                user_data_len = 1 + len(app_layer_children)  # 1 for transport + app bytes

            # DNP3 Length = 5 (ctrl+dest+src) + user_data_bytes
            length_value = 5 + user_data_len
            self.log.debug(
                f"[DNP3-Fuzz] Request {name}: user_data_len={user_data_len}, length_field={length_value}"
            )

            return Request(
                f"DNP3_{name}",
                children=(
                    # Link header block - the data-link CRC covers the start
                    # bytes (0x0564) THROUGH the source address, per IEEE 1815.
                    Block(
                        f"Link_Header_{name}",
                        children=(
                            Bytes(f"Start_Bytes_{name}", b"\x05\x64", fuzzable=False),
                            Byte(f"Length_{name}", length_value),
                            Byte(f"Control_{name}", control),
                            Word(f"Dest_Addr_{name}", dest_addr, endian="<"),
                            Word(f"Src_Addr_{name}", src_addr, endian="<"),
                        ),
                    ),
                    Checksum(
                        name=f"Header_CRC_{name}",
                        block_name=f"Link_Header_{name}",
                        algorithm=self._dnp3_crc16,
                        length=2,
                        endian="<",
                        fuzzable=False,
                    ),
                    # User data block (transport + application) - CRC covers this
                    Block(
                        f"User_Data_{name}",
                        children=(
                            Byte(f"Transport_{name}", 0xC0),  # FIR=1, FIN=1, SEQ=0
                            *app_layer_children,
                        ),
                    ),
                    Checksum(
                        name=f"Data_CRC_{name}",
                        block_name=f"User_Data_{name}",
                        algorithm=self._dnp3_crc16,
                        length=2,
                        endian="<",
                        fuzzable=False,
                    ),
                ),
            )

        # ==================== REQUEST DEFINITIONS ====================
        self.log.debug("[DNP3-Fuzz] Defining request structures")

        # BASELINE: Simple Read request to verify DNP3 service responds
        self.log.debug("[DNP3-Fuzz] Creating baseline read request")
        baseline_read = create_dnp3_request(
            "Baseline",
            (
                Byte("App_Control_Base", 0xC0, fuzzable=True),  # At least one fuzzable field
                Byte("Function_Code_Base", DNP3FunctionCodes.READ),
                Byte("Base_Object_Group", DNP3ObjectGroups.BINARY_INPUT),
                Byte("Base_Object_Variation", 0x02),
                Byte("Base_Qualifier", 0x06),
            ),
        )

        # PHASE 1: Quick FC Sweep - ALL function codes once with minimal params
        # Goal: Touch every FC in first 30 seconds for maximum breadth coverage
        self.log.debug("[DNP3-Fuzz] Creating Quick_FC_Coverage request (31 function codes)")
        quick_fc_coverage = Request(
            "DNP3_Quick_FC_Coverage",
            children=(
                Block(
                    "Link_Header_QFC",
                    children=(
                        Bytes("Start_Bytes_QFC", b"\x05\x64", fuzzable=False),
                        Byte("Length_QFC", 10),  # 5 + 5 user data bytes
                        Byte("Control_QFC", 0x44),
                        Word("Dest_Addr_QFC", dest_addr, endian="<"),
                        Word("Src_Addr_QFC", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_QFC",
                    block_name="Link_Header_QFC",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_QFC",
                    children=(
                        Byte("Transport_QFC", 0xC0),
                        Byte("App_Control_QFC", 0xC0),
                        # ALL DNP3 function codes for quick sweep
                        Group(
                            "Function_Code_Sweep",
                            values=[
                                bytes([DNP3FunctionCodes.CONFIRM]),  # 0x00
                                bytes([DNP3FunctionCodes.READ]),  # 0x01
                                bytes([DNP3FunctionCodes.WRITE]),  # 0x02
                                bytes([DNP3FunctionCodes.SELECT]),  # 0x03
                                bytes([DNP3FunctionCodes.OPERATE]),  # 0x04
                                bytes([DNP3FunctionCodes.DIRECT_OPERATE]),  # 0x05
                                bytes([DNP3FunctionCodes.DIRECT_OPERATE_NR]),  # 0x06
                                bytes([DNP3FunctionCodes.FREEZE]),  # 0x07
                                bytes([DNP3FunctionCodes.FREEZE_CLEAR]),  # 0x08
                                bytes([DNP3FunctionCodes.FREEZE_AT_TIME]),  # 0x09
                                bytes([DNP3FunctionCodes.FREEZE_AT_TIME_NR]),  # 0x0A
                                bytes([DNP3FunctionCodes.COLD_RESTART]),  # 0x0D
                                bytes([DNP3FunctionCodes.WARM_RESTART]),  # 0x0E
                                bytes([DNP3FunctionCodes.INITIALIZE_DATA]),  # 0x0F
                                bytes([DNP3FunctionCodes.INITIALIZE_APPLICATION]),  # 0x10
                                bytes([DNP3FunctionCodes.START_APPLICATION]),  # 0x11
                                bytes([DNP3FunctionCodes.STOP_APPLICATION]),  # 0x12
                                bytes([DNP3FunctionCodes.SAVE_CONFIGURATION]),  # 0x13
                                bytes([DNP3FunctionCodes.ENABLE_UNSOLICITED]),  # 0x14
                                bytes([DNP3FunctionCodes.DISABLE_UNSOLICITED]),  # 0x15
                                bytes([DNP3FunctionCodes.ASSIGN_CLASS]),  # 0x16
                                bytes([DNP3FunctionCodes.DELAY_MEASUREMENT]),  # 0x17
                                bytes([DNP3FunctionCodes.RECORD_CURRENT_TIME]),  # 0x18
                                bytes([DNP3FunctionCodes.OPEN_FILE]),  # 0x19
                                bytes([DNP3FunctionCodes.CLOSE_FILE]),  # 0x1A
                                bytes([DNP3FunctionCodes.DELETE_FILE]),  # 0x1B
                                bytes([DNP3FunctionCodes.GET_FILE_INFO]),  # 0x1C
                                bytes([DNP3FunctionCodes.AUTHENTICATE_FILE]),  # 0x1D
                                bytes([DNP3FunctionCodes.ABORT_FILE]),  # 0x1E
                                bytes([DNP3FunctionCodes.AUTHENTICATE_REQUEST]),  # 0x20
                                bytes([DNP3FunctionCodes.AUTHENTICATE_ERROR]),  # 0x21
                            ],
                        ),
                        # Minimal valid params (object header with all objects qualifier)
                        Bytes(
                            "Minimal_Params", b"\x01\x02\x06", fuzzable=False
                        ),  # Group 1, Var 2, Qual 0x06
                    ),
                ),
                Checksum(
                    name="Data_CRC_QFC",
                    block_name="User_Data_QFC",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ==================== PHASE 2: HIGH-CRASH TESTS ====================
        self.log.debug("[DNP3-Fuzz] Creating Phase 2 high-crash test requests")

        # Length Field Overflow - CVE-2020-10615 pattern (stack buffer overflow)
        self.log.debug("[DNP3-Fuzz] Creating Length_Overflow request (CVE-2020-10615)")
        length_overflow = Request(
            "DNP3_Length_Overflow",
            children=(
                Block(
                    "Link_Header_LO",
                    children=(
                        Bytes("Start_Bytes_LO", b"\x05\x64", fuzzable=False),
                        # DNP3 Length field - oversized values to trigger buffer overflow
                        Group(
                            "Length_Overflow",
                            values=[
                                bytes([0xFF]),  # Maximum (255) - claims huge payload
                                bytes([0xFE]),  # Near maximum
                                bytes([0x80]),  # 128 - larger than typical
                                bytes([0x40]),  # 64 - boundary
                                bytes([0x00]),  # Zero length - edge case
                                bytes([0x01]),  # Minimum - truncated
                            ],
                        ),
                        Byte("Control_LO", 0x44),
                        Word("Dest_Addr_LO", dest_addr, endian="<"),
                        Word("Src_Addr_LO", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_LO",
                    block_name="Link_Header_LO",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_LO",
                    children=(
                        Byte("Transport_LO", 0xC0),
                        Byte("App_Control_LO", 0xC0),
                        Byte("Function_Code_LO", DNP3FunctionCodes.READ),
                        # Oversized payload to test buffer handling
                        SmartString(
                            "Overflow_Payload",
                            "dnp3-overflow-payload",
                            max_len=250,
                            fuzzable=True,
                        ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_LO",
                    block_name="User_Data_LO",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Data Link Control Field Attacks
        self.log.debug(
            "[DNP3-Fuzz] Creating control field attack request (8 control byte variations)"
        )
        control_field_attack = Request(
            "DNP3_Control_Field_Attack",
            children=(
                Block(
                    "Link_Header_CFA",
                    children=(
                        Bytes("Start_Bytes_CFA", b"\x05\x64", fuzzable=False),
                        Byte("Length_CFA", 8),
                        # Control field: DIR, PRM, FCB, FCV, FC (4 bits)
                        Group(
                            "Control_Attack",
                            values=[
                                bytes([0x00]),  # All flags clear
                                bytes([0xFF]),  # All flags set
                                bytes([0x80]),  # DIR=1 only (from master)
                                bytes([0x40]),  # PRM=1 only (primary station)
                                bytes([0xC0]),  # DIR=1, PRM=1
                                bytes([0x44]),  # Normal master request
                                bytes([0x73]),  # Invalid function code in control
                                bytes([0x5F]),  # All secondary function codes
                            ],
                        ),
                        Word("Dest_Addr_CFA", dest_addr, endian="<"),
                        Word("Src_Addr_CFA", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_CFA",
                    block_name="Link_Header_CFA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_CFA",
                    children=(
                        Byte("Transport_CFA", 0xC0),
                        Byte("App_Control_CFA", 0xC0),
                        Byte("Function_Code_CFA", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_CFA",
                    block_name="User_Data_CFA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Object Count Overflow - triggers heap/stack overflow in object parsing
        self.log.debug(
            "[DNP3-Fuzz] Creating object count overflow request (6 qualifier variations)"
        )
        object_count_overflow = Request(
            "DNP3_Object_Count_Overflow",
            children=(
                Block(
                    "Link_Header_OCO",
                    children=(
                        Bytes("Start_Bytes_OCO", b"\x05\x64", fuzzable=False),
                        Byte("Length_OCO", 12),
                        Byte("Control_OCO", 0x44),
                        Word("Dest_Addr_OCO", dest_addr, endian="<"),
                        Word("Src_Addr_OCO", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_OCO",
                    block_name="Link_Header_OCO",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_OCO",
                    children=(
                        Byte("Transport_OCO", 0xC0),
                        Byte("App_Control_OCO", 0xC0),
                        Byte("Function_Code_OCO", DNP3FunctionCodes.READ),
                        Byte("Object_Group_OCO", DNP3ObjectGroups.BINARY_INPUT),
                        Byte("Object_Var_OCO", 0x02),
                        # Qualifier with count - using 8-bit start/stop (0x00)
                        Group(
                            "Qualifier_Count_Attack",
                            values=[
                                b"\x00\xff\x00",  # Start=255, Stop=0 (inverted range)
                                b"\x00\x00\xff",  # Start=0, Stop=255 (huge range)
                                b"\x00\xff\xff",  # Start=255, Stop=255 (max)
                                b"\x07\xff",  # 1-byte count prefix, count=255
                                b"\x17\xff\xff",  # 2-byte count prefix, count=65535
                                b"\x27\xff\xff\xff\xff",  # 4-byte count, max
                            ],
                        ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_OCO",
                    block_name="User_Data_OCO",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Transport Layer Sequence Attacks
        self.log.debug(
            "[DNP3-Fuzz] Creating transport layer attack request (8 transport header variations)"
        )
        transport_attack = Request(
            "DNP3_Transport_Attack",
            children=(
                Block(
                    "Link_Header_TA",
                    children=(
                        Bytes("Start_Bytes_TA", b"\x05\x64", fuzzable=False),
                        Byte("Length_TA", 8),
                        Byte("Control_TA", 0x44),
                        Word("Dest_Addr_TA", dest_addr, endian="<"),
                        Word("Src_Addr_TA", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_TA",
                    block_name="Link_Header_TA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_TA",
                    children=(
                        # Transport header: FIR, FIN, SEQ (6 bits)
                        Group(
                            "Transport_Attack",
                            values=[
                                bytes([0x00]),  # No FIR/FIN, SEQ=0
                                bytes([0xFF]),  # All bits set
                                bytes([0x80]),  # FIR only
                                bytes([0x40]),  # FIN only
                                bytes([0xC0]),  # FIR+FIN (single fragment, valid)
                                bytes([0x3F]),  # SEQ=63 (max), no FIR/FIN
                                bytes([0xBF]),  # FIR, SEQ=63
                                bytes([0x7F]),  # FIN, SEQ=63
                            ],
                        ),
                        Byte("App_Control_TA", 0xC0),
                        Byte("Function_Code_TA", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_TA",
                    block_name="User_Data_TA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Application Control Field Attacks
        self.log.debug(
            "[DNP3-Fuzz] Creating app control field attack request (9 app control variations)"
        )
        app_control_attack = Request(
            "DNP3_App_Control_Attack",
            children=(
                Block(
                    "Link_Header_ACA",
                    children=(
                        Bytes("Start_Bytes_ACA", b"\x05\x64", fuzzable=False),
                        Byte("Length_ACA", 8),
                        Byte("Control_ACA", 0x44),
                        Word("Dest_Addr_ACA", dest_addr, endian="<"),
                        Word("Src_Addr_ACA", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_ACA",
                    block_name="Link_Header_ACA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_ACA",
                    children=(
                        Byte("Transport_ACA", 0xC0),
                        # App Control: FIR, FIN, CON, UNS, SEQ (4 bits)
                        Group(
                            "App_Control_Attack",
                            values=[
                                bytes([0x00]),  # All clear
                                bytes([0xFF]),  # All set
                                bytes([0xC0]),  # FIR+FIN (normal)
                                bytes([0xE0]),  # FIR+FIN+CON (confirm requested)
                                bytes([0xD0]),  # FIR+FIN+UNS (unsolicited)
                                bytes([0xF0]),  # All flags, SEQ=0
                                bytes([0xCF]),  # FIR+FIN, SEQ=15 (max)
                                bytes([0x20]),  # CON only (malformed)
                                bytes([0x10]),  # UNS only (malformed)
                            ],
                        ),
                        Byte("Function_Code_ACA", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_ACA",
                    block_name="User_Data_ACA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Combined Mismatch Attack - Length says short but data is long
        self.log.debug(
            "[DNP3-Fuzz] Creating combined mismatch attack request (length/data mismatch)"
        )
        combined_mismatch = Request(
            "DNP3_Combined_Mismatch",
            children=(
                Block(
                    "Link_Header_CM",
                    children=(
                        Bytes("Start_Bytes_CM", b"\x05\x64", fuzzable=False),
                        Byte("Length_CM", 8),  # Says 3 user bytes
                        Byte("Control_CM", 0x44),
                        Word("Dest_Addr_CM", dest_addr, endian="<"),
                        Word("Src_Addr_CM", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_CM",
                    block_name="Link_Header_CM",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_CM",
                    children=(
                        Byte("Transport_CM", 0xC0),
                        Byte("App_Control_CM", 0xC0),
                        Byte("Function_Code_CM", DNP3FunctionCodes.READ),
                        # Extra data beyond what length field declares
                        Bytes("Extra_Data", b"\x01\x02\x06" + b"A" * 50, fuzzable=True),
                    ),
                ),
                Checksum(
                    name="Data_CRC_CM",
                    block_name="User_Data_CM",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS ====================
        self.log.debug("[DNP3-Fuzz] Creating Phase 3 CVE-targeted operation requests")

        # Control operations - Direct Operate (CROB)
        self.log.debug("[DNP3-Fuzz] Creating control operation requests (CROB)")
        direct_operate = create_dnp3_request(
            "Direct_Operate",
            (
                Byte("App_Control_DO", 0xC0),
                Byte("Function_Code_DO", DNP3FunctionCodes.DIRECT_OPERATE),
                Byte("CROB_Group", DNP3ObjectGroups.CONTROL_RELAY_OUTPUT_BLOCK),
                Byte("CROB_Variation", 0x01),  # CROB
                Byte("CROB_Qualifier", 0x28),  # 1-byte index prefix, 1-byte count
                Byte("CROB_Count", 0x01),
                Byte("CROB_Index", 0x00),
                Byte("CROB_Control_Code", 0x03),  # Latch ON
                Byte("CROB_Count_Field", 0x01),
                DWord("CROB_On_Time", 1000, endian="<"),
                DWord("CROB_Off_Time", 1000, endian="<"),
                Byte("CROB_Status", 0x00),
            ),
            user_data_len=18,  # transport(1) + 9 Byte(9) + 2 DWord(8) = 18
        )

        # Select (SBO step 1)
        select_request = create_dnp3_request(
            "Select",
            (
                Byte("App_Control_Sel", 0xC0),
                Byte("Function_Code_Sel", DNP3FunctionCodes.SELECT),
                Byte("Sel_CROB_Group", DNP3ObjectGroups.CONTROL_RELAY_OUTPUT_BLOCK),
                Byte("Sel_CROB_Variation", 0x01),
                Byte("Sel_Qualifier", 0x28),
                Byte("Sel_Count", 0x01),
                Byte("Sel_Index", 0x00),
                Byte("Sel_Control_Code", 0x03),
                Byte("Sel_Count_Field", 0x01),
                DWord("Sel_On_Time", 1000, endian="<"),
                DWord("Sel_Off_Time", 1000, endian="<"),
                Byte("Sel_Status", 0x00),
            ),
            user_data_len=18,  # transport(1) + 9 Byte(9) + 2 DWord(8) = 18
        )

        # Operate (SBO step 2)
        operate_request = create_dnp3_request(
            "Operate",
            (
                Byte("App_Control_Op", 0xC0),
                Byte("Function_Code_Op", DNP3FunctionCodes.OPERATE),
                Byte("Op_CROB_Group", DNP3ObjectGroups.CONTROL_RELAY_OUTPUT_BLOCK),
                Byte("Op_CROB_Variation", 0x01),
                Byte("Op_Qualifier", 0x28),
                Byte("Op_Count", 0x01),
                Byte("Op_Index", 0x00),
                Byte("Op_Control_Code", 0x03),
                Byte("Op_Count_Field", 0x01),
                DWord("Op_On_Time", 1000, endian="<"),
                DWord("Op_Off_Time", 1000, endian="<"),
                Byte("Op_Status", 0x00),
            ),
            user_data_len=18,  # transport(1) + 9 Byte(9) + 2 DWord(8) = 18
        )

        # Analog Output - Write
        analog_output = create_dnp3_request(
            "Analog_Output_Write",
            (
                Byte("App_Control_AOW", 0xC0),
                Byte("Function_Code_AOW", DNP3FunctionCodes.DIRECT_OPERATE),
                Byte("AO_Group", DNP3ObjectGroups.ANALOG_OUTPUT_BLOCK),
                Byte("AO_Variation", 0x02),  # 16-bit
                Byte("AO_Qualifier", 0x28),
                Byte("AO_Count", 0x01),
                Byte("AO_Index", 0x00),
                Word("AO_Value", 0x1000, endian="<"),
                Byte("AO_Status", 0x00),
            ),
            user_data_len=11,
        )

        # File operations - CVE-2020-10611 targets
        self.log.debug("[DNP3-Fuzz] Creating file operation requests (CVE-2020-10611)")
        get_file_info = create_dnp3_request(
            "Get_File_Info",
            (
                Byte("App_Control_GFI", 0xC0),
                Byte("Function_Code_GFI", DNP3FunctionCodes.GET_FILE_INFO),
                Byte("File_Group", DNP3ObjectGroups.FILE_CONTROL),
                Byte("File_Variation", 0x07),  # File descriptor
                Byte("File_Qualifier", 0x5B),  # Free format string
                Word("File_Size", 0x000D, endian="<"),  # 13 bytes
                Static("File_Name", b"config.txt\x00"),
            ),
            user_data_len=19,  # transport(1) + 5 Byte(5) + Word(2) + Static(11) = 19
        )

        open_file = create_dnp3_request(
            "Open_File",
            (
                Byte("App_Control_OF", 0xC0),
                Byte("Function_Code_OF", DNP3FunctionCodes.OPEN_FILE),
                Byte("Open_File_Group", DNP3ObjectGroups.FILE_CONTROL),
                Byte("Open_File_Variation", 0x03),  # File command
                Byte("Open_File_Qualifier", 0x5B),
                Word("Open_File_Size", 0x0018, endian="<"),  # 24 bytes
                Static("Open_File_Name", b"test.log\x00"),
                DWord("Open_File_Mode", 0x01, endian="<"),  # Read mode
                Word("Open_File_Block", 0x0100, endian="<"),  # Block size
            ),
            user_data_len=23,  # transport(1) + 5 Byte(5) + Word(2) + Static(9) + DWord(4) + Word(2) = 23
        )

        delete_file = create_dnp3_request(
            "Delete_File",
            (
                Byte("App_Control_DF", 0xC0),
                Byte("Function_Code_DF", DNP3FunctionCodes.DELETE_FILE),
                Byte("Del_File_Group", DNP3ObjectGroups.FILE_CONTROL),
                Byte("Del_File_Variation", 0x07),
                Byte("Del_File_Qualifier", 0x5B),
                Word("Del_File_Size", 0x000D, endian="<"),
                Static("Del_File_Name", b"temp.dat\x00\x00\x00\x00"),
            ),
            user_data_len=20,  # transport(1) + 5 Byte(5) + Word(2) + Static(12) = 20
        )

        # File path traversal attack
        self.log.debug("[DNP3-Fuzz] Creating file path traversal request (4 path variations)")
        file_path_traversal = create_dnp3_request(
            "File_Path_Traversal",
            (
                Byte("App_Control_FPT", 0xC0),
                Byte("Function_Code_FPT", DNP3FunctionCodes.OPEN_FILE),
                Byte("FPT_File_Group", DNP3ObjectGroups.FILE_CONTROL),
                Byte("FPT_File_Variation", 0x03),
                Byte("FPT_File_Qualifier", 0x5B),
                Word("FPT_File_Size", 0x0020, endian="<"),
                Group(
                    "Path_Traversal",
                    values=[
                        b"../../../etc/passwd\x00",
                        b"..\\..\\..\\windows\\system32\\config\\sam\x00",
                        b"/etc/shadow\x00",
                        b"C:\\boot.ini\x00",
                    ],
                ),
            ),
            user_data_len=28,  # transport(1) + 5 Byte(5) + Word(2) + Group(~20) = 28
        )

        # Authentication request - DNP3 SAv5 Challenge
        # Uses SmartString CREDENTIAL context for proper auth fuzzing
        auth_username = self.dnp3_username or "admin"
        auth_key = self.dnp3_auth_key or "0000000000000000"
        self.log.debug(
            f"[DNP3-Fuzz] Creating auth requests: username={auth_username}, key_len={len(auth_key)}"
        )

        auth_request = create_dnp3_request(
            "Auth_Request",
            (
                Byte("App_Control_Auth", 0xC0),
                Byte("Function_Code_Auth", DNP3FunctionCodes.AUTHENTICATE_REQUEST),
                Byte("Auth_Group", DNP3ObjectGroups.AUTHENTICATION),
                Byte("Auth_Variation", 0x01),  # Challenge
                Byte("Auth_Qualifier", 0x5B),
                Word("Auth_Data_Size", 0x0010, endian="<"),
                DWord("Auth_Seq", 0x00000001, endian="<"),
                DWord("Auth_User", 0x00000001, endian="<"),
                # Use SmartString CREDENTIAL for auth challenge data fuzzing
                SmartString(
                    "Auth_Challenge",
                    auth_key[:16],
                    max_len=16,
                    context=StringContext.CREDENTIAL,
                ),
            ),
            user_data_len=32,  # transport(1) + 5 Byte(5) + Word(2) + 2 DWord(8) + SmartString(16) = 32
        )

        # SAv5 Authentication Reply - responds to challenge with HMAC
        self.log.debug("[DNP3-Fuzz] Creating SAv5 auth reply request")
        auth_reply = create_dnp3_request(
            "Auth_Reply",
            (
                Byte("App_Control_Reply", 0xC0),
                Byte("Function_Code_Reply", DNP3FunctionCodes.AUTHENTICATE_REQUEST),
                Byte("Auth_Reply_Group", DNP3ObjectGroups.AUTHENTICATION),
                Byte("Auth_Reply_Variation", 0x02),  # Reply
                Byte("Auth_Reply_Qualifier", 0x5B),
                Word("Auth_Reply_Size", 0x0024, endian="<"),  # 36 bytes
                DWord("Auth_Reply_Seq", 0x00000001, endian="<"),
                DWord("Auth_Reply_User", 0x00000001, endian="<"),
                # HMAC value - use SmartString CREDENTIAL for fuzzing
                SmartString("Auth_HMAC", auth_key, max_len=32, context=StringContext.CREDENTIAL),
            ),
            user_data_len=32,  # transport(1) + 5 Byte(5) + Word(2) + 2 DWord(8) + SmartString(16) = 32
        )

        # SAv5 Aggressive Mode Authentication
        self.log.debug("[DNP3-Fuzz] Creating SAv5 aggressive mode auth request")
        auth_aggressive = create_dnp3_request(
            "Auth_Aggressive",
            (
                Byte("App_Control_Agg", 0xC0),
                Byte("Function_Code_Agg", DNP3FunctionCodes.AUTHENTICATE_REQUEST),
                Byte("Auth_Agg_Group", DNP3ObjectGroups.AUTHENTICATION),
                Byte("Auth_Agg_Variation", 0x03),  # Aggressive mode request
                Byte("Auth_Agg_Qualifier", 0x5B),
                Word("Auth_Agg_Size", 0x0030, endian="<"),  # 48 bytes
                DWord("Auth_Agg_Seq", 0x00000001, endian="<"),
                DWord("Auth_Agg_User", 0x00000001, endian="<"),
                # Username - use SmartString CREDENTIAL
                SmartString(
                    "Auth_Username",
                    auth_username,
                    max_len=16,
                    context=StringContext.CREDENTIAL,
                ),
                # Challenge data - use SmartString CREDENTIAL
                SmartString(
                    "Auth_Agg_Challenge",
                    auth_key[:16],
                    max_len=16,
                    context=StringContext.CREDENTIAL,
                ),
            ),
            user_data_len=37,  # transport(1) + 5 Byte(5) + Word(2) + 2 DWord(8) + SmartString(5+16) = 37
        )

        # SAv5 Session Key Status request
        self.log.debug("[DNP3-Fuzz] Creating SAv5 key status request")
        auth_key_status = create_dnp3_request(
            "Auth_Key_Status",
            (
                Byte("App_Control_KeyStat", 0xC0),
                Byte("Function_Code_KeyStat", DNP3FunctionCodes.AUTHENTICATE_REQUEST),
                Byte("Auth_KeyStat_Group", DNP3ObjectGroups.AUTHENTICATION),
                Byte("Auth_KeyStat_Variation", 0x04),  # Key status
                Byte("Auth_KeyStat_Qualifier", 0x5B),
                Word("Auth_KeyStat_Size", 0x0008, endian="<"),
                DWord("Auth_KeyStat_User", 0x00000001, endian="<"),
                Word("Auth_KeyStat_KeyWrap", 0x0001, endian="<"),  # Key wrap algorithm
                Word("Auth_KeyStat_KeyStatus", 0x0001, endian="<"),  # Key status
            ),
            user_data_len=16,  # transport(1) + 5 Byte(5) + Word(2) + DWord(4) + 2 Word(4) = 16
        )

        # SAv5 Session Key Change
        self.log.debug("[DNP3-Fuzz] Creating SAv5 key change request")
        auth_key_change = create_dnp3_request(
            "Auth_Key_Change",
            (
                Byte("App_Control_KeyChg", 0xC0),
                Byte("Function_Code_KeyChg", DNP3FunctionCodes.AUTHENTICATE_REQUEST),
                Byte("Auth_KeyChg_Group", DNP3ObjectGroups.AUTHENTICATION),
                Byte("Auth_KeyChg_Variation", 0x05),  # Key change
                Byte("Auth_KeyChg_Qualifier", 0x5B),
                Word("Auth_KeyChg_Size", 0x0028, endian="<"),  # 40 bytes
                DWord("Auth_KeyChg_Seq", 0x00000001, endian="<"),
                DWord("Auth_KeyChg_User", 0x00000001, endian="<"),
                # New session key - use SmartString CREDENTIAL
                SmartString(
                    "Auth_New_Key",
                    auth_key,
                    max_len=32,
                    context=StringContext.CREDENTIAL,
                ),
            ),
            user_data_len=32,  # transport(1) + 5 Byte(5) + Word(2) + 2 DWord(8) + SmartString(16) = 32
        )

        # SAv5 Error - test error handling in auth
        self.log.debug("[DNP3-Fuzz] Creating SAv5 auth error request")
        auth_error = create_dnp3_request(
            "Auth_Error",
            (
                Byte("App_Control_AuthErr", 0xC0),
                Byte("Function_Code_AuthErr", DNP3FunctionCodes.AUTHENTICATE_ERROR),
                Byte("Auth_Err_Group", DNP3ObjectGroups.AUTHENTICATION),
                Byte("Auth_Err_Variation", 0x07),  # Error
                Byte("Auth_Err_Qualifier", 0x5B),
                Word("Auth_Err_Size", 0x0010, endian="<"),
                DWord("Auth_Err_Seq", 0x00000001, endian="<"),
                DWord("Auth_Err_User", 0x00000001, endian="<"),
                Word("Auth_Err_Assoc", 0x0001, endian="<"),  # Association ID
                Byte("Auth_Err_Code", 0x01),  # Error code
                DWord("Auth_Err_Time", 0x00000000, endian="<"),  # Timestamp
                # Error text - use SmartString CREDENTIAL to test error message parsing
                SmartString(
                    "Auth_Err_Text",
                    "Authentication failed",
                    max_len=32,
                    context=StringContext.CREDENTIAL,
                ),
            ),
            user_data_len=44,  # transport(1) + 6 Byte(6) + 2 Word(4) + 3 DWord(12) + SmartString(21) = 44
        )

        # ==================== PHASE 4: BOUNDARY ATTACKS ====================
        self.log.debug("[DNP3-Fuzz] Creating Phase 4 boundary attack requests")

        # Address Boundary Testing
        self.log.debug("[DNP3-Fuzz] Creating address boundary requests (12 address variations)")
        address_boundary = Request(
            "DNP3_Address_Boundary",
            children=(
                Block(
                    "Link_Header_AB",
                    children=(
                        Bytes("Start_Bytes_AB", b"\x05\x64", fuzzable=False),
                        Byte("Length_AB", 8),
                        Byte("Control_AB", 0x44),
                        # Destination address boundaries
                        Group(
                            "Dest_Addr_Boundary",
                            values=[
                                b"\x00\x00",  # Zero (self-address)
                                b"\x01\x00",  # Typical outstation (1)
                                b"\xff\x00",  # 255
                                b"\x00\x01",  # 256
                                b"\xff\x7f",  # 32767
                                b"\x00\x80",  # 32768 (sign bit)
                                b"\xef\xff",  # 65519 (max valid)
                                b"\xf0\xff",  # 65520 (reserved start)
                                b"\xfc\xff",  # 65532 (broadcast - self address)
                                b"\xfd\xff",  # 65533 (broadcast - all outstations)
                                b"\xfe\xff",  # 65534 (broadcast - all stations)
                                b"\xff\xff",  # 65535 (broadcast - reserved)
                            ],
                        ),
                        Word("Src_Addr_AB", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_AB",
                    block_name="Link_Header_AB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_AB",
                    children=(
                        Byte("Transport_AB", 0xC0),
                        Byte("App_Control_AB", 0xC0),
                        Byte("Function_Code_AB", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_AB",
                    block_name="User_Data_AB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Qualifier Code Boundary Testing
        self.log.debug("[DNP3-Fuzz] Creating qualifier boundary request (11 qualifier codes)")
        qualifier_boundary = Request(
            "DNP3_Qualifier_Boundary",
            children=(
                Block(
                    "Link_Header_QB",
                    children=(
                        Bytes("Start_Bytes_QB", b"\x05\x64", fuzzable=False),
                        Byte("Length_QB", 14),
                        Byte("Control_QB", 0x44),
                        Word("Dest_Addr_QB", dest_addr, endian="<"),
                        Word("Src_Addr_QB", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_QB",
                    block_name="Link_Header_QB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_QB",
                    children=(
                        Byte("Transport_QB", 0xC0),
                        Byte("App_Control_QB", 0xC0),
                        Byte("Function_Code_QB", DNP3FunctionCodes.READ),
                        Byte("Object_Group_QB", DNP3ObjectGroups.BINARY_INPUT),
                        Byte("Object_Var_QB", 0x02),
                        # All qualifier codes
                        Group(
                            "Qualifier_Boundary",
                            values=[
                                b"\x00\x00\x0a",  # 0x00: 8-bit start/stop, 0-10
                                b"\x01\x00\x00\x00\x0a\x00",  # 0x01: 16-bit start/stop, 0-10
                                b"\x06",  # 0x06: All objects (no range)
                                b"\x07\x0a",  # 0x07: 8-bit count, 10 objects
                                b"\x08\x0a\x00",  # 0x08: 16-bit count, 10 objects
                                b"\x17\x01\x00",  # 0x17: 8-bit count with prefix, 1 object
                                b"\x27\x01",  # 0x27: 8-bit count with 2-byte prefix
                                b"\x28\x01\x00",  # 0x28: 8-bit count with 1-byte prefix
                                b"\x37\x01",  # 0x37: 8-bit count with 4-byte prefix
                                b"\x5b\x05\x00test",  # 0x5B: Free format (variable sized)
                                b"\xff",  # Invalid qualifier
                            ],
                        ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_QB",
                    block_name="User_Data_QB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Object Group/Variation Boundary Testing
        self.log.debug(
            "[DNP3-Fuzz] Creating object group boundary request (11 group/var combinations)"
        )
        object_group_boundary = Request(
            "DNP3_Object_Group_Boundary",
            children=(
                Block(
                    "Link_Header_OGB",
                    children=(
                        Bytes("Start_Bytes_OGB", b"\x05\x64", fuzzable=False),
                        Byte("Length_OGB", 10),
                        Byte("Control_OGB", 0x44),
                        Word("Dest_Addr_OGB", dest_addr, endian="<"),
                        Word("Src_Addr_OGB", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_OGB",
                    block_name="Link_Header_OGB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_OGB",
                    children=(
                        Byte("Transport_OGB", 0xC0),
                        Byte("App_Control_OGB", 0xC0),
                        Byte("Function_Code_OGB", DNP3FunctionCodes.READ),
                        # Object group boundaries
                        Group(
                            "Object_Group_Boundary",
                            values=[
                                b"\x00\x00",  # Group 0 (device attributes), Var 0
                                b"\x01\x00",  # Group 1, Var 0 (any variation)
                                b"\x01\xff",  # Group 1, Var 255 (invalid)
                                b"\x3c\x00",  # Group 60 (class data), Var 0
                                b"\x3c\x04",  # Group 60, Var 4 (Class 3)
                                b"\x46\x00",  # Group 70 (file control), Var 0
                                b"\x78\x00",  # Group 120 (authentication), Var 0
                                b"\x79\x00",  # Group 121 (secure auth), Var 0
                                b"\x7f\xff",  # Group 127, Var 255 (upper boundary)
                                b"\xff\x00",  # Group 255 (invalid), Var 0
                                b"\xff\xff",  # Group 255, Var 255 (max invalid)
                            ],
                        ),
                        Byte("Qualifier_OGB", 0x06),
                    ),
                ),
                Checksum(
                    name="Data_CRC_OGB",
                    block_name="User_Data_OGB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ==================== PHASE 5: STANDARD OPERATIONS ====================
        self.log.debug("[DNP3-Fuzz] Creating Phase 5 standard operation requests")

        # Read operations
        self.log.debug("[DNP3-Fuzz] Creating standard read requests")
        read_binary_inputs = create_dnp3_request(
            "Read_Request",
            (
                Byte("App_Control_Read", 0xC0),
                Byte("Function_Code_Read", DNP3FunctionCodes.READ),
                Byte("Object_Group", DNP3ObjectGroups.BINARY_INPUT),
                Byte("Object_Variation", 0x02),  # With flags
                Byte("Qualifier", 0x06),  # All objects
            ),
        )

        read_analog_inputs = create_dnp3_request(
            "Analog_Input_Read",
            (
                Byte("App_Control_Analog", 0xC0),
                Byte("Function_Code_Analog", DNP3FunctionCodes.READ),
                Byte("Analog_Object_Group", DNP3ObjectGroups.ANALOG_INPUT),
                Byte("Analog_Object_Variation", 0x01),  # 32-bit with flag
                Byte("Analog_Qualifier", 0x06),
            ),
        )

        read_counters = create_dnp3_request(
            "Counter_Read",
            (
                Byte("App_Control_Counter", 0xC0),
                Byte("Function_Code_Counter", DNP3FunctionCodes.READ),
                Byte("Counter_Object_Group", DNP3ObjectGroups.COUNTER),
                Byte("Counter_Object_Variation", 0x01),
                Byte("Counter_Qualifier", 0x06),
            ),
        )

        read_class_poll = create_dnp3_request(
            "Class_Poll",
            (
                Byte("App_Control_Class", 0xC0),
                Byte("Function_Code_Class", DNP3FunctionCodes.READ),
                Byte("Class_Object_Group", DNP3ObjectGroups.CLASS_DATA),
                Byte("Class_Object_Variation", 0x01),  # Class 0
                Byte("Class_Qualifier", 0x06),
            ),
        )

        read_binary_output = create_dnp3_request(
            "Binary_Output_Read",
            (
                Byte("App_Control_BO", 0xC0),
                Byte("Function_Code_BO", DNP3FunctionCodes.READ),
                Byte("BO_Object_Group", DNP3ObjectGroups.BINARY_OUTPUT),
                Byte("BO_Object_Variation", 0x02),
                Byte("BO_Qualifier", 0x06),
            ),
        )

        read_binary_events = create_dnp3_request(
            "Binary_Event_Read",
            (
                Byte("App_Control_BIE", 0xC0),
                Byte("Function_Code_BIE", DNP3FunctionCodes.READ),
                Byte("BIE_Group", DNP3ObjectGroups.BINARY_INPUT_EVENT),
                Byte("BIE_Variation", 0x02),
                Byte("BIE_Qualifier", 0x06),
            ),
        )

        read_analog_events = create_dnp3_request(
            "Analog_Event_Read",
            (
                Byte("App_Control_AIE", 0xC0),
                Byte("Function_Code_AIE", DNP3FunctionCodes.READ),
                Byte("AIE_Group", DNP3ObjectGroups.ANALOG_INPUT_EVENT),
                Byte("AIE_Variation", 0x02),
                Byte("AIE_Qualifier", 0x06),
            ),
        )

        read_time = create_dnp3_request(
            "Read_Time",
            (
                Byte("App_Control_Time", 0xC0),
                Byte("Function_Code_Time", DNP3FunctionCodes.READ),
                Byte("Time_Object_Group", DNP3ObjectGroups.TIME_AND_DATE),
                Byte("Time_Object_Variation", 0x01),
                Byte("Time_Qualifier", 0x06),
            ),
        )

        # System operations
        self.log.debug("[DNP3-Fuzz] Creating system operation requests (restart, time, freeze)")
        cold_restart = create_dnp3_request(
            "Cold_Restart",
            (
                Byte("App_Control_Restart", 0xC0),
                Byte("Function_Code_Restart", DNP3FunctionCodes.COLD_RESTART),
            ),
        )

        warm_restart = create_dnp3_request(
            "Warm_Restart",
            (
                Byte("App_Control_Warm", 0xC0),
                Byte("Function_Code_Warm", DNP3FunctionCodes.WARM_RESTART),
            ),
        )

        delay_measure = create_dnp3_request(
            "Delay_Measure",
            (
                Byte("App_Control_Delay", 0xC0),
                Byte("Function_Code_Delay", DNP3FunctionCodes.DELAY_MEASUREMENT),
            ),
        )

        record_time = create_dnp3_request(
            "Record_Time",
            (
                Byte("App_Control_RecTime", 0xC0),
                Byte("Function_Code_RecTime", DNP3FunctionCodes.RECORD_CURRENT_TIME),
            ),
        )

        enable_unsolicited = create_dnp3_request(
            "Enable_Unsolicited",
            (
                Byte("App_Control_Enable", 0xC0),
                Byte("Function_Code_Enable", DNP3FunctionCodes.ENABLE_UNSOLICITED),
                Byte("Enable_Class1_Group", DNP3ObjectGroups.CLASS_DATA),
                Byte("Enable_Class1_Var", 0x02),
                Byte("Enable_Class1_Qual", 0x06),
                Byte("Enable_Class2_Group", DNP3ObjectGroups.CLASS_DATA),
                Byte("Enable_Class2_Var", 0x03),
                Byte("Enable_Class2_Qual", 0x06),
                Byte("Enable_Class3_Group", DNP3ObjectGroups.CLASS_DATA),
                Byte("Enable_Class3_Var", 0x04),
                Byte("Enable_Class3_Qual", 0x06),
            ),
            user_data_len=12,
        )

        disable_unsolicited = create_dnp3_request(
            "Disable_Unsolicited",
            (
                Byte("App_Control_Disable", 0xC0),
                Byte("Function_Code_Disable", DNP3FunctionCodes.DISABLE_UNSOLICITED),
                Byte("Disable_Class1_Group", DNP3ObjectGroups.CLASS_DATA),
                Byte("Disable_Class1_Var", 0x02),
                Byte("Disable_Class1_Qual", 0x06),
            ),
        )

        freeze_counters = create_dnp3_request(
            "Freeze_Counters",
            (
                Byte("App_Control_Freeze", 0xC0),
                Byte("Function_Code_Freeze", DNP3FunctionCodes.FREEZE),
                Byte("Freeze_Group", DNP3ObjectGroups.COUNTER),
                Byte("Freeze_Variation", 0x00),
                Byte("Freeze_Qualifier", 0x06),
            ),
        )

        freeze_clear = create_dnp3_request(
            "Freeze_Clear",
            (
                Byte("App_Control_FC", 0xC0),
                Byte("Function_Code_FC", DNP3FunctionCodes.FREEZE_CLEAR),
                Byte("FC_Group", DNP3ObjectGroups.COUNTER),
                Byte("FC_Variation", 0x00),
                Byte("FC_Qualifier", 0x06),
            ),
        )

        assign_class = create_dnp3_request(
            "Assign_Class",
            (
                Byte("App_Control_AC", 0xC0),
                Byte("Function_Code_AC", DNP3FunctionCodes.ASSIGN_CLASS),
                Byte("AC_Class_Group", DNP3ObjectGroups.CLASS_DATA),
                Byte("AC_Class_Var", 0x01),
                Byte("AC_Class_Qual", 0x06),
                Byte("AC_Target_Group", DNP3ObjectGroups.BINARY_INPUT),
                Byte("AC_Target_Var", 0x00),
                Byte("AC_Target_Qual", 0x06),
            ),
            user_data_len=9,  # transport(1) + 8 Byte(8) = 9
        )

        # Malformed packets
        self.log.debug("[DNP3-Fuzz] Creating malformed packet requests")
        malformed_fc = Request(
            "DNP3_Malformed_FC",
            children=(
                Block(
                    "Link_Header_MFC",
                    children=(
                        Bytes("Start_Bytes_MFC", b"\x05\x64", fuzzable=False),
                        Byte("Length_MFC", 8),
                        Byte("Control_MFC", 0x44),
                        Word("Dest_Addr_MFC", dest_addr, endian="<"),
                        Word("Src_Addr_MFC", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_MFC",
                    block_name="Link_Header_MFC",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_MFC",
                    children=(
                        Byte("Transport_MFC", 0xC0),
                        Byte("App_Control_MFC", 0xC0),
                        Group(
                            "Invalid_FC",
                            values=[
                                bytes([0xFF]),  # Invalid max
                                bytes([0x80]),  # Response code (invalid for request)
                                bytes([0x81]),  # Response code
                                bytes([0x82]),  # Unsolicited response
                                bytes([0x83]),  # Auth response
                                bytes([0x50]),  # Undefined
                                bytes([0x30]),  # Undefined
                                bytes([0x0B]),  # Undefined (gap)
                                bytes([0x0C]),  # Undefined (gap)
                                bytes([0x1F]),  # Undefined
                            ],
                        ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_MFC",
                    block_name="User_Data_MFC",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        malformed_addr = Request(
            "DNP3_Malformed_Addr",
            children=(
                Block(
                    "Link_Header_MA",
                    children=(
                        Bytes("Start_Bytes_MA", b"\x05\x64", fuzzable=False),
                        Byte("Length_MA", 8),
                        Byte("Control_MA", 0x44),
                        Group(
                            "Invalid_Dest",
                            values=[
                                b"\xff\xff",  # Broadcast reserved
                                b"\xfe\xff",  # Broadcast all stations
                                b"\x00\x00",  # Zero (self-address)
                                b"\xf0\xff",  # Reserved range start
                            ],
                        ),
                        Word("Src_Addr_MA", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_MA",
                    block_name="Link_Header_MA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_MA",
                    children=(
                        Byte("Transport_MA", 0xC0),
                        Byte("App_Control_MA", 0xC0),
                        Byte("Function_Code_MA", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_MA",
                    block_name="User_Data_MA",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Invalid start bytes
        self.log.debug("[DNP3-Fuzz] Creating invalid start bytes request (5 start byte variations)")
        invalid_start_bytes = Request(
            "DNP3_Invalid_Start_Bytes",
            children=(
                Group(
                    "Invalid_Start",
                    values=[
                        b"\x05\x65",  # Wrong second byte
                        b"\x06\x64",  # Wrong first byte
                        b"\x00\x00",  # All zeros
                        b"\xff\xff",  # All ones
                        b"\x64\x05",  # Reversed
                    ],
                ),
                Block(
                    "Link_Header_ISB",
                    children=(
                        Byte("Length_ISB", 8),
                        Byte("Control_ISB", 0x44),
                        Word("Dest_Addr_ISB", dest_addr, endian="<"),
                        Word("Src_Addr_ISB", src_addr, endian="<"),
                    ),
                ),
                Checksum(
                    name="Header_CRC_ISB",
                    block_name="Link_Header_ISB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
                Block(
                    "User_Data_ISB",
                    children=(
                        Byte("Transport_ISB", 0xC0),
                        Byte("App_Control_ISB", 0xC0),
                        Byte("Function_Code_ISB", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_ISB",
                    block_name="User_Data_ISB",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ==================== EXTENDED COVERAGE REQUESTS ====================
        # New requests added per ref/dnp3/cve_patterns.json:
        #   - dnp3-object-group-sweep   -> DNP3_Object_Sweep
        #   - dnp3-iin-flags-master     -> DNP3_IIN_Master
        #   - dnp3-dl-crc-bypass        -> DNP3_DL_Bad_CRC

        # Object Group x Variation Sweep -- iterate (1..89) x (0..16) READ requests.
        # Each Group value is a single byte; combining them sweeps the (group, variation)
        # space against the READ function code to surface per-group parser bugs.
        self.log.debug("[DNP3-Fuzz] Creating Object_Sweep request (Group 1-89 x Variation 0-16)")
        object_sweep = create_dnp3_request(
            "Object_Sweep",
            (
                Byte("App_Control_OS", 0xC0),
                Byte("Function_Code_OS", DNP3FunctionCodes.READ),
                Group(
                    "Object_Sweep_Group",
                    values=[bytes([g]) for g in range(1, 90)],
                ),
                Group(
                    "Object_Sweep_Variation",
                    values=[bytes([v]) for v in range(0, 17)],
                ),
                Byte("Object_Sweep_Qualifier", 0x06),  # All objects
            ),
        )

        # IIN Master Emulation -- craft a Response (FC 0x81) carrying a fuzzed
        # 16-bit IIN (Internal Indications) field; targets master-side IIN parsers.
        # IIN immediately follows the function code in a Response application header.
        self.log.debug("[DNP3-Fuzz] Creating IIN_Master request (16-bit IIN flag fuzzing)")
        iin_master = create_dnp3_request(
            "IIN_Master",
            (
                Byte("App_Control_IIN", 0xC0),
                Byte("Function_Code_IIN", DNP3FunctionCodes.RESPONSE),  # 0x81 master-emulated
                # 16-bit IIN field (IIN1 + IIN2) -- default boofuzz mutations on a Word
                Word("IIN_Flags", 0x0000, endian="<", fuzzable=True),
            ),
            # Master emulation flips DIR/PRM: 0x44 (master->outstation) becomes
            # 0x05 (outstation primary->master). Keep frame symmetrical with a
            # standard outstation control byte so the link layer parses cleanly.
            control=0x44,
        )

        # Data-Link Bad CRC -- the auto-Checksum() over Link_Header recomputes a
        # valid CRC, so we hand-build the frame with a Static invalid CRC in place
        # to exercise the peer's CRC-validation / drop path (cve_patterns.json
        # mutation_values: 0x0000, 0xFFFF). Data block CRC stays valid so only the
        # header CRC is under test.
        self.log.debug("[DNP3-Fuzz] Creating DL_Bad_CRC request (static invalid header CRC)")
        dl_bad_crc = Request(
            "DNP3_DL_Bad_CRC",
            children=(
                Block(
                    "Link_Header_BadCRC",
                    children=(
                        Bytes("Start_Bytes_BadCRC", b"\x05\x64", fuzzable=False),
                        Byte("Length_BadCRC", 8),
                        Byte("Control_BadCRC", 0x44),
                        Word("Dest_Addr_BadCRC", dest_addr, endian="<"),
                        Word("Src_Addr_BadCRC", src_addr, endian="<"),
                    ),
                ),
                # Static invalid header CRC -- boofuzz Group fuzzes through the two
                # known-bad values; using Static (not Checksum) ensures the bytes are
                # NOT recomputed by the send pipeline.
                Group(
                    "Header_CRC_BadCRC",
                    values=[b"\x00\x00", b"\xff\xff"],
                ),
                Block(
                    "User_Data_BadCRC",
                    children=(
                        Byte("Transport_BadCRC", 0xC0),
                        Byte("App_Control_BadCRC", 0xC0),
                        Byte("Function_Code_BadCRC", DNP3FunctionCodes.READ),
                    ),
                ),
                Checksum(
                    name="Data_CRC_BadCRC",
                    block_name="User_Data_BadCRC",
                    algorithm=self._dnp3_crc16,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Reordered for fast coverage + early crash detection:
        # - PHASE 1: Quick FC sweep (all 31 FCs in ~30 sec)
        # - PHASE 2: High-crash tests (overflow, buffer attacks)
        # - PHASE 3: CVE-targeted operations (control, file, auth)
        # - PHASE 4: Boundary attacks
        # - PHASE 5: Everything else (reads, system ops, malformed)
        self.log.debug("[DNP3-Fuzz] Connecting requests to session in optimized order")

        # ==================== PHASE 1: QUICK FC SWEEP (~30 sec) ====================
        self.log.debug("[DNP3-Fuzz] PHASE 1: Quick FC Sweep")
        if self.is_request_enabled("DNP3_Baseline"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_Baseline requests")
            self.session.connect(quick_fc_coverage)
            self.session.connect(baseline_read)

        # ==================== PHASE 2: HIGH-CRASH TESTS (~3 min) ====================
        self.log.debug("[DNP3-Fuzz] PHASE 2: High-Crash Tests")
        if self.is_request_enabled("DNP3_Overflow"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_Overflow requests (CVE-2020-10615 pattern)")
            # Length overflow - CVE-2020-10615 pattern
            self.session.connect(length_overflow)
            # Control field attacks
            self.session.connect(control_field_attack)
            # Object count overflow
            self.session.connect(object_count_overflow)
            # Transport layer attacks
            self.session.connect(transport_attack)
            # App control attacks
            self.session.connect(app_control_attack)

        if self.is_request_enabled("DNP3_Combined"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_Combined requests")
            # Combined mismatch attack
            self.session.connect(combined_mismatch)

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS (~3 min) ====================
        self.log.debug("[DNP3-Fuzz] PHASE 3: CVE-Targeted Operations")
        if not self.enable_write:
            self.log.warning(
                "[DNP3] Write operations disabled (enable_write=False). "
                "Skipping DNP3_Control, DNP3_File, and write system ops."
            )

        if self.is_request_enabled("DNP3_Control") and self.enable_control:
            self.log.debug(
                "[DNP3-Fuzz] Enabling DNP3_Control requests (Direct Operate, Select, Operate)"
            )
            self.session.connect(direct_operate)
            self.session.connect(select_request)
            self.session.connect(operate_request)
            self.session.connect(analog_output)

        if self.is_request_enabled("DNP3_File") and self.enable_file:
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_File requests (CVE-2020-10611 target)")
            self.session.connect(get_file_info)
            self.session.connect(open_file)
            self.session.connect(delete_file)
            self.session.connect(file_path_traversal)

        if self.is_request_enabled("DNP3_Auth") and self.enable_auth:
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_Auth requests (SAv5 fuzzing)")
            self.session.connect(auth_request)
            self.session.connect(auth_reply)
            self.session.connect(auth_aggressive)
            self.session.connect(auth_key_status)
            self.session.connect(auth_key_change)
            self.session.connect(auth_error)
        elif self.is_request_enabled("DNP3_Auth") and not self.enable_auth:
            self.log.debug("[DNP3-Fuzz] DNP3_Auth requested but enable_auth=False, skipping")

        # ==================== PHASE 4: BOUNDARY ATTACKS (~3 min) ====================
        self.log.debug("[DNP3-Fuzz] PHASE 4: Boundary Attacks")
        if self.is_request_enabled("DNP3_Boundary"):
            self.log.debug(
                "[DNP3-Fuzz] Enabling DNP3_Boundary requests (address, qualifier, object)"
            )
            self.session.connect(address_boundary)
            self.session.connect(qualifier_boundary)
            self.session.connect(object_group_boundary)

        # ==================== PHASE 5: REMAINING TESTS ====================
        self.log.debug("[DNP3-Fuzz] PHASE 5: Remaining Tests")
        if self.is_request_enabled("DNP3_Read"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_Read requests (8 read operations)")
            self.session.connect(read_binary_inputs)
            self.session.connect(read_analog_inputs)
            self.session.connect(read_counters)
            self.session.connect(read_class_poll)
            self.session.connect(read_binary_output)
            self.session.connect(read_binary_events)
            self.session.connect(read_analog_events)
            self.session.connect(read_time)

        if self.is_request_enabled("DNP3_System"):
            # Safe read-like system operations (always enabled)
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_System safe requests (delay, time)")
            self.session.connect(delay_measure)
            self.session.connect(record_time)

            # Write/destructive system operations (gated by enable_write)
            if self.enable_write:
                self.log.debug(
                    "[DNP3-Fuzz] Enabling DNP3_System write requests "
                    "(restart, freeze, unsolicited, assign_class)"
                )
                self.session.connect(cold_restart)
                self.session.connect(warm_restart)
                self.session.connect(enable_unsolicited)
                self.session.connect(disable_unsolicited)
                self.session.connect(freeze_counters)
                self.session.connect(freeze_clear)
                self.session.connect(assign_class)

        if self.is_request_enabled("DNP3_Malformed"):
            self.log.debug(
                "[DNP3-Fuzz] Enabling DNP3_Malformed requests (invalid FC, addr, start bytes)"
            )
            self.session.connect(malformed_fc)
            self.session.connect(malformed_addr)
            self.session.connect(invalid_start_bytes)

        # ==================== EXTENDED COVERAGE WIRING ====================
        if self.is_request_enabled("DNP3_Object_Sweep"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_Object_Sweep (Group x Variation)")
            self.session.connect(object_sweep)

        if self.is_request_enabled("DNP3_IIN_Master"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_IIN_Master (master-emulation IIN fuzz)")
            self.session.connect(iin_master)

        if self.is_request_enabled("DNP3_DL_Bad_CRC"):
            self.log.debug("[DNP3-Fuzz] Enabling DNP3_DL_Bad_CRC (static invalid header CRC)")
            self.session.connect(dl_bad_crc)

        self.log.debug("[DNP3-Fuzz] Exiting _define_protocol() - protocol definition complete")


# For backward compatibility and explicit exports
__all__ = ["DNP3Fuzzer", "DNP3FunctionCodes", "DNP3ObjectGroups"]
