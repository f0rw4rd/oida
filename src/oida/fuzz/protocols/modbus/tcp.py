"""Modbus TCP Protocol Fuzzer"""

from typing import Any, Dict, List, Optional

from boofuzz import Block, Byte, DWord, Group, Request, Size, Static, Word

from ...core.base_fuzzer import BaseFuzzer, RequestInfo
from ...core.config import ProtocolType
from ...core.session.logging import get_logger
from ...monitors import BaseMonitor, ModbusMonitor

from .constants import (
    ADDRESS_BOUNDARIES,
    BROADCAST_WRITE_FUNCTION_CODES,
    INVALID_FUNCTION_CODES,
    ModbusDiagnosticCodes,
    ModbusFunctionCodes,
    READ_FUNCTION_CODES,
    RESERVED_UNIT_IDS,
    UNIT_ID_BOUNDARIES,
)
from .pdu import (
    create_address_boundary_pdu,
    create_baseline_read_pdu,
    create_byte_count_boundary_pdu,
    create_canopen_mei_pdu,
    create_coil_value_boundary_pdu,
    create_coils_boundary_pdu,
    create_combined_byte_count_mismatch_pdu,
    create_combined_high_addr_max_qty_pdu,
    create_combined_invalid_fc_address_pdu,
    create_combined_oversized_pdu,
    create_combined_zero_quantity_pdu,
    create_device_id_pdu,
    create_diagnostics_pdu,
    create_discrete_inputs_boundary_pdu,
    create_error_testing_pdu,
    create_exception_responses_pdu,
    create_file_record_pdu,
    create_get_comm_event_counter_pdu,
    create_get_comm_event_log_pdu,
    create_holding_registers_boundary_pdu,
    create_input_registers_boundary_pdu,
    create_malformed_pdu,
    create_mask_write_pdu,
    create_memory_overflow_pdu,
    create_quantity_boundary_pdu,
    create_read_exception_status_pdu,
    create_read_fifo_queue_pdu,
    create_read_pdu,
    create_read_write_multiple_pdu,
    create_register_value_boundary_pdu,
    create_report_slave_id_pdu,
    create_quick_fc_pdu,
    create_trigger_illegal_address_pdu,
    create_trigger_illegal_function_pdu,
    create_trigger_illegal_value_pdu,
    create_user_defined_pdu,
    create_vendor_functions_pdu,
    create_write_coils_boundary_pdu,
    create_write_multiple_pdu,
    create_write_registers_boundary_pdu,
    create_write_single_pdu,
)

# Scanner FC detection (uses pymodbus for proper protocol handling)
from ....protocols.modbus.scanner import (
    execute_pdu,
    GenericPDU,
    FUNCTION_CODES,
    _get_modbus_tcp_client,
)

logger = get_logger(__name__)


class ModbusFuzzer(BaseFuzzer):
    """Comprehensive Modbus TCP protocol fuzzer implementation

    Supports both TCP (default) and UDP transports via the --transport option.
    """

    # Protocol-specific monitor: Modbus read check every 10 tests
    DEFAULT_MONITORS = "modbus:10"

    PROTOCOL_OPTIONS = {
        "transport": {
            "type": str,
            "default": "tcp",
            "description": "Transport protocol (tcp or udp)",
            "choices": ["tcp", "udp"],
            "example": "tcp",
        },
        "unit_id": {
            "type": int,
            "default": 1,
            "description": "Modbus Unit ID / Slave Address (1-247)",
            "example": "1",
        },
        "transaction_id": {
            "type": int,
            "default": 1,
            "description": "Starting transaction ID for MBAP header",
            "example": "1",
        },
        "timeout": {
            "type": float,
            "default": 1.0,
            "description": "Response timeout in seconds",
            "example": "2.0",
        },
        "enum_timeout": {
            "type": float,
            "default": 0.5,
            "description": "Timeout for enumeration probes in seconds",
            "example": "1.0",
        },
        "enable_write": {
            "type": bool,
            "default": True,
            "description": "Enable write operations (risky for production devices)",
        },
        "enable_broadcast": {
            "type": bool,
            "default": False,
            "description": "Enable broadcast (Unit ID 0) testing",
        },
        "monitor_timeout": {
            "type": int,
            "default": 2,
            "description": "Monitor connection/receive timeout in seconds",
            "example": "3",
        },
        "monitor_retry_count": {
            "type": int,
            "default": 2,
            "description": "Number of monitor retry attempts before failure",
            "example": "3",
        },
        "monitor_failure_threshold": {
            "type": int,
            "default": 2,
            "description": "Consecutive monitor failures before reporting target down",
            "example": "3",
        },
    }

    def __init__(self, config, connection_factory=None):
        """Initialize Modbus TCP fuzzer with transport selection."""
        # Set protocol type based on transport option
        transport = config.get_option("transport", "tcp").lower()
        if transport == "udp":
            config.protocol_type = ProtocolType.UDP
        else:
            config.protocol_type = ProtocolType.TCP

        # Configured Modbus Unit ID / Slave Address (1-247). Used for every
        # request that targets a specific unit (i.e. not the broadcast or
        # Unit_ID-boundary requests, which deliberately override it).
        self.unit_id = config.get_option("unit_id", 1)

        super().__init__(config, connection_factory)

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Baseline (includes Quick_FC_Coverage for fast breadth)
            RequestInfo("Modbus_Baseline", "Quick FC sweep (19 FCs) + baseline read", "baseline"),
            # High-crash tests (prioritized early)
            RequestInfo(
                "Modbus_MBAP_Testing",
                "MBAP header overflow/malformation (CVE-2024-10918)",
                "protocol",
            ),
            RequestInfo(
                "Modbus_Combined_Fuzzing",
                "Combined overflow/mismatch attacks",
                "boundary",
            ),
            RequestInfo("Modbus_Memory_Map", "Memory overflow and boundary testing", "protocol"),
            # Write operations (CVE targets)
            RequestInfo(
                "Modbus_Write_Operations",
                "Write functions (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17)",
                "write",
            ),
            RequestInfo("Modbus_File_Record", "File record operations (0x14, 0x15)", "write"),
            # Boundary testing
            RequestInfo(
                "Modbus_Boundary_Testing",
                "Field boundary fuzzing (address, quantity, byte count)",
                "boundary",
            ),
            RequestInfo(
                "Modbus_Exception_Testing",
                "Exception response and error triggers",
                "boundary",
            ),
            # Read operations (safe)
            RequestInfo(
                "Modbus_Read_Operations",
                "Read functions (0x01-0x04, 0x07, 0x0B, 0x0C, 0x11, 0x18)",
                "read",
            ),
            RequestInfo("Modbus_Diagnostics", "Diagnostic functions (0x08)", "read"),
            RequestInfo("Modbus_Device_ID", "Read device identification (0x2B)", "read"),
            RequestInfo("Modbus_System_Functions", "System/vendor-specific functions", "read"),
            # Broadcast testing
            RequestInfo("Modbus_Broadcast", "Broadcast address (0x00) testing", "broadcast"),
            # Special
            RequestInfo(
                "Modbus_User_Defined",
                "User-defined function codes (0x41-0x48)",
                "special",
            ),
            RequestInfo("Modbus_Malformed", "Malformed/random Modbus packets", "special"),
        ]

    def setup_custom_monitors(self) -> List[BaseMonitor]:
        timeout = self.config.get_option("monitor_timeout", 2)
        retry_count = self.config.get_option("monitor_retry_count", 2)
        failure_threshold = self.config.get_option("monitor_failure_threshold", 2)

        return [
            ModbusMonitor(
                self.config.target_ip,
                self.config.target_port or 502,
                timeout=timeout,
                check_interval=self.config.monitor_check_interval,
                retry_count=retry_count,
                failure_threshold=failure_threshold,
            )
        ]

    def _enumerate_capabilities(self) -> Optional[Dict[str, Any]]:
        """Probe Modbus device capabilities using scanner's FC detection.

        Uses pymodbus via the scanner module for proper protocol handling
        and accurate FC detection (interprets exception codes correctly).

        Returns:
            Dictionary with detected capabilities:
            - supported_fcs: Set of supported function codes
            - unit_id: Configured Unit ID
            - vendor: Device vendor name (if available)
            - product: Product code (if available)
        """
        capabilities: Dict[str, Any] = {
            "supported_fcs": set(),
            "unit_id": self.config.get_option("unit_id", 1),
            "vendor": None,
            "product": None,
        }

        fuzz_log = self._get_fuzz_logger()
        timeout = self.config.get_option("enum_timeout", 2.0)
        unit_id = capabilities["unit_id"]

        # FC range to test (1-127 covers all valid Modbus FCs)
        fc_range = range(1, 128)

        try:
            # Create pymodbus TCP client
            ModbusTcpClient = _get_modbus_tcp_client()
            client = ModbusTcpClient(
                host=self.config.target_ip,
                port=self.config.target_port or 502,
                timeout=timeout,
            )

            if not client.connect():
                fuzz_log.warning("Could not connect for FC enumeration")
                return capabilities

            try:
                fuzz_log.display("Enumerating function codes (1-127)...")

                for fc in fc_range:
                    try:
                        pdu = GenericPDU(function_code=fc)
                        result = execute_pdu(client, pdu, unit_id)

                        if not result.isError():
                            # Normal response - FC supported
                            capabilities["supported_fcs"].add(fc)
                        else:
                            # Check exception code
                            exc_code = getattr(result, "exception_code", None)
                            # Exception 1 = ILLEGAL_FUNCTION (not supported)
                            # Exception 2/3 = supported but invalid params
                            if exc_code in (2, 3):
                                capabilities["supported_fcs"].add(fc)
                            elif exc_code and exc_code != 1:
                                # Other exceptions also indicate FC is implemented
                                capabilities["supported_fcs"].add(fc)

                    except Exception as e:
                        err_str = str(e).lower()
                        # Decode errors mean FC responded with vendor-specific format
                        if "unable to decode" in err_str or "unknown response" in err_str:
                            capabilities["supported_fcs"].add(fc)
            finally:
                client.close()

            # Log results
            supported = sorted(capabilities["supported_fcs"])
            if supported:
                fc_names = [f"0x{fc:02X} ({FUNCTION_CODES.get(fc, '?')})" for fc in supported[:10]]
                if len(supported) > 10:
                    fc_names.append(f"... +{len(supported) - 10} more")
                fuzz_log.display(f"Supported FCs: {len(supported)}/127")
                for name in fc_names:
                    fuzz_log.display(f"  {name}")
            else:
                fuzz_log.display("Function Codes: none detected (fuzzing all)")

        except Exception as e:
            fuzz_log.warning(f"FC enumeration failed: {e}")

        return capabilities

    def _supports_function_code(self, fc: int) -> bool:
        """Check if function code is supported by target.

        Used to filter fuzz requests based on enumeration results.

        Args:
            fc: Function code to check (e.g., 0x03)

        Returns:
            True if FC is supported or enumeration was skipped/failed
        """
        if not self.config.enumerate:
            return True
        if not self.capabilities.get("supported_fcs"):
            return True  # Assume all supported if enumeration failed
        return fc in self.capabilities["supported_fcs"]

    def _create_mbap_header(self) -> Block:
        """Create standard MBAP header block.

        MBAP Header format (Modbus TCP/IP):
        - Transaction ID: 2 bytes
        - Protocol ID: 2 bytes (0x0000 for Modbus)
        - Length: 2 bytes (Unit ID + PDU length)
        - Unit ID: 1 byte

        The Length field must include the Unit ID byte (1) plus the PDU length.
        """
        return Block(
            "MBAP_Header",
            children=(
                Word("Transaction_ID", 0x0001, endian=">", fuzzable=False),
                Word("Protocol_ID", 0x0000, endian=">", fuzzable=False),
                Size(
                    "Length",
                    block_name="PDU",
                    length=2,
                    endian=">",
                    inclusive=False,
                    math=lambda x: x + 1,
                    fuzzable=False,
                ),
                Byte("Unit_ID", self.unit_id, fuzzable=False),
            ),
        )

    def _create_broadcast_mbap_header(self, transaction_id: int = 0x0001) -> Block:
        """Create MBAP header with broadcast address (Unit ID 0)."""
        return Block(
            "MBAP_Header",
            children=(
                Word("Transaction_ID", transaction_id, endian=">", fuzzable=False),
                Word("Protocol_ID", 0x0000, endian=">", fuzzable=False),
                Size(
                    "Length",
                    block_name="PDU",
                    length=2,
                    endian=">",
                    inclusive=False,
                    math=lambda x: x + 1,
                    fuzzable=False,
                ),
                Byte("Unit_ID", 0x00, fuzzable=False),  # Broadcast address
            ),
        )

    def _define_protocol(self) -> None:
        """Define the complete Modbus TCP protocol structure"""

        # ================================================================
        # BASELINE: Simple Read Holding Register + Quick FC Sweep
        # ================================================================

        # Note: Transaction_ID is fuzzable=True to ensure boofuzz sends at least one packet
        # (boofuzz skips requests with 0 mutations entirely)
        baseline_read = Request(
            "Modbus_Baseline",
            children=(
                Block(
                    "MBAP_Header_Baseline",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">", fuzzable=True),
                        Word("Protocol_ID", 0x0000, endian=">", fuzzable=False),
                        Word("Length", 0x0006, endian=">", fuzzable=False),
                        Byte("Unit_ID", self.unit_id, fuzzable=False),
                    ),
                ),
                create_baseline_read_pdu(),
            ),
        )

        # PHASE 1: Quick FC Sweep - All 19 function codes once with minimal params
        quick_fc_coverage = Request(
            "Quick_FC_Coverage",
            children=(
                self._create_mbap_header(),
                create_quick_fc_pdu(),
            ),
        )

        # ================================================================
        # STANDARD READ OPERATIONS
        # ================================================================

        read_request = Request(
            "Standard_Read_Request",
            children=(
                self._create_mbap_header(),
                create_read_pdu(),
            ),
        )

        read_exception_status = Request(
            "Read_Exception_Status",
            children=(
                self._create_mbap_header(),
                create_read_exception_status_pdu(),
            ),
        )

        get_comm_event_counter = Request(
            "Get_Comm_Event_Counter",
            children=(
                self._create_mbap_header(),
                create_get_comm_event_counter_pdu(),
            ),
        )

        get_comm_event_log = Request(
            "Get_Comm_Event_Log",
            children=(
                self._create_mbap_header(),
                create_get_comm_event_log_pdu(),
            ),
        )

        report_slave_id = Request(
            "Report_Slave_ID",
            children=(
                self._create_mbap_header(),
                create_report_slave_id_pdu(),
            ),
        )

        read_fifo_queue = Request(
            "Read_FIFO_Queue",
            children=(
                self._create_mbap_header(),
                create_read_fifo_queue_pdu(),
            ),
        )

        # ================================================================
        # WRITE OPERATIONS
        # ================================================================

        write_single = Request(
            "Write_Single",
            children=(
                self._create_mbap_header(),
                create_write_single_pdu(),
            ),
        )

        write_multiple = Request(
            "Write_Multiple",
            children=(
                self._create_mbap_header(),
                create_write_multiple_pdu(),
            ),
        )

        mask_write = Request(
            "Mask_Write_Register",
            children=(
                self._create_mbap_header(),
                create_mask_write_pdu(),
            ),
        )

        read_write_multiple = Request(
            "Read_Write_Multiple",
            children=(
                self._create_mbap_header(),
                create_read_write_multiple_pdu(),
            ),
        )

        file_record = Request(
            "File_Record",
            children=(
                self._create_mbap_header(),
                create_file_record_pdu(),
            ),
        )

        # ================================================================
        # DIAGNOSTIC AND DEVICE ID
        # ================================================================

        diagnostic = Request(
            "Diagnostic",
            children=(
                self._create_mbap_header(),
                create_diagnostics_pdu(),
            ),
        )

        read_device_id = Request(
            "Read_Device_Identification",
            children=(
                self._create_mbap_header(),
                create_device_id_pdu(),
            ),
        )

        canopen_general_ref = Request(
            "CANopen_General_Reference",
            children=(
                self._create_mbap_header(),
                create_canopen_mei_pdu(),
            ),
        )

        system_functions = Request(
            "System_Functions",
            children=(
                self._create_mbap_header(),
                create_vendor_functions_pdu(),
            ),
        )

        # ================================================================
        # BOUNDARY TESTING
        # ================================================================

        address_boundary = Request(
            "Address_Boundary_Testing",
            children=(
                self._create_mbap_header(),
                create_address_boundary_pdu(),
            ),
        )

        quantity_boundary = Request(
            "Quantity_Boundary_Testing",
            children=(
                self._create_mbap_header(),
                create_quantity_boundary_pdu(),
            ),
        )

        byte_count_boundary = Request(
            "Byte_Count_Boundary_Testing",
            children=(
                self._create_mbap_header(),
                create_byte_count_boundary_pdu(),
            ),
        )

        value_boundary_coils = Request(
            "Value_Boundary_Coils",
            children=(
                self._create_mbap_header(),
                create_coil_value_boundary_pdu(),
            ),
        )

        value_boundary_registers = Request(
            "Value_Boundary_Registers",
            children=(
                self._create_mbap_header(),
                create_register_value_boundary_pdu(),
            ),
        )

        # ================================================================
        # MEMORY MAP BOUNDARY TESTING
        # ================================================================

        coils_boundary = Request(
            "Coils_Memory_Boundary",
            children=(
                self._create_mbap_header(),
                create_coils_boundary_pdu(),
            ),
        )

        discrete_inputs_boundary = Request(
            "Discrete_Inputs_Memory_Boundary",
            children=(
                self._create_mbap_header(),
                create_discrete_inputs_boundary_pdu(),
            ),
        )

        input_registers_boundary = Request(
            "Input_Registers_Memory_Boundary",
            children=(
                self._create_mbap_header(),
                create_input_registers_boundary_pdu(),
            ),
        )

        holding_registers_boundary = Request(
            "Holding_Registers_Memory_Boundary",
            children=(
                self._create_mbap_header(),
                create_holding_registers_boundary_pdu(),
            ),
        )

        write_coils_boundary = Request(
            "Write_Coils_Memory_Boundary",
            children=(
                self._create_mbap_header(),
                create_write_coils_boundary_pdu(),
            ),
        )

        write_holding_registers_boundary = Request(
            "Write_Holding_Registers_Memory_Boundary",
            children=(
                self._create_mbap_header(),
                create_write_registers_boundary_pdu(),
            ),
        )

        coils_overflow = Request(
            "Coils_Memory_Overflow",
            children=(
                self._create_mbap_header(),
                create_memory_overflow_pdu(ModbusFunctionCodes.READ_COILS),
            ),
        )

        holding_registers_overflow = Request(
            "Holding_Registers_Memory_Overflow",
            children=(
                self._create_mbap_header(),
                create_memory_overflow_pdu(ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            ),
        )

        # ================================================================
        # EXCEPTION TESTING
        # ================================================================

        exception_responses = Request(
            "Exception_Responses",
            children=(
                self._create_mbap_header(),
                create_exception_responses_pdu(),
            ),
        )

        trigger_illegal_address = Request(
            "Trigger_Illegal_Data_Address",
            children=(
                self._create_mbap_header(),
                create_trigger_illegal_address_pdu(),
            ),
        )

        trigger_illegal_value = Request(
            "Trigger_Illegal_Data_Value",
            children=(
                self._create_mbap_header(),
                create_trigger_illegal_value_pdu(),
            ),
        )

        trigger_illegal_function = Request(
            "Trigger_Illegal_Function",
            children=(
                self._create_mbap_header(),
                create_trigger_illegal_function_pdu(),
            ),
        )

        # ================================================================
        # COMBINED FIELD FUZZING
        # ================================================================

        combined_invalid_fc_address = Request(
            "Combined_Invalid_FC_Address",
            children=(
                self._create_mbap_header(),
                create_combined_invalid_fc_address_pdu(),
            ),
        )

        combined_valid_fc_zero_qty = Request(
            "Combined_Valid_FC_Zero_Qty",
            children=(
                self._create_mbap_header(),
                create_combined_zero_quantity_pdu(),
            ),
        )

        combined_write_mismatch = Request(
            "Combined_Write_Byte_Count_Mismatch",
            children=(
                self._create_mbap_header(),
                create_combined_byte_count_mismatch_pdu(),
            ),
        )

        combined_oversized = Request(
            "Combined_Oversized_Fields",
            children=(
                self._create_mbap_header(),
                create_combined_oversized_pdu(),
            ),
        )

        combined_high_addr_max_qty = Request(
            "Combined_High_Address_Max_Quantity",
            children=(
                self._create_mbap_header(),
                create_combined_high_addr_max_qty_pdu(),
            ),
        )

        # ================================================================
        # MBAP HEADER TESTING (TCP-Specific)
        # ================================================================

        transaction_id_boundary = Request(
            "Transaction_ID_Boundary",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Group("Transaction_ID_Boundary", values=ADDRESS_BOUNDARIES),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Size(
                            "Length",
                            block_name="PDU",
                            length=2,
                            endian=">",
                            inclusive=False,
                            math=lambda x: x + 1,
                        ),
                        Byte("Unit_ID", self.unit_id),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        invalid_protocol_id = Request(
            "Invalid_Protocol_ID",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">"),
                        Group(
                            "Invalid_Protocol_ID",
                            values=[
                                b"\x00\x01",  # Invalid (only 0x0000 valid for Modbus/TCP)
                                b"\x00\x02",
                                b"\x00\xff",
                                b"\x12\x34",
                                b"\x7f\xff",
                                b"\xff\xff",
                            ],
                        ),
                        Size(
                            "Length",
                            block_name="PDU",
                            length=2,
                            endian=">",
                            inclusive=False,
                            math=lambda x: x + 1,
                        ),
                        Byte("Unit_ID", self.unit_id),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        length_too_short = Request(
            "Length_Field_Too_Short",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Word("Length_Too_Short", 0x0003, endian=">"),  # Says 3 bytes
                        Byte("Unit_ID", self.unit_id),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),  # But actual PDU is 5 bytes
                    ),
                ),
            ),
        )

        length_too_long = Request(
            "Length_Field_Too_Long",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Word("Length_Too_Long", 0x0014, endian=">"),  # Says 20 bytes
                        Byte("Unit_ID", self.unit_id),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),  # But actual PDU is only 5 bytes
                    ),
                ),
            ),
        )

        length_boundary = Request(
            "Length_Field_Boundary",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Group(
                            "Length_Boundary",
                            values=[
                                b"\x00\x00",  # Zero (invalid)
                                b"\x00\x01",  # Minimum (just Unit_ID, no PDU)
                                b"\x00\x06",  # Typical valid (Unit_ID + 5 byte PDU)
                                b"\x00\xfc",  # 252 (maximum PDU + Unit_ID)
                                b"\x01\x00",  # 256 (oversized)
                                b"\xff\xff",  # Maximum (65535)
                            ],
                        ),
                        Byte("Unit_ID", self.unit_id),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # Length overflow attack - sends oversized payloads
        length_overflow = Request(
            "Length_Field_Overflow",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Size(
                            "Length",
                            block_name="PDU",
                            length=2,
                            endian=">",
                            inclusive=False,
                            math=lambda x: x + 1,
                        ),
                        Byte("Unit_ID", self.unit_id),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Group(
                            "Overflow_Payload",
                            values=[
                                b"\x00\x00\x00\x01" + b"A" * 60,  # 64 bytes total (borderline)
                                b"\x00\x00\x00\x01" + b"A" * 96,  # 100 bytes total (overflow)
                                b"\x00\x00\x00\x01"
                                + b"A" * 196,  # 200 bytes total (large overflow)
                                b"\x00\x00\x00\x01" + b"A" * 252,  # 256 bytes total (max overflow)
                            ],
                        ),
                    ),
                ),
            ),
        )

        unit_id_boundary = Request(
            "Unit_ID_Boundary",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0001, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Size(
                            "Length",
                            block_name="PDU",
                            length=2,
                            endian=">",
                            inclusive=False,
                            math=lambda x: x + 1,
                        ),
                        Group("Unit_ID_Boundary", values=UNIT_ID_BOUNDARIES),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        # ================================================================
        # BROADCAST TESTING (TCP-Specific)
        # ================================================================

        broadcast_write_single_coil = Request(
            "Broadcast_Write_Single_Coil",
            children=(
                self._create_broadcast_mbap_header(0x0001),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_COIL),
                        Word("Coil_Address", 0x0000, endian=">"),
                        Group("Coil_Value", values=[b"\x00\x00", b"\xff\x00"]),
                    ),
                ),
            ),
        )

        broadcast_write_single_register = Request(
            "Broadcast_Write_Single_Register",
            children=(
                self._create_broadcast_mbap_header(0x0002),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_REGISTER),
                        Word("Register_Address", 0x0000, endian=">"),
                        Word("Register_Value", 0x1234, endian=">"),
                    ),
                ),
            ),
        )

        broadcast_write_multiple_coils = Request(
            "Broadcast_Write_Multiple_Coils",
            children=(
                self._create_broadcast_mbap_header(0x0003),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_COILS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0010, endian=">"),  # 16 coils
                        Byte("Byte_Count", 0x02),
                        Word("Coil_Values", 0xFFFF, endian=">"),
                    ),
                ),
            ),
        )

        broadcast_write_multiple_registers = Request(
            "Broadcast_Write_Multiple_Registers",
            children=(
                self._create_broadcast_mbap_header(0x0004),
                Block(
                    "PDU",
                    children=(
                        Static(
                            "Function_Code",
                            ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS,
                        ),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0002, endian=">"),
                        Byte("Byte_Count", 0x04),
                        DWord("Register_Values", 0x12345678, endian=">"),
                    ),
                ),
            ),
        )

        broadcast_read_invalid = Request(
            "Broadcast_Read_Invalid",
            children=(
                self._create_broadcast_mbap_header(0x0005),
                Block(
                    "PDU",
                    children=(
                        Group("Read_Function_Code", values=READ_FUNCTION_CODES),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        broadcast_diagnostics = Request(
            "Broadcast_Diagnostics",
            children=(
                self._create_broadcast_mbap_header(0x0006),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.DIAGNOSTICS),
                        Group(
                            "Diagnostic_Sub_Function",
                            values=[
                                ModbusDiagnosticCodes.RESTART_COMMUNICATIONS,
                                ModbusDiagnosticCodes.FORCE_LISTEN_ONLY_MODE,
                                ModbusDiagnosticCodes.CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER,
                            ],
                        ),
                        Word("Data", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        reserved_unit_ids_write = Request(
            "Reserved_Unit_IDs_Write",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0007, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Size(
                            "Length",
                            block_name="PDU",
                            length=2,
                            endian=">",
                            inclusive=False,
                            math=lambda x: x + 1,
                        ),
                        Group("Reserved_Unit_ID", values=RESERVED_UNIT_IDS),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_REGISTER),
                        Word("Register_Address", 0x0000, endian=">"),
                        Word("Register_Value", 0xABCD, endian=">"),
                    ),
                ),
            ),
        )

        reserved_unit_ids_read = Request(
            "Reserved_Unit_IDs_Read",
            children=(
                Block(
                    "MBAP_Header",
                    children=(
                        Word("Transaction_ID", 0x0008, endian=">"),
                        Word("Protocol_ID", 0x0000, endian=">"),
                        Size(
                            "Length",
                            block_name="PDU",
                            length=2,
                            endian=">",
                            inclusive=False,
                            math=lambda x: x + 1,
                        ),
                        Group("Reserved_Unit_ID", values=RESERVED_UNIT_IDS),
                    ),
                ),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
            ),
        )

        broadcast_cross_function = Request(
            "Broadcast_Cross_Function",
            children=(
                self._create_broadcast_mbap_header(0x0009),
                Block(
                    "PDU",
                    children=(
                        Group("Function_Code", values=BROADCAST_WRITE_FUNCTION_CODES),
                        Block(
                            "Generic_Parameters",
                            children=(
                                Word("Parameter1", 0x0000, endian=">"),
                                Word("Parameter2", 0x0000, endian=">"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        broadcast_invalid_function = Request(
            "Broadcast_Invalid_Function",
            children=(
                self._create_broadcast_mbap_header(0x000A),
                Block(
                    "PDU",
                    children=(
                        Group("Invalid_Function_Code", values=INVALID_FUNCTION_CODES[:6]),
                        Word("Dummy_Data", 0x0000, endian=">"),
                    ),
                ),
            ),
        )

        broadcast_boundary_addresses = Request(
            "Broadcast_Boundary_Addresses",
            children=(
                self._create_broadcast_mbap_header(0x000B),
                Block(
                    "PDU",
                    children=(
                        Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_REGISTER),
                        Group(
                            "Boundary_Address",
                            values=[
                                b"\x00\x00",
                                b"\x7f\xff",
                                b"\x80\x00",
                                b"\xff\xff",
                            ],
                        ),
                        Word("Register_Value", 0x5555, endian=">"),
                    ),
                ),
            ),
        )

        # ================================================================
        # MALFORMED AND USER-DEFINED
        # ================================================================

        malformed_modbus = Request(
            "Malformed_Modbus",
            children=(
                self._create_mbap_header(),
                create_malformed_pdu(),
            ),
        )

        user_defined = Request(
            "User_Defined",
            children=(
                self._create_mbap_header(),
                create_user_defined_pdu(),
            ),
        )

        error_testing = Request(
            "Error_Testing",
            children=(
                self._create_mbap_header(),
                create_error_testing_pdu(),
            ),
        )

        # ================================================================
        # OPTIMIZED REQUEST ORDERING
        # ================================================================

        # PHASE 1: QUICK FC SWEEP (~30 sec)
        if self.is_request_enabled("Modbus_Baseline"):
            self.session.connect(quick_fc_coverage)
            self.session.connect(baseline_read)

        # PHASE 2: HIGH-CRASH TESTS (~3 min)
        if self.is_request_enabled("Modbus_MBAP_Testing"):
            self.session.connect(length_overflow)
            self.session.connect(length_too_long)
            self.session.connect(length_too_short)
            self.session.connect(length_boundary)
            self.session.connect(transaction_id_boundary)
            self.session.connect(invalid_protocol_id)
            self.session.connect(unit_id_boundary)

        if self.is_request_enabled("Modbus_Combined_Fuzzing"):
            self.session.connect(combined_oversized)
            self.session.connect(combined_write_mismatch)
            self.session.connect(combined_high_addr_max_qty)
            self.session.connect(combined_invalid_fc_address)
            self.session.connect(combined_valid_fc_zero_qty)

        if self.is_request_enabled("Modbus_Memory_Map"):
            self.session.connect(holding_registers_overflow)
            self.session.connect(coils_overflow)
            self.session.connect(coils_boundary)
            self.session.connect(discrete_inputs_boundary)
            self.session.connect(input_registers_boundary)
            self.session.connect(holding_registers_boundary)
            self.session.connect(write_coils_boundary)
            self.session.connect(write_holding_registers_boundary)

        # PHASE 3: CVE-TARGETED WRITES (~3 min)
        if self.is_request_enabled("Modbus_Write_Operations"):
            self.session.connect(write_single)
            self.session.connect(write_multiple)
            self.session.connect(read_write_multiple)
            self.session.connect(mask_write)

        if self.is_request_enabled("Modbus_File_Record"):
            self.session.connect(file_record)

        # PHASE 4: BOUNDARY ATTACKS (~3 min)
        if self.is_request_enabled("Modbus_Boundary_Testing"):
            self.session.connect(quantity_boundary)
            self.session.connect(address_boundary)
            self.session.connect(byte_count_boundary)
            self.session.connect(value_boundary_coils)
            self.session.connect(value_boundary_registers)

        if self.is_request_enabled("Modbus_Exception_Testing"):
            self.session.connect(exception_responses)
            self.session.connect(trigger_illegal_address)
            self.session.connect(trigger_illegal_value)
            self.session.connect(trigger_illegal_function)

        # PHASE 5: REMAINING TESTS
        if self.is_request_enabled("Modbus_Read_Operations"):
            self.session.connect(read_request)
            if self._supports_function_code(0x07):
                self.session.connect(read_exception_status)
            if self._supports_function_code(0x0B):
                self.session.connect(get_comm_event_counter)
            if self._supports_function_code(0x0C):
                self.session.connect(get_comm_event_log)
            if self._supports_function_code(0x11):
                self.session.connect(report_slave_id)
            if self._supports_function_code(0x18):
                self.session.connect(read_fifo_queue)

        if self.is_request_enabled("Modbus_Diagnostics"):
            if self._supports_function_code(0x08):
                self.session.connect(diagnostic)

        if self.is_request_enabled("Modbus_Device_ID"):
            if self._supports_function_code(0x2B):
                self.session.connect(read_device_id)
                self.session.connect(canopen_general_ref)

        if self.is_request_enabled("Modbus_System_Functions"):
            self.session.connect(system_functions)

        if self.is_request_enabled("Modbus_Broadcast"):
            self.session.connect(broadcast_write_single_coil)
            self.session.connect(broadcast_write_single_register)
            self.session.connect(broadcast_write_multiple_coils)
            self.session.connect(broadcast_write_multiple_registers)
            self.session.connect(broadcast_read_invalid)
            self.session.connect(broadcast_diagnostics)
            self.session.connect(reserved_unit_ids_write)
            self.session.connect(reserved_unit_ids_read)
            self.session.connect(broadcast_cross_function)
            self.session.connect(broadcast_invalid_function)
            self.session.connect(broadcast_boundary_addresses)

        if self.is_request_enabled("Modbus_User_Defined"):
            self.session.connect(user_defined)
            self.session.connect(error_testing)

        if self.is_request_enabled("Modbus_Malformed"):
            self.session.connect(malformed_modbus)

        return self.session

    def fuzz_node(self, node_name: str) -> None:
        """Override to add specific node fuzzing logic for Modbus.

        Logs the node-specific value ranges being tested, then delegates
        to the base class which calls ``self.session.fuzz(node_path)``
        to drive the actual fuzzing run.
        """
        fuzz_log = self._get_fuzz_logger()
        if node_name == "Function_Code":
            fuzz_log.display("Fuzzing all 255 function codes (0x00-0xFE)")
        elif node_name == "Unit_ID":
            fuzz_log.display("Fuzzing all 255 unit IDs (0x00-0xFE)")
        elif node_name == "Sub_Function":
            fuzz_log.display("Fuzzing diagnostic sub-functions (16x255 combinations)")
        super().fuzz_node(node_name)
