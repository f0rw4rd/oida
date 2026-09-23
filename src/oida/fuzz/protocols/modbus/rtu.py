"""Modbus RTU Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.
Test ordering follows the progressive depth strategy:
- Phase 1: Quick FC sweep (all function codes once in ~30 sec)
- Phase 2: High-crash tests (overflow, buffer attacks)
- Phase 3: CVE-targeted operations (write functions)
- Phase 4: Boundary attacks
- Phase 5: Standard operations and diagnostics
"""

from typing import List

from boofuzz import Block, Byte, Bytes, Checksum, Group, Request, Word

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import ProtocolType
from oida.fuzz.monitors import BaseMonitor, ModbusRTUMonitor

from oida.fuzz.protocols.modbus.constants import (
    ADDRESS_BOUNDARIES,
    COIL_VALUE_BOUNDARIES,
    DEVICE_ID_READ_CODES,
    INVALID_FUNCTION_CODES,
    ModbusDeviceIDObjects,
    ModbusDiagnosticCodes,
    ModbusFunctionCodes,
    ModbusMEITypes,
    QUANTITY_BOUNDARIES,
    READ_FUNCTION_CODES,
    UNIT_ID_BOUNDARIES,
    WRITE_SINGLE_FUNCTION_CODES,
)
from oida.fuzz.protocols.modbus.pdu import (
    create_byte_count_mismatch_values,
    create_oversized_quantity_values,
    create_truncated_pdu_values,
)


class ModbusRTUFuzzer(BaseFuzzer):
    """Modbus RTU Protocol Fuzzer for serial and RTU-over-TCP security testing

    Implements Modbus RTU fuzzing with support for:
    - Serial (RS-232/RS-485) - default
    - RTU over TCP - RTU frame format sent over TCP connection

    Uses 1-byte slave address, PDU, and 2-byte CRC-16.

    Test Ordering Strategy:
    - Phase 1 (0-30s): Quick_FC_Coverage touches all 17 FCs once
    - Phase 2 (30s-3min): High-crash overflow and buffer attacks
    - Phase 3 (3-6min): CVE-targeted write operations
    - Phase 4 (6-9min): Boundary value attacks
    - Phase 5 (9min+): Standard reads, diagnostics, broadcast
    """

    PROTOCOL_OPTIONS = {
        "transport": {
            "type": str,
            "default": "serial",
            "description": "Transport protocol (serial or tcp for RTU-over-TCP)",
            "choices": ["serial", "tcp"],
            "example": "serial",
        },
        "slave_address": {
            "type": int,
            "default": 1,
            "description": "Modbus RTU slave address (1-247)",
            "example": "1",
        },
        "baudrate": {
            "type": int,
            "default": 9600,
            "description": "Serial baudrate (serial transport only)",
            "choices": [9600, 19200, 38400, 57600, 115200],
            "example": "9600",
        },
        "bytesize": {
            "type": int,
            "default": 8,
            "description": "Number of data bits (serial transport only)",
            "choices": [5, 6, 7, 8],
            "example": "8",
        },
        "parity": {
            "type": str,
            "default": "N",
            "description": "Parity (serial transport only)",
            "choices": ["N", "E", "O", "M", "S"],
            "example": "N",
        },
        "stopbits": {
            "type": int,
            "default": 1,
            "description": "Number of stop bits (serial transport only)",
            "choices": [1, 2],
            "example": "1",
        },
        "timeout": {
            "type": float,
            "default": 1.0,
            "description": "Read timeout in seconds",
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
            "description": "Enable broadcast (slave address 0) testing",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo("RTU_Baseline", "Quick FC sweep (17 FCs) + baseline read", "baseline"),
            # Phase 2: High-crash tests (prioritized early)
            RequestInfo("RTU_Overflow_Testing", "Frame overflow and buffer attacks", "protocol"),
            # Phase 3: CVE-targeted operations
            RequestInfo(
                "RTU_Write_Operations",
                "Write functions (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17)",
                "write",
            ),
            RequestInfo("RTU_File_Record", "File record operations (0x14)", "write"),
            # Phase 4: Boundary attacks
            RequestInfo(
                "RTU_Boundary_Testing", "Field boundary fuzzing (address, quantity)", "boundary"
            ),
            RequestInfo("RTU_Memory_Map", "Memory area boundary testing", "boundary"),
            # Phase 5: Standard operations
            RequestInfo(
                "RTU_Read_Operations", "Read functions (0x01-0x04, 0x07, 0x11, 0x18)", "read"
            ),
            RequestInfo("RTU_Diagnostics", "Diagnostic functions (0x08)", "read"),
            RequestInfo("RTU_Device_ID", "Device identification (0x2B)", "read"),
            RequestInfo("RTU_Broadcast", "Broadcast address (0x00) testing", "broadcast"),
            RequestInfo("RTU_Invalid_FC", "Invalid function codes testing", "special"),
        ]

    def __init__(self, config, connection_factory=None):
        """Initialize Modbus RTU fuzzer with transport selection.

        Args:
            config: FuzzerConfig with protocol options
            connection_factory: Optional connection factory override

        Transport options:
            - 'serial': RS-232/RS-485 serial connection (default)
            - 'tcp': RTU over TCP (RTU frame format over TCP socket)
        """
        # Set protocol type based on transport option
        transport = config.get_option("transport", "serial").lower()
        if transport == "tcp":
            config.protocol_type = ProtocolType.TCP
        else:
            config.protocol_type = ProtocolType.SERIAL

        super().__init__(config, connection_factory)

        # Calculate frame gap based on baudrate (3.5 character times)
        # Only relevant for serial transport, but harmless for TCP
        baudrate = config.get_option("baudrate", 9600)
        char_time = 11.0 / baudrate  # 11 bits per char (8N1 + overhead)
        self.frame_gap = char_time * 3.5

    def _calculate_modbus_crc(self, data: bytes) -> bytes:
        """
        Calculate Modbus RTU CRC-16.

        Uses polynomial 0xA001 (reversed 0x8005).

        Args:
            data: Frame bytes (slave address + PDU)

        Returns:
            2-byte CRC in little-endian format
        """
        crc = 0xFFFF

        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1

        # Return little-endian (low byte first)
        return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    def _define_protocol(self) -> None:
        """Define optimized Modbus RTU protocol structure.

        Test ordering follows progressive depth strategy for maximum
        early coverage and crash detection:
        - Phase 1: Quick FC sweep (~30 sec) - touch all 17 FCs once
        - Phase 2: High-crash tests (~2 min) - overflow, buffer attacks
        - Phase 3: CVE-targeted writes (~2 min) - FC 05/06/0F/10/16/17
        - Phase 4: Boundary attacks (~2 min) - address, quantity, value limits
        - Phase 5: Standard operations (~3 min) - reads, diagnostics, broadcast
        """

        slave_addr = self.config.get_option("slave_address", 1)
        enable_write = self.config.get_option("enable_write", True)
        enable_broadcast = self.config.get_option("enable_broadcast", False)

        # ================================================================
        # PHASE 1: QUICK FC COVERAGE (~30 sec)
        # ================================================================

        # Quick FC sweep - all function codes with minimal valid params
        # Uses shared ALL_FUNCTION_CODES from constants (excludes FC 0B/0C not in RTU list)
        rtu_function_codes = [
            ModbusFunctionCodes.READ_COILS,  # 0x01
            ModbusFunctionCodes.READ_DISCRETE_INPUTS,  # 0x02
            ModbusFunctionCodes.READ_HOLDING_REGISTERS,  # 0x03
            ModbusFunctionCodes.READ_INPUT_REGISTERS,  # 0x04
            ModbusFunctionCodes.WRITE_SINGLE_COIL,  # 0x05
            ModbusFunctionCodes.WRITE_SINGLE_REGISTER,  # 0x06
            ModbusFunctionCodes.READ_EXCEPTION_STATUS,  # 0x07
            ModbusFunctionCodes.DIAGNOSTICS,  # 0x08
            ModbusFunctionCodes.WRITE_MULTIPLE_COILS,  # 0x0F
            ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS,  # 0x10
            ModbusFunctionCodes.REPORT_SLAVE_ID,  # 0x11
            ModbusFunctionCodes.READ_FILE_RECORD,  # 0x14
            ModbusFunctionCodes.MASK_WRITE_REGISTER,  # 0x16
            ModbusFunctionCodes.READ_WRITE_MULTIPLE_REGISTERS,  # 0x17
            ModbusFunctionCodes.READ_FIFO_QUEUE,  # 0x18
            ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT,  # 0x2B
        ]

        quick_fc_coverage = Request(
            "RTU_Quick_FC_Coverage",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr, fuzzable=False),
                        Group("Function_Code", values=rtu_function_codes),
                        Bytes("Params", b"\x00\x00\x00\x01", size=4, fuzzable=False),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        baseline_read = Request(
            "RTU_Baseline",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr, fuzzable=False),
                        Byte(
                            "Function_Code",
                            ModbusFunctionCodes.READ_HOLDING_REGISTERS,
                            fuzzable=False,
                        ),
                        Word("Starting_Address", 0x0000, endian=">", fuzzable=False),
                        Word("Quantity", 0x0001, endian=">", fuzzable=False),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (~2 min)
        # ================================================================

        # Oversized PDU - buffer overflow attack (RTU max is 256 bytes)
        oversized_pdu = Request(
            "RTU_Oversized_PDU",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Group("Excessive_Quantity", values=create_oversized_quantity_values()),
                        Byte("Byte_Count", 0xFE),
                        Bytes("Overflow_Data", b"A" * 254, size=254, max_len=4096),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Byte count mismatch - heap corruption attack
        byte_count_mismatch = Request(
            "RTU_Byte_Count_Mismatch",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0005, endian=">"),
                        Group("Mismatched_Byte_Count", values=create_byte_count_mismatch_values()),
                        Word("Insufficient_Data", 0x1234, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Slave address boundary attacks
        slave_address_overflow = Request(
            "RTU_Slave_Address_Overflow",
            children=(
                Block(
                    "PDU",
                    children=(
                        Group("Slave_Address_Boundary", values=UNIT_ID_BOUNDARIES),
                        Byte("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # CRC attack - malformed CRC (RTU-specific)
        crc_attack = Request(
            "RTU_CRC_Attack",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr, fuzzable=False),
                        Byte(
                            "Function_Code",
                            ModbusFunctionCodes.READ_HOLDING_REGISTERS,
                            fuzzable=False,
                        ),
                        Word("Starting_Address", 0x0000, endian=">", fuzzable=False),
                        Word("Quantity", 0x0001, endian=">", fuzzable=False),
                    ),
                ),
                Group(
                    "Malformed_CRC",
                    values=[
                        b"\x00\x00",  # All zeros
                        b"\xff\xff",  # All ones
                        b"\xde\xad",  # Invalid pattern
                        b"\x00",  # Truncated (1 byte only)
                    ],
                ),
            ),
        )

        # Frame truncation attack - incomplete frames (RTU-specific)
        frame_truncation = Request(
            "RTU_Frame_Truncation",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr, fuzzable=False),
                        Group("Truncated_PDU", values=create_truncated_pdu_values()),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ================================================================
        # PHASE 3: CVE-TARGETED WRITE OPERATIONS (~2 min)
        # ================================================================

        write_single = Request(
            "RTU_Write_Single",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Group("Function_Code", values=WRITE_SINGLE_FUNCTION_CODES),
                        Word("Address", 0x0000, endian=">"),
                        Word("Value", 0x0000, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        write_multiple_coils = Request(
            "RTU_Write_Multiple_Coils",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_COILS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity_of_Outputs", 0x0008, endian=">"),
                        Byte("Byte_Count", 0x01),
                        Bytes("Output_Value", b"\xff", size=1),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        write_multiple_registers = Request(
            "RTU_Write_Multiple_Registers",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Word("Quantity_of_Registers", 0x0002, endian=">"),
                        Byte("Byte_Count", 0x04),
                        Bytes("Register_Values", b"\x00\x0a\x01\x02", size=4),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        mask_write_register = Request(
            "RTU_Mask_Write_Register",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.MASK_WRITE_REGISTER),
                        Word("Reference_Address", 0x0004, endian=">"),
                        Word("And_Mask", 0x00F2, endian=">"),
                        Word("Or_Mask", 0x0025, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        read_write_multiple = Request(
            "RTU_Read_Write_Multiple",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.READ_WRITE_MULTIPLE_REGISTERS),
                        Word("Read_Starting_Address", 0x0000, endian=">"),
                        Word("Quantity_to_Read", 0x0001, endian=">"),
                        Word("Write_Starting_Address", 0x0000, endian=">"),
                        Word("Quantity_to_Write", 0x0001, endian=">"),
                        Byte("Write_Byte_Count", 0x02),
                        Word("Write_Register_Value", 0x0000, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        read_file_record = Request(
            "RTU_Read_File_Record",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.READ_FILE_RECORD),
                        Byte("Byte_Count", 0x07),
                        Byte("Reference_Type", 0x06),
                        Word("File_Number", 0x0001, endian=">"),
                        Word("Record_Number", 0x0000, endian=">"),
                        Word("Record_Length", 0x0001, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ================================================================
        # PHASE 4: BOUNDARY VALUE ATTACKS (~2 min)
        # ================================================================

        address_boundary = Request(
            "RTU_Address_Boundary",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Group("Address_Boundary", values=ADDRESS_BOUNDARIES),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        quantity_boundary = Request(
            "RTU_Quantity_Boundary",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("Starting_Address", 0x0000, endian=">"),
                        Group("Quantity_Boundary", values=QUANTITY_BOUNDARIES),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        coil_value_boundary = Request(
            "RTU_Coil_Value_Boundary",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_COIL),
                        Word("Coil_Address", 0x0000, endian=">"),
                        Group("Coil_Value_Boundary", values=COIL_VALUE_BOUNDARIES),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        memory_overflow = Request(
            "RTU_Memory_Overflow",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
                        Word("High_Address", 0xFFFF, endian=">"),
                        Group(
                            "Overflow_Quantity",
                            values=[
                                b"\x00\x01",
                                b"\x00\x02",
                                b"\x00\x0a",
                                b"\x07\xd0",
                            ],
                        ),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ================================================================
        # PHASE 5: STANDARD OPERATIONS (~3 min)
        # ================================================================

        read_request = Request(
            "RTU_Standard_Read",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Group("Function_Code", values=READ_FUNCTION_CODES),
                        Block(
                            "Parameters",
                            children=(
                                Word("Starting_Address", 0x0000, endian=">"),
                                Word("Quantity", 0x0001, endian=">"),
                            ),
                        ),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        read_exception_status = Request(
            "RTU_Read_Exception_Status",
            children=(
                Block(
                    "PDU",
                    children=(Byte("Function_Code", ModbusFunctionCodes.READ_EXCEPTION_STATUS),),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        report_slave_id = Request(
            "RTU_Report_Slave_ID",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.REPORT_SLAVE_ID),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        read_fifo = Request(
            "RTU_Read_FIFO_Queue",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.READ_FIFO_QUEUE),
                        Word("FIFO_Pointer_Address", 0x04DE, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Diagnostic functions - uses subset of diagnostic codes
        rtu_diagnostic_codes = [
            ModbusDiagnosticCodes.RETURN_QUERY_DATA,
            ModbusDiagnosticCodes.RESTART_COMMUNICATIONS,
            ModbusDiagnosticCodes.RETURN_DIAGNOSTIC_REGISTER,
            ModbusDiagnosticCodes.FORCE_LISTEN_ONLY_MODE,
            ModbusDiagnosticCodes.CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER,
            ModbusDiagnosticCodes.RETURN_BUS_MESSAGE_COUNT,
            ModbusDiagnosticCodes.RETURN_BUS_EXCEPTION_COUNT,
            ModbusDiagnosticCodes.RETURN_SLAVE_MESSAGE_COUNT,
        ]

        diagnostics = Request(
            "RTU_Diagnostics",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.DIAGNOSTICS),
                        Group("Sub_Function", values=rtu_diagnostic_codes),
                        Word("Data", 0x0000, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        read_device_id = Request(
            "RTU_Read_Device_Identification",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Byte("Function_Code", ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT),
                        Byte("MEI_Type", ModbusMEITypes.READ_DEVICE_IDENTIFICATION),
                        Group("Read_Device_ID_Code", values=DEVICE_ID_READ_CODES),
                        Group(
                            "Object_ID",
                            values=[
                                bytes([ModbusDeviceIDObjects.VENDOR_NAME]),
                                bytes([ModbusDeviceIDObjects.PRODUCT_CODE]),
                                bytes([ModbusDeviceIDObjects.MAJOR_MINOR_REVISION]),
                                b"\x80",  # Vendor specific
                            ],
                        ),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        invalid_function_codes = Request(
            "RTU_Invalid_Function_Codes",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", slave_addr),
                        Group("Function_Code", values=INVALID_FUNCTION_CODES),
                        Word("Dummy_Data", 0x0000, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # Broadcast testing
        broadcast_write_fcs = [
            ModbusFunctionCodes.WRITE_SINGLE_COIL,
            ModbusFunctionCodes.WRITE_SINGLE_REGISTER,
            ModbusFunctionCodes.WRITE_MULTIPLE_COILS,
            ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS,
        ]

        broadcast_write = Request(
            "RTU_Broadcast_Write",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", 0x00),  # Broadcast
                        Group("Function_Code", values=broadcast_write_fcs),
                        Word("Address", 0x0000, endian=">"),
                        Word("Value", 0xFF00, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        broadcast_read_invalid = Request(
            "RTU_Broadcast_Read_Invalid",
            children=(
                Block(
                    "PDU",
                    children=(
                        Byte("Slave_Address", 0x00),
                        Group(
                            "Function_Code",
                            values=[
                                ModbusFunctionCodes.READ_COILS,
                                ModbusFunctionCodes.READ_HOLDING_REGISTERS,
                            ],
                        ),
                        Word("Address", 0x0000, endian=">"),
                        Word("Quantity", 0x0001, endian=">"),
                    ),
                ),
                Checksum(
                    "CRC",
                    block_name="PDU",
                    algorithm=self._calculate_modbus_crc,
                    length=2,
                    endian="<",
                    fuzzable=False,
                ),
            ),
        )

        # ================================================================
        # OPTIMIZED REQUEST CONNECTION ORDER
        # ================================================================

        # PHASE 1: Quick FC Coverage
        if self.is_request_enabled("RTU_Baseline"):
            self.session.connect(quick_fc_coverage)
            self.session.connect(baseline_read)

        # PHASE 2: High-Crash Tests
        if self.is_request_enabled("RTU_Overflow_Testing"):
            self.session.connect(oversized_pdu)
            self.session.connect(byte_count_mismatch)
            self.session.connect(slave_address_overflow)
            self.session.connect(crc_attack)
            self.session.connect(frame_truncation)

        # PHASE 3: CVE-Targeted Writes
        if enable_write and self.is_request_enabled("RTU_Write_Operations"):
            self.session.connect(write_single)
            self.session.connect(write_multiple_coils)
            self.session.connect(write_multiple_registers)
            self.session.connect(mask_write_register)
            self.session.connect(read_write_multiple)

        if enable_write and self.is_request_enabled("RTU_File_Record"):
            self.session.connect(read_file_record)

        # PHASE 4: Boundary Attacks
        if self.is_request_enabled("RTU_Boundary_Testing"):
            self.session.connect(address_boundary)
            self.session.connect(quantity_boundary)
            self.session.connect(coil_value_boundary)

        if self.is_request_enabled("RTU_Memory_Map"):
            self.session.connect(memory_overflow)

        # PHASE 5: Standard Operations
        if self.is_request_enabled("RTU_Read_Operations"):
            self.session.connect(read_request)
            self.session.connect(read_exception_status)
            self.session.connect(report_slave_id)
            self.session.connect(read_fifo)

        if self.is_request_enabled("RTU_Diagnostics"):
            self.session.connect(diagnostics)

        if self.is_request_enabled("RTU_Device_ID"):
            self.session.connect(read_device_id)

        if self.is_request_enabled("RTU_Invalid_FC"):
            self.session.connect(invalid_function_codes)

        # Broadcast Testing (only if enabled)
        if enable_broadcast and self.is_request_enabled("RTU_Broadcast"):
            self.session.connect(broadcast_write)
            self.session.connect(broadcast_read_invalid)

    def setup_custom_monitors(self) -> List[BaseMonitor]:
        """Setup Modbus RTU health monitoring.

        Returns a ModbusRTUMonitor configured for the current transport
        (serial or RTU-over-TCP) that periodically sends a read request
        to verify the target device is still responsive.
        """
        transport = self.config.get_option("transport", "serial").lower()
        slave_address = self.config.get_option("slave_address", 1)
        timeout = self.config.get_option("monitor_timeout", 2.0)
        retry_count = self.config.get_option("monitor_retry_count", 2)
        failure_threshold = self.config.get_option("monitor_failure_threshold", 2)

        return [
            ModbusRTUMonitor(
                port=self.config.target_ip,
                slave_address=slave_address,
                transport=transport,
                tcp_port=self.config.target_port or 502,
                baudrate=self.config.get_option("baudrate", 9600),
                bytesize=self.config.get_option("bytesize", 8),
                parity=self.config.get_option("parity", "N"),
                stopbits=self.config.get_option("stopbits", 1),
                timeout=timeout,
                check_interval=self.config.monitor_check_interval,
                retry_count=retry_count,
                failure_threshold=failure_threshold,
            )
        ]
