"""Modbus PDU Builders

Shared PDU (Protocol Data Unit) builders for Modbus TCP and RTU fuzzers.
These functions create boofuzz Block objects containing just the PDU portion,
without any framing (no MBAP header for TCP, no slave address or CRC for RTU).
"""

from typing import Optional

from boofuzz import Block, Byte, Bytes, DWord, Group, RandomData, Static, Word

from .constants import (
    ADDRESS_BOUNDARIES,
    ALL_DIAGNOSTIC_CODES,
    ALL_FUNCTION_CODES,
    BYTE_COUNT_BOUNDARIES,
    COIL_VALUE_BOUNDARIES,
    DEVICE_ID_OBJECT_IDS,
    DEVICE_ID_READ_CODES,
    EXCEPTION_CODES,
    EXCEPTION_FUNCTION_CODES,
    ICS_ADDRESS_BOUNDARIES,
    INVALID_FUNCTION_CODES,
    MEMORY_AREA_BOUNDARIES,
    ModbusFunctionCodes,
    ModbusMEITypes,
    QUANTITY_BOUNDARIES,
    READ_FUNCTION_CODES,
    REGISTER_VALUE_BOUNDARIES,
    VENDOR_FUNCTION_CODES,
    WRITE_MULTIPLE_FUNCTION_CODES,
    WRITE_SINGLE_FUNCTION_CODES,
)


def create_quick_fc_pdu() -> Block:
    """Create Quick FC Coverage PDU - all 19 function codes with minimal params.

    Goal: Touch every FC in first 30 seconds for maximum breadth coverage.
    """
    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=ALL_FUNCTION_CODES),
            # Minimal valid params that work for most FCs (address + quantity)
            Bytes("Params", b"\x00\x00\x00\x01", size=4, fuzzable=False),
        ),
    )


def create_baseline_read_pdu() -> Block:
    """Create baseline read PDU - simple Read Holding Registers.

    Used to verify Modbus service responds before complex fuzzing.
    """
    return Block(
        "PDU",
        children=(
            Byte("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS, fuzzable=False),
            Word("Starting_Address", 0x0000, endian=">", fuzzable=False),
            Word("Quantity", 0x0001, endian=">", fuzzable=False),
        ),
    )


def create_read_pdu() -> Block:
    """Create standard read operations PDU (FC 01-04)."""
    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=READ_FUNCTION_CODES),
            Block(
                "Parameters",
                children=(
                    Word(
                        "Starting_Address", 0x0000, endian=">", fuzz_values=ICS_ADDRESS_BOUNDARIES
                    ),
                    Word("Quantity", 0x0001, endian=">"),
                ),
            ),
        ),
    )


def create_write_single_pdu() -> Block:
    """Create single write operations PDU (FC 05, 06)."""
    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=WRITE_SINGLE_FUNCTION_CODES),
            Block(
                "Parameters",
                children=(
                    Word("Output_Address", 0x0000, endian=">", fuzz_values=ICS_ADDRESS_BOUNDARIES),
                    Word("Output_Value", 0xFF00, endian=">"),
                ),
            ),
        ),
    )


def create_write_multiple_pdu() -> Block:
    """Create multiple write operations PDU (FC 0F, 10)."""
    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=WRITE_MULTIPLE_FUNCTION_CODES),
            Block(
                "Parameters",
                children=(
                    Word(
                        "Starting_Address", 0x0000, endian=">", fuzz_values=ICS_ADDRESS_BOUNDARIES
                    ),
                    Word("Quantity", 0x0002, endian=">"),
                    Byte("Byte_Count", 0x04),
                    DWord("Register_Values", 0x00000000, endian=">"),
                ),
            ),
        ),
    )


def create_diagnostics_pdu() -> Block:
    """Create diagnostics PDU (FC 08) with all sub-function codes."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.DIAGNOSTICS),
            Group("Sub_Function", values=ALL_DIAGNOSTIC_CODES),
            Word("Data", 0x0000, endian=">"),
        ),
    )


def create_file_record_pdu() -> Block:
    """Create file record operations PDU (FC 14, 15)."""
    return Block(
        "PDU",
        children=(
            Group(
                "Function_Code",
                values=[
                    ModbusFunctionCodes.READ_FILE_RECORD,
                    ModbusFunctionCodes.WRITE_FILE_RECORD,
                ],
            ),
            Byte("Byte_Count", 0x07),
            Block(
                "File_Record",
                children=(
                    Byte("Reference_Type", 0x06),
                    Word("File_Number", 0x0001, endian=">"),
                    Word("Record_Number", 0x0000, endian=">"),
                    Word("Record_Length", 0x0001, endian=">"),
                ),
            ),
        ),
    )


def create_mask_write_pdu() -> Block:
    """Create mask write register PDU (FC 16)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.MASK_WRITE_REGISTER),
            Word("Reference_Address", 0x0000, endian=">"),
            Word("And_Mask", 0xFFFF, endian=">"),
            Word("Or_Mask", 0x0000, endian=">"),
        ),
    )


def create_read_write_multiple_pdu() -> Block:
    """Create read/write multiple registers PDU (FC 17)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_WRITE_MULTIPLE_REGISTERS),
            Block(
                "Read_Parameters",
                children=(
                    Word(
                        "Read_Starting_Address",
                        0x0000,
                        endian=">",
                        fuzz_values=ICS_ADDRESS_BOUNDARIES,
                    ),
                    Word("Quantity_to_Read", 0x0001, endian=">"),
                ),
            ),
            Block(
                "Write_Parameters",
                children=(
                    Word(
                        "Write_Starting_Address",
                        0x0000,
                        endian=">",
                        fuzz_values=ICS_ADDRESS_BOUNDARIES,
                    ),
                    Word("Quantity_to_Write", 0x0001, endian=">"),
                    Byte("Write_Byte_Count", 0x02),
                    Word("Write_Data", 0x0000, endian=">"),
                ),
            ),
        ),
    )


def create_device_id_pdu() -> Block:
    """Create read device identification PDU (FC 2B/MEI)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT),
            Byte("MEI_Type", ModbusMEITypes.READ_DEVICE_IDENTIFICATION),
            Group("Read_Device_ID_Code", values=DEVICE_ID_READ_CODES),
            Group("Object_ID", values=DEVICE_ID_OBJECT_IDS),
        ),
    )


def create_canopen_mei_pdu() -> Block:
    """Create MEI CANopen General Reference PDU (FC 2B/MEI Type 0x0D)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT),
            Byte("MEI_Type", ModbusMEITypes.CANOPEN_GENERAL_REFERENCE),
            Block(
                "CANopen_Request",
                children=(
                    Byte("Node_Address", 0x01),
                    Word("Object_Index", 0x1000, endian=">"),
                    Byte("Sub_Index", 0x00),
                    Byte("Data_Length", 0x04),
                    DWord("Data", 0x12345678, endian=">"),
                ),
            ),
        ),
    )


def create_read_exception_status_pdu() -> Block:
    """Create read exception status PDU (FC 07)."""
    return Block(
        "PDU", children=(Static("Function_Code", ModbusFunctionCodes.READ_EXCEPTION_STATUS),)
    )


def create_get_comm_event_counter_pdu() -> Block:
    """Create get comm event counter PDU (FC 0B)."""
    return Block(
        "PDU", children=(Static("Function_Code", ModbusFunctionCodes.GET_COMM_EVENT_COUNTER),)
    )


def create_get_comm_event_log_pdu() -> Block:
    """Create get comm event log PDU (FC 0C)."""
    return Block("PDU", children=(Static("Function_Code", ModbusFunctionCodes.GET_COMM_EVENT_LOG),))


def create_report_slave_id_pdu() -> Block:
    """Create report slave ID PDU (FC 11)."""
    return Block("PDU", children=(Static("Function_Code", ModbusFunctionCodes.REPORT_SLAVE_ID),))


def create_read_fifo_queue_pdu() -> Block:
    """Create read FIFO queue PDU (FC 18)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_FIFO_QUEUE),
            Word("FIFO_Pointer_Address", 0x0000, endian=">"),
        ),
    )


def create_vendor_functions_pdu() -> Block:
    """Create vendor-specific functions PDU (FC 44-48)."""
    from ...primitives.dynamic import SmartString

    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=VENDOR_FUNCTION_CODES),
            Block(
                "Program_Data",
                children=(
                    Word("Program_Address", 0x0000, endian=">"),
                    Byte("Program_Length", 0x10),
                    SmartString("Program_Code", "modbus-program-code", max_len=240),
                ),
            ),
        ),
    )


# ============================================================
# Boundary Testing PDUs
# ============================================================


def create_address_boundary_pdu() -> Block:
    """Create address boundary testing PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            Group("Address_Boundary", values=ADDRESS_BOUNDARIES),
            Word("Quantity", 0x0001, endian=">"),
        ),
    )


def create_quantity_boundary_pdu() -> Block:
    """Create quantity boundary testing PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            Word("Starting_Address", 0x0000, endian=">"),
            Group("Quantity_Boundary", values=QUANTITY_BOUNDARIES),
        ),
    )


def create_byte_count_boundary_pdu() -> Block:
    """Create byte count boundary testing PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS),
            Word("Starting_Address", 0x0000, endian=">"),
            Word("Quantity", 0x0002, endian=">"),  # Says 2 registers = 4 bytes
            Group("Byte_Count_Boundary", values=BYTE_COUNT_BOUNDARIES),
            DWord("Register_Values", 0x12345678, endian=">"),
        ),
    )


def create_coil_value_boundary_pdu() -> Block:
    """Create coil value boundary testing PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_COIL),
            Word("Coil_Address", 0x0000, endian=">"),
            Group("Coil_Value_Boundary", values=COIL_VALUE_BOUNDARIES),
        ),
    )


def create_register_value_boundary_pdu() -> Block:
    """Create register value boundary testing PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_REGISTER),
            Word("Register_Address", 0x0000, endian=">"),
            Group("Register_Value_Boundary", values=REGISTER_VALUE_BOUNDARIES),
        ),
    )


# ============================================================
# Memory Area Testing PDUs
# ============================================================


def create_coils_boundary_pdu() -> Block:
    """Create coils memory area boundary testing PDU (FC 01)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_COILS),
            Group("Coils_Address_Boundary", values=MEMORY_AREA_BOUNDARIES),
            Word("Quantity", 0x0001, endian=">"),
        ),
    )


def create_discrete_inputs_boundary_pdu() -> Block:
    """Create discrete inputs memory area boundary testing PDU (FC 02)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_DISCRETE_INPUTS),
            Group("Discrete_Inputs_Address_Boundary", values=MEMORY_AREA_BOUNDARIES),
            Word("Quantity", 0x0001, endian=">"),
        ),
    )


def create_input_registers_boundary_pdu() -> Block:
    """Create input registers memory area boundary testing PDU (FC 04)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_INPUT_REGISTERS),
            Group("Input_Registers_Address_Boundary", values=MEMORY_AREA_BOUNDARIES),
            Word("Quantity", 0x0001, endian=">"),
        ),
    )


def create_holding_registers_boundary_pdu() -> Block:
    """Create holding registers memory area boundary testing PDU (FC 03)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            Group("Holding_Registers_Address_Boundary", values=MEMORY_AREA_BOUNDARIES),
            Word("Quantity", 0x0001, endian=">"),
        ),
    )


def create_write_coils_boundary_pdu() -> Block:
    """Create write coils memory area boundary testing PDU (FC 05)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_COIL),
            Group("Write_Coils_Address_Boundary", values=MEMORY_AREA_BOUNDARIES),
            Word("Coil_Value", 0xFF00, endian=">"),  # ON
        ),
    )


def create_write_registers_boundary_pdu() -> Block:
    """Create write holding registers memory area boundary testing PDU (FC 06)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_REGISTER),
            Group("Write_Holding_Registers_Address_Boundary", values=MEMORY_AREA_BOUNDARIES),
            Word("Register_Value", 0x1234, endian=">"),
        ),
    )


def create_memory_overflow_pdu(function_code: Optional[bytes] = None) -> Block:
    """Create memory overflow testing PDU - high address + high quantity.

    Args:
        function_code: Optional function code, defaults to READ_HOLDING_REGISTERS
    """
    if function_code is None:
        function_code = ModbusFunctionCodes.READ_HOLDING_REGISTERS
    return Block(
        "PDU",
        children=(
            Static("Function_Code", function_code),
            Word("High_Address", 0xFFFF, endian=">"),  # Maximum address
            Group(
                "Overflow_Quantity",
                values=[
                    b"\x00\x01",  # Would access 65535-65535 (valid)
                    b"\x00\x02",  # Would access 65535-65536 (overflow!)
                    b"\x00\x0a",  # Would access 65535-65544 (overflow!)
                    b"\x07\xd0",  # 2000 registers from max address (massive overflow)
                ],
            ),
        ),
    )


# ============================================================
# Exception Testing PDUs
# ============================================================


def create_exception_responses_pdu() -> Block:
    """Create exception response frames PDU."""
    return Block(
        "PDU",
        children=(
            Group("Exception_Function_Code", values=EXCEPTION_FUNCTION_CODES),
            Group("Exception_Code", values=EXCEPTION_CODES),
        ),
    )


def create_trigger_illegal_address_pdu() -> Block:
    """Create PDU to trigger ILLEGAL_DATA_ADDRESS exception."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            Word("Out_Of_Range_Address", 0xFFFF, endian=">"),  # Maximum address
            Word("Excessive_Quantity", 0xFFFF, endian=">"),  # Would overflow
        ),
    )


def create_trigger_illegal_value_pdu() -> Block:
    """Create PDU to trigger ILLEGAL_DATA_VALUE exception."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_SINGLE_COIL),
            Word("Coil_Address", 0x0000, endian=">"),
            Word("Invalid_Coil_Value", 0x1234, endian=">"),  # Invalid (not 0x0000 or 0xFF00)
        ),
    )


def create_trigger_illegal_function_pdu() -> Block:
    """Create PDU to trigger ILLEGAL_FUNCTION exception."""
    return Block(
        "PDU",
        children=(
            Group(
                "Unsupported_Function_Code",
                values=[
                    b"\x00",  # Reserved
                    b"\x09",  # Reserved
                    b"\x0d",  # Reserved
                    b"\x0e",  # Reserved
                    b"\x1c",  # Unassigned
                    b"\x50",  # Unassigned
                ],
            ),
            Word("Dummy_Address", 0x0000, endian=">"),
            Word("Dummy_Quantity", 0x0001, endian=">"),
        ),
    )


# ============================================================
# Combined Field Fuzzing PDUs
# ============================================================


def create_combined_invalid_fc_address_pdu() -> Block:
    """Create combined invalid FC + out-of-range address PDU."""
    return Block(
        "PDU",
        children=(
            Group(
                "Invalid_Function_Code",
                values=[
                    b"\x00",  # Reserved
                    b"\x09",  # Reserved
                    b"\xff",  # Invalid
                ],
            ),
            Word("Out_Of_Range_Address", 0xFFFF, endian=">"),
            Word("Excessive_Quantity", 0xFFFF, endian=">"),
        ),
    )


def create_combined_zero_quantity_pdu() -> Block:
    """Create valid FC + zero quantity PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            Word("Starting_Address", 0x0000, endian=">"),
            Word("Zero_Quantity", 0x0000, endian=">"),  # Invalid: zero
        ),
    )


def create_combined_byte_count_mismatch_pdu() -> Block:
    """Create write multiple with byte count mismatch PDU."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS),
            Word("Starting_Address", 0x0000, endian=">"),
            Word("Quantity", 0x0005, endian=">"),  # Says 5 registers = 10 bytes
            Byte("Byte_Count", 0x02),  # But only provides 2 bytes (mismatch!)
            Word("Insufficient_Data", 0x1234, endian=">"),
        ),
    )


def create_combined_oversized_pdu() -> Block:
    """Create oversized quantity + byte count PDU."""
    from ...primitives.dynamic import SmartString

    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS),
            Word("Starting_Address", 0xF000, endian=">"),  # High address
            Word("Excessive_Quantity", 0x1388, endian=">"),  # 5000 registers
            Byte("Excessive_Byte_Count", 0xFF),  # 255 bytes
            SmartString("Excessive_Data", "modbus-excessive-data", max_len=255, fuzzable=True),
        ),
    )


def create_combined_high_addr_max_qty_pdu() -> Block:
    """Create high address + maximum quantity PDU (memory overflow)."""
    return Block(
        "PDU",
        children=(
            Static("Function_Code", ModbusFunctionCodes.READ_HOLDING_REGISTERS),
            Word("High_Address", 0xF000, endian=">"),  # 61440
            Word("Maximum_Quantity", 0x07D0, endian=">"),  # 2000 (would overflow address space)
        ),
    )


# ============================================================
# Invalid/Malformed PDUs
# ============================================================


def create_invalid_fc_pdu() -> Block:
    """Create invalid function codes PDU."""
    return Block(
        "PDU",
        children=(
            Group("Invalid_Function_Code", values=INVALID_FUNCTION_CODES),
            Word("Dummy_Data", 0x0000, endian=">"),
        ),
    )


def create_malformed_pdu() -> Block:
    """Create malformed Modbus with invalid function codes and random data."""
    from ...primitives.dynamic import SmartString

    return Block(
        "PDU",
        children=(
            Group(
                "Invalid_Function_Code",
                values=[
                    b"\x00",  # Reserved
                    b"\x09",  # Reserved
                    b"\x0a",  # Reserved
                    b"\x0d",  # Reserved
                    b"\x0e",  # Reserved
                    b"\x19",  # Reserved
                    b"\x1a",  # Reserved
                    b"\x1b",  # Reserved
                    b"\x80",  # Exception response
                    b"\xff",  # Invalid
                ],
            ),
            Block(
                "Invalid_Data",
                children=(
                    SmartString("Random_Data", "modbus-random-data", max_len=250, fuzzable=True),
                ),
            ),
        ),
    )


def create_user_defined_pdu() -> Block:
    """Create user-defined function codes PDU (0x41-0x48)."""
    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=[bytes([x]) for x in range(0x41, 0x48)]),
            Block("Custom_Data", children=(DWord("Data", 0x00000000, endian=">"),)),
        ),
    )


def create_error_testing_pdu() -> Block:
    """Create error testing PDU - all function codes with random data."""
    return Block(
        "PDU",
        children=(
            Group("Function_Code", values=[bytes([x]) for x in range(0x00, 0xFF)]),
            Block(
                "Invalid_Data",
                children=(
                    RandomData("Random_Data", min_length=0, max_length=252, max_mutations=25),
                ),
            ),
        ),
    )


# ============================================================
# RTU-Specific PDU Helpers
# ============================================================


def create_truncated_pdu_values() -> list:
    """Get truncated PDU values for frame truncation attack."""
    return [
        b"\x03",  # FC only, no params
        b"\x03\x00",  # FC + partial address
        b"\x03\x00\x00",  # FC + address, no quantity
        b"\x03\x00\x00\x00",  # FC + address + partial quantity
    ]


def create_oversized_quantity_values() -> list:
    """Get oversized quantity values for buffer overflow attack."""
    return [
        b"\x00\x7e",  # 126 registers (252 bytes - borderline)
        b"\x00\x80",  # 128 registers (256 bytes - max frame)
        b"\x00\xff",  # 255 registers (510 bytes - overflow!)
        b"\x01\x00",  # 256 registers (512 bytes - overflow!)
    ]


def create_byte_count_mismatch_values() -> list:
    """Get byte count mismatch values for heap corruption attack."""
    return [
        b"\x02",  # 2 bytes (underflow - only 1 register)
        b"\x14",  # 20 bytes (overflow - claims more than provided)
        b"\xff",  # 255 bytes (massive overflow)
        b"\x00",  # 0 bytes (invalid)
    ]
