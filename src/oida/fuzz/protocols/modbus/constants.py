"""Modbus Protocol Constants

Shared constants for Modbus TCP and RTU fuzzers.
"""


class ModbusFunctionCodes:
    """Modbus function codes and their descriptions"""

    # Standard Read Functions
    READ_COILS = b"\x01"
    READ_DISCRETE_INPUTS = b"\x02"
    READ_HOLDING_REGISTERS = b"\x03"
    READ_INPUT_REGISTERS = b"\x04"

    # Standard Write Functions
    WRITE_SINGLE_COIL = b"\x05"
    WRITE_SINGLE_REGISTER = b"\x06"
    WRITE_MULTIPLE_COILS = b"\x0f"
    WRITE_MULTIPLE_REGISTERS = b"\x10"

    # Diagnostic Functions
    READ_EXCEPTION_STATUS = b"\x07"
    DIAGNOSTICS = b"\x08"
    GET_COMM_EVENT_COUNTER = b"\x0b"
    GET_COMM_EVENT_LOG = b"\x0c"
    REPORT_SLAVE_ID = b"\x11"

    # Advanced File and Register Functions
    READ_FILE_RECORD = b"\x14"
    WRITE_FILE_RECORD = b"\x15"
    MASK_WRITE_REGISTER = b"\x16"
    READ_WRITE_MULTIPLE_REGISTERS = b"\x17"
    READ_FIFO_QUEUE = b"\x18"

    # System and Discovery Functions
    ENCAPSULATED_INTERFACE_TRANSPORT = b"\x2b"

    # Vendor Specific Functions
    PROGRAM_484 = b"\x44"
    PROGRAM_584_984 = b"\x45"
    PROGRAM_START = b"\x46"
    PROGRAM_STOP = b"\x47"
    PROGRAM_UPLOAD = b"\x48"

    # User Defined Functions (65-72 decimal)
    USER_DEFINED_START = b"\x41"
    USER_DEFINED_END = b"\x48"


class ModbusDiagnosticCodes:
    """Modbus diagnostic sub-function codes"""

    RETURN_QUERY_DATA = b"\x00\x00"
    RESTART_COMMUNICATIONS = b"\x00\x01"
    RETURN_DIAGNOSTIC_REGISTER = b"\x00\x02"
    CHANGE_ASCII_INPUT_DELIMITER = b"\x00\x03"
    FORCE_LISTEN_ONLY_MODE = b"\x00\x04"
    CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER = b"\x00\x0a"
    RETURN_BUS_MESSAGE_COUNT = b"\x00\x0b"
    RETURN_BUS_COMM_ERROR_COUNT = b"\x00\x0c"
    RETURN_BUS_EXCEPTION_COUNT = b"\x00\x0d"
    RETURN_SLAVE_MESSAGE_COUNT = b"\x00\x0e"
    RETURN_SLAVE_NO_RESPONSE_COUNT = b"\x00\x0f"
    RETURN_SLAVE_NAK_COUNT = b"\x00\x10"
    RETURN_SLAVE_BUSY_COUNT = b"\x00\x11"
    RETURN_BUS_CHARACTER_OVERRUN_COUNT = b"\x00\x12"
    CLEAR_OVERRUN_COUNTER_AND_FLAG = b"\x00\x14"


class ModbusMEITypes:
    """Modbus Encapsulated Interface Transport MEI types"""

    READ_DEVICE_IDENTIFICATION = 0x0E
    CANOPEN_GENERAL_REFERENCE = 0x0D


class ModbusDeviceIDObjects:
    """Device Identification Object IDs"""

    # Basic Device Identification (mandatory)
    VENDOR_NAME = 0x00
    PRODUCT_CODE = 0x01
    MAJOR_MINOR_REVISION = 0x02

    # Regular Device Identification (optional)
    VENDOR_URL = 0x03
    PRODUCT_NAME = 0x04
    MODEL_NAME = 0x05
    USER_APPLICATION_NAME = 0x06

    # Extended Device Identification (optional)
    # Objects 0x07 to 0x7F are reserved
    # Objects 0x80 to 0xFF are vendor specific


# ICS-realistic address boundaries based on real PLC register maps
# Derived from analysis of 49 real devices: Schneider, Siemens, ABB, Allen-Bradley, etc.
# These addresses are commonly used for system status, I/O, and memory areas
ICS_ADDRESS_BOUNDARIES = [
    # System/Status registers (very common: 0-30)
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    12,
    14,
    16,
    18,
    20,
    22,
    24,
    26,
    28,
    30,
    # Extended system area (50-99)
    50,
    64,
    80,
    96,
    99,
    # Memory word area %MW (100-199) - 28.6% of PLCs use address 100
    100,
    101,
    102,
    103,
    104,
    105,
    110,
    115,
    120,
    125,
    127,
    128,
    150,
    175,
    199,
    # Memory double area %MD (200-299)
    200,
    201,
    202,
    204,
    224,
    250,
    255,
    256,
    # Input registers %IW (300-399)
    300,
    302,
    304,
    310,
    320,
    350,
    399,
    # Output registers %QW (400-499)
    400,
    402,
    410,
    420,
    450,
    499,
    # Extended data areas (500+)
    500,
    512,
    1000,
    1024,
    2000,
    4096,
    5000,
    # SunSpec/Solar inverter common addresses
    40000,
    40001,
    40069,
    40070,
    # Power meter common addresses
    30001,
    30071,
    30073,
]


# Boundary values for fuzzing - shared between TCP and RTU

# Address field boundaries
ADDRESS_BOUNDARIES = [
    b"\x00\x00",  # Minimum (0)
    b"\x00\x01",  # Minimum valid (1)
    b"\x7f\xff",  # Mid-range (32767)
    b"\x80\x00",  # Sign bit flip (32768)
    b"\xff\xfe",  # Maximum - 1 (65534)
    b"\xff\xff",  # Maximum (65535)
]

# Quantity field boundaries
QUANTITY_BOUNDARIES = [
    b"\x00\x00",  # Zero (invalid)
    b"\x00\x01",  # Minimum valid
    b"\x00\x7d",  # 125 (common device max)
    b"\x07\xd0",  # 2000 (protocol max per spec)
    b"\x07\xd1",  # 2001 (just over protocol max)
    b"\xff\xff",  # 65535 (maximum possible)
]

# Coil value boundaries (FC 05)
COIL_VALUE_BOUNDARIES = [
    b"\x00\x00",  # OFF (valid)
    b"\xff\x00",  # ON (valid)
    b"\x00\x01",  # Invalid coil value
    b"\x00\xff",  # Invalid coil value
    b"\xff\xff",  # Invalid coil value
    b"\x12\x34",  # Invalid coil value
]

# Register value boundaries
REGISTER_VALUE_BOUNDARIES = [
    b"\x00\x00",  # Minimum (0)
    b"\x00\x01",  # Minimum non-zero
    b"\x7f\xff",  # Maximum positive signed (32767)
    b"\x80\x00",  # Sign bit (32768 / -32768 signed)
    b"\xff\xfe",  # Maximum - 1
    b"\xff\xff",  # Maximum (65535)
]

# Memory area address boundaries (for per-area testing)
MEMORY_AREA_BOUNDARIES = [
    b"\x00\x00",  # Start of area (0)
    b"\x00\x01",  # Register/Coil 1
    b"\x27\x0f",  # 9999 (common device limit)
    b"\x7f\xff",  # 32767 (mid-range)
    b"\x80\x00",  # 32768 (sign bit)
    b"\xc3\x4f",  # 49999 (extended addressing)
    b"\xff\xfe",  # 65534 (near end)
    b"\xff\xff",  # 65535 (end of area)
]

# Byte count boundaries for write multiple operations
BYTE_COUNT_BOUNDARIES = [
    b"\x00",  # Zero bytes (invalid)
    b"\x01",  # Minimum (1 byte)
    b"\x04",  # Typical valid (4 bytes = 2 registers)
    b"\xfc",  # 252 (maximum PDU payload)
    b"\xfd",  # 253 (just over maximum)
    b"\xff",  # 255 (maximum byte value)
]

# Invalid function codes for exception testing
INVALID_FUNCTION_CODES = [
    b"\x00",  # Reserved
    b"\x09",  # Reserved
    b"\x0a",  # Reserved
    b"\x0d",  # Reserved
    b"\x0e",  # Reserved
    b"\x80",  # Exception flag (invalid for request)
    b"\x8f",  # Exception flag
    b"\xff",  # Invalid high
]

# Exception function codes (original + 0x80)
EXCEPTION_FUNCTION_CODES = [
    b"\x81",  # Read Coils exception (0x01 + 0x80)
    b"\x82",  # Read Discrete Inputs exception (0x02 + 0x80)
    b"\x83",  # Read Holding Registers exception (0x03 + 0x80)
    b"\x84",  # Read Input Registers exception (0x04 + 0x80)
    b"\x85",  # Write Single Coil exception (0x05 + 0x80)
    b"\x86",  # Write Single Register exception (0x06 + 0x80)
    b"\x8f",  # Write Multiple Coils exception (0x0F + 0x80)
    b"\x90",  # Write Multiple Registers exception (0x10 + 0x80)
]

# Exception codes
EXCEPTION_CODES = [
    b"\x01",  # ILLEGAL_FUNCTION
    b"\x02",  # ILLEGAL_DATA_ADDRESS
    b"\x03",  # ILLEGAL_DATA_VALUE
    b"\x04",  # SLAVE_DEVICE_FAILURE
    b"\x05",  # ACKNOWLEDGE
    b"\x06",  # SLAVE_DEVICE_BUSY
    b"\x07",  # NEGATIVE_ACKNOWLEDGE
    b"\x08",  # MEMORY_PARITY_ERROR
    b"\x0a",  # GATEWAY_PATH_UNAVAILABLE
    b"\x0b",  # GATEWAY_TARGET_FAILED
]

# Unit ID / Slave address boundaries
UNIT_ID_BOUNDARIES = [
    b"\x00",  # Broadcast address
    b"\x01",  # Minimum valid
    b"\x7f",  # Mid-range valid
    b"\xf7",  # Maximum valid (247)
    b"\xf8",  # Reserved (248)
    b"\xf9",  # Reserved (249)
    b"\xfa",  # Reserved (250)
    b"\xfb",  # Reserved (251)
    b"\xfc",  # Reserved (252)
    b"\xfd",  # Reserved (253)
    b"\xfe",  # Reserved (254)
    b"\xff",  # Reserved (255)
]

# Reserved unit IDs (248-255)
RESERVED_UNIT_IDS = [
    b"\xf8",  # Reserved (248)
    b"\xf9",  # Reserved (249)
    b"\xfa",  # Reserved (250)
    b"\xfb",  # Reserved (251)
    b"\xfc",  # Reserved (252)
    b"\xfd",  # Reserved (253)
    b"\xfe",  # Reserved (254)
    b"\xff",  # Reserved (255)
]

# All 19 standard function codes for quick FC sweep
ALL_FUNCTION_CODES = [
    ModbusFunctionCodes.READ_COILS,  # 0x01
    ModbusFunctionCodes.READ_DISCRETE_INPUTS,  # 0x02
    ModbusFunctionCodes.READ_HOLDING_REGISTERS,  # 0x03
    ModbusFunctionCodes.READ_INPUT_REGISTERS,  # 0x04
    ModbusFunctionCodes.WRITE_SINGLE_COIL,  # 0x05
    ModbusFunctionCodes.WRITE_SINGLE_REGISTER,  # 0x06
    ModbusFunctionCodes.READ_EXCEPTION_STATUS,  # 0x07
    ModbusFunctionCodes.DIAGNOSTICS,  # 0x08
    ModbusFunctionCodes.GET_COMM_EVENT_COUNTER,  # 0x0B
    ModbusFunctionCodes.GET_COMM_EVENT_LOG,  # 0x0C
    ModbusFunctionCodes.WRITE_MULTIPLE_COILS,  # 0x0F
    ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS,  # 0x10
    ModbusFunctionCodes.REPORT_SLAVE_ID,  # 0x11
    ModbusFunctionCodes.READ_FILE_RECORD,  # 0x14
    ModbusFunctionCodes.WRITE_FILE_RECORD,  # 0x15
    ModbusFunctionCodes.MASK_WRITE_REGISTER,  # 0x16
    ModbusFunctionCodes.READ_WRITE_MULTIPLE_REGISTERS,  # 0x17
    ModbusFunctionCodes.READ_FIFO_QUEUE,  # 0x18
    ModbusFunctionCodes.ENCAPSULATED_INTERFACE_TRANSPORT,  # 0x2B
]

# Read function codes (FC 01-04)
READ_FUNCTION_CODES = [
    ModbusFunctionCodes.READ_COILS,
    ModbusFunctionCodes.READ_DISCRETE_INPUTS,
    ModbusFunctionCodes.READ_HOLDING_REGISTERS,
    ModbusFunctionCodes.READ_INPUT_REGISTERS,
]

# Single write function codes (FC 05, 06)
WRITE_SINGLE_FUNCTION_CODES = [
    ModbusFunctionCodes.WRITE_SINGLE_COIL,
    ModbusFunctionCodes.WRITE_SINGLE_REGISTER,
]

# Multiple write function codes (FC 0F, 10)
WRITE_MULTIPLE_FUNCTION_CODES = [
    ModbusFunctionCodes.WRITE_MULTIPLE_COILS,
    ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS,
]

# All diagnostic sub-function codes
ALL_DIAGNOSTIC_CODES = [
    ModbusDiagnosticCodes.RETURN_QUERY_DATA,
    ModbusDiagnosticCodes.RESTART_COMMUNICATIONS,
    ModbusDiagnosticCodes.RETURN_DIAGNOSTIC_REGISTER,
    ModbusDiagnosticCodes.CHANGE_ASCII_INPUT_DELIMITER,
    ModbusDiagnosticCodes.FORCE_LISTEN_ONLY_MODE,
    ModbusDiagnosticCodes.CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER,
    ModbusDiagnosticCodes.RETURN_BUS_MESSAGE_COUNT,
    ModbusDiagnosticCodes.RETURN_BUS_COMM_ERROR_COUNT,
    ModbusDiagnosticCodes.RETURN_BUS_EXCEPTION_COUNT,
    ModbusDiagnosticCodes.RETURN_SLAVE_MESSAGE_COUNT,
    ModbusDiagnosticCodes.RETURN_SLAVE_NO_RESPONSE_COUNT,
    ModbusDiagnosticCodes.RETURN_SLAVE_NAK_COUNT,
    ModbusDiagnosticCodes.RETURN_SLAVE_BUSY_COUNT,
    ModbusDiagnosticCodes.RETURN_BUS_CHARACTER_OVERRUN_COUNT,
    ModbusDiagnosticCodes.CLEAR_OVERRUN_COUNTER_AND_FLAG,
]

# Device ID read codes
DEVICE_ID_READ_CODES = [
    b"\x01",  # Basic device identification
    b"\x02",  # Regular device identification
    b"\x03",  # Extended device identification
    b"\x04",  # Specific identification object
]

# Device ID object IDs
DEVICE_ID_OBJECT_IDS = [
    bytes([ModbusDeviceIDObjects.VENDOR_NAME]),
    bytes([ModbusDeviceIDObjects.PRODUCT_CODE]),
    bytes([ModbusDeviceIDObjects.MAJOR_MINOR_REVISION]),
    bytes([ModbusDeviceIDObjects.VENDOR_URL]),
    bytes([ModbusDeviceIDObjects.PRODUCT_NAME]),
    bytes([ModbusDeviceIDObjects.MODEL_NAME]),
    bytes([ModbusDeviceIDObjects.USER_APPLICATION_NAME]),
    b"\x80",  # Vendor specific start
    b"\xff",  # Vendor specific end
]

# Vendor-specific function codes
VENDOR_FUNCTION_CODES = [
    ModbusFunctionCodes.PROGRAM_484,
    ModbusFunctionCodes.PROGRAM_584_984,
    ModbusFunctionCodes.PROGRAM_START,
    ModbusFunctionCodes.PROGRAM_STOP,
    ModbusFunctionCodes.PROGRAM_UPLOAD,
]

# Broadcast-compatible write function codes
BROADCAST_WRITE_FUNCTION_CODES = [
    ModbusFunctionCodes.WRITE_SINGLE_COIL,
    ModbusFunctionCodes.WRITE_SINGLE_REGISTER,
    ModbusFunctionCodes.WRITE_MULTIPLE_COILS,
    ModbusFunctionCodes.WRITE_MULTIPLE_REGISTERS,
    ModbusFunctionCodes.MASK_WRITE_REGISTER,
    ModbusFunctionCodes.DIAGNOSTICS,
]
