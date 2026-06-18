"""
Modbus Protocol Constants and Enumerations

This module contains all Modbus-related constants, enums, and lookup tables
used throughout the Modbus scanner implementation.
"""

from enum import Enum, IntEnum


class ModbusFunctionCode(IntEnum):
    """Modbus function codes enumeration"""

    READ_COILS = 1
    READ_DISCRETE_INPUTS = 2
    READ_HOLDING_REGISTERS = 3
    READ_INPUT_REGISTERS = 4
    WRITE_SINGLE_COIL = 5
    WRITE_SINGLE_REGISTER = 6
    READ_EXCEPTION_STATUS = 7
    DIAGNOSTICS = 8
    GET_COMM_EVENT_COUNTER = 11
    GET_COMM_EVENT_LOG = 12
    WRITE_MULTIPLE_COILS = 15
    WRITE_MULTIPLE_REGISTERS = 16
    REPORT_SERVER_ID = 17
    READ_FILE_RECORD = 20
    WRITE_FILE_RECORD = 21
    MASK_WRITE_REGISTER = 22
    READ_WRITE_MULTIPLE_REGISTERS = 23
    READ_FIFO_QUEUE = 24
    DEVICE_INFORMATION = 43


class ModbusExceptionCode(IntEnum):
    """Modbus exception codes enumeration"""

    ILLEGAL_FUNCTION = 1
    ILLEGAL_DATA_ADDRESS = 2
    ILLEGAL_DATA_VALUE = 3
    SERVER_DEVICE_FAILURE = 4
    ACKNOWLEDGE = 5
    SERVER_DEVICE_BUSY = 6
    NEGATIVE_ACKNOWLEDGE = 7
    MEMORY_PARITY_ERROR = 8
    GATEWAY_PATH_UNAVAILABLE = 10
    GATEWAY_TARGET_DEVICE_FAILED = 11


class MEIType(IntEnum):
    """MEI (Modbus Encapsulated Interface) Type codes"""

    READ_DEVICE_ID = 14  # 0x0E - Device identification
    CANOPEN = 13  # 0x0D - CANopen (CiA 309-2)


class MEIReadDeviceIdCode(IntEnum):
    """MEI Read Device ID codes"""

    BASIC = 1  # Basic device identification (stream access)
    REGULAR = 2  # Regular device identification (stream access)
    EXTENDED = 3  # Extended device identification (stream access)
    SPECIFIC = 4  # Specific identification object (individual access)


class MEIObjectId(IntEnum):
    """MEI Device Identification Object IDs"""

    VENDOR_NAME = 0x00
    PRODUCT_CODE = 0x01
    MAJOR_MINOR_REVISION = 0x02
    VENDOR_URL = 0x03
    PRODUCT_NAME = 0x04
    MODEL_NAME = 0x05
    USER_APPLICATION_NAME = 0x06
    # 0x07-0x7F reserved
    # 0x80-0xFF private objects


# MEI Object ID descriptions
MEI_OBJECT_NAMES = {
    0x00: "VendorName",
    0x01: "ProductCode",
    0x02: "MajorMinorRevision",
    0x03: "VendorUrl",
    0x04: "ProductName",
    0x05: "ModelName",
    0x06: "UserApplicationName",
}


class CANopenMEICommand(IntEnum):
    """CANopen MEI command codes.

    These use standard CANopen SDO Client Command Specifier (CCS) values
    from CiA 301. CiA 309-2 gateways may use different command codes.
    """

    GET_INFO = 0x01  # Get gateway information (vendor-specific)
    SDO_DOWNLOAD = 0x20  # SDO download/write (CCS=1 from CiA 301)
    SDO_UPLOAD = 0x40  # SDO upload/read (CCS=2 from CiA 301)


# CANopen data types (CiA 301 / CiA 309-2)
CANOPEN_DATA_TYPES = {
    0x01: ("BOOLEAN", 1),
    0x02: ("INTEGER8", 1),
    0x03: ("INTEGER16", 2),
    0x04: ("INTEGER32", 4),
    0x05: ("UNSIGNED8", 1),
    0x06: ("UNSIGNED16", 2),
    0x07: ("UNSIGNED32", 4),
    0x08: ("REAL32", 4),
    0x09: ("VISIBLE_STRING", 0),
    0x0A: ("OCTET_STRING", 0),
    0x0B: ("UNICODE_STRING", 0),
    0x0F: ("DOMAIN", 0),
    0x10: ("INTEGER24", 3),
    0x11: ("REAL64", 8),
    0x12: ("INTEGER40", 5),
    0x13: ("INTEGER48", 6),
    0x14: ("INTEGER56", 7),
    0x15: ("INTEGER64", 8),
    0x16: ("UNSIGNED24", 3),
    0x18: ("UNSIGNED40", 5),
    0x19: ("UNSIGNED48", 6),
    0x1A: ("UNSIGNED56", 7),
    0x1B: ("UNSIGNED64", 8),
}

# Common CANopen Object Dictionary entries
CANOPEN_COMMON_OBJECTS = {
    (0x1000, 0): "Device Type",
    (0x1001, 0): "Error Register",
    (0x1008, 0): "Manufacturer Device Name",
    (0x1009, 0): "Manufacturer Hardware Version",
    (0x100A, 0): "Manufacturer Software Version",
    (0x1017, 0): "Producer Heartbeat Time",
    (0x1018, 1): "Vendor ID",
    (0x1018, 2): "Product Code",
    (0x1018, 3): "Revision Number",
    (0x1018, 4): "Serial Number",
}


class DiagnosticSubfunction(IntEnum):
    """Modbus Diagnostics (FC 8) Subfunctions"""

    RETURN_QUERY_DATA = 0x00
    RESTART_COMM_OPTION = 0x01
    RETURN_DIAGNOSTIC_REGISTER = 0x02
    CHANGE_ASCII_INPUT_DELIMITER = 0x03
    FORCE_LISTEN_ONLY_MODE = 0x04
    CLEAR_COUNTERS = 0x0A
    RETURN_BUS_MESSAGE_COUNT = 0x0B
    RETURN_BUS_COMM_ERROR_COUNT = 0x0C
    RETURN_BUS_EXCEPTION_ERROR_COUNT = 0x0D
    RETURN_SERVER_MESSAGE_COUNT = 0x0E
    RETURN_SERVER_NO_RESPONSE_COUNT = 0x0F
    RETURN_SERVER_NAK_COUNT = 0x10
    RETURN_SERVER_BUSY_COUNT = 0x11
    RETURN_BUS_CHARACTER_OVERRUN_COUNT = 0x12
    CLEAR_OVERRUN_COUNTER = 0x14


# Diagnostic subfunction descriptions
DIAGNOSTIC_SUBFUNCTIONS = {
    0x00: "Return Query Data",
    0x01: "Restart Communications Option",
    0x02: "Return Diagnostic Register",
    0x03: "Change ASCII Input Delimiter",
    0x04: "Force Listen Only Mode",
    0x0A: "Clear Counters and Diagnostic Register",
    0x0B: "Return Bus Message Count",
    0x0C: "Return Bus Communication Error Count",
    0x0D: "Return Bus Exception Error Count",
    0x0E: "Return Server Message Count",
    0x0F: "Return Server No Response Count",
    0x10: "Return Server NAK Count",
    0x11: "Return Server Busy Count",
    0x12: "Return Bus Character Overrun Count",
    0x14: "Clear Overrun Counter and Flag",
}


class RegisterType(Enum):
    """Modbus register types"""

    COILS = "coils"
    DISCRETE_INPUTS = "discrete_inputs"
    HOLDING_REGISTERS = "holding_registers"
    INPUT_REGISTERS = "input_registers"


# Legacy dictionaries for backward compatibility
FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Device Information",
    # Vendor-specific function codes
    65: "Schneider Unity (0x41)",  # Schneider - older
    90: "Schneider Unity (0x5A)",  # Schneider M340/M580/Unity - Read/Write internal
    100: "Vendor Specific (0x64)",
    110: "Vendor Specific (0x6E)",
}

EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    7: "Negative Acknowledge",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond",
}

# Common FCs across major PLC vendors
DISCOVERY_FUNCTION_CODES = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 22, 23, 43]

# Protocol-specific options for Modbus
PROTOCOL_OPTIONS = {
    "unit-id": {
        "type": "int",
        "description": "Modbus Unit ID (slave address)",
        "required": False,
        "default": 1,
    },
    "scan-range": {
        "type": "string",
        "description": "Register range to scan (e.g., 0-100)",
        "required": False,
        "default": "0-100",
    },
    "register-type": {
        "type": "enum",
        "description": "Type of registers to scan",
        "values": ["coil", "discrete-input", "holding", "input", "all"],
        "required": False,
        "default": "all",
    },
    "serial-port": {
        "type": "string",
        "description": "Serial port for Modbus RTU (e.g., /dev/ttyUSB0)",
        "required": False,
        "default": "",
    },
    "baudrate": {
        "type": "int",
        "description": "Baudrate for serial connection",
        "required": False,
        "default": 9600,
    },
    "discover-units": {
        "type": "bool",
        "description": "Discover active unit IDs",
        "required": False,
        "default": False,
    },
    "unit-range": {
        "type": "string",
        "description": "Range of unit IDs to scan",
        "required": False,
        "default": "0-254",
    },
    "function-range": {
        "type": "string",
        "description": "Range of function codes to test",
        "required": False,
        "default": "1-127",
    },
    "get-device-id": {
        "type": "bool",
        "description": "Read MEI device identification (FC 43/14)",
        "required": False,
        "default": False,
    },
}
