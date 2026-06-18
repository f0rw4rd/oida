"""CoAP protocol constants and configuration."""

from typing import Dict, Any

# Protocol defaults
DEFAULT_PORT = 5683
DEFAULT_DTLS_PORT = 5684
DEFAULT_TIMEOUT = 2.0

# CoAP message types
CON = 0  # Confirmable
NON = 1  # Non-confirmable
ACK = 2  # Acknowledgement
RST = 3  # Reset

MSG_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}

# CoAP method codes
METHODS = {
    "GET": 0x01,
    "POST": 0x02,
    "PUT": 0x03,
    "DELETE": 0x04,
    "FETCH": 0x05,
    "PATCH": 0x06,
    "IPATCH": 0x07,
}

# CoAP response codes
RESPONSE_CODES = {
    "2.01": "Created",
    "2.02": "Deleted",
    "2.03": "Valid",
    "2.04": "Changed",
    "2.05": "Content",
    "4.00": "Bad Request",
    "4.01": "Unauthorized",
    "4.02": "Bad Option",
    "4.03": "Forbidden",
    "4.04": "Not Found",
    "4.05": "Method Not Allowed",
    "4.06": "Not Acceptable",
    "4.12": "Precondition Failed",
    "4.13": "Request Entity Too Large",
    "4.15": "Unsupported Content-Format",
    "5.00": "Internal Server Error",
    "5.01": "Not Implemented",
    "5.02": "Bad Gateway",
    "5.03": "Service Unavailable",
    "5.04": "Gateway Timeout",
    "5.05": "Proxying Not Supported",
}

# Content formats (Option 12)
CONTENT_FORMATS = {
    0: "text/plain",
    40: "application/link-format",
    41: "application/xml",
    42: "application/octet-stream",
    47: "application/exi",
    50: "application/json",
    60: "application/cbor",
    110: "application/senml+json",
    11542: "application/vnd.oma.lwm2m+tlv",
    11543: "application/vnd.oma.lwm2m+json",
}

# Shorthand names -> Content-Format IDs
CONTENT_FORMAT_ALIASES = {
    "text": 0,
    "link-format": 40,
    "xml": 41,
    "octet": 42,
    "exi": 47,
    "json": 50,
    "cbor": 60,
    "senml": 110,
    "lwm2m-tlv": 11542,
    "lwm2m-json": 11543,
}

# Block size exponents for Block-wise Transfer (RFC 7959)
# SZX value -> block size in bytes (size = 2^(SZX+4))
BLOCK_SIZES = {16: 0, 32: 1, 64: 2, 128: 3, 256: 4, 512: 5, 1024: 6}
VALID_BLOCK_SIZES = sorted(BLOCK_SIZES.keys())

# LwM2M standard objects for fingerprinting
LWM2M_OBJECTS = {
    0: {
        "name": "Security",
        "resources": {0: "URI", 2: "Mode", 3: "PubKey", 5: "SecretKey"},
    },
    1: {
        "name": "Server",
        "resources": {0: "ShortID", 1: "Lifetime", 6: "Binding", 7: "RegUpdate"},
    },
    3: {
        "name": "Device",
        "resources": {
            0: "Manufacturer",
            1: "Model",
            2: "Serial",
            3: "FirmwareVer",
            4: "Reboot",
            5: "FactoryReset",
            6: "PowerSources",
            7: "Voltage",
            9: "Battery",
            13: "CurrentTime",
            14: "UTCOffset",
            16: "SupportedBindings",
        },
    },
    4: {
        "name": "Connectivity Monitor",
        "resources": {0: "Bearer", 1: "IP", 4: "LinkQuality"},
    },
    5: {
        "name": "Firmware Update",
        "resources": {0: "Package", 1: "PackageURI", 3: "State", 5: "Result"},
    },
    6: {
        "name": "Location",
        "resources": {0: "Latitude", 1: "Longitude", 2: "Altitude"},
    },
}

# LwM2M security modes (/0/x/2)
LWM2M_SEC_MODES = {0: "PSK", 1: "RPK", 2: "Certificate", 3: "NoSec"}

# Common IoT resource paths to probe (beyond /.well-known/core)
COMMON_PATHS = [
    "/.well-known/core",
    "/api",
    "/api/v1",
    "/status",
    "/config",
    "/sensor",
    "/sensor/temperature",
    "/sensor/humidity",
    "/sensor/pressure",
    "/sensor/large-data",
    "/sensor/data.cbor",
    "/sensor/measurements",
    "/actuator",
    "/actuator/led",
    "/actuator/relay",
    "/actuator/valve",
    "/firmware",
    "/firmware/version",
    "/admin",
    "/debug",
    "/time",
    "/location",
    "/device",
    "/info",
]

# Write methods (security-relevant)
WRITE_METHODS = {"PUT", "POST", "DELETE", "PATCH", "IPATCH"}

# Protocol options dictionary for scanner registration
protocol_options: Dict[str, Dict[str, Any]] = {
    "resources": {
        "type": "bool",
        "description": "Enumerate resources via /.well-known/core",
        "required": False,
        "default": True,
    },
    "probe-paths": {
        "type": "bool",
        "description": "Probe common IoT paths",
        "required": False,
        "default": False,
    },
    "lwm2m": {
        "type": "bool",
        "description": "Probe LwM2M Device Object /3/0",
        "required": False,
        "default": False,
    },
    "lwm2m-full": {
        "type": "bool",
        "description": "Full LwM2M object enumeration",
        "required": False,
        "default": False,
    },
    "methods": {
        "type": "bool",
        "description": "Test all CoAP methods on discovered resources",
        "required": False,
        "default": False,
    },
    "observe": {
        "type": "bool",
        "description": "Subscribe to observable resources",
        "required": False,
        "default": False,
    },
    "observe-count": {
        "type": "int",
        "description": "Notifications to collect per resource",
        "required": False,
        "default": 5,
    },
}
