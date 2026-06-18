#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CIP (Common Industrial Protocol) Object and Attribute Definitions

Comprehensive definitions for encoding/decoding CIP data based on:
- CIP Specification (ODVA)
- EtherNet/IP Specification
- Volume 1: Common Industrial Protocol

Each attribute definition includes:
- name: Human-readable name
- type: CIP data type
- parse: Function to decode bytes to value
- encode: Function to encode value to bytes (optional)
"""

import struct
from typing import Any, Callable, Dict, Optional, Tuple
from dataclasses import dataclass

import logging

logger = logging.getLogger(__name__)


# =============================================================================
# CIP Data Type Codes (from CIP Vol 1, Appendix C)
# =============================================================================
CIP_TYPE_CODES = {
    0x00: "?",
    0xC1: "BOOL",
    0xC2: "SINT",
    0xC3: "INT",
    0xC4: "DINT",
    0xC5: "LINT",
    0xC6: "USINT",
    0xC7: "UINT",
    0xC8: "UDINT",
    0xC9: "ULINT",
    0xCA: "REAL",
    0xCB: "LREAL",
    0xCC: "STIME",
    0xCD: "DATE",
    0xCE: "TIME_OF_DAY",
    0xCF: "DATE_AND_TIME",
    0xD0: "STRING",
    0xD1: "BYTE",
    0xD2: "WORD",
    0xD3: "DWORD",
    0xD4: "LWORD",
    0xD5: "STRING2",
    0xD6: "FTIME",
    0xD7: "LTIME",
    0xD8: "ITIME",
    0xD9: "STRINGN",
    0xDA: "SHORT_STRING",
    0xDB: "TIME",
    0xDC: "EPATH",
    0xDD: "ENGUNIT",
    0xDE: "STRINGI",
}


# =============================================================================
# Parsing Functions
# =============================================================================


def parse_usint(data: bytes) -> int:
    """Parse USINT (unsigned 8-bit)"""
    return data[0] if data else 0


def parse_sint(data: bytes) -> int:
    """Parse SINT (signed 8-bit)"""
    return struct.unpack("<b", data[:1])[0] if data else 0


def parse_uint(data: bytes) -> int:
    """Parse UINT (unsigned 16-bit)"""
    return struct.unpack("<H", data[:2])[0] if len(data) >= 2 else 0


def parse_int(data: bytes) -> int:
    """Parse INT (signed 16-bit)"""
    return struct.unpack("<h", data[:2])[0] if len(data) >= 2 else 0


def parse_udint(data: bytes) -> int:
    """Parse UDINT (unsigned 32-bit)"""
    return struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0


def parse_dint(data: bytes) -> int:
    """Parse DINT (signed 32-bit)"""
    return struct.unpack("<i", data[:4])[0] if len(data) >= 4 else 0


def parse_ulint(data: bytes) -> int:
    """Parse ULINT (unsigned 64-bit)"""
    return struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0


def parse_lint(data: bytes) -> int:
    """Parse LINT (signed 64-bit)"""
    return struct.unpack("<q", data[:8])[0] if len(data) >= 8 else 0


def parse_real(data: bytes) -> float:
    """Parse REAL (32-bit float)"""
    return struct.unpack("<f", data[:4])[0] if len(data) >= 4 else 0.0


def parse_lreal(data: bytes) -> float:
    """Parse LREAL (64-bit float)"""
    return struct.unpack("<d", data[:8])[0] if len(data) >= 8 else 0.0


def parse_bool(data: bytes) -> bool:
    """Parse BOOL"""
    return bool(data[0]) if data else False


def parse_string(data: bytes) -> str:
    """Parse SHORT_STRING (length-prefixed)"""
    if not data or len(data) < 1:
        return ""
    length = data[0]
    return data[1 : 1 + length].decode("ascii", errors="ignore")


def parse_string2(data: bytes) -> str:
    """Parse STRING2 (2-byte length-prefixed)"""
    if not data or len(data) < 2:
        return ""
    length = struct.unpack("<H", data[:2])[0]
    return data[2 : 2 + length].decode("ascii", errors="ignore")


def parse_mac(data: bytes) -> str:
    """Parse MAC address (6 bytes)"""
    if len(data) >= 6:
        return ":".join(f"{b:02X}" for b in data[:6])
    return ""


def parse_ipv4(data: bytes) -> str:
    """Parse IPv4 address (4 bytes, network order for CIP)"""
    if len(data) >= 4:
        # CIP uses big-endian for IP addresses
        return ".".join(str(b) for b in data[:4])
    return ""


def parse_dlr_node_address(data: bytes) -> dict:
    """Parse DLR Node Address (MAC + IP = 10 bytes)"""
    if len(data) >= 10:
        mac = ":".join(f"{b:02X}" for b in data[:6])
        ip = ".".join(str(b) for b in data[6:10])
        return {"mac": mac, "ip": ip}
    return {"raw": data.hex()}


def parse_dlr_capability_flags(data: bytes) -> dict:
    """Parse DLR Capability Flags (DWORD)"""
    if len(data) >= 4:
        flags = struct.unpack("<I", data[:4])[0]
        return {
            "raw": f"0x{flags:08X}",
            "announce_based": bool(flags & 0x01),
            "beacon_based": bool(flags & 0x02),
            "supervisor_capable": bool(flags & 0x80),
            "redundant_gateway_capable": bool(flags & 0x100),
            "flush_table_capable": bool(flags & 0x200),
        }
    return {"raw": data.hex()}


def parse_revision(data: bytes) -> str:
    """Parse revision (major.minor)"""
    if len(data) >= 2:
        return f"{data[0]}.{data[1]}"
    return ""


def parse_word(data: bytes) -> int:
    """Parse WORD (16-bit)"""
    return struct.unpack("<H", data[:2])[0] if len(data) >= 2 else 0


def parse_dword(data: bytes) -> int:
    """Parse DWORD (32-bit)"""
    return struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0


def parse_bytes(data: bytes) -> str:
    """Parse as hex string"""
    return data.hex() if data else ""


def parse_epath(data: bytes) -> str:
    """Parse EPATH (Encoded Path)"""
    # Simplified EPATH parsing
    if not data:
        return ""
    result = []
    i = 0
    while i < len(data):
        segment_type = data[i] >> 5
        if segment_type == 1:  # Port segment
            port = data[i] & 0x0F
            link = data[i + 1] if i + 1 < len(data) else 0
            result.append(f"Port:{port}/Link:{link}")
            i += 2
        elif segment_type == 0:  # Class/Instance/Attribute segment
            seg_subtype = data[i] & 0x03
            if seg_subtype == 0:  # 8-bit class
                cls = data[i + 1] if i + 1 < len(data) else 0
                result.append(f"Class:0x{cls:02X}")
                i += 2
            elif seg_subtype == 1:  # 16-bit class
                cls = struct.unpack("<H", data[i + 1 : i + 3])[0] if i + 3 <= len(data) else 0
                result.append(f"Class:0x{cls:04X}")
                i += 4
            else:
                i += 1
        else:
            i += 1
    return "/".join(result) if result else data.hex()


def parse_interface_config(data: bytes) -> dict:
    """Parse TCP/IP Interface Configuration structure"""
    if len(data) < 22:
        return {"raw": data.hex()}

    return {
        "ip": parse_ipv4(data[0:4]),
        "netmask": parse_ipv4(data[4:8]),
        "gateway": parse_ipv4(data[8:12]),
        "dns1": parse_ipv4(data[12:16]),
        "dns2": parse_ipv4(data[16:20]),
        "domain": data[20:].decode("ascii", errors="ignore").rstrip("\x00"),
    }


def parse_interface_counters(data: bytes) -> dict:
    """Parse Ethernet Link Interface Counters structure"""
    if len(data) < 44:
        return {"raw": data.hex()}

    return {
        "in_octets": struct.unpack("<I", data[0:4])[0],
        "in_ucast": struct.unpack("<I", data[4:8])[0],
        "in_nucast": struct.unpack("<I", data[8:12])[0],
        "in_discards": struct.unpack("<I", data[12:16])[0],
        "in_errors": struct.unpack("<I", data[16:20])[0],
        "in_unknown": struct.unpack("<I", data[20:24])[0],
        "out_octets": struct.unpack("<I", data[24:28])[0],
        "out_ucast": struct.unpack("<I", data[28:32])[0],
        "out_nucast": struct.unpack("<I", data[32:36])[0],
        "out_discards": struct.unpack("<I", data[36:40])[0],
        "out_errors": struct.unpack("<I", data[40:44])[0],
    }


def parse_media_counters(data: bytes) -> dict:
    """Parse Ethernet Link Media Counters structure (attr 5)"""
    if len(data) < 48:
        return {"raw": data.hex()}

    return {
        "align_errors": struct.unpack("<I", data[0:4])[0],
        "fcs_errors": struct.unpack("<I", data[4:8])[0],
        "single_collisions": struct.unpack("<I", data[8:12])[0],
        "multiple_collisions": struct.unpack("<I", data[12:16])[0],
        "sqe_test_errors": struct.unpack("<I", data[16:20])[0],
        "deferred_tx": struct.unpack("<I", data[20:24])[0],
        "late_collisions": struct.unpack("<I", data[24:28])[0],
        "excessive_collisions": struct.unpack("<I", data[28:32])[0],
        "mac_tx_errors": struct.unpack("<I", data[32:36])[0],
        "carrier_sense_errors": struct.unpack("<I", data[36:40])[0],
        "frame_too_long": struct.unpack("<I", data[40:44])[0],
        "mac_rx_errors": struct.unpack("<I", data[44:48])[0],
    }


def parse_interface_control(data: bytes) -> dict:
    """Parse Ethernet Link Interface Control structure (attr 6)"""
    if len(data) < 4:
        return {"raw": data.hex()}

    control_bits = struct.unpack("<H", data[0:2])[0]
    forced_speed = struct.unpack("<H", data[2:4])[0]

    # Decode control bits
    auto_neg = bool(control_bits & 0x01)
    full_duplex = bool(control_bits & 0x02)

    speed_names = {0: "auto", 10: "10Mbps", 100: "100Mbps", 1000: "1Gbps"}
    speed = speed_names.get(forced_speed, f"{forced_speed}Mbps")

    return {
        "auto_negotiate": auto_neg,
        "forced_duplex": "full" if full_duplex else "half",
        "forced_speed": speed,
    }


def parse_interface_capability(data: bytes) -> dict:
    """Parse Ethernet Link Interface Capability structure (attr 11)"""
    if len(data) < 5:
        return {"raw": data.hex()}

    caps = struct.unpack("<I", data[0:4])[0]
    count = data[4]

    # Decode capability bits
    result = {
        "manual_speed_duplex": bool(caps & 0x01),
        "auto_negotiate": bool(caps & 0x02),
        "auto_mdix": bool(caps & 0x04),
        "manual_mdix": bool(caps & 0x08),
    }

    # Parse speed/duplex options array
    if count > 0 and len(data) >= 5 + count * 4:
        speeds = []
        for i in range(count):
            offset = 5 + i * 4
            speed = struct.unpack("<H", data[offset : offset + 2])[0]
            duplex = struct.unpack("<H", data[offset + 2 : offset + 4])[0]
            duplex_name = {0: "half", 1: "full"}.get(duplex, str(duplex))
            speeds.append(f"{speed}Mbps/{duplex_name}")
        result["supported_speeds"] = speeds

    return result


def parse_multicast_config(data: bytes) -> dict:
    """Parse TCP/IP Multicast Configuration structure (attr 9)"""
    if len(data) < 8:
        return {"raw": data.hex()}

    alloc_control = data[0]
    # data[1] is reserved
    num_mcast = struct.unpack("<H", data[2:4])[0]
    mcast_addr = parse_ipv4(data[4:8])

    alloc_names = {0: "default", 1: "static"}

    return {
        "alloc_control": alloc_names.get(alloc_control, str(alloc_control)),
        "num_mcast": num_mcast,
        "mcast_start_addr": mcast_addr,
    }


def parse_acd_last_conflict(data: bytes) -> dict:
    """Parse TCP/IP Last ACD Conflict structure (attr 11)"""
    if len(data) < 10:
        if all(b == 0 for b in data):
            return {"status": "no conflict"}
        return {"raw": data.hex()}

    acd_activity = data[0]
    remote_mac = ":".join(f"{b:02X}" for b in data[1:7])
    # Rest is ARP PDU

    activity_names = {0: "no conflict", 1: "probe conflict", 2: "ongoing conflict"}

    if acd_activity == 0 and all(b == 0 for b in data[1:7]):
        return {"status": "no conflict"}

    return {
        "acd_activity": activity_names.get(acd_activity, str(acd_activity)),
        "remote_mac": remote_mac,
        "arp_pdu": data[7:].hex() if len(data) > 7 else "",
    }


# =============================================================================
# Parameter Object Descriptor Parsing
# =============================================================================

# Parameter Object (0x0F) Descriptor Bit Definitions
PARAM_DESC_SUPPORTS_SCALING = 0x0001  # Bit 0: Scaling supported
PARAM_DESC_SUPPORTS_LINKS = 0x0002  # Bit 1: Parameter links supported
PARAM_DESC_SCALING_REQUIRED = 0x0004  # Bit 2: Scaling required
PARAM_DESC_CALIBRATION = 0x0008  # Bit 3: Calibration data
PARAM_DESC_READ_ONLY = 0x0010  # Bit 4: Read-only (cannot be set)
PARAM_DESC_MONITOR = 0x0020  # Bit 5: Monitor parameter (real-time display)
PARAM_DESC_RESERVED_6 = 0x0040  # Bit 6: Reserved
PARAM_DESC_RESERVED_7 = 0x0080  # Bit 7: Reserved
PARAM_DESC_RESERVED_8 = 0x0100  # Bit 8: Reserved
PARAM_DESC_RESERVED_9 = 0x0200  # Bit 9: Reserved
PARAM_DESC_NON_DISPLAYED = 0x0400  # Bit 10: Non-displayed (hidden from UIs)
PARAM_DESC_INDIRECT = 0x0800  # Bit 11: Indirect parameter reference
PARAM_DESC_RESERVED_12 = 0x1000  # Bit 12: Reserved
PARAM_DESC_RESERVED_13 = 0x2000  # Bit 13: Reserved
PARAM_DESC_WRITE_ONLY = 0x4000  # Bit 14: Write-only (cannot be read)
PARAM_DESC_RESERVED_15 = 0x8000  # Bit 15: Reserved


def parse_param_descriptor(descriptor: int) -> dict:
    """Parse Parameter Object Descriptor (Attribute 4) bits.

    The Descriptor is a 16-bit field in the Parameter Object that defines
    access permissions and display properties.

    Args:
        descriptor: 16-bit descriptor value

    Returns:
        Dict with parsed permission and property flags
    """
    return {
        "read_only": bool(descriptor & PARAM_DESC_READ_ONLY),  # Bit 4
        "write_only": bool(descriptor & PARAM_DESC_WRITE_ONLY),  # Bit 14
        "monitor": bool(descriptor & PARAM_DESC_MONITOR),  # Bit 5
        "non_displayed": bool(descriptor & PARAM_DESC_NON_DISPLAYED),  # Bit 10
        "indirect": bool(descriptor & PARAM_DESC_INDIRECT),  # Bit 11
        "supports_scaling": bool(descriptor & PARAM_DESC_SUPPORTS_SCALING),  # Bit 0
        "supports_links": bool(descriptor & PARAM_DESC_SUPPORTS_LINKS),  # Bit 1
        "scaling_required": bool(descriptor & PARAM_DESC_SCALING_REQUIRED),  # Bit 2
        "raw": descriptor,
    }


def get_permission_from_descriptor(descriptor: int) -> str:
    """Get permission string from Parameter Object Descriptor.

    Args:
        descriptor: 16-bit descriptor value

    Returns:
        Permission string: "R" (read-only), "W" (write-only), "RW" (read/write)
    """
    read_only = bool(descriptor & PARAM_DESC_READ_ONLY)
    write_only = bool(descriptor & PARAM_DESC_WRITE_ONLY)

    if read_only and write_only:
        return "?"  # Invalid combination
    elif read_only:
        return "R"
    elif write_only:
        return "W"
    else:
        return "RW"


# CIP General Status Codes for Access Errors
CIP_STATUS_SUCCESS = 0x00
CIP_STATUS_PATH_SEGMENT_ERROR = 0x04
CIP_STATUS_PATH_DESTINATION_UNKNOWN = 0x05
CIP_STATUS_SERVICE_NOT_SUPPORTED = 0x08
CIP_STATUS_INVALID_ATTRIBUTE = 0x09
CIP_STATUS_ATTRIBUTE_LIST_ERROR = 0x0A
CIP_STATUS_STATE_CONFLICT = 0x0C
CIP_STATUS_OBJECT_STATE_CONFLICT = 0x0C
CIP_STATUS_ATTRIBUTE_NOT_SETTABLE = 0x0E  # Definitive read-only
CIP_STATUS_PRIVILEGE_VIOLATION = 0x0F  # Permission denied (user/role)
CIP_STATUS_DEVICE_STATE_CONFLICT = 0x10  # Mode prohibits writes
CIP_STATUS_WRITE_ONCE_WRITTEN = 0x21  # One-time programmable limit
CIP_STATUS_ATTRIBUTE_NOT_GETTABLE = 0x2C  # Write-only attribute


def interpret_write_error(status_code: int) -> tuple:
    """Interpret CIP error code from Set_Attribute_Single response.

    Args:
        status_code: CIP general status code

    Returns:
        Tuple of (permission_str, explanation)
    """
    interpretations = {
        CIP_STATUS_SUCCESS: ("RW", "Write succeeded"),
        CIP_STATUS_ATTRIBUTE_NOT_SETTABLE: ("R", "Attribute is read-only by design"),
        CIP_STATUS_PRIVILEGE_VIOLATION: ("R?", "Permission denied - may need authentication"),
        CIP_STATUS_OBJECT_STATE_CONFLICT: (
            "R*",
            "State-dependent - may be writable in different mode",
        ),
        CIP_STATUS_DEVICE_STATE_CONFLICT: ("R*", "Device mode prohibits writes"),
        CIP_STATUS_SERVICE_NOT_SUPPORTED: ("R?", "Object doesn't implement Set service"),
        CIP_STATUS_WRITE_ONCE_WRITTEN: ("R", "Write-once attribute already written"),
        CIP_STATUS_INVALID_ATTRIBUTE: ("?", "Attribute doesn't exist"),
    }
    return interpretations.get(status_code, ("?", f"Unknown error 0x{status_code:02X}"))


# =============================================================================
# Encoding Functions
# =============================================================================


def encode_usint(value: int) -> bytes:
    return bytes([value & 0xFF])


def encode_uint(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def encode_udint(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def encode_string(value: str) -> bytes:
    encoded = value.encode("ascii", errors="ignore")[:255]
    return bytes([len(encoded)]) + encoded


def encode_bool(value: bool) -> bytes:
    return bytes([1 if value else 0])


def encode_ipv4(value: str) -> bytes:
    parts = value.split(".")
    return bytes([int(p) for p in parts[:4]])


# =============================================================================
# Attribute Definition
# =============================================================================


@dataclass
class AttrDef:
    """CIP Attribute Definition"""

    name: str
    cip_type: str
    parse: Callable[[bytes], Any]
    encode: Optional[Callable[[Any], bytes]] = None
    desc: str = ""
    perm: str = "R"  # R=Read-only, RW=Read/Write, W=Write-only


# =============================================================================
# CIP Object Definitions
# =============================================================================

# Class-level attributes common to all objects (all read-only per CIP spec)
CLASS_ATTRIBUTES = {
    1: AttrDef("Revision", "UINT", parse_uint, perm="R"),
    2: AttrDef("Max Instance", "UINT", parse_uint, perm="R"),
    3: AttrDef("Num Instances", "UINT", parse_uint, perm="R"),
    6: AttrDef("Max Class Attr", "UINT", parse_uint, perm="R"),
    7: AttrDef("Max Inst Attr", "UINT", parse_uint, perm="R"),
}

# Object definitions: {class_id: {attr_id: AttrDef}}
CIP_OBJECTS: Dict[int, Dict[str, Any]] = {
    # =========================================================================
    # Identity Object (0x01) - Required for all CIP devices
    # =========================================================================
    0x01: {
        "name": "Identity",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Vendor ID", "UINT", parse_uint, desc="Vendor identification"),
            2: AttrDef("Device Type", "UINT", parse_uint, desc="Device type code"),
            3: AttrDef("Product Code", "UINT", parse_uint, desc="Product identification"),
            4: AttrDef("Revision", "UINT[2]", parse_revision, desc="Major.Minor revision"),
            5: AttrDef("Status", "WORD", parse_word, desc="Device status bits"),
            6: AttrDef("Serial Number", "UDINT", parse_udint, desc="Unique serial number"),
            7: AttrDef("Product Name", "SHORT_STRING", parse_string, desc="Product name"),
            8: AttrDef("State", "USINT", parse_usint, desc="Device state"),
            9: AttrDef("Config Consist Value", "UINT", parse_uint),
            10: AttrDef("Heartbeat Interval", "USINT", parse_usint),
            11: AttrDef("Active Language", "STRUCT", parse_bytes),
            12: AttrDef("Supported Languages", "STRUCT", parse_bytes),
            13: AttrDef("International Product Name", "STRINGI", parse_bytes),
        },
    },
    # =========================================================================
    # Message Router Object (0x02)
    # =========================================================================
    0x02: {
        "name": "Message Router",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Object List", "STRUCT", parse_bytes, desc="Supported object list"),
            2: AttrDef("Max Conn Supported", "UINT", parse_uint),
            3: AttrDef("Num Active Conn", "UINT", parse_uint),
            4: AttrDef("Active Conn List", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # Assembly Object (0x04)
    # =========================================================================
    0x04: {
        "name": "Assembly",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Num Members", "UINT", parse_uint),
            2: AttrDef("Member List", "STRUCT", parse_bytes),
            3: AttrDef("Data", "BYTE[]", parse_bytes, desc="Assembly I/O data"),
            4: AttrDef("Size", "UINT", parse_uint, desc="Data size in bytes"),
        },
    },
    # =========================================================================
    # Connection Manager Object (0x06)
    # =========================================================================
    0x06: {
        "name": "Connection Manager",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Open Requests", "UINT", parse_uint),
            2: AttrDef("Open Format Rejects", "UINT", parse_uint),
            3: AttrDef("Open Resource Rejects", "UINT", parse_uint),
            4: AttrDef("Other Open Rejects", "UINT", parse_uint),
            5: AttrDef("Close Requests", "UINT", parse_uint),
            6: AttrDef("Close Format Requests", "UINT", parse_uint),
            7: AttrDef("Close Other Requests", "UINT", parse_uint),
            8: AttrDef("Connection Timeouts", "UINT", parse_uint),
            9: AttrDef("Connection Entry List", "STRUCT", parse_bytes),
            10: AttrDef("Explicit Conn List", "STRUCT", parse_bytes),
            11: AttrDef("Non-Conn Msg Timeout", "USINT", parse_usint),
        },
    },
    # =========================================================================
    # Discrete Input Point Object (0x08)
    # =========================================================================
    0x08: {
        "name": "Discrete Input Point",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Value", "BOOL", parse_bool),
            2: AttrDef("Status", "USINT", parse_usint),
            3: AttrDef("Force Enable", "BOOL", parse_bool),
            4: AttrDef("Forced Value", "BOOL", parse_bool),
        },
    },
    # =========================================================================
    # Discrete Output Point Object (0x09)
    # =========================================================================
    0x09: {
        "name": "Discrete Output Point",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Value", "BOOL", parse_bool, encode_bool),
            2: AttrDef("Status", "USINT", parse_usint),
            3: AttrDef("Force Enable", "BOOL", parse_bool),
            4: AttrDef("Forced Value", "BOOL", parse_bool),
        },
    },
    # =========================================================================
    # Analog Input Point Object (0x0A)
    # =========================================================================
    0x0A: {
        "name": "Analog Input Point",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Value", "REAL", parse_real),
            2: AttrDef("Status", "USINT", parse_usint),
            3: AttrDef("Min Value", "REAL", parse_real),
            4: AttrDef("Max Value", "REAL", parse_real),
        },
    },
    # =========================================================================
    # Analog Output Point Object (0x0B)
    # =========================================================================
    0x0B: {
        "name": "Analog Output Point",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Value", "REAL", parse_real),
            2: AttrDef("Status", "USINT", parse_usint),
            3: AttrDef("Min Value", "REAL", parse_real),
            4: AttrDef("Max Value", "REAL", parse_real),
            5: AttrDef("Fault Value", "REAL", parse_real),
        },
    },
    # =========================================================================
    # Parameter Object (0x0F)
    # =========================================================================
    0x0F: {
        "name": "Parameter",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Value", "VARIES", parse_bytes),
            2: AttrDef("Link Path Size", "USINT", parse_usint),
            3: AttrDef("Link Path", "EPATH", parse_epath),
            4: AttrDef("Descriptor", "WORD", parse_word),
            5: AttrDef("Data Type", "USINT", parse_usint, desc="CIP type code"),
            6: AttrDef("Data Size", "USINT", parse_usint),
            7: AttrDef("Name", "SHORT_STRING", parse_string),
            8: AttrDef("Units", "SHORT_STRING", parse_string),
            9: AttrDef("Help", "SHORT_STRING", parse_string),
            10: AttrDef("Min Value", "VARIES", parse_bytes),
            11: AttrDef("Max Value", "VARIES", parse_bytes),
            12: AttrDef("Default Value", "VARIES", parse_bytes),
            13: AttrDef("Scaling Mult", "UINT", parse_uint),
            14: AttrDef("Scaling Div", "UINT", parse_uint),
            15: AttrDef("Scaling Base", "UINT", parse_uint),
            16: AttrDef("Scaling Offset", "INT", parse_int),
            17: AttrDef("Mult Link", "UINT", parse_uint),
            18: AttrDef("Div Link", "UINT", parse_uint),
            19: AttrDef("Base Link", "UINT", parse_uint),
            20: AttrDef("Offset Link", "UINT", parse_uint),
            21: AttrDef("Decimal Precision", "USINT", parse_usint),
        },
    },
    # =========================================================================
    # File Object (0x37)
    # =========================================================================
    0x37: {
        "name": "File",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("State", "USINT", parse_usint),
            2: AttrDef("Instance Name", "SHORT_STRING", parse_string),
            3: AttrDef("Instance Format", "UINT", parse_uint),
            4: AttrDef("File Name", "SHORT_STRING", parse_string),
            5: AttrDef("File Revision", "UINT[2]", parse_revision),
            6: AttrDef("File Size", "UDINT", parse_udint),
            7: AttrDef("File Checksum", "INT", parse_int),
            8: AttrDef("Invocation Method", "USINT", parse_usint),
            9: AttrDef("File Save Params", "USINT", parse_usint),
            10: AttrDef("File Type", "USINT", parse_usint),
            11: AttrDef("File Encoding", "USINT", parse_usint),
        },
    },
    # =========================================================================
    # Time Sync Object (0x43) - IEEE 1588 PTP
    # =========================================================================
    0x43: {
        "name": "Time Sync",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("PTP Enable", "BOOL", parse_bool, encode_bool),
            2: AttrDef("Port Enable", "BOOL", parse_bool),
            3: AttrDef("Port Log Announce Interval", "INT", parse_int),
            4: AttrDef("Port Log Sync Interval", "INT", parse_int),
            5: AttrDef("Priority1", "USINT", parse_usint),
            6: AttrDef("Priority2", "USINT", parse_usint),
            7: AttrDef("Domain Number", "USINT", parse_usint),
            8: AttrDef("Clock Type", "WORD", parse_word),
            9: AttrDef("Manufacturer ID", "SHORT_STRING", parse_string),
            10: AttrDef("Product Description", "SHORT_STRING", parse_string),
            11: AttrDef("Revision Data", "SHORT_STRING", parse_string),
            12: AttrDef("User Description", "SHORT_STRING", parse_string),
            13: AttrDef("Port Profile Identity", "STRUCT", parse_bytes),
            14: AttrDef("Port Physical Address", "STRUCT", parse_bytes),
            15: AttrDef("Port Protocol Address", "STRUCT", parse_bytes),
            16: AttrDef("Steps Removed", "UINT", parse_uint),
            17: AttrDef("System Time Microseconds", "ULINT", parse_ulint),
            18: AttrDef("System Time Nanoseconds", "ULINT", parse_ulint),
            19: AttrDef("Offset From Master", "LINT", parse_lint),
            20: AttrDef("Max Offset From Master", "ULINT", parse_ulint),
            21: AttrDef("Mean Path Delay To Master", "LINT", parse_lint),
            22: AttrDef("Grand Master Clock Info", "STRUCT", parse_bytes),
            23: AttrDef("Parent Clock Info", "STRUCT", parse_bytes),
            24: AttrDef("Local Clock Info", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # Device Level Ring (DLR) Object (0x47)
    # =========================================================================
    0x47: {
        "name": "Device Level Ring (DLR)",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Network Topology", "USINT", parse_usint, desc="0=Linear, 1=Ring"),
            2: AttrDef("Network Status", "USINT", parse_usint, desc="0=Normal, 1-4=Fault states"),
            3: AttrDef("Ring Supervisor Status", "USINT", parse_usint),
            4: AttrDef("Ring Supervisor Config", "STRUCT", parse_bytes),
            5: AttrDef("Ring Faults Count", "UINT", parse_uint),
            6: AttrDef("Last Active Node Port 1", "STRUCT", parse_dlr_node_address),
            7: AttrDef("Last Active Node Port 2", "STRUCT", parse_dlr_node_address),
            8: AttrDef("Ring Participants Count", "UINT", parse_uint),
            9: AttrDef("Ring Participants List", "STRUCT", parse_bytes),
            10: AttrDef("Active Supervisor Address", "STRUCT", parse_dlr_node_address),
            11: AttrDef("Active Supervisor Precedence", "USINT", parse_usint),
            12: AttrDef("Capability Flags", "DWORD", parse_dlr_capability_flags),
        },
    },
    # =========================================================================
    # QoS Object (0x48) - Quality of Service
    # =========================================================================
    0x48: {
        "name": "QoS",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("802.1Q Tag Enable", "BOOL", parse_bool),
            2: AttrDef("DSCP Urgent", "USINT", parse_usint),
            3: AttrDef("DSCP Scheduled", "USINT", parse_usint),
            4: AttrDef("DSCP High", "USINT", parse_usint),
            5: AttrDef("DSCP Low", "USINT", parse_usint),
            6: AttrDef("DSCP Explicit", "USINT", parse_usint),
        },
    },
    # =========================================================================
    # CIP Security Object (0x5D)
    # =========================================================================
    0x5D: {
        "name": "CIP Security",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("State", "USINT", parse_usint),
            2: AttrDef("Security Profiles", "STRUCT", parse_bytes),
            3: AttrDef("Security Profiles Capacity", "UDINT", parse_udint),
            4: AttrDef("Configured Security Profiles", "UDINT", parse_udint),
            5: AttrDef("Currently Active Security Profile", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # EtherNet/IP Security Object (0x5E)
    # =========================================================================
    0x5E: {
        "name": "EtherNet/IP Security",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("State", "USINT", parse_usint),
            2: AttrDef("Capability Flags", "DWORD", parse_dword),
            3: AttrDef("Available Cipher Suites", "STRUCT", parse_bytes),
            4: AttrDef("Allowed Cipher Suites", "STRUCT", parse_bytes),
            5: AttrDef("Pre-Shared Keys", "STRUCT", parse_bytes),
            6: AttrDef("Active Device Certificates", "STRUCT", parse_bytes),
            7: AttrDef("Trusted Authorities", "STRUCT", parse_bytes),
            8: AttrDef("Pull Model Enable", "BOOL", parse_bool),
            9: AttrDef("Pull Model Status", "USINT", parse_usint),
        },
    },
    # =========================================================================
    # Certificate Management Object (0x5F)
    # =========================================================================
    0x5F: {
        "name": "Certificate Management",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Capability Flags", "DWORD", parse_dword),
            2: AttrDef("Certificate List", "STRUCT", parse_bytes),
            3: AttrDef("Certificate Verify Mode", "USINT", parse_usint),
        },
    },
    # =========================================================================
    # Symbol Object (0x6B) - Rockwell Logix
    # =========================================================================
    0x6B: {
        "name": "Symbol",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Symbol Name", "SHORT_STRING", parse_string),
            2: AttrDef("Symbol Type", "UINT", parse_uint),
            3: AttrDef("Symbol Dimensions", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # Template Object (0x6C) - Rockwell Logix UDT definitions
    # =========================================================================
    0x6C: {
        "name": "Template",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Object Definition Size", "UDINT", parse_udint),
            2: AttrDef("Structure Handle", "UINT", parse_uint),
            3: AttrDef("Member Count", "UINT", parse_uint),
            4: AttrDef("Template Handle", "UINT", parse_uint),
            5: AttrDef("Template Definition", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # Wall Clock Time Object (0x8B)
    # =========================================================================
    0x8B: {
        "name": "Wall Clock Time",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Time Value", "ULINT", parse_ulint, desc="Microseconds since 1970"),
            2: AttrDef("Local Time Adjustment", "LINT", parse_lint),
            3: AttrDef("Time Zone String", "SHORT_STRING", parse_string),
            4: AttrDef("DST Info", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # PCCC Object (0xB2) - Legacy AB protocol
    # =========================================================================
    0xB2: {
        "name": "PCCC",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("PCCC", "STRUCT", parse_bytes),
        },
    },
    # =========================================================================
    # TCP/IP Interface Object (0xF5)
    # =========================================================================
    0xF5: {
        "name": "TCP/IP Interface",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Status", "DWORD", parse_dword, desc="Interface status bits"),
            2: AttrDef("Configuration Capability", "DWORD", parse_dword),
            3: AttrDef("Configuration Control", "DWORD", parse_dword),
            4: AttrDef("Physical Link Object", "EPATH", parse_epath),
            5: AttrDef("Interface Configuration", "STRUCT", parse_interface_config),
            6: AttrDef("Host Name", "STRING", parse_string2),
            7: AttrDef("Safety Net Number", "STRUCT", parse_bytes),
            8: AttrDef("TTL Value", "USINT", parse_usint),
            9: AttrDef("Multicast Config", "STRUCT", parse_multicast_config),
            10: AttrDef("Select ACD", "BOOL", parse_bool),
            11: AttrDef("Last Conflict Detected", "STRUCT", parse_acd_last_conflict),
            12: AttrDef("Quick Connect", "BOOL", parse_bool),
            13: AttrDef("Encapsulation Inactivity Timeout", "UINT", parse_uint),
        },
    },
    # =========================================================================
    # Ethernet Link Object (0xF6)
    # =========================================================================
    0xF6: {
        "name": "Ethernet Link",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Interface Speed", "UDINT", parse_udint, desc="Speed in Mbps"),
            2: AttrDef("Interface Flags", "DWORD", parse_dword, desc="Link status flags"),
            3: AttrDef("Physical Address", "MAC", parse_mac, desc="MAC address"),
            4: AttrDef("Interface Counters", "STRUCT", parse_interface_counters),
            5: AttrDef("Media Counters", "STRUCT", parse_media_counters),
            6: AttrDef("Interface Control", "STRUCT", parse_interface_control),
            7: AttrDef("Interface Type", "USINT", parse_usint),
            8: AttrDef("Interface State", "USINT", parse_usint),
            9: AttrDef("Admin State", "USINT", parse_usint),
            10: AttrDef("Interface Label", "SHORT_STRING", parse_string),
            11: AttrDef("Interface Capability", "STRUCT", parse_interface_capability),
        },
    },
    # =========================================================================
    # Port Object (0xF4)
    # =========================================================================
    0xF4: {
        "name": "Port",
        "class_attrs": CLASS_ATTRIBUTES,
        "inst_attrs": {
            1: AttrDef("Port Type", "UINT", parse_uint, desc="Port type code"),
            2: AttrDef("Port Number", "UINT", parse_uint),
            3: AttrDef("Link Object", "EPATH", parse_epath),
            4: AttrDef("Port Name", "SHORT_STRING", parse_string),
            7: AttrDef("Node Address", "STRUCT", parse_bytes),
            8: AttrDef("Port Node Range", "STRUCT", parse_bytes),
            9: AttrDef("Associated Comms Objects", "STRUCT", parse_bytes),
        },
    },
}


# =============================================================================
# Port Type Definitions
# =============================================================================
PORT_TYPES = {
    0: "Backplane",
    1: "Backplane (Redundant)",
    2: "ControlNet",
    3: "ControlNet (Redundant)",
    4: "EtherNet/IP",
    5: "EtherNet/IP (Redundant)",
    6: "DeviceNet",
    7: "DeviceNet (Redundant)",
    8: "SerialPort",
    9: "SerialPort (Redundant)",
    100: "USB",
    101: "CompoNet",
    200: "Modbus",
    65534: "Any",
    65535: "None",
}


# =============================================================================
# Device Type Definitions
# =============================================================================
DEVICE_TYPES = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x03: "Motor Overload",
    0x04: "Limit Switch",
    0x05: "Inductive Proximity Switch",
    0x06: "Photoelectric Sensor",
    0x07: "General Purpose Discrete I/O",
    0x09: "Resolver",
    0x0A: "General Purpose Analog I/O",
    0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller",
    0x10: "Position Controller",
    0x12: "DC Drive",
    0x13: "Contactor",
    0x14: "Motor Starter",
    0x15: "Soft Start",
    0x16: "Human Machine Interface",
    0x17: "Mass Flow Controller",
    0x18: "Pneumatic Valve",
    0x19: "Vacuum Pump",
    0x1A: "DC Power Generator",
    0x1B: "DC Power Generator",
    0x1C: "CIP Motion Drive",
    0x1D: "CompoNet Repeater",
    0x1E: "Mass Flow Controller (Enhanced)",
    0x1F: "CIP Modbus Device",
    0x20: "CIP Modbus Translator",
    0x21: "Safety Discrete I/O",
    0x22: "Safety Controller",
    0x23: "Safety Drive",
    0x24: "Safety Discrete I/O (Device Level Safety)",
    0x25: "Safety Analog I/O (Device Level Safety)",
    0x26: "Encoder",
    0x27: "Resolver (Absolute Position)",
    0x28: "Switch/Router",
    0x29: "Safety Encoder",
    0x2B: "Safety Discrete I/O (Configurable I/O)",
    0x2C: "Safety Drive (Functional Safety)",
    0xC8: "Embedded Component",
}


# =============================================================================
# Vendor IDs (partial list of common vendors)
# =============================================================================
VENDOR_IDS = {
    1: "Rockwell Automation",
    2: "Mitsubishi Electric",
    5: "Allen-Bradley",
    15: "OMRON",
    36: "Schneider Electric",
    50: "IDEC",
    85: "Parker Hannifin",
    90: "ABB",
    283: "Phoenix Contact",
    340: "Siemens",
    674: "WAGO",
    702: "Beckhoff",
    777: "ifm electronic",
    906: "Moxa",
    1032: "Turck",
    1160: "Hilscher",
    1204: "HMS Industrial Networks",
    1245: "SICK",
    1297: "Balluff",
    1402: "E-T-A Elektrotechnische Apparate GmbH",
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_object_def(class_id: int) -> Optional[Dict]:
    """Get object definition by class ID"""
    return CIP_OBJECTS.get(class_id)


def get_attr_def(class_id: int, instance: int, attr_id: int) -> Optional[AttrDef]:
    """Get attribute definition"""
    obj_def = CIP_OBJECTS.get(class_id)
    if not obj_def:
        return None

    if instance == 0:
        # Class-level attribute
        return obj_def.get("class_attrs", {}).get(attr_id)
    else:
        # Instance-level attribute
        return obj_def.get("inst_attrs", {}).get(attr_id)


def parse_attribute(
    class_id: int, instance: int, attr_id: int, data: bytes
) -> Tuple[str, str, Any]:
    """
    Parse a CIP attribute and return (name, type, parsed_value)

    Args:
        class_id: CIP class ID
        instance: Instance number (0 for class attributes)
        attr_id: Attribute ID
        data: Raw attribute data

    Returns:
        Tuple of (name, cip_type, parsed_value)
    """
    attr_def = get_attr_def(class_id, instance, attr_id)

    if attr_def:
        try:
            value = attr_def.parse(data)
        except Exception:
            value = data.hex() if data else ""
        return (attr_def.name, attr_def.cip_type, value)

    # Unknown attribute - infer type from data
    inferred_type = infer_type_from_data(data)
    return ("", inferred_type, data.hex() if data else "")


def infer_type_from_data(data: bytes) -> str:
    """Infer CIP data type from raw bytes"""
    if not data:
        return "?"

    size = len(data)

    # Check for string (length-prefixed)
    if size >= 2 and data[0] == size - 1:
        try:
            text = data[1:].decode("ascii")
            if text.isprintable():
                return "STRING"
        except Exception as e:
            logger.debug(
                f"Failed to get text: {e}"
            )  # Not a valid ASCII string, continue type inference

    # Size-based inference
    type_map = {
        1: "USINT",
        2: "UINT",
        4: "UDINT",
        6: "MAC",
        8: "ULINT",
    }

    return type_map.get(size, f"BYTE[{size}]")


def get_object_name(class_id: int) -> str:
    """Get object name by class ID"""
    obj_def = CIP_OBJECTS.get(class_id)
    if obj_def:
        return obj_def.get("name", f"Unknown_0x{class_id:02X}")
    return f"Unknown_0x{class_id:02X}"


def get_vendor_name(vendor_id: int) -> str:
    """Get vendor name by vendor ID"""
    return VENDOR_IDS.get(vendor_id, f"Unknown ({vendor_id})")


def get_device_type_name(device_type: int) -> str:
    """Get device type name"""
    return DEVICE_TYPES.get(device_type, f"Unknown (0x{device_type:02X})")


def get_port_type_name(port_type: int) -> str:
    """Get port type name"""
    return PORT_TYPES.get(port_type, f"Unknown ({port_type})")
