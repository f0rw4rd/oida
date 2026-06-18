"""
DNP3 Protocol Constants

Protocol-level constants, group names, device attribute definitions,
and quality flag decoding for DNP3 (IEEE 1815).
"""

from typing import Dict, List, Tuple

# DNP3 quality flag bits (IEEE 1815 / IEC 62351-5)
_FLAG_BITS: List[Tuple[int, str]] = [
    (0x01, "ON"),  # Online
    (0x02, "RST"),  # Restart
    (0x04, "CL"),  # Comm Lost
    (0x08, "RF"),  # Remote Forced
    (0x10, "LF"),  # Local Forced
    (0x20, "OR"),  # Over-Range (analog) / Chatter Filter (binary)
    (0x40, "RE"),  # Reference Error (analog) / Discontinuity (counter)
    (0x80, "ST"),  # State (binary value bit)
]


def _decode_flags(flags_val: int) -> str:
    """Decode DNP3 quality flags bitmask into abbreviated string."""
    if not isinstance(flags_val, int):
        return str(flags_val)
    parts = [abbr for mask, abbr in _FLAG_BITS if flags_val & mask]
    return ",".join(parts) if parts else "0"


# Well-known Group 0 device attribute variations
KNOWN_ATTRIBUTES: Dict[int, str] = {
    196: "All Attributes Request",
    211: "Max Analog Output Index",
    212: "Number of Analog Outputs",
    213: "Max Binary Output Index",
    214: "Number of Binary Outputs",
    215: "Max Frozen Counter Index",
    216: "Number of Frozen Counters",
    217: "Max Counter Index",
    218: "Number of Counter Points",
    219: "Max Analog Input Index",
    220: "Number of Analog Inputs",
    221: "Max Double-Bit BI Index",
    222: "Number of Double-Bit BIs",
    223: "Max Binary Input Index",
    224: "Number of Binary Inputs",
    240: "Max TX Fragment Size",
    241: "Max RX Fragment Size",
    242: "Software Version",
    243: "Hardware Version",
    245: "Location",
    246: "ID Code / User-Assigned Location",
    247: "User-Assigned ID / Device Name",
    248: "User-Assigned Owner Name",
    249: "Device Serial Number",
    250: "Device Subset and Conformance",
    252: "Device Manufacturer's Product Name",
    254: "Device Manufacturer's Name",
    255: "List of Attribute Variations",
}

DNP3_GROUP_NAMES: Dict[int, str] = {
    0: "Device Attributes",
    1: "Binary Input",
    2: "Binary Input Event",
    3: "Double-Bit Binary Input",
    4: "Double-Bit BI Event",
    10: "Binary Output Status",
    11: "Binary Output Event",
    12: "Binary Output Command",
    13: "BO Command Event",
    20: "Counter",
    21: "Frozen Counter",
    22: "Counter Event",
    23: "Frozen Counter Event",
    30: "Analog Input",
    31: "Frozen Analog Input",
    32: "Analog Input Event",
    33: "Frozen AI Event",
    34: "Analog Input Dead Band",
    40: "Analog Output Status",
    41: "Analog Output Block",
    42: "Analog Output Event",
    43: "AO Command Event",
    50: "Time and Date",
    51: "Time and Date CTO",
    52: "Time Delay",
    60: "Class Data",
    70: "File Control",
    80: "Internal Indications",
    102: "Unsigned Integer",
    110: "Octet String",
    111: "Octet String Event",
    112: "Virtual Terminal Output",
    113: "Virtual Terminal Event",
    120: "Authentication",
    121: "Security Statistics",
    122: "Security Statistic Event",
}

# Attributes shown by default, ordered by importance for security assessment.
# Point counts / max index values (211-239) are hidden unless --dump-attrs.
# Each entry: (variation_number, short_display_label)
SECURITY_RELEVANT_ATTRS = (
    (254, "Vendor"),
    (252, "Product"),
    (249, "Serial Number"),
    (242, "Software Version"),
    (243, "Hardware Version"),
    (250, "Conformance"),
    (247, "Device Name"),
    (248, "Owner"),
    (245, "Location"),
    (246, "ID Code"),
)

# Set for fast membership checks
SECURITY_RELEVANT_ATTR_IDS = {var for var, _ in SECURITY_RELEVANT_ATTRS}

protocol_options = {
    "master-address": {
        "type": "int",
        "description": "Master DNP3 address",
        "required": False,
        "default": 1,
    },
    "outstation-address": {
        "type": "int",
        "description": "Outstation DNP3 address",
        "required": False,
        "default": 1024,
    },
    "read-class": {
        "type": "string",
        "description": "Class to read (0, 1, 2, 3, all)",
        "required": False,
        "default": "all",
    },
    "timeout": {
        "type": "int",
        "description": "Operation timeout in seconds",
        "required": False,
        "default": 10,
    },
}
