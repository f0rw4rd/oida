#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared EtherNet/IP packet parsers.

Centralised ListIdentity response parsing used by the standalone
broadcast_discovery() helper and the DiscoveryMixin broadcast loop.
"""

import struct
from typing import Any, Dict, Optional

from .constants import ENIP_CMD_LIST_IDENTITY
from ...utils.vendor_maps import ethernetip_vendor_ids as VENDOR_IDS
from ...utils.vendor_maps import ethernetip_device_types as DEVICE_TYPE_IDS


def parse_list_identity(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a raw ListIdentity response packet into a device info dict.

    Handles the full ENIP header + CPF envelope + CIP Identity item.

    Args:
        data: Raw bytes received from a ListIdentity UDP/TCP response.

    Returns:
        Dict with parsed device fields, or ``None`` when the packet is
        invalid / not a ListIdentity response.
    """
    if len(data) < 24:
        return None

    # ENIP header
    command = struct.unpack("<H", data[0:2])[0]
    if command != ENIP_CMD_LIST_IDENTITY:
        return None

    length = struct.unpack("<H", data[2:4])[0]
    if len(data) < 24 + length:
        return None

    cpf_data = data[24 : 24 + length]
    if len(cpf_data) < 6:
        return None

    # CPF item count
    item_count = struct.unpack("<H", cpf_data[0:2])[0]
    if item_count < 1:
        return None

    # First CPF item (Identity)
    type_id, item_length = struct.unpack("<HH", cpf_data[2:6])
    if type_id != 0x000C:  # List Identity response type
        return None

    if len(cpf_data) < 6 + item_length:
        return None

    item_data = cpf_data[6 : 6 + item_length]

    # Identity payload: protocol version (2) + sockaddr (16) + fields
    if len(item_data) < 33:
        return None

    offset = 18  # skip protocol version + sockaddr
    vendor_id = struct.unpack("<H", item_data[offset : offset + 2])[0]
    offset += 2

    device_type = struct.unpack("<H", item_data[offset : offset + 2])[0]
    offset += 2

    product_code = struct.unpack("<H", item_data[offset : offset + 2])[0]
    offset += 2

    major, minor = struct.unpack("<BB", item_data[offset : offset + 2])
    offset += 2

    status = struct.unpack("<H", item_data[offset : offset + 2])[0]
    offset += 2

    serial_number = struct.unpack("<I", item_data[offset : offset + 4])[0]
    offset += 4

    product_name = ""
    if len(item_data) > offset:
        name_length = item_data[offset]
        offset += 1
        if len(item_data) >= offset + name_length:
            product_name = item_data[offset : offset + name_length].decode(
                "utf-8", errors="replace"
            )
            offset += name_length

    state = 0
    if len(item_data) > offset:
        state = item_data[offset]

    # State names
    state_names = {
        0: "Nonexistent",
        1: "Device Self Testing",
        2: "Standby",
        3: "Operational",
        4: "Major Recoverable Fault",
        5: "Major Unrecoverable Fault",
        255: "Default",
    }

    return {
        "success": True,
        "vendor_id": vendor_id,
        "vendor_name": VENDOR_IDS.get(vendor_id, f"Vendor {vendor_id}"),
        "device_type": device_type,
        "device_type_name": DEVICE_TYPE_IDS.get(device_type, f"Type {device_type}"),
        "product_code": product_code,
        "product_name": product_name,
        "revision": (major, minor),
        "serial_number": serial_number,
        "state": state,
        "state_name": state_names.get(state, f"Unknown ({state})"),
        "status": status,
    }
