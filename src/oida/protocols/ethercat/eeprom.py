#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EtherCAT EEPROM/ESI Parser

Parsing functions for EtherCAT Slave Information (ESI) stored in EEPROM.
Per ETG.2010 - EtherCAT Slave Information specification.

License: AGPL-3.0-or-later
"""

import struct
from typing import Any, Dict, List

from .constants import (
    FMMU_TYPES,
    SM_TYPES,
    COE_DATA_TYPES,
    PORT_TYPES,
    lookup_vendor,
)


def calculate_sii_crc(data: bytes) -> int:
    """Calculate CRC-8 for SII header (first 14 bytes).

    ETG.2010 specifies CRC-8 with polynomial 0x07, initial value 0xFF.

    Args:
        data: EEPROM data (at least 14 bytes).

    Returns:
        Calculated CRC-8 value.
    """
    crc = 0xFF
    for byte in data[:14]:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) if (crc & 0x80) else (crc << 1)
            crc &= 0xFF
    return crc


def parse_sii_header(data: bytes) -> Dict[str, Any]:
    """Parse SII header (bytes 0x00-0x7F) per ETG.2010.

    The SII header contains device identity, mailbox configuration,
    and PDI settings. Total size is 128 bytes (64 words).

    Args:
        data: EEPROM data (at least 128 bytes).

    Returns:
        Dict with parsed header fields including:
        - vendor_id, product_code, revision, serial_number: Identity
        - mailbox offsets and sizes (bootstrap and standard)
        - mailbox_protocol_flags: Supported protocols (AoE, EoE, CoE, FoE, SoE, VoE)
        - crc, crc_valid: Header CRC validation
    """
    if len(data) < 128:
        return {"error": "Insufficient data for SII header (need 128 bytes)"}

    header = {
        # PDI Configuration (bytes 0x00-0x09)
        "station_alias": struct.unpack_from("<H", data, 0x08)[0],
        # CRC at byte 0x0E (word 7, low byte)
        "crc": data[0x0E],
        # Device Identity (bytes 0x10-0x1F)
        "vendor_id": struct.unpack_from("<I", data, 0x10)[0],
        "product_code": struct.unpack_from("<I", data, 0x14)[0],
        "revision": struct.unpack_from("<I", data, 0x18)[0],
        "serial_number": struct.unpack_from("<I", data, 0x1C)[0],
        # Bootstrap Mailbox (bytes 0x28-0x2F); 0x20-0x27 is reserved (shall be zero)
        "bootstrap_rx_mbx_offset": struct.unpack_from("<H", data, 0x28)[0],
        "bootstrap_rx_mbx_size": struct.unpack_from("<H", data, 0x2A)[0],
        "bootstrap_tx_mbx_offset": struct.unpack_from("<H", data, 0x2C)[0],
        "bootstrap_tx_mbx_size": struct.unpack_from("<H", data, 0x2E)[0],
        # Standard Mailbox (bytes 0x30-0x39)
        "std_rx_mbx_offset": struct.unpack_from("<H", data, 0x30)[0],
        "std_rx_mbx_size": struct.unpack_from("<H", data, 0x32)[0],
        "std_tx_mbx_offset": struct.unpack_from("<H", data, 0x34)[0],
        "std_tx_mbx_size": struct.unpack_from("<H", data, 0x36)[0],
        "mailbox_protocols": struct.unpack_from("<H", data, 0x38)[0],
        # EEPROM info (bytes 0x7C-0x7F)
        "eeprom_size_kbit": struct.unpack_from("<H", data, 0x7C)[0] + 1,
        "sii_version": struct.unpack_from("<H", data, 0x7E)[0],
    }

    # Parse mailbox protocol flags (ETG.1000)
    mbx = header["mailbox_protocols"]
    header["mailbox_protocol_flags"] = {
        "AoE": bool(mbx & 0x01),  # ADS over EtherCAT
        "EoE": bool(mbx & 0x02),  # Ethernet over EtherCAT
        "CoE": bool(mbx & 0x04),  # CANopen over EtherCAT
        "FoE": bool(mbx & 0x08),  # File over EtherCAT
        "SoE": bool(mbx & 0x10),  # Servo over EtherCAT
        "VoE": bool(mbx & 0x20),  # Vendor over EtherCAT
    }

    # Add vendor name lookup
    header["vendor_name"] = lookup_vendor(header["vendor_id"])

    # Verify CRC
    expected_crc = data[0x0E]
    actual_crc = calculate_sii_crc(data)
    header["crc_valid"] = expected_crc == actual_crc

    return header


def parse_strings_category(data: bytes) -> List[str]:
    """Parse STRINGS category (type 10).

    The strings category contains device description strings referenced
    by index from other categories.

    Args:
        data: Category data (without header).

    Returns:
        List of strings, 1-indexed (index 0 is empty string).
    """
    strings = [""]  # Index 0 = no string
    if not data:
        return strings

    n_strings = data[0]
    offset = 1

    for _ in range(n_strings):
        if offset >= len(data):
            break
        length = data[offset]
        if offset + 1 + length > len(data):
            break
        string = data[offset + 1 : offset + 1 + length].decode("ascii", errors="replace")
        strings.append(string)
        offset += 1 + length

    return strings


def parse_general_category(data: bytes, strings: List[str]) -> Dict[str, Any]:
    """Parse GENERAL category (type 30) per ETG.2010.

    Contains device classification, CoE/FoE/EoE details, and port config.

    Args:
        data: Category data (without header), minimum 18 bytes.
        strings: String list from STRINGS category (1-indexed).

    Returns:
        Dict with device info including:
        - name, group, order, image: Device description strings
        - coe_flags: CoE capability flags
        - device_flags: Device behavior flags
        - ports: Physical port configuration
        - current_on_ebus_ma: E-Bus current consumption
    """
    if len(data) < 18:
        return {"error": "Insufficient data for GENERAL category (need 18 bytes)"}

    general = {
        "group_idx": data[0],
        "image_idx": data[1],
        "order_idx": data[2],
        "name_idx": data[3],
        # data[4] is reserved
        "coe_details": data[5],
        # data[6:11] are foe/eoe/soe/ds402/sysman detail bytes (not surfaced)
        "flags": data[11],
        "current_on_ebus_ma": struct.unpack_from("<h", data, 12)[0],  # signed int16
        # data[14:16] reserved
        "physical_port": struct.unpack_from("<H", data, 16)[0],
    }

    # Resolve string indices to actual strings
    for key in ["group_idx", "image_idx", "order_idx", "name_idx"]:
        idx = general[key]
        str_key = key.replace("_idx", "")
        general[str_key] = strings[idx] if 0 < idx < len(strings) else ""

    # Parse CoE details (ETG.1000)
    coe = general["coe_details"]
    general["coe_flags"] = {
        "sdo": bool(coe & 0x01),
        "sdo_info": bool(coe & 0x02),
        "pdo_assign": bool(coe & 0x04),
        "pdo_config": bool(coe & 0x08),
        "upload_at_startup": bool(coe & 0x10),
        "complete_access": bool(coe & 0x20),
    }

    # Parse device flags
    flags = general["flags"]
    general["device_flags"] = {
        "enable_safeop": bool(flags & 0x01),
        "enable_not_lrw": bool(flags & 0x02),
        "mbox_data_link_layer": bool(flags & 0x04),
        "ident_al_status": bool(flags & 0x08),
        "ident_physical_mem": bool(flags & 0x10),
    }

    # Parse physical port configuration (4 bits per port, 4 ports)
    port = general["physical_port"]
    general["ports"] = [PORT_TYPES.get((port >> (i * 4)) & 0x0F, "unknown") for i in range(4)]

    return general


def parse_syncmanager_category(data: bytes) -> List[Dict[str, Any]]:
    """Parse SyncManager category (type 41).

    Each SyncManager entry is 8 bytes describing memory region for
    PDO or mailbox data exchange.

    Args:
        data: Category data (without header).

    Returns:
        List of SyncManager configurations with:
        - start: Physical start address
        - length: Size in bytes
        - type: SM type (mbx_out, mbx_in, pdo_out, pdo_in)
        - control_flags: Operation mode and settings
    """
    sms = []

    for i in range(0, len(data), 8):
        if i + 8 > len(data):
            break

        start = struct.unpack_from("<H", data, i)[0]
        length = struct.unpack_from("<H", data, i + 2)[0]
        control = data[i + 4]
        sm_type = data[i + 7]

        # Parse control byte
        ctrl_flags = {
            "op_mode": control & 0x03,  # 0=3-buffer, 2=mailbox
            "direction": "write" if (control & 0x04) else "read",
            "ecat_event": bool(control & 0x08),
            "watchdog": bool(control & 0x20),
        }

        sms.append(
            {
                "start": f"0x{start:04X}",
                "length": length,
                "control": f"0x{control:02X}",
                "control_flags": ctrl_flags,
                "type": SM_TYPES.get(sm_type, f"unknown_{sm_type}"),
            }
        )

    return sms


def parse_fmmu_category(data: bytes) -> List[Dict[str, Any]]:
    """Parse FMMU category (type 40).

    Each FMMU entry is 1 byte indicating the FMMU type.

    Args:
        data: Category data (without header).

    Returns:
        List of FMMU configurations with type.
    """
    return [
        {"fmmu": i, "type": FMMU_TYPES.get(b, f"unknown_{b}"), "type_code": b}
        for i, b in enumerate(data)
    ]


def parse_pdo_category(data: bytes, strings: List[str]) -> List[Dict[str, Any]]:
    """Parse TxPDO (type 50) or RxPDO (type 51) category.

    PDO categories describe Process Data Objects with their entries.

    Args:
        data: Category data (without header).
        strings: String list from STRINGS category.

    Returns:
        List of PDO definitions with entries.
    """
    pdos = []
    offset = 0

    while offset + 8 <= len(data):
        pdo_index = struct.unpack_from("<H", data, offset)[0]
        n_entries = data[offset + 2]
        sm_index = data[offset + 3]
        dc_sync = data[offset + 4]
        name_idx = data[offset + 5]
        flags = struct.unpack_from("<H", data, offset + 6)[0]
        offset += 8

        pdo_name = strings[name_idx] if 0 < name_idx < len(strings) else f"PDO_0x{pdo_index:04X}"

        entries = []
        for _ in range(n_entries):
            if offset + 8 > len(data):
                break
            entry_index = struct.unpack_from("<H", data, offset)[0]
            subindex = data[offset + 2]
            entry_name_idx = data[offset + 3]
            data_type = data[offset + 4]
            bit_length = data[offset + 5]
            offset += 8

            entry_name = strings[entry_name_idx] if 0 < entry_name_idx < len(strings) else ""
            entries.append(
                {
                    "index": f"0x{entry_index:04X}",
                    "subindex": subindex,
                    "name": entry_name,
                    "data_type": COE_DATA_TYPES.get(data_type, f"type_{data_type}"),
                    "bit_length": bit_length,
                }
            )

        pdos.append(
            {
                "index": f"0x{pdo_index:04X}",
                "name": pdo_name,
                "sm": sm_index,
                "dc_sync": dc_sync,
                "flags": {"fixed": bool(flags & 0x01), "mandatory": bool(flags & 0x02)},
                "entries": entries,
            }
        )

    return pdos


def parse_dc_category(data: bytes, strings: List[str]) -> Dict[str, Any]:
    """Parse Distributed Clocks category (type 60).

    Contains DC synchronization settings.

    Args:
        data: Category data (without header), minimum 24 bytes.
        strings: String list from STRINGS category.

    Returns:
        Dict with DC configuration including cycle times and sync modes.
    """
    if len(data) < 24:
        return {"error": "Insufficient data for DC category (need 24 bytes)"}

    dc_modes = {
        0x0000: "free_run",
        0x0100: "sm_sync",
        0x0300: "dc_sync0",
        0x0700: "dc_sync0_sync1",
    }

    assign_activate = struct.unpack_from("<H", data, 18)[0]
    name_idx = data[22]
    desc_idx = data[23]

    return {
        "cycle_time0_ns": struct.unpack_from("<I", data, 0)[0],
        "shift_time0_ns": struct.unpack_from("<I", data, 4)[0],
        "cycle_time1_ns": struct.unpack_from("<I", data, 8)[0],
        "shift_time1_ns": struct.unpack_from("<I", data, 12)[0],
        "assign_activate_mode": dc_modes.get(assign_activate, f"mode_0x{assign_activate:04X}"),
        "name": strings[name_idx] if 0 < name_idx < len(strings) else "",
        "description": strings[desc_idx] if 0 < desc_idx < len(strings) else "",
    }
