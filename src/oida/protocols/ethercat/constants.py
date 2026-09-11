#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EtherCAT Protocol Constants

State codes, error codes, and lookup tables per ETG specifications.

License: AGPL-3.0-or-later
"""

from typing import Dict
from ...utils.vendor_maps import ethercat_vendor_ids as vendor_ids

# Canonical CoE definitions live in coe.py — re-export for backward compat
from .coe import get_al_state_name as get_slave_state_name  # noqa: F401

# AL Status Codes (ETG.1000.6)
AL_STATUS_CODES: Dict[int, str] = {
    0x0000: "No error",
    0x0001: "Unspecified error",
    0x0011: "Invalid requested state change",
    0x0012: "Unknown requested state",
    0x0013: "Bootstrap not supported",
    0x0014: "No valid firmware",
    0x0015: "Invalid mailbox configuration",
    0x0016: "Invalid mailbox configuration (PREOP)",
    0x0017: "Invalid sync manager configuration",
    0x0018: "No valid inputs available",
    0x0019: "No valid outputs",
    0x001A: "Synchronization error",
    0x001B: "Sync manager watchdog",
    0x001C: "Invalid sync manager types",
    0x001D: "Invalid output configuration",
    0x001E: "Invalid input configuration",
    0x001F: "Invalid watchdog configuration",
    0x0020: "Slave needs cold start",
    0x0021: "Slave needs INIT",
    0x0022: "Slave needs PREOP",
    0x0023: "Slave needs SAFEOP",
    0x0024: "Invalid input mapping",
    0x0025: "Invalid output mapping",
    0x0026: "Invalid DC SYNC configuration",
    0x0027: "Invalid DC latch configuration",
    0x0028: "PLL error",
    0x0029: "DC sync IO error",
    0x002A: "DC sync timeout",
    0x002B: "DC invalid sync cycle time",
    0x002C: "DC sync0 cycle time",
    0x002D: "Invalid output FMMU configuration",
    0x002E: "Invalid input FMMU configuration",
    0x0030: "Invalid DC sync event config",
    0x0032: "Application controller available",
    0x0050: "MBX_EOE",
    0x0051: "MBX_COE",
    0x0052: "MBX_FOE",
    0x0053: "MBX_SOE",
    0x0054: "MBX_VOE",
    0x0055: "EEPROM no access",
    0x0056: "EEPROM access error",
}

# FMMU Types
FMMU_TYPES: Dict[int, str] = {
    0: "unused",
    1: "outputs",
    2: "inputs",
    3: "sm_status",
}

# SyncManager Types
SM_TYPES: Dict[int, str] = {
    0: "unused",
    1: "mbx_out",
    2: "mbx_in",
    3: "pdo_out",
    4: "pdo_in",
}

# CoE Data Types
COE_DATA_TYPES: Dict[int, str] = {
    0x01: "BOOL",
    0x02: "INT8",
    0x03: "INT16",
    0x04: "INT32",
    0x05: "UINT8",
    0x06: "UINT16",
    0x07: "UINT32",
    0x08: "REAL32",
    0x09: "VISIBLE_STRING",
    0x0A: "OCTET_STRING",
    0x11: "REAL64",
}

# ESI Category Types (ETG.2010)
ESI_CATEGORY_TYPES: Dict[int, str] = {
    10: "STRINGS",
    20: "DataTypes",
    30: "GENERAL",
    40: "FMMU",
    41: "SyncManager",
    50: "TxPDO",
    51: "RxPDO",
    60: "DC",
}

# Physical Port Types
PORT_TYPES: Dict[int, str] = {
    0: "not_impl",
    1: "not_config",
    2: "ebus",
    3: "mii",
}


# ESC Register Map (address → name, size in bytes)
# Matches registers from _dump_esc_registers() for ADS bridge access via ig=0xF300
ESC_REGISTER_MAP: Dict[int, tuple] = {
    0x0000: ("Type", 1),
    0x0001: ("Revision", 1),
    0x0002: ("Build", 2),
    0x0004: ("FMMU supported", 1),
    0x0005: ("SM supported", 1),
    0x0008: ("RAM size", 1),
    0x0010: ("Configured station address", 2),
    0x0012: ("Configured station alias", 2),
    0x0100: ("DL Control", 4),
    0x0110: ("DL Status", 2),
    0x0120: ("AL Control", 2),
    0x0130: ("AL Status", 2),
    0x0134: ("AL Status Code", 2),
    0x0140: ("PDI Control", 1),
    0x0200: ("ECAT Event Mask", 2),
    0x0220: ("ECAT Event Request", 2),
    # Error counters (Port 0-3, 2 bytes each)
    0x0300: ("Error Counter Port 0", 2),
    0x0302: ("Error Counter Port 1", 2),
    0x0304: ("Error Counter Port 2", 2),
    0x0306: ("Error Counter Port 3", 2),
    # Watchdog (ET1100/ESC datasheet section II watchdog block)
    0x0400: ("Watchdog Divider", 2),
    0x0410: ("Watchdog Time PDI", 2),
    0x0420: ("Watchdog Time Process Data", 2),
    0x0440: ("Watchdog Status Process Data", 1),
    0x0442: ("Watchdog Counter Process Data", 1),
    # FMMU 0-3 (16 bytes each)
    0x0600: ("FMMU0", 16),
    0x0610: ("FMMU1", 16),
    0x0620: ("FMMU2", 16),
    0x0630: ("FMMU3", 16),
    # SyncManager 0-3 (8 bytes each)
    0x0800: ("SM0", 8),
    0x0808: ("SM1", 8),
    0x0810: ("SM2", 8),
    0x0818: ("SM3", 8),
    # Distributed Clocks
    0x0980: ("DC Cycle Unit Control", 1),
    0x0981: ("DC Activation", 1),
    0x0990: ("DC System Time", 8),
    0x09A0: ("DC System Offset", 8),
    0x09B0: ("DC Transmission Delay", 4),
}


def lookup_vendor(vendor_id: int) -> str:
    """Look up vendor name by ID."""
    return vendor_ids.get(vendor_id, f"Unknown (0x{vendor_id:08X})")


def get_al_status_error(al_status_code: int) -> str:
    """Decode AL Status Code (register 0x0134) to human-readable error."""
    return AL_STATUS_CODES.get(al_status_code, f"Unknown error (0x{al_status_code:04X})")
