#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servo-over-EtherCAT (SoE) Shared Data & Helpers

Pure data module — no transport dependencies (no pysoem, no pyads).
Used by both the EtherCAT (pysoem) and ADS (pyads) scanners.

License: AGPL-3.0-or-later
"""

from typing import Dict

# ---------------------------------------------------------------------------
# SoE Element IDs — SERCOS III / ETG.1000
# ---------------------------------------------------------------------------

SOE_ELEMENTS: Dict[int, str] = {
    1: "DataStatus",
    2: "Name",
    3: "Attribute",
    4: "Unit",
    5: "Min",
    6: "Max",
    7: "Value",
    8: "Default",
}

# ---------------------------------------------------------------------------
# Standard SERCOS IDNs (Identification Numbers)
# ---------------------------------------------------------------------------

SOE_STANDARD_IDNS: Dict[int, str] = {
    1: "NC cycle time",
    2: "Communication cycle time",
    15: "Telegram type",
    17: "Application number",
    24: "Manufacturer version",
    25: "Manufacturer serial",
    32: "Position cmd",
    40: "Velocity cmd",
    47: "Position feedback 1",
    51: "Position feedback 2",
    84: "Torque feedback",
    134: "Master control word",
    135: "Drive status word",
    142: "CU cycle time",
    145: "IDN list of all SoE IDNs",
}


def encode_soe_offset(idn: int, element: int = 7, drive: int = 0) -> int:
    """Encode SoE offset for ADS ig=0xF420/0xF421.

    Per Beckhoff/SOEM spec, confirmed by Wireshark ADSIOFFS_ECAT_SOE_* constants:
      DATASTATE=0x00010000, NAME=0x00020000, VALUE=0x00400000, drive_mask=0x07000000
    Offset: LOWORD=IDN, byte2=element_bitmask, byte3=drive.
    Element IDs 1-8 map to bitmask bits 0-7 (e.g., 7=Value -> 0x40, 8=Default -> 0x80).
    """
    element_bitmask = 1 << (element - 1)  # element 7 (Value) → 0x40
    return (idn & 0xFFFF) | (element_bitmask << 16) | ((drive & 0xFF) << 24)
