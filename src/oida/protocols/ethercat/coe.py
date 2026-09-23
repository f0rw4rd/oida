#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CANopen-over-EtherCAT (CoE) Shared Data & Helpers

Pure data module — no transport dependencies (no pysoem, no pyads).
Used by both the EtherCAT (pysoem) and ADS (pyads) scanners.

License: AGPL-3.0-or-later
"""

from typing import Dict, List, Tuple

from oida.protocols.can.constants import CANOPEN_PDO_ENTRIES

# ---------------------------------------------------------------------------
# AL (Application Layer) States  — ETG.1000
# ---------------------------------------------------------------------------

AL_STATES: Dict[int, str] = {
    0x00: "NONE",
    0x01: "INIT",
    0x02: "PRE-OP",
    0x03: "BOOTSTRAP",
    0x04: "SAFE-OP",
    0x08: "OP",
}


def get_al_state_name(state_code: int) -> str:
    """Parse AL state with error flag (bit 4).

    Returns e.g. ``"SAFE-OP+ERROR"`` when the error bit is set.

    pysoem state constants:
    - NONE_STATE = 0, INIT_STATE = 1, PREOP_STATE = 2
    - SAFEOP_STATE = 4, OP_STATE = 8, STATE_ERROR = 16
    """
    error_flag = state_code & 0x10
    base_state = state_code & 0x0F
    state_name = AL_STATES.get(base_state, f"Unknown({base_state})")
    if error_flag:
        state_name += "+ERROR"
    return state_name


# ---------------------------------------------------------------------------
# CoE Object Dictionary Names  — CiA DS-301 / ETG.1000
# ---------------------------------------------------------------------------

COE_OBJECT_NAMES: Dict[int, str] = {
    # ---- Communication Profile Area (0x1000-0x1FFF) — CiA DS-301 ----
    0x1000: "Device Type",
    0x1001: "Error Register",
    0x1002: "Manufacturer Status Register",
    0x1003: "Pre-defined Error Field",
    0x1005: "COB-ID SYNC",
    0x1006: "Communication Cycle Period",
    0x1007: "Synchronous Window Length",
    0x1008: "Device Name",
    0x1009: "Hardware Version",
    0x100A: "Software Version",
    0x100B: "Guard Identifier",
    0x100C: "Guard Time",
    0x100D: "Life Time Factor",
    0x1010: "Store Parameters",
    0x1011: "Restore Default Parameters",
    0x1012: "COB-ID TIME",
    0x1013: "High Resolution Timestamp",
    0x1014: "COB-ID EMCY",
    0x1015: "Inhibit Time EMCY",
    0x1016: "Consumer Heartbeat Time",
    0x1017: "Producer Heartbeat Time",
    0x1018: "Identity Object",
    0x1019: "Synchronous Counter Overflow",
    0x1020: "Verify Configuration",
    0x1023: "OS Command",
    0x1024: "OS Command Mode",
    0x1026: "OS Prompt",
    0x1027: "Module List",
    0x1028: "Emergency Consumer",
    0x1029: "Error Behavior",
    0x102A: "NMT Inhibit Time",
    # SDO Parameters (0x1200-0x13FF)
    0x1200: "SDO Server Parameter",
    0x1201: "SDO Server Parameter 2",
    0x1280: "SDO Client Parameter",
    0x1281: "SDO Client Parameter 2",
    # RPDO/TPDO (shared with CAN — CiA DS-301)
    **CANOPEN_PDO_ENTRIES,
    # Sync Manager (0x1C00-0x1C3F) — ETG.1000
    0x1C00: "SM Communication Type",
    0x1C10: "SM0 PDO Assignment",
    0x1C11: "SM1 PDO Assignment",
    0x1C12: "SM2 PDO Assignment (RxPDO)",
    0x1C13: "SM3 PDO Assignment (TxPDO)",
    0x1C32: "SM2 Synchronization",
    0x1C33: "SM3 Synchronization",
    # ---- Standardized Device Profile (0x6000-0x9FFF) — CiA 4xx ----
    0x6000: "Digital Inputs",
    0x6010: "Analog Inputs",
    0x6020: "Analog Input Status",
    0x6030: "Analog Input Parameters",
    0x7000: "Digital Outputs",
    0x7010: "Analog Outputs",
    0x7020: "Analog Output Status",
    0x8000: "Configuration",
    # ---- System / Diagnosis (0xF000-0xFFFF) — ETG.1000 / ETG.5000 ----
    0xF000: "Modular Device Profile",
    0xF010: "Module Profile List",
    0xF020: "Detected Module List",
    0xF030: "Error Settings",
    0xF050: "Device Identification Value",
    0xF100: "Diagnosis History",
    0xF120: "Diagnosis Object",
}


def get_coe_object_name(index: int, subindex: int = 0) -> str:
    """Get human-readable name for a CoE object index/subindex.

    Handles exact matches, Identity subindex names, PDO/SDO ranges,
    device-profile ranges, manufacturer-specific ranges, and system objects.
    """
    # Exact match
    if index in COE_OBJECT_NAMES:
        name = COE_OBJECT_NAMES[index]
        if subindex > 0:
            if index == 0x1018:  # Identity Object
                sub_names = {1: "Vendor ID", 2: "Product Code", 3: "Revision", 4: "Serial"}
                return sub_names.get(subindex, f"{name}[{subindex}]")
            return f"{name}[{subindex}]"
        return name

    # --- Communication Profile Area (0x1000-0x1FFF) ---

    # SDO server/client parameters
    if 0x1200 <= index <= 0x127F:
        return f"SDO Server Param {index - 0x1200}"
    if 0x1280 <= index <= 0x12FF:
        return f"SDO Client Param {index - 0x1280}"

    # RPDO communication parameters
    if 0x1400 <= index <= 0x15FF:
        pdo_num = index - 0x1400
        suffix = f"[{subindex}]" if subindex > 0 else ""
        return f"RPDO{pdo_num} Comm{suffix}"

    # RxPDO mapping (0x1600-0x17FF)
    if 0x1600 <= index <= 0x17FF:
        pdo_num = index - 0x1600
        if subindex == 0:
            return f"RxPDO{pdo_num} Mapping"
        return f"RxPDO{pdo_num}[{subindex}]"

    # TPDO communication parameters
    if 0x1800 <= index <= 0x19FF:
        pdo_num = index - 0x1800
        suffix = f"[{subindex}]" if subindex > 0 else ""
        return f"TPDO{pdo_num} Comm{suffix}"

    # TxPDO mapping (0x1A00-0x1BFF)
    if 0x1A00 <= index <= 0x1BFF:
        pdo_num = index - 0x1A00
        if subindex == 0:
            return f"TxPDO{pdo_num} Mapping"
        return f"TxPDO{pdo_num}[{subindex}]"

    # Sync Manager (0x1C00-0x1C3F)
    if 0x1C00 <= index <= 0x1C3F:
        return f"SM 0x{index:04X}:{subindex}"

    # FSoE parameter set mapping (0x1E00-0x1EFF) — ETG.5100
    if 0x1E00 <= index <= 0x1EFF:
        return f"FSoE Param Set {index - 0x1E00}"

    # --- Manufacturer Specific (0x2000-0x5FFF) ---
    if 0x2000 <= index <= 0x5FFF:
        return f"Vendor 0x{index:04X}:{subindex}"

    # --- Standardized Device Profile (0x6000-0x9FFF) — CiA 4xx ---
    if 0x6000 <= index <= 0x6FFF:
        return f"Input 0x{index:04X}:{subindex}"
    if 0x7000 <= index <= 0x7FFF:
        return f"Output 0x{index:04X}:{subindex}"
    if 0x8000 <= index <= 0x8FFF:
        return f"Config 0x{index:04X}:{subindex}"
    if 0x9000 <= index <= 0x9FFF:
        return f"Info 0x{index:04X}:{subindex}"

    # --- Interface Profile (0xA000-0xBFFF) ---
    if 0xA000 <= index <= 0xBFFF:
        return f"Interface 0x{index:04X}:{subindex}"

    # --- System / Diagnosis (0xF000-0xFFFF) ---
    if 0xF000 <= index <= 0xFFFF:
        return f"System 0x{index:04X}:{subindex}"

    return f"Object 0x{index:04X}:{subindex}"


# ---------------------------------------------------------------------------
# Common SDO Objects — standard slave identification reads
# ---------------------------------------------------------------------------

COMMON_SDO_OBJECTS: List[Tuple[int, int, str]] = [
    (0x1000, 0, "Device Type"),
    (0x1001, 0, "Error Register"),
    (0x1008, 0, "Device Name"),
    (0x1009, 0, "Hardware Version"),
    (0x100A, 0, "Software Version"),
    (0x1018, 1, "Vendor ID"),
    (0x1018, 2, "Product Code"),
    (0x1018, 3, "Revision Number"),
    (0x1018, 4, "Serial Number"),
]


# ---------------------------------------------------------------------------
# ADS transport helpers — SDO offset encoding
# ---------------------------------------------------------------------------


def encode_sdo_offset(index: int, subindex: int, complete_access: int = 0) -> int:
    """Encode an SDO index/subindex into ADS offset format.

    TwinCAT ADS encodes CoE SDO addresses as::

        (index << 16) | (subindex << 8) | complete_access_flag

    However the Beckhoff implementation uses the *low byte* for subindex
    when complete_access is 0 (the common case)::

        (index << 16) | subindex

    We match what the working Beckhoff firmware expects.
    """
    if complete_access:
        return (index << 16) | (subindex << 8) | complete_access
    return (index << 16) | subindex


# Pre-encoded offsets keyed by legacy names for ADS backward compat
COE_SDO_OFFSETS: Dict[str, int] = {
    "DEVICE_NAME": encode_sdo_offset(0x1008, 0),  # 0x10080000
    "HW_VERSION": encode_sdo_offset(0x1009, 0),  # 0x10090000
    "SW_VERSION": encode_sdo_offset(0x100A, 0),  # 0x100A0000
    "VENDOR_ID": encode_sdo_offset(0x1018, 1),  # 0x10180001
    "PRODUCT_CODE": encode_sdo_offset(0x1018, 2),  # 0x10180002
    "REVISION": encode_sdo_offset(0x1018, 3),  # 0x10180003
    "SERIAL": encode_sdo_offset(0x1018, 4),  # 0x10180004
}


# ---------------------------------------------------------------------------
# CoE Dictionary Scan Ranges
# ---------------------------------------------------------------------------


def coe_category_for(index: int) -> str:
    """Look up the COE_SCAN_RANGES category for a given index."""
    for start, end, label in COE_SCAN_RANGES:
        if start <= index < end:
            return label
    return "Custom"


def parse_coe_ranges(spec: str) -> List[Tuple[int, int, str, "list | None"]]:
    """Parse a ``--coe-range`` spec into a list of (start, end, label, subs) tuples.

    Accepts comma-separated entries:
      - A single index: ``0xFB00``
      - An index with subindex: ``0xFB00:1``
      - An index range: ``0x2000-0x3000``

    The 4th element *subs* is ``None`` (scan all subindices) or a list of
    specific subindex numbers.

    Labels are resolved from :data:`COE_SCAN_RANGES` when the range falls
    within a known area, otherwise ``"Custom"``.

    Raises :class:`ValueError` on malformed input.
    """
    ranges: list = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part and not part.startswith("-"):
            # Range: 0x2000-0x3000
            lo, hi = part.split("-", 1)
            start = int(lo, 0)
            end = int(hi, 0)
            if end <= start:
                raise ValueError(f"Invalid range {part}: end must be > start")
            label = coe_category_for(start)
            ranges.append((start, end, label, None))
        elif ":" in part:
            # Index:subindex — e.g. 0xFB00:1
            idx_str, sub_str = part.split(":", 1)
            idx = int(idx_str, 0)
            sub = int(sub_str, 0)
            label = coe_category_for(idx)
            # Merge with existing range for the same index
            merged = False
            for i, (s, e, lbl, subs) in enumerate(ranges):
                if s == idx and e == idx + 1 and subs is not None:
                    ranges[i] = (s, e, lbl, subs + [sub])
                    merged = True
                    break
            if not merged:
                ranges.append((idx, idx + 1, label, [sub]))
        else:
            # Single index: 0xF110
            idx = int(part, 0)
            label = coe_category_for(idx)
            ranges.append((idx, idx + 1, label, None))
    if not ranges:
        raise ValueError("Empty --coe-range specification")
    return ranges


COE_SCAN_RANGES: List[Tuple[int, int, str]] = [
    # Communication Profile Area (CiA DS-301 / ETG.1000)
    (0x1000, 0x1030, "Communication"),
    (0x1200, 0x1300, "SDO Parameters"),
    (0x1400, 0x1480, "RPDO Communication"),
    (0x1600, 0x1800, "RxPDO Mapping"),
    (0x1800, 0x1880, "TPDO Communication"),
    (0x1A00, 0x1C00, "TxPDO Mapping"),
    (0x1C00, 0x1C40, "Sync Manager"),
    (0x1E00, 0x1F00, "FSoE Parameters"),
    # Manufacturer Specific — sample first 0x80 of each 0x1000 block
    (0x2000, 0x2080, "Vendor Specific"),
    (0x3000, 0x3080, "Vendor Specific"),
    (0x4000, 0x4080, "Vendor Specific"),
    (0x5000, 0x5080, "Vendor Specific"),
    # Standardized Device Profile (CiA 4xx)
    (0x6000, 0x6100, "Inputs"),
    (0x7000, 0x7100, "Outputs"),
    (0x8000, 0x8100, "Configuration"),
    (0x9000, 0x9100, "Information"),
    (0xA000, 0xA100, "Interface Profile"),
    # System / Diagnosis (ETG.1000 / ETG.5000)
    (0xF000, 0xF060, "Modular Device Profile"),
    (0xF100, 0xF130, "Device Status"),
    (0xF200, 0xF210, "Device Control"),
    (0xF600, 0xF800, "Device I/O"),
    (0xF800, 0xF900, "Device Config"),
    (0xF900, 0xFA00, "Device Information"),
    (0xFB00, 0xFC00, "Device Command"),
]
