#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Functional Safety over EtherCAT (FSoE) Shared Data

Pure data module - no transport dependencies (no pysoem, no pyads).
Derived from pcap analysis and ETG.5100 specification.

License: AGPL-3.0-or-later
"""

from typing import List, Tuple

# ---------------------------------------------------------------------------
# FSoE CoE Objects - 0xF1xx/0xF9xx range (ETG.5100)
# Each entry: (index, subindex, name, type, read_size)
# Supported dtypes: uint8, uint16, uint32, string, octets
# ---------------------------------------------------------------------------

FSOE_COE_OBJECTS: List[Tuple[int, int, str, str, int]] = [
    # 0xF100 - FSoE Module / Safety Project Status (TwinSAFE EL6900)
    (0xF100, 0, "FSoE Module (subindex count)", "uint8", 1),
    (0xF100, 1, "Safety Project State", "uint8", 1),
    (0xF100, 5, "FSoE Module Count", "uint8", 1),
    (0xF100, 8, "Login Active", "uint8", 1),
    (0xF100, 9, "Input Size Mismatch", "uint8", 1),
    (0xF100, 10, "Output Size Mismatch", "uint8", 1),
    (0xF100, 15, "TxPDO State", "uint8", 1),
    (0xF100, 16, "TxPDO Toggle", "uint8", 1),
    # 0xF102 - FSoE Channels
    (0xF102, 0, "FSoE Channels (subindex count)", "uint8", 1),
    (0xF102, 5, "FSoE Channel Status", "uint16", 2),
    # 0xF10F - FSoE Config
    (0xF10F, 0, "FSoE Config (subindex count)", "uint8", 1),
    (0xF10F, 2, "FSoE Config Value", "uint16", 2),
    # 0xF111 - FSoE Module Info
    (0xF111, 0, "FSoE Module Info (subindex count)", "uint8", 1),
    (0xF111, 1, "Module Name", "string", 32),
    (0xF111, 7, "Serial Number", "uint32", 4),
    (0xF111, 8, "Order Number", "uint32", 4),
    # 0xF113 - FSoE Device Info
    (0xF113, 0, "FSoE Device Info (subindex count)", "uint8", 1),
    (0xF113, 11, "Device Firmware Version", "string", 32),
    (0xF113, 13, "Device Firmware Checksum", "string", 64),
    # 0xF114 - FSoE Safety Identification
    (0xF114, 0, "FSoE Safety ID (subindex count)", "uint8", 1),
    (0xF114, 2, "Firmware Version", "string", 32),
    (0xF114, 5, "Firmware Checksum", "octets", 64),
    (0xF114, 7, "Safety Application Checksum", "octets", 64),
    (0xF114, 12, "SafeApp Write Counter", "uint32", 4),
    (0xF114, 14, "Safety Application Version", "string", 32),
    (0xF114, 15, "Safety App Checksum (ASCII)", "string", 64),
    # 0xF115 - FSoE Additional Safety Info
    (0xF115, 0, "FSoE Additional Info (subindex count)", "uint8", 1),
    (0xF115, 5, "Additional Firmware Checksum", "octets", 64),
    # 0xF980 - FSoE Connection
    (0xF980, 0, "FSoE Connection (subindex count)", "uint8", 1),
    (0xF980, 1, "FSoE Connection Count", "uint16", 2),
]

# ---------------------------------------------------------------------------
# FSoE Parameter Set objects - 0x1E00-0x1EFF (ETG.5100)
# Safety communication parameters between FSoE master and slave.
# Each 0x1Exx index is one parameter set; subindices vary by device.
# We probe a representative set of base indices with common subindices.
# ---------------------------------------------------------------------------

FSOE_PARAM_OBJECTS: List[Tuple[int, int, str, str, int]] = [
    # 0x1E00 - FSoE Parameter Set 0
    (0x1E00, 0, "FSoE Param Set 0 (subindex count)", "uint8", 1),
    (0x1E00, 1, "FSoE Watchdog Time", "uint16", 2),
    (0x1E00, 2, "FSoE Slave Address", "uint16", 2),
    (0x1E00, 3, "FSoE Connection ID", "uint16", 2),
    # 0x1E01 - FSoE Parameter Set 1
    (0x1E01, 0, "FSoE Param Set 1 (subindex count)", "uint8", 1),
    (0x1E01, 1, "FSoE Watchdog Time", "uint16", 2),
    (0x1E01, 2, "FSoE Slave Address", "uint16", 2),
    (0x1E01, 3, "FSoE Connection ID", "uint16", 2),
    # 0x1E02 - FSoE Parameter Set 2
    (0x1E02, 0, "FSoE Param Set 2 (subindex count)", "uint8", 1),
    (0x1E02, 1, "FSoE Watchdog Time", "uint16", 2),
    (0x1E02, 2, "FSoE Slave Address", "uint16", 2),
    (0x1E02, 3, "FSoE Connection ID", "uint16", 2),
    # 0x1E03 - FSoE Parameter Set 3
    (0x1E03, 0, "FSoE Param Set 3 (subindex count)", "uint8", 1),
    (0x1E03, 1, "FSoE Watchdog Time", "uint16", 2),
    (0x1E03, 2, "FSoE Slave Address", "uint16", 2),
    (0x1E03, 3, "FSoE Connection ID", "uint16", 2),
]
