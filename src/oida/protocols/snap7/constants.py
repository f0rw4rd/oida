#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S7 Protocol Constants
"""


class S7MemoryArea:
    """S7 memory area constants"""

    PE = 0x81  # Process Inputs (I)
    PA = 0x82  # Process Outputs (Q)
    MK = 0x83  # Flags/Markers (M)
    DB = 0x84  # Data Blocks (DB)
    CT = 0x1C  # Counters (C)
    TM = 0x1D  # Timers (T)
