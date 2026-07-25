#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Siemens S7 Protocol Module

This module provides scanning and enumeration capabilities for Siemens S7 PLCs
using the Snap7 library. It supports S7-300, S7-400, S7-1200, and S7-1500 series.

Architecture:
- scanner.py: Main Snap7Scanner class and protocol implementation
- cli_runner.py: NXC-style auto-executing s7 class
- constants.py: Protocol constants (S7MemoryArea)
- models.py: Data models (S7CPUInfo, S7FirmwareVersion)
- device_lookup.py: Device name lookup tables
- szl_parser.py: SZL binary data parser
"""

# Core scanner and NXC-style connection
from .scanner import Snap7Scanner, protocol_options, metadata, run
from .cli_runner import s7, snap7

# Data models and constants
from .constants import S7MemoryArea
from .models import S7CPUInfo, S7FirmwareVersion
from .device_lookup import SIEMENS_DEVICES, lookup_device_name
from .szl_parser import SZLParser

__all__ = [
    # Scanner and protocol
    "Snap7Scanner",
    "protocol_options",
    "metadata",
    "run",
    # NXC-style connection
    "s7",
    "snap7",
    # Constants and models
    "S7MemoryArea",
    "S7CPUInfo",
    "S7FirmwareVersion",
    # Device lookup
    "SIEMENS_DEVICES",
    "lookup_device_name",
    # Parser
    "SZLParser",
]
