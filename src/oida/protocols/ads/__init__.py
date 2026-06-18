"""
Beckhoff ADS (Automation Device Specification) Protocol Scanner

This module provides scanning and interaction capabilities for Beckhoff
TwinCAT/ADS devices including symbol discovery, memory access, and state control.

Module structure:
    helpers.py        -- Shared low-level ADS primitives (read/write, error helpers)
    ethercat_ops.py   -- EtherCAT-over-ADS bridge operations mixin
    scanner.py        -- ADSScanner class (Layer 1, traditional BaseScanner)
    nxc_connection.py -- ads NXC class (Layer 2, auto-execute on instantiation)
    constants.py      -- ADS protocol constants
    proto_args.py     -- CLI argument definitions
"""

# Re-export the NXC-style connection class
from .nxc_connection import ads

# Re-export the scanner class and metadata
from .scanner import ADSScanner, metadata, run, protocol_options

# Re-export constants used by tests and external code
from .constants import ADS_STATE_MAP, ADS_PORT_MAP

# Re-export helpers used by tests and mock patches
from .helpers import _get_memory_areas, _get_pyads, COE_SDO_OFFSET, _pyads

__all__ = [
    "ads",
    "ADSScanner",
    "metadata",
    "run",
    "protocol_options",
    "ADS_STATE_MAP",
    "ADS_PORT_MAP",
    "_get_memory_areas",
    "_get_pyads",
    "_pyads",
    "COE_SDO_OFFSET",
]
