"""Modbus Protocol Fuzzers

This module provides fuzzers for Modbus TCP and RTU protocols.
"""

from .tcp import ModbusFuzzer
from .rtu import ModbusRTUFuzzer

# Re-export constants for backward compatibility
from .constants import (
    ModbusFunctionCodes,
    ModbusDiagnosticCodes,
    ModbusMEITypes,
    ModbusDeviceIDObjects,
    ICS_ADDRESS_BOUNDARIES,
)

__all__ = [
    "ModbusFuzzer",
    "ModbusRTUFuzzer",
    # Constants (for backward compatibility)
    "ModbusFunctionCodes",
    "ModbusDiagnosticCodes",
    "ModbusMEITypes",
    "ModbusDeviceIDObjects",
    "ICS_ADDRESS_BOUNDARIES",
]
