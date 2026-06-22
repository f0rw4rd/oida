"""
Modbus Protocol Module

This module provides comprehensive Modbus scanning capabilities including:
- MEI Device Identification (FC 43/14)
- Diagnostics (FC 8)
- Communication Events (FC 11/12)
- File Records (FC 20/21)
- FIFO Queue (FC 24)
- Multiple transport layers (TCP, TLS, UDP, RTU-over-TCP, Serial)
- Data decoding (float32, int32, strings, etc.)
- Continuous monitoring mode

Easy CLI examples:
    oida modbus 192.168.1.100 -i                # Device identification
    oida modbus 192.168.1.100 -r 0-100 -d f32   # Decode as float32
    oida modbus 192.168.1.100 --diag            # Run diagnostics
    oida modbus 192.168.1.100 --tls             # Use TLS
    oida modbus 192.168.1.100 --monitor         # Monitor mode
"""

# Import from decoder module
from .decoder import (
    ModbusDecoder,
    DataType,
    TYPE_ALIASES,
    REGISTERS_PER_TYPE,
)

# Import from scanner module
from .scanner import (
    ModbusScanner,
    protocol_options,
    metadata,
    run,
)

# Import constants (previously re-exported via scanner)
from .constants import (
    ModbusFunctionCode,
    ModbusExceptionCode,
    MEIType,
    MEIReadDeviceIdCode,
    MEIObjectId,
    MEI_OBJECT_NAMES,
    DiagnosticSubfunction,
    DIAGNOSTIC_SUBFUNCTIONS,
    RegisterType,
    FUNCTION_CODES,
    EXCEPTION_CODES,
    DISCOVERY_FUNCTION_CODES,
)

# Import NXC-style class
from .nxc_connection import modbus

__all__ = [
    # Decoder exports
    "ModbusDecoder",
    "DataType",
    "TYPE_ALIASES",
    "REGISTERS_PER_TYPE",
    # Scanner exports
    "ModbusScanner",
    "ModbusFunctionCode",
    "ModbusExceptionCode",
    "MEIType",
    "MEIReadDeviceIdCode",
    "MEIObjectId",
    "MEI_OBJECT_NAMES",
    "DiagnosticSubfunction",
    "DIAGNOSTIC_SUBFUNCTIONS",
    "RegisterType",
    "FUNCTION_CODES",
    "EXCEPTION_CODES",
    "DISCOVERY_FUNCTION_CODES",
    "protocol_options",
    "metadata",
    "run",
    "modbus",
]
