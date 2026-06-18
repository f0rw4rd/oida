"""
CAN bus protocol module.

Controller Area Network (CAN) scanner for automotive and industrial
security testing. Supports passive traffic sniffing, UDS/OBD-II
service discovery, CANopen node detection, and raw frame operations.

Dependency: python-can >= 4.0.0
    pip install python-can
"""

# Re-export the NXC-style connection class
from .nxc_connection import can

# Re-export constants and data structures used by tests and external code
from .constants import (
    CAN_BAUDRATES,
    CANOPEN_DEVICE_PROFILES,
    CANOPEN_NMT_STATES,
    CANDevice,
    CANMessage,
    CANopenNode,
    CANopenScanResult,
    CANTrafficStats,
    OBD2_SERVICES,
    OBD2_VEHICLE_INFO_PIDS,
    UDS_NEGATIVE_RESPONSE,
    UDS_NRC,
    UDS_POSITIVE_RESPONSE_OFFSET,
    UDSScanResult,
)

# Re-export the Layer 1 scanner
from .scanner import CANScanner

__all__ = [
    "CAN_BAUDRATES",
    "CANOPEN_DEVICE_PROFILES",
    "CANOPEN_NMT_STATES",
    "OBD2_SERVICES",
    "OBD2_VEHICLE_INFO_PIDS",
    "UDS_NEGATIVE_RESPONSE",
    "UDS_NRC",
    "UDS_POSITIVE_RESPONSE_OFFSET",
    "CANDevice",
    "CANMessage",
    "CANopenNode",
    "CANopenScanResult",
    "CANTrafficStats",
    "UDSScanResult",
    "CANScanner",
    "can",
]
