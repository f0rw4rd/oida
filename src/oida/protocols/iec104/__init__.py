"""
IEC 60870-5-104 Protocol Module

Supports:
- IEC 104 (TCP): Type ID discovery via general interrogation
- IEC 101 (Serial): FT1.2 framing over RS-232/RS-485
- File transfer capability probing (Type IDs 120-127)
- Custom/extended type ID detection
- Listen mode for capturing spontaneous ASDUs
- Security analysis

Usage:
    # IEC 104 (TCP)
    oida iec104 192.168.1.100

    # IEC 101 (Serial)
    oida iec104 --iec101 /dev/ttyUSB0:9600:E:1
"""

# Constants and data types
from oida.protocols.iec104.constants import (
    FT12_START_FIXED,
    FT12_START_VARIABLE,
    FT12_END,
    FC_RESET_REMOTE_LINK,
    FC_RESET_USER_PROCESS,
    FC_USER_DATA_CONFIRMED,
    FC_USER_DATA_NO_REPLY,
    FC_REQUEST_ACCESS_DEMAND,
    FC_REQUEST_STATUS_LINK,
    FC_REQUEST_USER_DATA_CLASS1,
    FC_REQUEST_USER_DATA_CLASS2,
    DIR_MASTER,
    PRM_PRIMARY,
    FCB,
    FCV,
    IEC104_TYPE_IDS,
    IEC104_COT,
    CapturedASDU,
    ListenStats,
    INFO_ELEMENT_SIZES,
    protocol_options,
)

# Dependency helpers
from oida.protocols.iec104._deps import _c104, _serial, _get_c104, c104, PYSERIAL_AVAILABLE

# Scanner
from oida.protocols.iec104.scanner import IEC104Scanner

# NXC-style class
from oida.protocols.iec104.cli_runner import iec104

__all__ = [
    # Constants
    "FT12_START_FIXED",
    "FT12_START_VARIABLE",
    "FT12_END",
    "FC_RESET_REMOTE_LINK",
    "FC_RESET_USER_PROCESS",
    "FC_USER_DATA_CONFIRMED",
    "FC_USER_DATA_NO_REPLY",
    "FC_REQUEST_ACCESS_DEMAND",
    "FC_REQUEST_STATUS_LINK",
    "FC_REQUEST_USER_DATA_CLASS1",
    "FC_REQUEST_USER_DATA_CLASS2",
    "DIR_MASTER",
    "PRM_PRIMARY",
    "FCB",
    "FCV",
    "IEC104_TYPE_IDS",
    "IEC104_COT",
    "CapturedASDU",
    "ListenStats",
    "INFO_ELEMENT_SIZES",
    "protocol_options",
    # Dependencies
    "_c104",
    "_serial",
    "_get_c104",
    "c104",
    "PYSERIAL_AVAILABLE",
    # Scanner
    "IEC104Scanner",
    # NXC
    "iec104",
]
