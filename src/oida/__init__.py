#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OIDA: OT/ICS Discovery & Assessment

A comprehensive framework for security testing of Industrial Control Systems (ICS),
OT networks, and SCADA protocols including Modbus, OPC UA, EtherCAT, IEC 104, KNX, and more.

This package provides both standalone utilities and network-focused modules
for penetration testing and security assessment of industrial networks.

Protocol scanners are loaded lazily to avoid importing heavy dependencies
(like c104 for IEC104) at package initialization time.
"""

import os

# Suppress c104 buffered mode warning before any protocol imports
os.environ.setdefault("PYTHONUNBUFFERED", "1")

__version__ = "0.9.9"
__author__ = "OIDA Team"
__email__ = "https://getoida.dev/contact"
__license__ = "AGPL-3.0-or-later"
__url__ = "https://github.com/f0rw4rd/oida"

# Export main classes and functions (base utilities - lightweight)
from .utils.base_scanner import BaseScanner, NetworkScanner, SerialScanner
from .utils.protocol_helpers import (
    ConnectionHelper,
    ProtocolParser,
    DataFormatter,
    SecurityAnalyzer,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__url__",
    # Base classes
    "BaseScanner",
    "NetworkScanner",
    "SerialScanner",
    # Utilities
    "ConnectionHelper",
    "ProtocolParser",
    "DataFormatter",
    "SecurityAnalyzer",
]
