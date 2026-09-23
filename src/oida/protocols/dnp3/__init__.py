#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNP3 Protocol Scanner

NXC-style callable class for DNP3 SCADA protocol scanning.
Uses yadnp3 (opendnp3 C++ library) as the sole backend.

Supports:
- Device discovery and connection testing
- Integrity polling (Class 0/1/2/3)
- Data point enumeration (binary, analog, counters)
- Device attribute reads (Group 0)
- Binary output control (SBO, Direct Operate)
- Analog output control (Group 41 - int16/int32/float/double)
- File transfer operations (Group 70 - directory, read, write, info)
- Point enumeration from device attributes
- Unsolicited response enable/disable
- Dead band configuration (Group 34)
- Time synchronization
- Cold/warm restart commands
- TLS encrypted channel support
- Serial and UDP transport
- Secure Authentication v5 (SA5)
- Channel retry tuning
- Security statistics (Group 121)
"""

from oida.protocols.dnp3.scanner import DNP3Scanner, protocol_options
from oida.protocols.dnp3.constants import KNOWN_ATTRIBUTES
from oida.protocols.dnp3.cli_runner import dnp3

__all__ = ["dnp3", "DNP3Scanner", "KNOWN_ATTRIBUTES", "protocol_options"]
