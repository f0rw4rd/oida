# HTTP/2 - Reference Materials

## Protocol Overview

HTTP/2 (RFC 9113, formerly RFC 7540) is a binary protocol that multiplexes multiple streams over a single TCP connection. It replaces HTTP/1.1's text-based format with binary framing, adds header compression (HPACK), server push, and stream prioritization.

- **Transport**: TCP (typically over TLS, ALPN "h2"), also cleartext "h2c"
- **Connection Preface**: Client sends magic "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS frame
- **Frame Format**: Length (3 bytes) + Type (1) + Flags (1) + Stream ID (4) = 9-byte header
- **Frame Types**: DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION
- **Header Compression**: HPACK (RFC 7541) with static/dynamic table

## Wireshark Dissectors

- **HTTP/2**: [packet-http2.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-http2.c)
- Frame type dispatch
- HPACK header decompression
- Stream state tracking
- Flow control window tracking

### Key dissector details:
- 9-byte frame header parsing
- HPACK indexed header field decoding
- HPACK Huffman decoding
- Stream dependency tree tracking
- SETTINGS parameter validation
- WINDOW_UPDATE delta tracking

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **nghttp2** | C | HTTP/2 library | [github.com/nghttp2/nghttp2](https://github.com/nghttp2/nghttp2) |
| **h2** | Python | HTTP/2 protocol library (hyper) | [github.com/python-hyper/h2](https://github.com/python-hyper/h2) |
| **h2** | Rust | Tokio HTTP/2 implementation | [github.com/hyperium/h2](https://github.com/hyperium/h2) |
| **grpc** | Multi-language | gRPC uses HTTP/2 as transport | [github.com/grpc/grpc](https://github.com/grpc/grpc) |
| **golang.org/x/net/http2** | Go | Go HTTP/2 implementation | [pkg.go.dev/golang.org/x/net/http2](https://pkg.go.dev/golang.org/x/net/http2) |
| **Envoy** | C++ | Envoy proxy HTTP/2 codec | [github.com/envoyproxy/envoy](https://github.com/envoyproxy/envoy) |

## Common Parsing Vulnerabilities

### 1. Frame Length Field (3 bytes)
- Maximum frame size default 16384, configurable via SETTINGS_MAX_FRAME_SIZE
- Length exceeding SETTINGS_MAX_FRAME_SIZE should trigger FRAME_SIZE_ERROR
- Length=0 for frames requiring payload (WINDOW_UPDATE, PRIORITY)
- Length mismatched with frame type expectations

### 2. HPACK Header Compression
- Dynamic table size manipulation (SETTINGS_HEADER_TABLE_SIZE)
- Huffman decoding: invalid Huffman codes, excessive padding
- Indexed header field with index > table size
- Dynamic table eviction attacks (HPACK bomb)
- Integer encoding: variable-length prefix encoding overflow

### 3. Stream Management
- Stream ID 0 (connection-level) vs. stream-specific frames
- Odd stream IDs (client-initiated) vs. even (server-initiated/push)
- Stream state machine violations (HEADERS on closed stream, etc.)
- Maximum concurrent streams exceeded (SETTINGS_MAX_CONCURRENT_STREAMS)
- Rapid stream creation and RST_STREAM (Rapid Reset attack)

### 4. Flow Control
- WINDOW_UPDATE with delta = 0 (protocol error)
- Flow control window overflow (exceeding 2^31-1)
- DATA frames exceeding peer's flow control window
- Connection-level vs. stream-level flow control mismatches

### 5. CONTINUATION Frames
- HEADERS + CONTINUATION frame sequences
- CONTINUATION without preceding HEADERS
- Extremely long CONTINUATION chains (memory exhaustion)
- CONTINUATION from different stream than HEADERS

### 6. SETTINGS Frame
- Unknown setting identifiers (must be ignored per spec)
- SETTINGS_MAX_FRAME_SIZE outside valid range (16384-16777215)
- SETTINGS_INITIAL_WINDOW_SIZE causing flow control overflow
- SETTINGS_ENABLE_PUSH with invalid value
- SETTINGS ACK with non-zero length

### 7. PUSH_PROMISE
- PUSH_PROMISE on stream ID 0
- PUSH_PROMISE when SETTINGS_ENABLE_PUSH is 0
- Promised stream ID conflicts (even IDs only)
- PUSH_PROMISE header block exceeding limits

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **HTTP/2 Rapid Reset PoC** | Python | Multiple PoC implementations for CVE-2023-44487 using H2SpaceX library | [github.com/nxenon/cve-2023-44487](https://github.com/nxenon/cve-2023-44487) |
| **CONTINUATION Flood PoC** | Python/Go | PoC for HTTP/2 CONTINUATION flood (CVE-2024-27316 and related) | [github.com/Vos68/HTTP2-Continuation-Flood-PoC](https://github.com/Vos68/HTTP2-Continuation-Flood-PoC) |
| **cont-flood-poc** | Go | PoC for CVE-2023-45288 CONTINUATION flood against Go servers | [github.com/hex0punk/cont-flood-poc](https://github.com/hex0punk/cont-flood-poc) |
| **Envoy CPU Exhaustion PoC** | Python | PoC for CVE-2024-30255 CONTINUATION flood CPU exhaustion in Envoy | [github.com/blackmagic2023/Envoy-CPU-Exhaustion-Vulnerability-PoC](https://github.com/blackmagic2023/Envoy-CPU-Exhaustion-Vulnerability-PoC) |
| **http2smugl** | Go | HTTP/2 request smuggling detection via H2->H1 conversion | [github.com/neex/http2smugl](https://github.com/neex/http2smugl) |
| **h2cSmuggler** | Python | HTTP Request Smuggling via h2c upgrade mechanism | [github.com/BishopFox/h2csmuggler](https://github.com/BishopFox/h2csmuggler) |

## Attack Surface Notes

### Server-Side Parsing Targets
- **CONTINUATION frames**: The most impactful HTTP/2 attack surface discovered in 2024. Servers must parse all CONTINUATION frames to maintain HPACK dynamic table state, even after deciding to reject the request. This fundamental protocol design flaw affected Apache (CVE-2024-27316), nghttp2 (CVE-2024-28182), Envoy (CVE-2024-30255), Go (CVE-2023-45288), Node.js (CVE-2024-27983), and Tomcat (CVE-2024-24549).
- **HPACK Huffman decoding**: CPU-intensive operation that attackers exploit cheaply; sending large Huffman-encoded header blocks in CONTINUATION frames maximizes server-side CPU cost.
- **Stream creation/cancellation**: Rapid Reset (CVE-2023-44487) exploits asymmetric cost of stream allocation vs. RST_STREAM.
- **SETTINGS frames**: Integer overflow from oversized SETTINGS in nghttp2 (CVE-2020-11080); SETTINGS flood (CVE-2019-9515) from excessive SETTINGS requiring ACK.
- **Flow control**: WINDOW_UPDATE with delta causing window > 2^31-1; DATA frames exceeding window; Internal Data Buffering (CVE-2019-9517) from not reading WINDOW_UPDATE.

### High-Value Fuzzing Strategies
- **CONTINUATION frame flooding**: Omit END_HEADERS flag and send unlimited CONTINUATION frames -- this found vulnerabilities in every major HTTP/2 implementation
- **Frame interleaving**: Invalid frame types between HEADERS and CONTINUATION sequences
- **HPACK state manipulation**: Dynamic table size changes, indexed fields beyond table bounds, invalid Huffman sequences
- **Rapid stream lifecycle**: HEADERS+RST_STREAM in tight loops with varying stream IDs
- **h2c upgrade smuggling**: HTTP/1.1 to HTTP/2 cleartext upgrade bypassing proxy access controls

## Notable Research

- **"HTTP/2: The Sequel is Always Worse" (James Kettle, PortSwigger)** - HTTP/2 desync/smuggling
- **Rapid Reset Attack (CVE-2023-44487)** - Stream creation/cancellation DoS
- **"CONTINUATION Flood" (Bartek Nowotarski, 2024)** - Memory/CPU exhaustion via CONTINUATION frames, affected virtually every HTTP/2 implementation
- **Netflix HTTP/2 DoS research (2019)** - Eight distinct server-side DoS vectors (CVE-2019-9511 through CVE-2019-9518)
- **"HTTP/2 CONTINUATION Flood" (CERT/CC VU#421644)** - Coordination advisory for multi-vendor CONTINUATION flood
