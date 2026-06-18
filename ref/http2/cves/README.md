# HTTP/2 - Notable CVEs

CVEs related to parsing and processing vulnerabilities in HTTP/2 implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2023-44487 | Multiple (nginx, Apache, Go, Node.js, etc.) | Rapid Reset: stream creation/RST_STREAM loop causing CPU exhaustion | DoS | 7.5 | [HTTP/2 Rapid Reset](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/) |
| CVE-2024-27316 | Apache httpd | CONTINUATION flood: memory exhaustion from endless CONTINUATION frames | DoS | 7.5 | [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html) |
| CVE-2024-28182 | nghttp2 | CONTINUATION flood DoS | DoS | 5.3 | [nghttp2 Advisory](https://github.com/nghttp2/nghttp2/security) |
| CVE-2024-24549 | Apache Tomcat | CONTINUATION flood causing OutOfMemoryError | DoS | 7.5 | [Apache Advisory](https://tomcat.apache.org/security-11.html) |
| CVE-2019-9511 | Multiple HTTP/2 implementations | Data Dribble: slow reads on large responses | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9512 | Multiple HTTP/2 implementations | Ping Flood: excessive PING frames | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9513 | Multiple HTTP/2 implementations | Resource Loop: stream priority manipulation | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9514 | Multiple HTTP/2 implementations | Reset Flood: large number of RST_STREAM frames | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9515 | Multiple HTTP/2 implementations | Settings Flood: excessive SETTINGS frames | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9516 | Multiple HTTP/2 implementations | 0-Length Headers Leak: empty header values causing memory leak | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9517 | Multiple HTTP/2 implementations | Internal Data Buffering: not reading WINDOW_UPDATE | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2019-9518 | Multiple HTTP/2 implementations | Empty Frame Flooding: frames with empty payloads | DoS | 7.5 | [Netflix Research](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md) |
| CVE-2020-11080 | nghttp2 | Overly large SETTINGS frame causing integer overflow | DoS | 7.5 | [nghttp2 Advisory](https://github.com/nghttp2/nghttp2/security) |
| CVE-2023-45288 | Go net/http | CONTINUATION flood via crafted HTTP/2 request | DoS | 7.5 | [Go Advisory](https://pkg.go.dev/vuln/GO-2024-2687) |

## Exploits and PoCs

### CVE-2023-44487 (Rapid Reset)
- **Product**: Multiple (nginx, Apache, Go, Node.js, Envoy, and many others)
- **Type**: DoS (CPU Exhaustion)
- **CVSS**: 7.5
- **Server-side**: Yes -- server allocates resources for each new stream, but RST_STREAM cancellation does not free resources quickly enough, leading to CPU exhaustion from rapid stream creation/cancellation loops
- **Root cause**: HTTP/2 implementations allocate per-stream state on HEADERS but do not rate-limit stream creation; RST_STREAM immediately after HEADERS creates an asymmetric cost (cheap for attacker, expensive for server)
- **PoC**: [github.com/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC](https://github.com/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC), [github.com/nxenon/cve-2023-44487](https://github.com/nxenon/cve-2023-44487), [github.com/studiogangster/CVE-2023-44487](https://github.com/studiogangster/CVE-2023-44487)
- **Metasploit**: N/A
- **Advisory**: [Cloudflare Technical Breakdown](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)
- **Analysis**: A fuzzer that rapidly opens streams (HEADERS) and immediately sends RST_STREAM in a tight loop would trigger this on any unpatched HTTP/2 server.

### CVE-2024-27316 (CONTINUATION Flood - Apache)
- **Product**: Apache httpd 2.4.17 through 2.4.58
- **Type**: DoS (Memory Exhaustion)
- **CVSS**: 7.5
- **Server-side**: Yes -- incoming headers exceeding the limit are temporarily buffered in nghttp2 to generate an HTTP 413 response; if client keeps sending CONTINUATION frames, memory is exhausted
- **Root cause**: Server must parse all CONTINUATION frames to maintain HPACK dynamic table state, even after deciding to reject the request. No limit on CONTINUATION frame count.
- **PoC**: [github.com/aeyesec/CVE-2024-27316_poc](https://github.com/aeyesec/CVE-2024-27316_poc)
- **Metasploit**: N/A
- **Advisory**: [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html)
- **Analysis**: Sending HEADERS without END_HEADERS flag followed by endless CONTINUATION frames causes OOM. A fuzzer omitting END_HEADERS and sending CONTINUATION in a loop would find this.

### CVE-2024-28182 (CONTINUATION Flood - nghttp2)
- **Product**: nghttp2 (used by many HTTP/2 implementations)
- **Type**: DoS
- **CVSS**: 5.3
- **Server-side**: Yes -- nghttp2 library does not limit CONTINUATION frames, allowing memory and CPU exhaustion
- **Root cause**: No per-stream or per-connection limit on the number of CONTINUATION frames that must be processed to maintain HPACK state
- **PoC**: [github.com/Vos68/HTTP2-Continuation-Flood-PoC](https://github.com/Vos68/HTTP2-Continuation-Flood-PoC)
- **Metasploit**: N/A
- **Advisory**: [nghttp2 Security](https://github.com/nghttp2/nghttp2/security)
- **Analysis**: Same pattern as CVE-2024-27316 but at the library level; any application using nghttp2 is affected.

### CVE-2024-30255 (CONTINUATION Flood - Envoy)
- **Product**: Envoy proxy before 1.29.3
- **Type**: DoS (CPU Exhaustion)
- **CVSS**: 5.3
- **Server-side**: Yes -- Envoy's HTTP/2 codec allows unlimited CONTINUATION frames even after exceeding header map limits, consuming ~1 CPU core per 300Mbit/s of attack traffic
- **Root cause**: No limit on CONTINUATION frame processing after header limits are exceeded; Huffman decoding of large header blocks is CPU-intensive
- **PoC**: [github.com/blackmagic2023/Envoy-CPU-Exhaustion-Vulnerability-PoC](https://github.com/blackmagic2023/Envoy-CPU-Exhaustion-Vulnerability-PoC)
- **Metasploit**: N/A
- **Advisory**: [Envoy Security Advisory](https://github.com/envoyproxy/envoy/security/advisories/GHSA-j654-3ccm-vfmm)
- **Analysis**: HPACK Huffman decoding is the expensive operation. A fuzzer sending CONTINUATION frames with Huffman-encoded header blocks would maximize CPU cost.

### CVE-2024-27983 (CONTINUATION Flood - Node.js)
- **Product**: Node.js HTTP/2 server
- **Type**: DoS
- **CVSS**: N/A
- **Server-side**: Yes -- CONTINUATION flood vulnerability in Node.js HTTP/2 server implementation
- **Root cause**: No rate limiting or count limiting on CONTINUATION frames in the Node.js HTTP/2 implementation
- **PoC**: [github.com/lirantal/CVE-2024-27983-nodejs-http2](https://github.com/lirantal/CVE-2024-27983-nodejs-http2)
- **Metasploit**: N/A
- **Advisory**: [Node.js Advisory](https://nodejs.org/en/blog/vulnerability)
- **Analysis**: Node.js HTTP/2 server with CONTINUATION flood demonstrates the vulnerability is pervasive across implementations.

### CVE-2023-45288 (CONTINUATION Flood - Go)
- **Product**: Go net/http (golang.org/x/net/http2)
- **Type**: DoS (CPU Exhaustion)
- **CVSS**: 7.5
- **Server-side**: Yes -- Go HTTP/2 server must parse all CONTINUATION frames to maintain HPACK state even after MaxHeaderBytes is exceeded; Huffman decoding burns CPU on headers that will be discarded
- **Root cause**: HPACK state is connection-level, so the server cannot stop parsing CONTINUATION frames even for rejected requests without breaking the connection's header compression state
- **PoC**: [github.com/hex0punk/cont-flood-poc](https://github.com/hex0punk/cont-flood-poc)
- **Metasploit**: N/A
- **Advisory**: [Go Advisory](https://pkg.go.dev/vuln/GO-2024-2687)
- **Analysis**: The fundamental issue is that HPACK requires processing all header data to keep the dynamic table synchronized. Any implementation maintaining HPACK state is vulnerable.

### CVE-2020-11080 (SETTINGS Overflow - nghttp2)
- **Product**: nghttp2
- **Type**: DoS (Integer Overflow)
- **CVSS**: 7.5
- **Server-side**: Yes -- overly large SETTINGS frame causes integer overflow in nghttp2
- **Root cause**: SETTINGS frame with many entries causes integer overflow when computing required processing
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [nghttp2 Security](https://github.com/nghttp2/nghttp2/security)
- **Analysis**: Fuzzing SETTINGS frames with extreme numbers of parameters and large values would trigger this overflow.

## Key Vulnerability Patterns for Fuzzing

1. **Frame Length Field**: 3-byte length exceeding SETTINGS_MAX_FRAME_SIZE or frame type constraints
2. **HPACK Encoding**: Integer overflow in prefix encoding, invalid Huffman sequences, dynamic table overflow
3. **Stream ID Manipulation**: Even IDs from client, stream 0 for stream-specific frames, ID reuse
4. **Rapid Reset**: Stream creation + immediate RST_STREAM at high rate
5. **CONTINUATION Flood**: Endless CONTINUATION frames without END_HEADERS flag
6. **SETTINGS Flood**: Rapid SETTINGS frames requiring ACK, extreme parameter values
7. **Flow Control Window**: WINDOW_UPDATE causing window > 2^31-1, DATA exceeding window
8. **PRIORITY Cycles**: Stream dependency creating cycles in priority tree
9. **Frame Interleaving**: Invalid frame types between HEADERS and CONTINUATION
10. **Connection Preface**: Malformed magic string, missing initial SETTINGS
