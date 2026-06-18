# HTTP/1.x - Reference Materials

## Protocol Overview

HTTP/1.0 (RFC 1945) and HTTP/1.1 (RFC 9110/9112) are the foundational web protocols. HTTP/1.1 adds persistent connections, chunked transfer encoding, and host-based virtual hosting. Widely used in ICS for web-based HMIs, REST APIs, and device management interfaces.

- **Transport**: TCP port 80 (HTTP), TCP port 443 (HTTPS/TLS)
- **Message Format**: Request-line/Status-line + Headers + CRLF + Body
- **Methods**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT
- **Key Headers**: Content-Length, Transfer-Encoding, Host, Content-Type, Connection

## Wireshark Dissectors

- **HTTP**: [packet-http.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-http.c)
- **HTTP2**: [packet-http2.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-http2.c)
- Request/response parsing, header field extraction, content type dispatch

### Key dissector details:
- Request-line: method + URI + HTTP-version
- Status-line: HTTP-version + status-code + reason-phrase
- Header field parsing (name: value pairs, line folding)
- Chunked transfer encoding reassembly
- Content-Length body extraction
- Multipart body parsing

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **http-parser/llhttp** | C | Node.js HTTP parser (used by many projects) | [github.com/nicholasgasior/llhttp](https://github.com/nicholasgasior/llhttp) |
| **h11** | Python | HTTP/1.1 protocol library | [github.com/python-hyper/h11](https://github.com/python-hyper/h11) |
| **httptools** | Python/C | Python bindings for llhttp | [github.com/MagicStack/httptools](https://github.com/MagicStack/httptools) |
| **nginx** | C | HTTP server/reverse proxy | [github.com/nginx/nginx](https://github.com/nginx/nginx) |
| **Apache httpd** | C | Apache HTTP Server | [github.com/apache/httpd](https://github.com/apache/httpd) |
| **Scapy** | Python | HTTP layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |

## Common Parsing Vulnerabilities

### 1. Request Smuggling / Desync
- Content-Length vs. Transfer-Encoding conflicts (CL.TE, TE.CL, TE.TE)
- Ambiguous Content-Length (duplicate headers, whitespace variations)
- Chunked encoding edge cases (chunk extensions, trailer headers)
- HTTP/1.0 vs HTTP/1.1 interpretation differences between proxy and server

### 2. Header Parsing
- Line folding (obs-fold): continuation lines starting with space/tab
- Header injection via CRLF in header values
- Very long header lines/values exceeding buffer sizes
- Null bytes in header names/values
- Multiple Host headers

### 3. Chunked Transfer Encoding
- Chunk size in hex: very large values, leading zeros, negative (signed interpretation)
- Chunk extensions (semicolon-separated key=value after size)
- Last-chunk (size 0) without proper trailer/CRLF termination
- Chunk data longer or shorter than specified size

### 4. URI Parsing
- Path traversal (../, encoded variants %2e%2e/)
- Double encoding (%252e%252e)
- Extremely long URIs
- URI with fragments, query parameters with special characters
- Absolute-URI vs. origin-form conflicts

### 5. Content-Length Issues
- Negative Content-Length (signed integer interpretation)
- Content-Length larger than body
- Content-Length = 0 with body present
- Multiple Content-Length headers with different values

### 6. Method Handling
- Unknown/non-standard HTTP methods
- Method override headers (X-HTTP-Method-Override)
- TRACE method reflecting request body (XSS vector)

## Fuzzing Tools

| Tool | Language | Description | Link |
|------|----------|-------------|------|
| **SmuggleFuzz** | Go | Rapid HTTP downgrade smuggling scanner with 125 built-in smuggling gadgets (2024) | [github.com/Moopinger/smugglefuzz](https://github.com/Moopinger/smugglefuzz) |
| **T-Reqs** | Python | Grammar-based HTTP/1 fuzzer with mutation ability, from ACM CCS 2021 paper "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" | [github.com/bahruzjabiyev/t-reqs](https://github.com/bahruzjabiyev/t-reqs) |
| **Smuggler** | Python | HTTP Request Smuggling / Desync testing tool with multiple config profiles (default, doubles, exhaustive) | [github.com/defparam/smuggler](https://github.com/defparam/smuggler) |
| **h2cSmuggler** | Python | HTTP Request Smuggling over HTTP/2 cleartext (h2c) upgrade bypass | [github.com/BishopFox/h2csmuggler](https://github.com/BishopFox/h2csmuggler) |
| **http2smugl** | Go | Detects and exploits HTTP request smuggling via HTTP/2 to HTTP/1.1 conversion | [github.com/neex/http2smugl](https://github.com/neex/http2smugl) |
| **h2rs** | Rust | Detects request smuggling via HTTP/2 downgrades | [github.com/riramar/h2rs](https://github.com/riramar/h2rs) |

## Attack Surface Notes

### Server-Side Parsing Targets
- **CL/TE desync**: Content-Length vs Transfer-Encoding conflicts remain the most common smuggling vector -- Gunicorn (CVE-2024-6827), Apache (CVE-2023-25690, CVE-2022-22720) all affected
- **Chunked encoding edge cases**: Chunk extensions with lone LF cause desync in ASP.NET Kestrel (CVE-2025-55315, CVSS 9.9)
- **Obs-fold line continuations**: Obsolete line folding creates parsing discrepancies between proxies (CVE-2025-32094)
- **URI encoding**: Double encoding, newlines in URI path, PATH_INFO manipulation (CVE-2019-11043 for RCE)
- **Header injection**: CRLF in header values, null bytes, multiple Host headers

### High-Value Fuzzing Strategies
- **Differential fuzzing**: Send same request through proxy+backend, compare interpretations -- this is how most smuggling bugs are found
- **Chunked encoding mutations**: Invalid hex in chunk size, chunk extensions with various line terminators, incomplete last-chunk
- **Content-Length variants**: Negative values, duplicates, leading +/-, whitespace, signed vs unsigned parsing
- **h2c upgrade smuggling**: HTTP/1.1 Upgrade to h2c can bypass proxy access controls if proxy forwards Upgrade/Connection headers

## Notable Research

- **"HTTP Request Smuggling" (Watchfire, 2005)** - Original request smuggling research
- **James Kettle (PortSwigger)** - Modern HTTP desync research
- **"HTTP/2: The Sequel is Always Worse"** - HTTP/2 smuggling via HTTP/1.1
- **"T-Reqs: HTTP Request Smuggling with Differential Fuzzing" (ACM CCS 2021)** - Grammar-based differential fuzzing
- **"How I Found the Worst ASP.NET Vulnerability" (Praetorian, 2025)** - CVE-2025-55315 discovery writeup
