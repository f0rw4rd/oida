# HTTP/1.x — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/http_protocol.py` |
| Boofuzz class | `HTTPFuzzer` (BaseFuzzer + state names, **audit B10**) |
| Requests | 18 |
| Mutation depth | 103 fuzzable : 0 default : 217 Static (deep, lots of framing) |
| State machine | Declared via state names but uses BaseFuzzer |
| Test coverage | Benchmark `(14, 30000, 140)`. Strong protocol-specific tests (custom headers, enumeration). |

## CVE patterns covered

See `ref/http/cves/README.md`. HTTP/1.x CVEs cluster on header parsing,
chunked transfer encoding, and HTTP smuggling vectors:

| CVE pattern | HTTP fuzzer request | Covered? |
|---|---|---|
| Request smuggling — Content-Length vs. Transfer-Encoding (CVE-2019-18935 class) | `HTTP_Smuggling_CL_TE` | ✓ |
| Header value injection (CR/LF) | `HTTP_Header_Injection` | ✓ |
| Chunked encoding — bad chunk size | `HTTP_Bad_Chunk` | ✓ |
| Long header line / many headers | `HTTP_Long_Header` | ✓ |
| Method tunneling (TRACE, CONNECT, PRI, undocumented) | `HTTP_Method_Sweep` | ✓ |
| URI parsing — long URI, path traversal, encoded bytes | `HTTP_URI_Mutation` | ✓ |
| Host header malforming | `HTTP_Host_Header` | ✓ |
| Range header (RFC 7233) abuse | `HTTP_Range` | ✓ |
| Authorization header parsing (Basic / Bearer / Digest / NTLM) | `HTTP_Auth_Header` | ✓ |

## Known gaps (audit finding)

- **B10**: state-aware requests use `BaseFuzzer` not `StatefulFuzzer`.
  Same class of issue as OPC UA / SMTP. Today the "state" is just a
  metadata tag.

## Coverage notes

HTTP is well-covered structurally. The fuzzer pairs nicely with the
`tests/unit/fuzz/test_http_custom_headers.py` and
`test_http_enumeration.py` suites that exercise specific header
combinations.

## Optimization recommendations

1. **Migrate to `StatefulFuzzer`** for Keep-Alive / pipelined request
   sequences. Today each request is independent; smuggling-class bugs
   often require *sequences* of requests on the same connection.
2. **HTTP/0.9 simple-request** as a separate Request — some libraries
   still accept it and parse the response weirdly.
