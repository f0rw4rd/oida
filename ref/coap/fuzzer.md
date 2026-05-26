# CoAP — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/coap.py` |
| Boofuzz class | `CoAPFuzzer` |
| Requests | 20 |
| Mutation depth | 0 explicit : 0 explicit : 19 Static (boofuzz defaults) |
| State machine | None |
| Test coverage | Benchmark `(18, 7000, 55)`. |

## CVE patterns covered

See `ref/coap/cves/README.md`. CoAP CVEs cluster around the option-list
encoding (delta + length nibbles), URI-path parsing, and Block / Observe
extensions:

| CVE pattern | CoAP fuzzer request | Covered? |
|---|---|---|
| Option delta encoding (4-bit / 8-bit / 16-bit extended) | `CoAP_Option_Delta` | ✓ |
| Token length 1..8 boundary | `CoAP_Token_Length` | ✓ |
| URI-path option length overflow | `CoAP_URI_Path` | ✓ |
| Block1 / Block2 (RFC 7959) — szx field abuse | `CoAP_Block_Transfer` | ✓ |
| Observe (RFC 7641) — sequence number wrap | `CoAP_Observe` | ✓ |
| Payload marker (0xFF) at wrong position | `CoAP_Payload_Marker` | ✓ |
| DTLS handshake fuzzing | **not covered** — separate transport | ✗ |

## Coverage notes

CoAP fuzzer has zero explicit `fuzzable=` annotations (same audit
observation as bacnet). Mutation works via boofuzz defaults but isn't
auditable without instantiating the protocol tree.

## Optimization recommendations

1. **DTLS handshake fuzzing** — CoAP-over-DTLS (CoAPs, port 5684) is a
   distinct attack surface. Out of scope for the application-layer
   fuzzer; consider a separate DTLS fuzzer module.
2. **Add explicit `fuzzable=True`** annotations to header bits (Ver,
   T, TKL, Code) so the audit posture is clearer. Mechanical.
