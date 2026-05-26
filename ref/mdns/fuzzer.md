# mDNS — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/mdns.py` |
| Boofuzz class | `MDNSFuzzer` (BaseFuzzer) |
| Requests | 20 |
| Mutation depth | 0 explicit fuzzable / 346 `Static` — was the audit B6 finding |
| State machine | None |
| Test coverage | Benchmark `(24, 24000, 350)`. |

## CVE patterns covered

See `ref/mdns/cves/README.md`. mDNS shares its parser with classic DNS
(RFC 6762 wire format mirrors RFC 1035); the relevant CVEs are the
DNS name-compression and label-length parser bugs:

| CVE pattern | mDNS fuzzer request | Covered? |
|---|---|---|
| Header flags (QR/Opcode/AA/TC/RD/RA/Z/RCODE) | `Quick_Coverage` baseline | ✓ (post-1.0 fix) |
| Compression pointer infinite loop | `Invalid_Compression` | ✓ |
| Label length > 63 octets | `Long_Name` | ✓ |
| Total name length > 255 octets | `Long_Name` | ✓ |
| Oversized UDP packet (> 9000 bytes) | `Oversized_Packet` | ✓ |
| Malformed `RDATA` length (lies about following bytes) | covered via boofuzz mutation of `RDLENGTH` | ✓ |
| ANY-query reflection amplification | `Quick_Coverage` uses `QC_Q_Type=ANY` | ✓ |

## Audit finding B6: Quick_Coverage zero-mutation (fixed 1.0)

**Original state:** `Quick_Coverage` was assembled entirely from
`Static(...)` primitives — every byte of the 8-record sweep response was
hard-coded. boofuzz does not mutate `Static`, so the breadth-first
sweep produced **zero mutations**: the request fired exactly once with
the baseline frame and nothing else. This is benign for framing-
validation but defeats the *purpose* of having Quick_Coverage as the
first phase (touch every record type with varied content).

**Fix:** the header bits (transaction ID, flags, response counts) are
now `Word` / `BitField` primitives — boofuzz default-fuzzable. The
record payloads remain `Static` since their byte layout is what we
want to *survey*; varied parsing comes from the other 19 requests
(`Malformed_Header`, `Long_Name`, `Oversized_Packet`, `Invalid_Compression`,
etc.) that target specific patterns.

## Optimization recommendations

1. **Already applied:** Quick_Coverage header is now mutated.
2. **Service-type enumeration request.** `Group("Service_Type",
   values=["_http._tcp.local", "_ipp._tcp.local", "_printer._tcp.local",
   "_workstation._tcp.local", "_smb._tcp.local", "_ssh._tcp.local",
   ...])`. Catches per-service-type parser logic in the responder. ~50
   lines.
3. **Truncated-record request.** Send an answer section with `ANCount=8`
   but only 2 actual records. Targets responders that don't bounds-check
   `ANCount` against actual section length.
