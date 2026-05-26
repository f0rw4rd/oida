# DNS — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/dns.py` + `dns_common.py` |
| Boofuzz class | `DNSFuzzer` |
| Requests | 64 — **highest count in the registry** |
| Mutation depth | 37 fuzzable : 11 default : 2 Static |
| State machine | None |
| Test coverage | Benchmark `(20, 50000, 350)`. Strong. |

The mdns fuzzer is a sibling — see `ref/mdns/fuzzer.md`.

## CVE patterns covered

See `ref/dns/cves/README.md`. DNS parser CVEs cluster around name
compression, label length, and RDLENGTH consistency:

| CVE pattern | DNS fuzzer request | Covered? |
|---|---|---|
| Compression pointer infinite loop (CVE-2020-25681 class) | `DNS_Compression_Pointer` | ✓ |
| Label length > 63 (CVE-2017-12132 class) | `DNS_Long_Label` | ✓ |
| Total name > 255 (CVE-2020-8617 class) | `DNS_Long_Name` | ✓ |
| RDLENGTH lies about RDATA | `DNS_RDLength_Mismatch` | ✓ |
| EDNS0 OPT record fuzzing | `DNS_EDNS_OPT` | ✓ |
| DNSSEC RRSIG / NSEC3 parsing | `DNS_DNSSEC_*` | ✓ |
| TKEY / TSIG signature length (CVE-2020-8617) | `DNS_TKEY` | ✓ |
| AXFR / IXFR zone transfer parsing | `DNS_Zone_Transfer` | ✓ |
| Recursive query loops | `DNS_Recursive_Loop` | ✓ |

## Coverage notes

This is the most thoroughly covered fuzzer in the registry. The
`dns_common.py` helper provides DNS-name building primitives (labels,
compression pointers, terminators) that all 64 requests compose. The
encoding consistency is good.

## Optimization recommendations

1. **No urgent gaps.** This fuzzer is one of the reference
   implementations for the registry.
2. **Optional: extend to DoT / DoH** as separate fuzzers (transport
   variant, not the wire format).
