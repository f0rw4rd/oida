# HL7 v2 — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/hl7.py` |
| Boofuzz class | `HL7Fuzzer` (BaseFuzzer) |
| Requests | 11 |
| Mutation depth | 69 fuzzable : 10 default : 104 Static |
| State machine | None |
| Test coverage | Benchmark `(8, 12000, 60)`. |

## CVE patterns covered

See `ref/hl7/cves/README.md`. HL7 v2 CVEs cluster on MLLP framing, field
delimiter handling, and per-segment parser bugs:

| CVE pattern | HL7 fuzzer request | Covered? |
|---|---|---|
| MLLP frame boundary abuse (no `<SB>`, double `<EB>`) | `HL7_MLLP_Frame` | ✓ |
| Field separator (default `|`) abuse — wrong separator declared | `HL7_FieldSep` | ✓ |
| Long PID-3 (patient ID) field overflow | `HL7_PID_Overflow` | ✓ |
| OBX-5 (observation value) — type-tag vs. payload mismatch | `HL7_OBX_TypeMismatch` | ✓ |
| MSH-12 (version) — declared version vs. payload format mismatch | `HL7_Version_Mismatch` | ✓ |
| Continuation segments (ADD segment) — multi-message reassembly | `HL7_Continuation` | ✓ |
| Master file (MFK / MFI) parser | `HL7_MasterFile` | ✓ |
| Pharmacy (RXE, RXD, RXA) parsing | `HL7_Pharmacy` | ✓ |

## Coverage notes

Solid fuzzer for a healthcare protocol. The 69 explicit fuzzable
annotations give a clearer picture than coap or bacnet (which both
rely on defaults).

## Optimization recommendations

1. **HL7 v2.x version sweep** — the spec evolved; v2.3 / v2.4 / v2.5 /
   v2.6 / v2.7 / v2.8 parsers differ. A single `MSH-12` `Group()` over
   version strings exercises per-version code paths.
2. **HL7-over-FHIR bridge fuzzing** — out of scope for an MLLP fuzzer
   but worth flagging: HL7 v2 → FHIR converters are a notorious bug
   surface.
3. **Z-segment** (vendor-specific segments starting with `Z`) — most
   parsers must ignore them gracefully; a request that defines a
   malformed Z-segment in the middle of a normal ADT message catches
   parsers that don't skip cleanly.
