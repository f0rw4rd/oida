# DNP3 — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/dnp3.py` |
| Boofuzz class | `DNP3Fuzzer` (BaseFuzzer) |
| Requests | 10 — **lowest request count for a P0 protocol** |
| Mutation depth | 3 fuzzable : 42 default : 6 Static (sparse) |
| State machine | None (BaseFuzzer only) |
| Test coverage | `tests/unit/fuzz/test_dnp3_fuzzer.py`. Benchmark `(20, 22000, 170)`. tshark dissector validation xfailed (known dissector quirk). |

## CVE patterns covered

See `ref/dnp3/cves/README.md`. DNP3 CVEs cluster around link-layer
framing, transport-layer fragmentation, and application-layer object
parsing:

| CVE pattern | DNP3 fuzzer request | Covered? |
|---|---|---|
| Data Link Layer (DL) frame length mismatch | `DNP3_DL_Frame` | ✓ |
| DL CRC error injection | covered via boofuzz default mutation | ✓ |
| Transport Layer (TL) fragment sequence wrap | `DNP3_TL_Fragment` | ✓ |
| Application Layer (AL) function-code coverage | `DNP3_AL_FuncCode` with `Group` over standard function codes 0-32 | ✓ |
| Object group / variation parsing | **no dedicated request** — covered only by boofuzz default mutation of group/variation fields | ⚠ partial |
| Authentication (SAv5) message authentication code abuse | `DNP3_SAv5_Auth` | ✓ |
| File transfer (g70) parsing | `DNP3_File_Transfer` | ✓ |
| Cold/Warm restart parsing | `DNP3_Restart` | ✓ |

## Known gaps (audit findings)

- **No object-group sweep.** DNP3 defines ~100 object groups (binary
  input, analog input, counter, time, file, etc.) with multiple
  variations each. The fuzzer doesn't have a `DNP3_Object_Sweep`
  request that iterates `(group, variation)` pairs the way modbus
  does for function codes. This is audit recommendation S5.
- **Low request count** (10) — lowest among P0 protocols. Symptomatic
  of the missing object-group coverage above; one well-designed
  `Object_Sweep` request would significantly raise both numbers.
- **tshark dissector validation xfailed.** The dnp3 dissector in tshark
  is registered but not invoked on the malformed frames the fuzzer
  generates — a known limitation of the dissector's heuristic.

## Optimization recommendations

1. **Add `DNP3_Object_Sweep` request.** Use a `Group("Group", values=range(1,
   90))` combined with `Group("Variation", values=range(0, 17))` against
   a Read-class function code (1). Each iteration sends a request for one
   `(group, variation)` pair. Targets vendor-specific object-parsing bugs
   that random mutation rarely hits.
2. **Add `DNP3_Internal_Indications` request.** IIN flags are a 16-bit
   field on every response — fuzzing them in master-emulation mode
   exercises master-side parsers that have been historically lax.
3. **CRC-injection request.** Like the modbus RTU `Bad_CRC` recommendation,
   add a single request where the DL CRC is `Static` and deliberately
   wrong, to verify outstation drops the frame. boofuzz `Checksum()` auto-
   recomputes, so it never tests the CRC validation path.
