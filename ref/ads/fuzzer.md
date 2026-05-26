# ADS (Beckhoff TwinCAT) — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/ads.py` |
| Boofuzz class | `ADSFuzzer` (BaseFuzzer) |
| Requests | 10 |
| Mutation depth | 1 fuzzable : 39 default : 18 Static (sparse) |
| State machine | None |
| Test coverage | Benchmark `(18, 12000, 100)`. |

## CVE patterns covered

See `ref/ads/cves/README.md`. ADS CVEs cluster around the AMS header
parser, the AdsRouter service, and per-command body fields:

| CVE pattern | ADS fuzzer request | Covered? |
|---|---|---|
| AMS header — `length` lies about actual data length | `ADS_Header_Mutation` | ✓ |
| AMS Net ID format abuse (non-6-byte) | `ADS_NetID_Mutation` | ✓ |
| Command Read / Write — index group/offset overflow | `ADS_Read`, `ADS_Write` | ✓ |
| ReadWrite combined operation byte_count mismatch | `ADS_ReadWrite` | ✓ |
| ReadState / WriteState — state value overflow | `ADS_ReadState`, `ADS_WriteState` | ✓ |
| AddDeviceNotification — handle reuse / overflow | `ADS_AddNotification` | ✓ |
| ReadDeviceInfo string fields | `ADS_ReadDeviceInfo` | ✓ |
| AdsRouter port enumeration | scanner side, not fuzzer-applicable | n/a |

## Known gap (audit S6)

- **`ADSMonitor` integration TODO.** The fuzzer declares an `ADSMonitor`
  class for crash detection but never wires it into the monitor chain.
  This means crashes detected by ADS-side error codes (e.g. `0x70A` =
  invalid index group) are recorded as failed test cases but not
  promoted to crash events. Fix: register `ADSMonitor` in the fuzzer's
  monitor list alongside `TCPMonitor`.

## Optimization recommendations

1. **Wire `ADSMonitor`.** Single-line registration once the monitor
   class is finished. Allows crash-class triage to distinguish
   protocol-error responses from genuine outstation crashes.
2. **AMS port enumeration request.** ADS uses logical ports (851 = PLC,
   500 = NC, 350 = SystemService, etc.). A `Group()` of well-known port
   values on `ADS_Read` exercises per-port parsers.
3. **Sumcommand / SumReadWrite fuzzing** (Beckhoff-specific bulk-op
   commands) — these are an unexplored surface in the current request
   set.
