# IEC 60870-5-104 — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/iec104.py` |
| Boofuzz class | `IEC104Fuzzer` (StatefulFuzzer) |
| Requests | 13 |
| Mutation depth | 185 fuzzable : 9 default : 5 Static (deep) |
| State machine | `StatefulFuzzer` — declares CONNECTED → DATA_TRANSFER, plus U-format control |
| Test coverage | `tests/unit/fuzz/test_iec104_fuzzer.py`. Benchmark `(90, 100000, 650)`. |

## CVE patterns covered

See `ref/iec104/cves/README.md`. IEC 104 CVEs cluster around APCI / ASDU
framing and IOA addressing:

| CVE pattern | IEC 104 fuzzer request | Covered? |
|---|---|---|
| APCI start-byte / length mismatch | `IEC104_APCI_Malformed` | ✓ |
| U-format control fuzzing (STARTDT / STOPDT / TESTFR) | `IEC104_UFormat_Control` | ✓ |
| I-format sequence number wrap | `IEC104_IFormat_SeqNo` | ✓ |
| ASDU type identification out-of-range | `IEC104_ASDU_TypeId` with `Group()` over valid + reserved type IDs | ✓ |
| IOA (Information Object Address) overflow | `IEC104_IOA_Overflow` | ✓ |
| Cause of Transmission (CoT) inconsistencies | covered via boofuzz mutation of `CoT` field | ✓ |
| Common Address (CA) range scanning | scanner side; fuzzer mutates CA via `Group` | ✓ |
| File transfer (Type 120-127) parsing | `IEC104_File_Transfer` | ✓ |
| Parameter activate (Type 113) abuse | `IEC104_Parameter_Activate` | ✓ |
| TLS variant (IEC 62351-3) cipher / cert | c104 library doesn't expose a hook; **xfail** | ✗ |

## Known gaps (audit findings)

- **`DATA_TRANSFER` state never reached** (audit B8). The state graph
  declares `INITIAL → CONNECTED → DATA_TRANSFER` but no transition fires
  the I-format request that would move into DATA_TRANSFER. Requests
  tagged `requires_state="DATA_TRANSFER"` therefore never gate
  meaningfully. Fix: add a STARTDT-act → wait for STARTDT-con transition
  callback that sets the state.
- **IEC 62351-3 TLS** is out of scope for the c104 library; the test
  `test_iec104_tls_fuzzing` is xfailed pending upstream support.

## Optimization recommendations

1. **Wire the DATA_TRANSFER transition.** One callback on `STARTDT_con`
   reception that sets `session.state = "DATA_TRANSFER"`. Small change,
   unlocks the four `requires_state="DATA_TRANSFER"` requests.
2. **Add Common Address (CA) sweep request** — `Group("CA", values=range(0,
   65535, 1000))` against a single I-frame template. The scanner side
   already does this for discovery; mirroring it in the fuzzer catches
   CA-parsing bugs not driven by random mutation.
3. **Reserved type-ID coverage** — the current `Group` covers valid IEC
   60870-5-101/104 type IDs (1-127). Extend with reserved range (128-135)
   and vendor-specific (136-255) — vendors frequently misparse these.

## RequestInfo naming

Same many-to-one grouping as modbus — `RequestInfo` labels are logical
groups, not individual `Request` objects. `--enable "IEC104_Control"`
runs all U-format and write-control variants. Documented here so it's
not confused with the OPC UA 1:1 convention.
