# Modbus — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/modbus/tcp.py` + `rtu.py` + `pdu.py` + `constants.py` |
| Boofuzz class | `ModbusFuzzer` (TCP, StatefulFuzzer) · `ModbusRTUFuzzer` (RTU, BaseFuzzer) |
| Requests | 15 (TCP) · 12 (RTU) |
| Mutation depth | 185 fuzzable : 5 Static (TCP), 124:0 (RTU) |
| State machine | `StatefulFuzzer` (TCP only); RTU is stateless |
| Test coverage | `tests/unit/fuzz/test_modbus_*` — strong: `test_modbus_critical_features`, `test_modbus_fuzzer_balance`, `test_modbus_tcp_fuzzer_coverage`, benchmark `(55, 20000, 180)`. |

## CVE patterns covered

See `ref/modbus/cves/README.md` for the full CVE table. The fuzzer maps to
these CVE classes:

| CVE pattern | Modbus fuzzer request | Covered? |
|---|---|---|
| MBAP length vs. PDU length mismatch (e.g. CVE-2024-10918, CVE-2022-0367) | `Quick_FC_Coverage` partially; **no dedicated length-mismatch request** | ⚠ partial |
| Function code boundaries — undocumented FCs 65-72, 100-110 | `Quick_FC_Coverage` (`Group("Function_Code", values=ALL_FUNCTION_CODES)`) | ✓ |
| Register/coil quantity overflow (CVE-2015-6490 class) | `Standard_Read_Request`, `read_*` requests with fuzzable quantity | ✓ |
| Exception response parsing (codes > 0x0B) | `Read_Exception_Status` request | ✓ |
| Write Multiple byte_count vs. quantity (CVE-2019-6857 class) | `Write_Multiple_Registers`, `Write_Multiple_Coils` | ✓ |
| Zero-length / near-empty PDUs | covered via boofuzz `Size` mutations on length blocks | ✓ |
| Maximum ADU size (260 bytes, RTU/TCP) | covered via boofuzz `String` overflow mutations | ✓ |
| MEI Device Identification (FC 0x2B/0x0E) field mismatches | `Read_Device_Identification` request | ✓ |
| Diagnostics sub-function parsing (FC 0x08) | `Diagnostics` request | ✓ |

## Known gaps

- **Length-mismatch as a dedicated request.** CVE-2024-10918 and
  CVE-2022-0367 both pivot on MBAP `length` lying about the actual PDU
  size. The current fuzzer mutates `length` via boofuzz `Size`, but a
  hand-crafted `Length_Mismatch` request that systematically declares
  large lengths with short / over-long payloads would hit these CVEs
  faster than random mutation of `Size`.
- **`Quick_FC_Coverage` PDU.** `Group("Function_Code", values=ALL_FUNCTION_CODES)`
  iterates every FC but the `Params` block is `Bytes(..., fuzzable=False)` —
  so the per-FC sweep only varies the function code, not the body. This
  is intentional for breadth, but does not exercise per-FC parser
  pathways. The deeper requests cover those, but document this as a
  trade-off.
- **RTU CRC fuzzing is minimal.** RTU frames have a 2-byte CRC-16; the
  fuzzer treats it as `Checksum()` so it's auto-recomputed on mutation,
  meaning the parser's CRC validation path is never exercised with a
  *deliberately wrong* CRC. Consider a single `RTU_Bad_CRC` request
  that flips one byte to verify the slave drops the frame.

## RequestInfo vs. Request mismatch

The `RequestInfo` entries are logical groups (e.g. `"Read_Operations"`,
`"Diagnostics_Suite"`) that don't 1:1 map to individual `Request` objects.
`--enable` and `--list-requests` show the logical groups; `--enable
"Read_Operations"` runs multiple underlying requests. Documented here so
the next contributor doesn't try to "fix" it. The opcua and iec104
fuzzers use the same convention.

## Optimization recommendations

1. **Add `MBAP_Length_Mismatch` request** — pin function code to a
   single FC (0x03 read holding registers), set `MBAP.length` to a
   `Group(values=[0, 1, 6, 7, 65535])` while keeping the actual PDU at
   normal size. Targets CVE-2024-10918 / CVE-2022-0367 directly.
2. **Add `RTU_Bad_CRC` request** — for RTU mode only. Use a `Static`
   CRC value instead of `Checksum()`. One-off request, low complexity.
3. **Cap maximum ADU** in `String`/`Bytes` overflow primitives at 1 MiB
   so a single test case can't OOM the target before the slave's TCP
   stack drops the connection.

The architectural blockers (crash dedup, state-machine routing,
zero-mutation Quick_FC_Coverage in the breadth sweep) are tracked in
`ref/FUZZER_REVIEW.md` — modbus is *not* affected by the last one
(Quick_FC_Coverage does mutate the function code, just not the body).
