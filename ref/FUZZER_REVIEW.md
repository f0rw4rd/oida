# OIDA Fuzzer Coverage Review

Per-fuzzer notes live in `ref/<proto>/fuzzer.md`. This index summarises the
state of every fuzzer in `src/oida/fuzz/protocols/`.

Format columns:

- **Tier** — `P0` critical ICS · `P1` critical IoT/network · `P2` standard
  · `P3` simple/transport/raw
- **Mutation depth** — `(fuzzable_fields : Static_fields)`; higher fuzzable
  with lower static = deeper coverage. Numbers from the 2026-05-26 audit.
- **State machine** — does the fuzzer extend `StatefulFuzzer` (i.e. have a
  session graph with state transitions) or `BaseFuzzer` only.
- **Coverage** — qualitative assessment vs. the protocol's known parser
  CVEs (see `ref/<proto>/cves/README.md`).

## Industrial Control Systems

| Protocol | OIDA module | Tier | State machine | Coverage | Notes |
|----------|-------------|------|---------------|----------|-------|
| modbus (TCP) | `fuzz/protocols/modbus/tcp.py` | P0 | StatefulFuzzer | Good (185 fuzzable / 5 Static) | 15 requests; covers FC enumeration, register overflows, exception parsing. Gaps: PDU/MBAP length mismatch (CVE-2024-10918 pattern) not modelled as a dedicated request. See `ref/modbus/fuzzer.md`. |
| modbus_rtu | `fuzz/protocols/modbus/rtu.py` | P0 | BaseFuzzer | Medium | XFAILed in benchmark (serial dep). CRC fuzzing minimal. |
| opcua | `fuzz/protocols/opcua.py` | P0 | BaseFuzzer (uses state names anyway) | Good (3:76:174) | 21 requests after the OPCUA_Query phantom was removed. 3 attack-pattern requests punted (xfail): `OPCUA_MalformedCert`, `OPCUA_NodeIdEncodingOverflow`, `OPCUA_State_Confusion`. |
| iec104 | `fuzz/protocols/iec104.py` | P0 | StatefulFuzzer | Good (185:9:5) | 13 requests. `DATA_TRANSFER` state is declared but no transition reaches it (audit B8). c104 TLS test xfail upstream-blocked. |
| mms | `fuzz/protocols/mms.py` | P0 | BaseFuzzer | Sparse (17:1:63) | ASN.1-heavy framing dominates; only 17 fuzzable fields. 14 requests. Lowest mutation count for P0. |
| dnp3 | `fuzz/protocols/dnp3.py` | P0 | BaseFuzzer | Sparse (3:42:6) | 10 requests — lowest request count for P0. No object-group coverage. tshark dissector validation xfailed. |
| ethernetip | `fuzz/protocols/ethernetip.py` | P0 | BaseFuzzer | Suspicious (1:121:0) | 11 requests. 121 explicit `fuzzable=False` annotations — likely a copy-paste leftover that disables most mutation. Audit S-flag. |
| bacnet | `fuzz/protocols/bacnet.py` | P0 | BaseFuzzer | Opaque (0:0:0) | 13 requests, **zero explicit** `fuzzable=` annotations. Mutations work via boofuzz defaults but per-field audit is impossible without instantiating the tree. |
| ads | `fuzz/protocols/ads.py` | P0 | BaseFuzzer | Sparse (1:39:18) | 10 requests. TODO for `ADSMonitor` integration. Most fields static. |

## ICS protocols *without* a fuzzer module (open work)

These have a scanner + `ref/<proto>/` but no `fuzz/protocols/<proto>.py`:

- **snap7 / s7comm** — `ref/s7comm/` exists. No fuzzer.
- **profinet (DCP/RPC)** — `ref/profinet_dcp/` exists. No fuzzer.
- **ethercat** — `ref/ethercat/` exists. No fuzzer (Layer-2 / pysoem).
- **tase2** — `ref/tase2/` exists. No fuzzer (depends on pyiec61850-ng MMS).
- **goose** — `ref/goose/` exists. No fuzzer (Layer-2 multicast).
- **hartip** — `ref/hartip/` exists. No fuzzer.
- **knx** — `ref/knx/` exists. No fuzzer.
- **fins** — `ref/fins/` exists. No fuzzer (Omron).
- **industrial_ethernet** (generic) — `ref/industrial_ethernet/` exists. No fuzzer.

These are the strongest candidates for new fuzzer modules — the protocol
spec material is already curated.

## IoT and messaging

| Protocol | OIDA module | Tier | State machine | Coverage | Notes |
|----------|-------------|------|---------------|----------|-------|
| mqtt | `fuzz/protocols/mqtt.py` | P1 | StatefulFuzzer | Medium (2:0:39) | 12 requests. Length-encoding boundaries covered. |
| coap | `fuzz/protocols/coap.py` | P2 | BaseFuzzer | Opaque (0:0:19) | 20 requests, no explicit `fuzzable=` annotations. |
| mdns | `fuzz/protocols/mdns.py` | P2 | BaseFuzzer | Mixed (0:0:346) | 20 requests; `Quick_Coverage` is 100% `Static` and therefore produces zero mutations on the breadth-first sweep (audit B6). **Fixed 2026-05-26**. |

## Network infrastructure

| Protocol | OIDA module | Tier | State machine | Coverage | Notes |
|----------|-------------|------|---------------|----------|-------|
| dns | `fuzz/protocols/dns.py` | P1 | BaseFuzzer | Good (37:11:2) | 64 requests — highest count in the registry. |
| dhcp / dhcpv6 | `fuzz/protocols/dhcp.py` | P2 | BaseFuzzer | Good (30:0:41) | 16 requests. |
| ntp | `fuzz/protocols/ntp.py` | P2 | BaseFuzzer | Deep (130:0:0) | 20 requests, all-fuzzable. Strong. |
| snmpv1 / snmpv2 / snmpv3 | `fuzz/protocols/snmpv*.py` | P1 | BaseFuzzer | Medium | 13 / 12 / 8 requests. v2c benchmark XFAILs (walk recursion). v3 has 1 tshark FAIL hidden in test summary. USM auth params not fuzzed. |
| tftp | `fuzz/protocols/tftp.py` | P2 | BaseFuzzer | Medium (9:0:14) | 8 requests. |

## Web

| Protocol | OIDA module | Tier | State machine | Coverage | Notes |
|----------|-------------|------|---------------|----------|-------|
| http | `fuzz/protocols/http_protocol.py` | P1 | BaseFuzzer + state names | Good (103:0:217) | 18 requests. |
| http2 | `fuzz/protocols/http2.py` | P1 (optional) | BaseFuzzer | Sparse (3:0:24) | Optional import. |
| ftp | `fuzz/protocols/ftp.py` | P1 | StatefulFuzzer | Medium (2:0:118) | 16 requests. Largest single file (2,560 lines). Dual state-machine path. |
| smtp | `fuzz/protocols/smtp.py` | P1 | BaseFuzzer + state names | Medium (35:0:96) | 12 requests. State machine only active under specific flags (audit B7). |
| vnc | `fuzz/protocols/vnc.py` | P2 | BaseFuzzer | Sparse (2:0:26) | 15 requests. Lowest mutation count for P2. |

## Healthcare

| Protocol | OIDA module | Tier | State machine | Coverage | Notes |
|----------|-------------|------|---------------|----------|-------|
| hl7 | `fuzz/protocols/hl7.py` | P2 | BaseFuzzer | Medium-deep (69:10:104) | 11 requests. MLLP framing well covered. |

Healthcare gap: `dicom` has `ref/dicom/` but no fuzzer module.

## Transport / Layer 2 / raw socket

| Protocol | OIDA module | Tier | Notes |
|----------|-------------|------|-------|
| ethernet | `fuzz/protocols/ethernet.py` | P3 | 11 requests, default fuzzable; raw socket. |
| ipv4 / ipv6 | `fuzz/protocols/ipv*.py` | P3 | Deep coverage (114-236 fuzzable). Skipped in benchmark (raw socket). |
| icmp / icmpv6 | `fuzz/protocols/icmp*.py` | P3 | Deep (271 / 175 fuzzable). Skipped in benchmark. |
| tcp | `fuzz/protocols/tcp.py` | P3 | 20 requests, dedicated state-integration module. |
| gatt | `fuzz/protocols/gatt.py` | P3 (optional) | 13 requests when imported. BLE dep gated. |
| echo / daytime | `fuzz/protocols/echo.py`, `daytime.py` | P3 | Demo-tier protocols. 7-10 requests each. |

## Generic mutation fuzzer

| Protocol | OIDA module | Notes |
|----------|-------------|-------|
| mutation | `fuzz/protocols/mutation.py` | Native radamsa-style mutation engine driven by user-supplied seed files. Works for any protocol where you can hand it a sample frame. |

## Cross-cutting audit findings (2026-05-26)

| ID | What | Status |
|----|------|--------|
| B1 | Crash table had no `crash_hash` for dedup | **Fixed 1.0** — `Crash.crash_hash` BLAKE2b column added |
| B2 | Two parallel DB backends (`SQLiteDatabase` raw + `SQLAlchemyDatabase` ORM) | **Fixed 1.0** — `SQLiteDatabase` removed, ORM is canonical |
| B4 | `OPCUA_Query` phantom request | **Fixed 1.0** — entry removed |
| B5 | 3 OPC UA attack patterns punted indefinitely | Open (xfailed in tests, tracked in `ref/opcua/fuzzer.md`) |
| B6 | `Quick_Coverage` zero-mutation pattern (mdns) | **Fixed 1.0** — see `ref/mdns/fuzzer.md` |
| B7-B8 | SMTP / IEC 104 state machine declared states unreachable | Open |
| B9-B10 | Some state-aware requests extend `BaseFuzzer` not `StatefulFuzzer` | Open |

The full audit (with line-numbered findings) lives in
`RELEASE_READINESS.md` and the working notes that fed it are in commit
`94362498` history.
