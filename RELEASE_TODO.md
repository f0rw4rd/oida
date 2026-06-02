# OIDA 1.0 Release TODO

**Release target:** 2026-07-16
**Created:** 2026-06-01 (T-6.5 weeks)
**Scope:** every module, every feature, every test, plus release/README/website prep.
**Status legend:** `[ ]` open · `[~]` in progress · `[x]` done · `[?]` needs decision

This is the long list. Cross-references:
- `RELEASE_READINESS.md` — audit baseline (86 fixes shipped, 6 blocker classes still open)
- `ref/_FUZZER_OPTIMIZATIONS_TODO.md` — per-protocol fuzzer items
- `docs/REAL_COVERAGE_PROPOSAL.md` — 3-axis coverage strategy
- `/tmp/oida_review_*.md` — full audit reports (move into `docs/audit/` first)

---

## 0. Pre-flight: clean working tree

- [x] Decide on uncommitted fuzz DB refactor — **kept** (perf refactor: bulk inserts, WAL+PRAGMA, single-query stats, covering indexes, BigInteger CRC32, crash_hash surfaced; 12 perf + 14 cli-deep tests all green)
- [x] Wire interface drift fix — added `target_ip`/`protocol`/`limit` params to abstract `DatabaseInterface.get_test_cases` and `MockDatabase`; `fuzz_cli.py:580` passes `limit=None` to avoid silently truncating crash listings
- [x] Wire new test files into the suite (no extra action needed — pytest auto-discovers `tests/integration/fuzz/test_*.py`)
- [x] Delete `.claude/agents/senior-dev-csharp.md`
- [x] **Bonus fix**: `tests/integration/conftest.py` PROTOCOL_SERVICES referenced ghost services (`msf-ics-mock`, `profinet-pnet-device`) — docker compose returned 1, cascading "FAILED" markers across 197 tests + 376 errors that had nothing to do with the real bugs. Replaced with `bacnet-mock`/`bacnet-conpot` and `profinet-device`.
- [ ] Move `/tmp/oida_review_*.md` (6 files) into `docs/audit/` before they vanish
- [ ] Verify `services.py up all` brings every mock healthy from a fresh clone

### Discovered during §0 and fixed (commits after `d1dbaf4f`)

- [x] `tests/integration/pcap/test_iec104_passive.py` — added `cot` to PROTOCOL_COLUMNS expected set; relaxed control-type tests to accept the listener's more-precise rw labels (read/error for type 100/58 with their actual COTs)
- [x] `tests/integration/pcap/test_modbus_passive.py` — accept FC 0x17 as legitimate Read+Write overlap; accept Get/Report as read-flavored verbs for diagnostic FCs (0x0B/0x0C/0x11)
- [x] `tests/integration/pcap/test_ads_passive.py` — listener gained per-bit `state_flags` extraction (state_adscmd, state_syscmd, etc.) from tshark's ams.state_* fields
- [x] `tests/integration/pcap/test_database_passive.py` — accept "Multi-message" as a valid PG response operation
- [x] ASTM port test stale (1394 → 12000)
- [x] `astm` AttributeError — patch `ConnectionHelper.create_tls_tcp_connection` instead of vanished `astm.socket`
- [x] `can` AttributeError — patch `can.nxc_connection._python_can` (separate from `can.scanner._python_can`); drop dead `can._python_can` patch target
- [x] 4 PACKET DROPs flagged as `pytest.xfail` via new `KNOWN_DROPS` map in `test_packet_coverage.py` — see "Real listener gaps" below

### Real listener gaps (documented as KNOWN_DROPS / xfails)

These are real product bugs but each needs a per-listener fix that's bigger than a one-liner. Tracked in `tests/integration/pcap/test_packet_coverage.py::KNOWN_DROPS`:

- [ ] **bacnet ARCNET unwrap** — `wireshark_bacnet_arcnet.cap` 100% drop. Listener can't unwrap ARCNET-encapsulated BACnet frames.
- [ ] **ldap SASL/GSSAPI (Kerberos-bound) parse** — `wireshark_ldap_krb5.cap` 100% drop. Listener only handles plaintext bind; Kerberos-wrapped credential frames are not parsed.
- [ ] **modbus payload variants** — `zeek_modbus_mixed_p502.pcap` 29% drop. Listener rejects some payload variants that real PLCs accept (likely diagnostic FCs in the mixed traffic).
- [ ] **pim Register messages** — `wireshark_pim_register.cap` 85% drop. Listener only handles top-level PIM, not unicast-encapsulated multicast Register frames.

### Still open (orthogonal to pcap)

- [ ] **Full unit suite: 0 timeouts at 60s**, 1 order-dependent failure (`test_logger_created_on_init` — passes in isolation, fails when integration conftest loads first)

---

## 1. Per-module feature test matrix

For each protocol below, add or extend integration tests that exercise the listed feature groups against the project's docker mock. **Acceptance:** each feature group has at least one passing test asserting on a specific output field, not just "no exception."

### 1.1 Industrial / OT (16 protocols)

#### modbus (62 flags)
- [ ] Discovery: identify, read-device-id, slave-id-scan
- [ ] Reads: holding/input/coil/discrete-input register dumps across `--scan-range`
- [ ] Writes (gated): single + multiple register write with `--confirm`
- [ ] RTU-over-TCP framing path
- [ ] RTU serial path (mock via socat — already covered? verify)
- [ ] Diagnostic function codes (08 subcodes)
- [ ] Exception code mapping (illegal function, illegal data address, etc.)
- [ ] Multi-unit-id sweep (`--unit-id-scan`)
- [ ] `--map-rw` (renamed `--read-write`) — exercise after rename in `de013849`
- [ ] `--raw-function-codes` (renamed from `--raw-fc`)
- [ ] Vendor fingerprinting (Schneider, Siemens, ABB MEI object 0x2B)
- [ ] Format outputs: JSON, CSV, XML, "all"

#### opcua (43 flags)
- [ ] Anonymous endpoint enumeration
- [ ] Username/password auth (`--user/--pass`)
- [ ] Certificate auth (`--cert/--key`)
- [ ] Security modes: None, Sign, SignAndEncrypt — coverage matrix
- [ ] Security policies: Basic128Rsa15, Basic256, Basic256Sha256
- [ ] Address-space browse with `--max-depth` (test 1, 3, max)
- [ ] Node read (single + batched)
- [ ] Subscription / monitored items (smoke)
- [ ] Method invocation enumeration
- [ ] Certificate-analysis output (issuer, subject, validity, key length)
- [ ] **Verify the phantom-flag fix from `19912af5`** (no `--bulk-export`/`--test-*` reach handlers)

#### snap7 / s7 (53 flags)
- [ ] CPU info / order code / module ID enumeration
- [ ] DB read across multiple data blocks
- [ ] System status list (SZL) IDs
- [ ] Run/stop (gated — requires `--confirm`)
- [ ] Password-file path NOT leaked in logs (fix open in audit)
- [ ] Both `s7` and `snap7` CLI aliases work (verify after `19912af5`)
- [ ] Verify `de013849` aliases still functional

#### iec104 (49 flags)
- [ ] STARTDT/STOPDT handshake
- [ ] Interrogation (general, group 1-16)
- [ ] Counter interrogation
- [ ] Clock sync
- [ ] Single/double-command write (gated)
- [ ] Setpoint command (gated)
- [ ] File transfer (read)
- [ ] Direction logic on non-standard ports (verify post-fix in `RELEASE_READINESS` item 19)
- [ ] No flag-name collisions with main parser (verify post-fix item 10)

#### ads (58 flags)
- [ ] Device info read
- [ ] Symbol enumeration (`--list-symbols`)
- [ ] Symbol read/write by name and by handle
- [ ] State read; **state-change ops need `--confirm` (OPEN BLOCKER)**
- [ ] Local Net ID fallback emits warning (verify post-fix item 15)
- [ ] Add `ADS_Port_Enumeration` fuzzer request (ties into §4)
- [ ] Auth via `--cert/--user/--pass` if applicable

#### dnp3 (93 flags — largest surface)
- [ ] Cold/warm restart (gated — verify post-fix item 1)
- [ ] Binary output (BO) direct/select-operate (gated)
- [ ] Analog output (AO) direct/select-operate (gated)
- [ ] Read static objects (group 1, 10, 20, 30, 40)
- [ ] Read event objects (group 2, 4, 22, 32)
- [ ] Class poll (class 0/1/2/3)
- [ ] Time sync
- [ ] File transfer / `--write-file` (gated)
- [ ] Application enable/disable, unsol enable/disable (gated)
- [ ] Freeze + freeze-immediate (gated)
- [ ] Every `--confirm`-gated op rejects without flag (regression — already added per item 1, extend to remaining ops)

#### ethernetip (33 flags)
- [ ] List identity (UDP + TCP)
- [ ] List services
- [ ] List interfaces
- [ ] Forward open / forward close
- [ ] CIP class enumeration (ties into §4 fuzzer add)
- [ ] Tag enumeration on Logix targets
- [ ] Read/write tag (gated)
- [ ] Banner emits "success" only once (verify post-fix in §3)
- [ ] pycomm3 log level restored after disconnect (verify post-fix item 6)

#### ethercat (?)
- [ ] EEPROM read
- [ ] EEPROM write (gated — verify item 2)
- [ ] Set alias (gated)
- [ ] CoE read / SDO read
- [ ] SDO write (gated)
- [ ] State transition: PREOP/SAFEOP/INIT (gated)
- [ ] `--op-state` / `--boot-state` require `--confirm` (verify post-fix item 2)
- [ ] `-p` collision with global `--port` — flag-drift cleanup (§3)
- [ ] Migrate to `proto_args_factory` (§3)

#### mms (7 flags)
- [ ] Initiate / Conclude
- [ ] Object discovery (domain + named-variable)
- [ ] Read named variable
- [ ] Write named variable (gated)
- [ ] File services (directory, open, read, close)
- [ ] Banner deduplication (§3)

#### tase2
- [ ] Bilateral table enumeration
- [ ] Data set enumeration
- [ ] Transfer set conditions
- [ ] Decide: derive from MMS or implement standalone? (ref/_NO_FUZZER_YET.md)

#### goose / rgoose
- [ ] Subscribe / capture frames (Layer-2; raw socket path)
- [ ] GoCB enumeration
- [ ] DataSet decode
- [ ] R-GOOSE UDP variant
- [ ] CAP_NET_RAW handling: clear error when missing

#### profinet
- [ ] DCP identify (Layer-2)
- [ ] Device read parameter
- [ ] Alarm subscription smoke
- [ ] Migrate to `proto_args_factory` (§3)

#### hart
- [ ] HART-IP gateway enumeration
- [ ] Universal commands (0, 1, 2, 3, 12, 13)
- [ ] Common-practice commands
- [ ] Lazy-import theatre fix (audit aux-B3 — verify against post-fix `19912af5` punch list)

#### knx
- [ ] Group address read
- [ ] Group address write (gated)
- [ ] Device descriptor / mask read
- [ ] BAOS / KNXnet/IP discovery
- [ ] `extract_knxproj_hash` no longer writes to `cwd()` (deferred in audit — close)
- [ ] Migrate to `proto_args_factory` (§3)

#### bacnet
- [ ] WhoIs / IAm (UDP broadcast)
- [ ] ReadProperty / ReadPropertyMultiple
- [ ] WriteProperty (gated)
- [ ] Object enumeration across types
- [ ] Replace 8.8.8.8 own-IP hack (audit aux-B5)

#### can
- [ ] J1939 PGN enumeration
- [ ] CANopen NMT / SDO read
- [ ] Banner deduplication (§3)
- [ ] socketcan vs vcan path

### 1.2 IoT / application (4 protocols)

#### mqtt
- [ ] Anonymous connect
- [ ] Auth connect (user/pass)
- [ ] TLS connect + cert validation
- [ ] Topic enumeration via `$SYS/#`
- [ ] Subscribe + publish (gated)
- [ ] MQTT v3.1.1 vs v5 negotiation
- [ ] Banner deduplication (§3)
- [ ] Stale `--listen-filter` test cleanup (RELEASE_READINESS skipped list)

#### coap
- [ ] GET / POST / PUT / DELETE
- [ ] `.well-known/core` enumeration
- [ ] Observe (notification stream smoke)
- [ ] Block-wise transfer
- [ ] DTLS variant

#### ocpp
- [ ] Boot notification + heartbeat
- [ ] Authorize / StartTransaction
- [ ] StopTransaction
- [ ] WebSocket subprotocol negotiation (`ocpp1.6`, `ocpp2.0.1`)

#### snmp
- [ ] v1 community sweep
- [ ] v2c get / get-next / walk (verify walk depth cap — see §4)
- [ ] v3 USM with min-length passphrase enforcement (verify post-fix item 4)
- [ ] v3 noAuthNoPriv / authNoPriv / authPriv matrix
- [ ] Trap receiver smoke
- [ ] OID resolution against MIB cache

### 1.3 Healthcare (4 protocols)

#### hl7
- [ ] MLLP framing (start/end markers)
- [ ] Bounded receive (verify post-fix item 5 — 16 MiB cap)
- [ ] Message types: ADT, ORM, ORU, MDM
- [ ] Z-segment handling (graceful skip)
- [ ] Version negotiation (MSH-12: 2.3/2.4/2.5/2.6/2.7/2.8)
- [ ] Lazy-import fix (audit aux-B3)

#### fhir
- [ ] Conformance/CapabilityStatement read
- [ ] Resource enumeration
- [ ] Patient/Observation search
- [ ] **Remove or gate `--bulk-export`, `--test-cross-patient`, `--test-scope`** (audit aux-B4)

#### dicom
- [ ] C-ECHO
- [ ] C-FIND on patient/study/series
- [ ] C-MOVE smoke
- [ ] C-STORE (gated)
- [ ] AET enumeration

#### astm
- [ ] **Fix `default_port = 1394` → 12000/5000/6000/9100** (audit aux-B6)
- [ ] ENQ/ACK framing
- [ ] H/P/O/R/L record decode

### 1.4 Discovery / passive (2 modules)

#### discovery
- [ ] LLDP
- [ ] CDP
- [ ] BBMD (BACnet broadcast forwarder)
- [ ] mDNS / Bonjour
- [ ] SSDP / UPnP (verify defusedxml hard-dep post-fix item 3)
- [ ] CODESYS gateway discovery
- [ ] Multicast group enumeration
- [ ] Migrate to `proto_args_factory` (§3)

#### pcap (109 listeners)
- [ ] DECODE_AS hints applied for ajp/rmi/rsync (verify post-fix item 17)
- [ ] BFD/RIP src_port/dst_port in interactions (verify post-fix item 18)
- [ ] See §2 for listener-by-listener coverage

---

## 2. PCAP listener test coverage (109 listeners)

### 2.1 Listeners with NO dedicated test file (28 from audit)

For each: add a `tests/integration/pcap/test_<listener>.py` that loads a fixture pcap, runs the listener, asserts at least one device/interaction/credential is harvested with non-empty fields.

- [ ] c1222
- [ ] can
- [ ] canopen
- [ ] cipsafety
- [ ] coap
- [ ] cotp
- [ ] devicenet
- [ ] dicom
- [ ] epl
- [ ] ff_hse
- [ ] hl7
- [ ] hsr
- [ ] iec101
- [ ] iec103
- [ ] j1939
- [ ] lontalk
- [ ] mdns
- [ ] nmea0183
- [ ] opcda
- [ ] opensafety
- [ ] pcom
- [ ] prp
- [ ] ptp
- [ ] rgoose
- [ ] sercos
- [ ] sv
- [ ] synchrophasor
- [ ] tftp

### 2.2 False-positive coverage gap

`test_false_positives.py` covers 6/109 listeners. Extend to high-traffic listeners:

- [ ] modbus
- [ ] dnp3
- [ ] s7comm
- [ ] iec104
- [ ] opcua
- [ ] enip
- [ ] bacnet
- [ ] hl7
- [ ] http
- [ ] tls

### 2.3 Direction-by-port hardcode (16 listeners)

iec104 was fixed (post-fix item 19). Apply same "lower port wins" fallback to:

- [ ] modbus
- [ ] dnp3
- [ ] s7comm
- [ ] enip
- [ ] mms
- [ ] profinet
- [ ] coap
- [ ] mqtt
- [ ] hl7
- [ ] hartip
- [ ] (remaining 6 — audit listener report has full list)

---

## 3. CLI consistency / polish

### 3.1 Double-success banner cleanup

Reference pattern: iec104. Apply to:

- [ ] ethernetip
- [ ] mqtt
- [ ] mms
- [ ] snap7
- [ ] can

### 3.2 Short-flag collisions

- [ ] Document the 8 collision letters (`-p -u -P -i -r -T -W -d`) in `STYLE_GUIDE.md`
- [ ] Resolve `-p = --eeprom-parse` (ethercat) vs `--port` everywhere else
- [ ] Resolve `-u = --unit-id` (modbus) vs other uses
- [ ] Mechanical sweep: every protocol picks one of the two and documents

### 3.3 `proto_args_factory` migration (6 holdouts)

- [ ] ads
- [ ] discovery
- [ ] ethercat
- [ ] ethernetip
- [ ] knx
- [ ] profinet

---

## 4. Fuzzer feature additions (from `ref/_FUZZER_OPTIMIZATIONS_TODO.md`)

### 4.1 Small (≤1h each)

- [ ] modbus: cap ADU overflow at 4096 in `tcp.py` and `rtu.py`
- [ ] modbus: audit RTU CRC mutation path; add `RTU_Bad_CRC` request if needed
- [ ] dnp3: add `DNP3_Object_Sweep`
- [ ] dnp3: add `DNP3_IIN_Master`
- [ ] dnp3: add `DNP3_DL_Bad_CRC`
- [ ] ethernetip: re-audit `fuzzable=False` in CIP_Path_*
- [ ] ethernetip: flip `Forward_Open.OT_RPI/TO_RPI` to fuzzable
- [ ] ethernetip: add `CIP_Class_Enumeration`
- [ ] iec104: extend `ASDU.TypeId` to reserved (128-135) + vendor (136-255)
- [ ] iec104: add `ASDU.CommonAddress` sweep
- [ ] mms: add `MMS_BER_Tag_Confusion`
- [ ] ads: wire `ADSMonitor` into monitor chain
- [ ] ads: add `ADS_Port_Enumeration`
- [ ] ads: add `ADS_SumReadWrite`
- [ ] snmp: cap walk recursion at 100
- [ ] snmp: add SNMPv3 USM auth-param fuzzing
- [ ] snmp: add v3 SetRequest-PDU
- [ ] snmp: add v3 Trap-PDU
- [ ] snmp: add v3 InformRequest-PDU
- [ ] snmp: add v3 GetBulkRequest-PDU
- [ ] opcua: extend ExtensionObject TypeId group to vendor-reserved 0x6XXX
- [ ] hl7: MSH-12 version sweep
- [ ] hl7: Z-segment injection request
- [ ] mqtt: Sparkplug B payload fuzzing
- [ ] mqtt: MQTT 5.0 reason code sweep
- [ ] coap: explicit `fuzzable=` annotations on Ver/T/TKL/Code bits

### 4.2 Medium (1-3 days each)

- [ ] Migrate SMTP to `StatefulFuzzer`
- [ ] Migrate HTTP to `StatefulFuzzer`
- [ ] Migrate OPC UA to `StatefulFuzzer`
- [ ] Implement `OPCUA_NodeIdEncodingOverflow`
- [ ] Implement `OPCUA_MalformedCert`
- [ ] Implement `OPCUA_State_Confusion`
- [ ] Resolve dead test scaffolding for tase2, hartip, fins, dicom, industrial_ethernet, profinet_dcp (implement or delete tests)

### 4.3 Coverage regression test

- [ ] Verify `tests/unit/fuzz/test_fuzzer_coverage.py` `ICS_AUDIT_REQUEST_COUNTS` updated for every new request above

---

## 5. Open release blockers (audit-identified, not yet fixed)

### 5.1 Safety (active OT)

- [ ] ADS state-change ops require `--confirm`
- [ ] snap7 password-file path leak (don't echo full path to logs)
- [ ] OPC UA security-mode handling correctness review
- [ ] (full list in `/tmp/oida_review_active_ot.md` — 12 items, 7 still open)

### 5.2 Aux protocols

- [ ] HL7 / HART lazy_import theatre — pick a model and stick to it
- [ ] BACnet replace `socket.connect((8.8.8.8, 80))` own-IP detection
- [ ] FHIR phantom flags — implement or gate behind `--experimental`
- [ ] ASTM default port correction (1394 → real ASTM port)

### 5.3 Core framework

- [ ] Layer-1 vs Layer-2 result-shape mismatch in `export_results()`
- [ ] `proto_logger()` contract drift between docstring and `__init__`
- [ ] Delete dead modules: `port_aliases.py`, `login_scanner.py`, `modbus_device_db.py`, `protocol_registry.py` (file)
- [ ] Delete 9 unused exception classes from `exceptions.py`
- [ ] Delete dead helpers from `platform_compat.py`

---

## 6. Real-coverage suite (`docs/REAL_COVERAGE_PROPOSAL.md`)

### 6.1 Axis 1 — scanner field-coverage (in progress: 16/25)

Extend `tests/coverage/scanner/` to remaining protocols. Skip with documented reason where unsupported.

- [ ] dnp3
- [ ] ethernetip
- [ ] ads
- [ ] bacnet
- [ ] knx
- [ ] profinet
- [ ] ethercat
- [ ] can
- [ ] tase2
- [ ] goose/rgoose (decide: in scope?)
- [ ] ocpp
- [ ] astm

### 6.2 Axis 2 — fuzzer CVE replication (NEW — none built yet)

- [ ] Scaffold `tests/coverage/fuzz/test_cve_replication.py`
- [ ] Parametrize over 56 CVE mocks in `compose.cve.yml`
- [ ] Assert crash within N=2000 cases per pair
- [ ] Mark `*-fake` mocks separately (canned response, weight lower)
- [ ] Publish gap report → file as fuzzer items

### 6.3 Axis 3 — Conpot-vs-mock fidelity (NEW — none built yet)

- [ ] Scaffold `tests/coverage/fidelity/test_conpot_diff.py`
- [ ] Diff scanner output between Conpot and Python mock for: modbus, s7, iec104, enip, bacnet
- [ ] Output `tests/coverage/results/fidelity_<date>.json`
- [ ] Classify each disagreement (both-wrong / python-lying / python-incomplete)

### 6.4 CI integration

- [ ] `.github/workflows/coverage-nightly.yml` (cron `0 3 * * *`)
- [ ] Publish dashboard.md to `coverage-dashboard` branch

---

## 7. Documentation

### 7.1 README.md

- [ ] Verify protocol count claim ("25 protocols") matches loader output
- [ ] Verify badge URLs resolve (PyPI, AGPL, Python version)
- [ ] Update install one-liner if extras changed since last edit (2026-05-26)
- [ ] Add a "Real-coverage status" section with link to nightly dashboard once §6.4 lands
- [ ] Screenshot or asciinema cast of a representative scan (modbus + opcua)
- [ ] Quickstart that runs end-to-end on a fresh `pip install oida[modbus]` without docs
- [ ] Trim or update "Supported protocols" table — currently truncates at S7

### 7.2 CHANGELOG.md

- [ ] Add `## [1.0.0] — 2026-07-16` section
- [ ] Group entries: Safety / Security / Correctness / CLI / Fuzzer / Listeners / Cleanup
- [ ] Reference RELEASE_READINESS.md for the 86 audit fixes
- [ ] Note breaking changes (renamed modbus flags `map_rw` → `read_write`, `raw_fc` → `raw_function_codes`)
- [ ] Note any flag-collision resolutions from §3.2 as breaking

### 7.3 docs/

- [ ] `ARCHITECTURE.md`: confirm post-`0b4dd4c4` (auto-call proto_logger) descriptions match code
- [ ] `new-protocol.md`: walk through it against a clean checkout — does it still produce a working scanner?
- [ ] `snmp-tools-comparison.md`: dates back to April; verify still accurate or stamp "as of 2026-04"
- [ ] Move `/tmp/oida_review_*.md` to `docs/audit/` (6 files)
- [ ] STYLE_GUIDE.md: document short-flag collision resolution from §3.2

### 7.4 CLI help text audit

- [ ] Every `--confirm`-gated flag's help text says "(requires --confirm)" AND validate_args enforces it (already done for dnp3 + ethercat — verify the rest)
- [ ] No "not yet implemented" warnings reachable in 1.0 — either implement, gate, or remove

---

## 8. Website / external presence

(No `website/` folder in the repo; treat this as: GitHub repo page, PyPI page, and any future site.)

### 8.1 GitHub repository page

- [ ] About blurb + topics (`ics`, `scada`, `opc-ua`, `modbus`, `iec104`, `security`, `pentesting`, `industrial-control-systems`)
- [ ] Repository description matches README tagline
- [ ] Pin a release-readiness or roadmap issue
- [ ] Releases page: draft 1.0 release notes from CHANGELOG
- [ ] License visible (AGPL-3.0 — confirm SPDX in pyproject)
- [ ] Security policy: `SECURITY.md` exists? (audit found AGPL/DISCLAIMER but no SECURITY.md — add one with private-disclosure email)
- [ ] CODE_OF_CONDUCT.md — add if missing
- [ ] Issue templates: bug, feature, protocol-add
- [ ] PR template
- [ ] Discussion enabled? Decide.

### 8.2 PyPI

- [ ] Project description renders (README.md → `long_description` from pyproject)
- [ ] Classifiers correct (Development Status :: 5 - Production/Stable for 1.0; OSI Approved AGPL; Topic :: Security; Topic :: System :: Networking :: Monitoring)
- [ ] Project URLs (`Homepage`, `Source`, `Issues`, `Changelog`, `Documentation`) populated in `[project.urls]`
- [ ] Extras list documented at top of README
- [ ] Test installation: fresh venv → `pip install oida` → `oida --help`
- [ ] Test installation with extras: `pip install oida[all]`

### 8.3 Future site (if planned)

- [ ] Decide: is there a separate website/landing planned for 1.0? If yes: scope, host, who owns
- [ ] If yes: feature parity check between site copy and README
- [ ] If yes: link from README, link back from site

---

## 9. Process gates before tagging

- [ ] `./scripts/release_check.sh --full` clean on a fresh clone with all mocks up
- [ ] Unit suite: 9,628+ passed, 0 failed (regression baseline from RELEASE_READINESS)
- [ ] Integration suite: re-validated (was "running in background" per audit — confirm numbers)
- [ ] PCAP integration suite: re-validated
- [ ] `ruff check src/oida/ tests/`: clean
- [ ] `ruff format --check src/oida/ tests/`: clean
- [ ] `bandit -lll src/oida/`: 0 HIGH (VNC TripleDES annotated per `2fb24024`)
- [ ] `bandit -r src/oida/`: Mediums down from 69 to ≤5 (xml.dom.minidom false positives annotated)
- [ ] CI matrix runs: Python 3.10 / 3.11 / 3.12 × ubuntu/macos (mentioned in `19912af5` — verify wired)
- [ ] `vulture --min-confidence 80`: down from ~40 unused mock vars (cleanup stale fixtures)
- [ ] `mypy src/oida/` wired in CI informational-only; knx + opcua clusters fixed
- [ ] Pre-commit hooks pass on a clean clone (`ruff` + `vulture` + `mypy` per CLAUDE.md)
- [ ] Tag `v1.0.0` only after all of the above

---

## 10. Risk register

Items that could slip the release if discovered late:

- [ ] CAP_NET_RAW dependence (Layer-2 scanners + 7 fuzzer modules) — confirm clean error message when unavailable
- [ ] Optional-dep gating: confirm `pip install oida[modbus]` does NOT pull every protocol's deps
- [ ] Docker mock health on macOS (some CVE mocks may be linux-only — document)
- [ ] Real hardware test session (do we have access to even one PLC? schedule if yes)
- [ ] Legal review of DISCLAIMER + LICENSE for "authorized testing only" framing (lightweight — confirm with maintainer)

---

## Sequencing (6.5 weeks, T-0 = 2026-07-16)

| Week | Focus |
|---|---|
| W1 (Jun 1–7)   | §0 pre-flight, §5 dead-module deletion, §1.4 / §1.3 small fixes (BACnet IP hack, ASTM port, FHIR phantom flags) |
| W2 (Jun 8–14)  | §3 CLI polish (banners, flag collisions, factory migration) |
| W3 (Jun 15–21) | §4.1 fuzzer small items; §6.2 CVE-replication scaffold |
| W4 (Jun 22–28) | §1.1 active-OT per-feature test gaps; §2.1 listener test files (first half) |
| W5 (Jun 29–Jul 5) | §2.1 listener test files (second half); §2.2 false-positive coverage |
| W6 (Jul 6–12)  | §6.3 fidelity axis; §7 docs (README, CHANGELOG, audit archive); §8 GitHub/PyPI prep |
| W6.5 (Jul 13–16) | Stop-ship fixes only. §9 process gates. Tag. |

---

## Done in this branch (reference)

From recent commits — do not re-do:

- [x] axis 1 scanner coverage (16 protocols) — `134a4d27`, `a914a96e`
- [x] fuzzer optimization roadmap — `5f5d1860`
- [x] IEC104 DATA_TRANSFER transition; modbus length-mismatch correction — `dea6dc90`
- [x] per-protocol fuzzer review notes + `cve_patterns.json` — `249aee17`, `00076bae`
- [x] 1.0 punch list: astm port (partial), hart lazy_import (partial), fhir/opcua phantom flags (partial), crash_hash dedup, single fuzzer DB backend, CI matrix scaffold, CHANGELOG bump — `19912af5`
- [x] README badge + protocol list, drop ai-doc boilerplate — `83efcff6`
- [x] modbus flag renames `map_rw` → `read_write`, `raw_fc` → `raw_function_codes` — `de013849`
- [x] auto-call proto_logger from `connection.__init__`, ARCHITECTURE.md — `0b4dd4c4`
- [x] dedup / setup slop cleanup — `bbcb36cc`
- [x] hl7apy honest ImportError — `3e408f3f`
- [x] bandit false-positive annotations — `2fb24024`
- [x] RELEASE_READINESS report — `94362498`
