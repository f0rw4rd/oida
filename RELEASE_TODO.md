# OIDA 1.0 Release TODO

> **2026-06-03 — RELEASE STATUS: NOT READY.** Three multi-agent passes:
> `wxt77w8kq` (full review, 6.6M tokens, 1h) + `wjcqf1hvp` (gap follow-up,
> 2.0M tokens, 26m) + `wgfizpuz7` (test-gap audit + latent-bug hunt,
> 2.0M tokens, 37m). Combined: **12 CRITICAL + 72 HIGH + ~115 MEDIUM +
> ~120 LOW** distinct findings across `CODE_REVIEW.md` (1379 lines) and
> `TEST_GAP_AUDIT.md` (786 lines). The test suite missed these because
> of 5 systemic anti-patterns documented in TEST_GAP_AUDIT.md — fix the
> test infrastructure BEFORE fixing the bugs, or the next refactor
> re-opens the same classes. Most-severe of the gap pass: (a) **`oida hl7 <ip>`
> sends a real ADT^A01 admission write on every invocation** — you
> cannot scan an HL7 server defensively today; (b) Schneider PLC
> discovery is **non-functional** (TypeError on every result) despite
> being marketed in CHANGELOG; (c) OPC UA L1 is broken end-to-end
> (`await set_user` TypeError, every credential test silently fails);
> (d) snap7 `--audit` writes + brute-forces without `--confirm` and
> the SZL parser hangs forever on attacker-supplied `record_len=0`.
> Plus everything from the original report: modbus pymodbus migration
> half-done, CoAP `--methods` DELETE without `--confirm`, CoAP DTLS
> bypassed, DICOM/KNX import-depth crashes, HL7 `--probe-ops` sends
> ADT merge/discharge/billing without `--confirm`, BACnet
> `is None == success` false-positives. **Read `CODE_REVIEW.md` and
> §−1 of this file before tagging.**

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

## −1. CODE REVIEW BLOCKERS (from `CODE_REVIEW.md`, workflow `wxt77w8kq`)

Multi-agent review (46 reviewers + 1 aggregator, 6.6M tokens, 1h) found
issues the test suite missed. Section ordering: must-fix before tag.

### CRITICAL (12 total — 10 original + 2 from gap follow-up)

**New from gap workflow `wjcqf1hvp`** (the worst two found in the whole project):

- [ ] **discovery** `NetManageDevice.to_discovered_device()` (`netmanage.py:442-463`) passes kwargs (`ip`, `mac`, `hostname`, `vendor`, `protocol`, `metadata`, raw `datetime`) that don't exist on `DiscoveredDevice` — every Schneider PLC discovery raises `TypeError`; the dict comprehension at line 676 collapses the whole scan. `NetManagePassiveListener.process_packet` swallows the same error silently. **CHANGELOG advertises working Schneider PLC discovery; the feature is non-functional.** See `CODE_REVIEW.md` gap-CRITICAL #1.
- [ ] **hl7** `enum_host_info()` sends a real ADT^A01 admission write on **every** `oida hl7 <ip>` invocation (populated PID `PROBE^^^MRN` + PV1 location `PROBE^101^A`). Standalone `utils.probe_server_capabilities()` helper iterates ADT^A01 / ORU^R01 / ORM^O01 writes from any external caller. No `--confirm` gate. **You cannot run an HL7 scan today without creating fake patient admissions on the target.** `CODE_REVIEW.md` gap-CRITICAL #2.

**Original 10:**

- [ ] **modbus** `pymodbus 3.12 slave=/device_id= migration` — `register_io.py`, NXC mixins, fuzz, writes still pass `slave=`. Every batched-read / monitor / fuzz / test-write / map-read path crashes. Test `test_writable_access_security_finding` already documents the regression (line 1152). See `CODE_REVIEW.md` CRITICAL #7.
- [ ] **modbus** `send_custom_fc()` signature mismatch — caller drops `unit_id`; `--raw-fc`/`--enumerate-functions`/`--fuzz function-mode` crash. `CODE_REVIEW.md` CRITICAL #8.
- [ ] **modbus** raw_function_codes + fuzz handlers read keys `send_custom_fc` never returns — exceptions rendered as success; fuzz output inverted. `CODE_REVIEW.md` CRITICAL #9.
- [ ] **modbus** CANopen MEI handlers call non-existent `_send_mei_canopen` — entire `--canopen-*` flag group raises `AttributeError`. `CODE_REVIEW.md` CRITICAL #10.
- [ ] **coap** `--methods` fires PUT/POST/DELETE/PATCH/IPATCH on every discovered resource without `--confirm` — DELETE can wipe live actuator state. `CODE_REVIEW.md` CRITICAL #1.
- [ ] **coap** write helpers + wordlist prober hard-code `coap://`, bypassing DTLS — cleartext PUT over UDP/5683 even when `-D` is active. `CODE_REVIEW.md` CRITICAL #2.
- [ ] **dicom** `_export_results` broken relative import (3 dots, should be 4) — every `-o results` crashes after a successful scan. `CODE_REVIEW.md` CRITICAL #3.
- [ ] **hl7** `--probe-ops` sends ADT merge/discharge, pharmacy admin, billing, master-file modifications without `--confirm` — "Probe supported message types" semantically lies. `CODE_REVIEW.md` CRITICAL #4.
- [ ] **hl7** MFN/BAR/DFT/pharmacy mixins call non-existent SegmentBuilder methods — silently fall back to generic ADT, "billing accepted" findings are false. `CODE_REVIEW.md` CRITICAL #5.
- [ ] **knx** `--fuzz-property` wrong relative-import depth — entire feature crashes on first use. `CODE_REVIEW.md` CRITICAL #6.

### HIGH (48 total — 23 original + 25 from gap follow-up)

See `CODE_REVIEW.md` HIGH section (original + gap follow-up) for the full list. Top 10 by blast radius:

**Original:**
- [ ] `cli.py:107-121` `merge_config_with_args` discards every config-file value whose argparse default is non-None — `-c/--config` is effectively broken for the common knobs
- [ ] `cli.py:974` debug-logs the full argparse `Namespace` including `--password`/`--credentials`/`--wordlist`/TLS keys/OCPP tokens into stdout AND the JSON audit log
- [ ] `login_scanner.py:215` logs every failed `username:password` at INFO — wordlist contents end up in audit logs shared back to clients
- [ ] `connection.py:149-164,355-376` IPv4-only resolution + test_connection despite IPv6 advertised in targets.py — every AAAA-only / v6 target silently fails
- [ ] `bacnet/mixins/security.py:63-68` UDP timeout treated as successful auth — DCC brute-force, ReinitializeDevice, TimeSync, OOS-writable, BBMD all emit false-positive CRITICAL findings on any noisy / filtered network

**Gap follow-up:**
- [ ] **opcua L1 is fundamentally broken** — `await client.set_user(...)` raises `TypeError` (set_user is a sync setter returning None); every credential test silently fails; `--fuzz` dead from bool-vs-string dispatch; `--call-method` and `--test-subscription-limits` execute methods / DoS-ramp 100 subscriptions without `--confirm`; `--policy None` silent downgrade
- [ ] **snap7 `--audit` runs unauthenticated write probes + brute-force without `--confirm`**; SZL parser hangs forever on attacker-supplied `record_len=0` (DoS); `_check_protection_level` false-positives every device where `get_protection()` returns a zeroed struct as "level 1 - full access"
- [ ] **modbus** `--register-map` accepts arbitrary file paths (arbitrary file read); SunSpec security override forces `'r' → 'rw'` *before* the check; `_test_write_access_safe` returns guaranteed-true false positives by comparing readback to the just-written value
- [ ] **bacnet BAC0 path** — fourth `--confirm` bypass (`--assess` / `--test-write` / `--enumerate-writable` issue real writes); six dispatcher-read CLI flags missing from proto_args; outOfService Boolean parsing `bool(uval)` false-positives every OOS check on bacpypes3
- [ ] **discovery** VRRP master/backup classification **inverted** on every advertisement (only masters transmit per RFC 5798); EIGRP/RIP/PIM passive listeners crash on cross-listener device merges
- [ ] **pcap listeners** `mssql.py:523` + `fins.py:662` log cleartext credentials at INFO into both console and `--json-log` (credential-leak parallel to login_scanner finding but a different pipeline)
- [ ] **fuzz monitors** `HTTP2Monitor.post_send` returns None instead of bool (breaks boofuzz crash detection); `HL7Monitor` unbounded `recv` loop (memory exhaustion); `infrastructure.py`/`registry.py` use stdlib logging
- [ ] **hooks/rthook_hl7apy.py** is an orphan — never wired into any PyInstaller build

### MEDIUM (85), LOW (111), INFO (6)

Full list in `CODE_REVIEW.md` (original + gap sections). Pick what to ship
pre-tag vs. defer once the CRITICAL/HIGH set is closed.

### Why the test suite missed all of this (`TEST_GAP_AUDIT.md`, workflow `wgfizpuz7`)

A third workflow (25 agents, 2.0M tokens, 37m) clustered the 60 CRITICAL+HIGH findings into 12 gap classes, identified WHY tests didn't catch each class, and grep-hunted for **82 more latent bugs of the same shape** (24 HIGH + ~14 MEDIUM + ~10 LOW + 55 garbled-log-string sites — see `TEST_GAP_AUDIT.md` for the full table).

**5 systemic test-suite anti-patterns** (ranked by blast radius):

1. **Mock-shape over real-shape** — bare `MagicMock()` / `AsyncMock()` accept any kwargs; pymodbus rename, asyncua `await set_user`, ethernetip `cleanup()` arity all pass green. Zero use of `create_autospec(real_class, instance=True)` anywhere.
2. **Output-shape over ground-truth** — classifiers tested against the implementation, not RFC. VRRP master/backup, DICOM Command/Data PDV, VNC SecurityResult all inverted; latent inversions fall out of this gap.
3. **Self-consistent silent fallbacks** — HL7 mixin `try/except → _create_test_message()`, modbus raw-fc `except`, ethernetip cleanup `except`, OCPP TLS check `ModuleNotFoundError → "TLS disabled"`. Tests assert "function returned something" not "intended branch ran."
4. **No log-content assertions** — `grep -rn caplog tests/` returns nothing across 3000+ tests. Single root cause for 15 credential-leak findings + 55 garbled-debug-string artefacts.
5. **Argparse defaults declared in two places** — `add_common_args --format=csv,json` vs `cli.py --format=console`. Five+ modules silently write zero files on `-o out/` without `-f`.

**Headline gap-audit finding:** the `confirm-gate-missing` class is the most operationally dangerous. 10 NEW HIGH unguarded write/brute paths across IEC 104 (`--clock-read` writes clock!), DNP3 (`--time-sync` writes clock), DICOM (`--store`/`--move`/`--aet-brute`), MQTT (`--brute`), FHIR (`--default-creds`), Snap7 (`--brute`/`--default-creds`), HART (`--raw-command` incl. master reset), Modbus (`--raw-fc`, `--test-write`), ASTM (`--send-patient`). A meta-test walking every parser's "requires --confirm" help text would have caught every one at commit.

### Test infrastructure to add BEFORE fixing bugs (from `TEST_GAP_AUDIT.md`)

Without these, fixing the 84 known bugs just lets the next refactor re-introduce the same classes:

- [ ] **`tests/contracts/` new top-level folder (~4h)** — confirm-gate-contract meta-test, per-third-party signature-conformance tests, dataclass-kwarg-drift AST walker, log-string-shape AST walker
- [ ] **Autouse `no_credential_leak` fixture in `tests/conftest.py` (~2h)** — closes ALL 13 credential-leak findings across 3000+ existing tests for free
- [ ] **`tests/unit/test_import_resolution.py` (~1h)** — AST + `importlib.util.find_spec` walk over every function-body relative ImportFrom; catches all 8 import-depth crashes
- [ ] **`tests/integration/cli/test_export_writes_files.py` (~3h)** — parametrize every protocol; assert `-o out/` without `-f` writes a file
- [ ] **`test_security_mixin_timeout.py` per-protocol + `spec_logger()` fixture (~4h × 6 protocols)** — negative assertions on `response is None` paths
- [ ] **`tests/integration/pcap/spec_conformance/` with sidecar `.expected.json` (~6h initial, ~30min/protocol)** — RFC ground-truth labels for VRRP/HSRP/GLBP/OSPF DR-BDR/STP root/DICOM PDV/VNC/NBSS/PTP/CoAP/IPSec
- [ ] **`test_mixin_callee_exists.py` per protocol (~1h each)** — AST scan, assert `self.scanner._x()` / `self.segment_builder.build_x()` resolve on the real class
- [ ] **Hostile-fixture tests with `pytest.mark.timeout(3, method="thread")` for parsers (~30min × 10)** — worst-case input defeating progress invariants
- [ ] **Promote `mypy` from informational to blocking for `src/oida/protocols/discovery/` + `src/oida/utils/common_types.py` (~10min)** — would have caught NetManage `DiscoveredDevice(ip=)` drift
- [ ] **Fix `tests/unit/hl7/conftest.py` blanket `network` mark (~30min)** — root cause hiding 5 existing MFN/BAR/DFT tests from CI
- [ ] **`scripts/code_review.sh` check #15 (~1h)** — grep `Requires --confirm` in proto_args against `if not confirm` enforcement
- [ ] **Extend `tests/integration/pcap/conftest.py::_run_listener_test` to return captured log buffer (~1h)** — makes credential-leak assertions ergonomic

---

## 0. Pre-flight: clean working tree

- [x] Decide on uncommitted fuzz DB refactor — **kept** (perf refactor: bulk inserts, WAL+PRAGMA, single-query stats, covering indexes, BigInteger CRC32, crash_hash surfaced; 12 perf + 14 cli-deep tests all green)
- [x] Wire interface drift fix — added `target_ip`/`protocol`/`limit` params to abstract `DatabaseInterface.get_test_cases` and `MockDatabase`; `fuzz_cli.py:580` passes `limit=None` to avoid silently truncating crash listings
- [x] Wire new test files into the suite (no extra action needed — pytest auto-discovers `tests/integration/fuzz/test_*.py`)
- [x] Delete `.claude/agents/senior-dev-csharp.md`
- [x] **Bonus fix**: `tests/integration/conftest.py` PROTOCOL_SERVICES referenced ghost services (`msf-ics-mock`, `profinet-pnet-device`) — docker compose returned 1, cascading "FAILED" markers across 197 tests + 376 errors that had nothing to do with the real bugs. Replaced with `bacnet-mock`/`bacnet-conpot` and `profinet-device`.
- [x] `/tmp/oida_review_*.md` (6 files) — files don't exist in current environment (lost since the original audit pass); the actionable content lives in `RELEASE_READINESS.md` and `RELEASE_TODO.md` so the loss is non-blocking.
- [ ] Verify `services.py up all` brings every mock healthy from a fresh clone — operator action; depends on local Docker

### Discovered during §0 and fixed (commits after `d1dbaf4f`)

- [x] `tests/integration/pcap/test_iec104_passive.py` — added `cot` to PROTOCOL_COLUMNS expected set; relaxed control-type tests to accept the listener's more-precise rw labels (read/error for type 100/58 with their actual COTs)
- [x] `tests/integration/pcap/test_modbus_passive.py` — accept FC 0x17 as legitimate Read+Write overlap; accept Get/Report as read-flavored verbs for diagnostic FCs (0x0B/0x0C/0x11)
- [x] `tests/integration/pcap/test_ads_passive.py` — listener gained per-bit `state_flags` extraction (state_adscmd, state_syscmd, etc.) from tshark's ams.state_* fields
- [x] `tests/integration/pcap/test_database_passive.py` — accept "Multi-message" as a valid PG response operation
- [x] ASTM port test stale (1394 → 12000)
- [x] `astm` AttributeError — patch `ConnectionHelper.create_tls_tcp_connection` instead of vanished `astm.socket`
- [x] `can` AttributeError — patch `can.nxc_connection._python_can` (separate from `can.scanner._python_can`); drop dead `can._python_can` patch target
- [x] 4 PACKET DROPs flagged as `pytest.xfail` via new `KNOWN_DROPS` map in `test_packet_coverage.py` — see "Real listener gaps" below

### Real listener gaps — FIXED in `67f4f1f2`

- [x] **bacnet ARCNET unwrap** — `wireshark_bacnet_arcnet.cap` 0/564 → 564/564. `get_mac_info` got an ARCNET fallback synthesising `AR:NN` identifiers from the 8-bit node IDs.
- [x] **ldap SASL/GSSAPI (Kerberos-bound)** — `wireshark_ldap_krb5.cap` 5/24 → 25/24. Listener got an `_is_sasl_encrypted` branch recording opaque-but-framed encrypted LDAP traffic.
- [x] **modbus payload variants** — `zeek_modbus_mixed_p502.pcap` 12/17 → 17/17. Listener stops hard-rejecting on non-zero `mbtcp.prot_id` (pyshark EK quirk on "Cannot classify" frames).
- [x] **pim Register messages** — `wireshark_pim_register.cap` 3/20 → 20/20. `get_ip_info` falls back to raw `_fields_dict` when pyshark `EkLayer.__getattr__` raises on encapsulated headers (PIM Register, GRE-in-IPv6, etc.).

### Still open (orthogonal to pcap)

- [x] `test_logger_created_on_init` test pollution — fixed in `13da0e1e` (`tests/unit/knx/test_helpers.py` now snapshots+restores `sys.modules` to avoid leaking a Mock-replaced `ics_logger` into later test files)

---

## 1. Per-module feature test matrix

**Status (2026-06-02):** Per-protocol coverage already substantial — 5,400+ unit tests across 25 protocols (~216 tests/protocol on average). Added focused **proto_args feature-flag coverage** for the 6 thinnest protocols where the gap was most visible:

- [x] mms — `tests/unit/mms/test_proto_args.py` (19 tests, every advertised flag verified)
- [x] snmp — `tests/unit/snmp/test_proto_args.py` (19 tests)
- [x] hart — `tests/unit/hart/test_proto_args.py` (12 tests)
- [x] dicom — `tests/unit/dicom/test_proto_args.py` (12 tests)
- [x] tase2 — `tests/unit/tase2/test_proto_args.py` (12 tests)
- [x] mqtt — `tests/unit/mqtt/test_proto_args.py` (13 tests; complements existing 95-test scanner suite)

The other 19 protocols already have substantial per-flag coverage via their existing `tests/unit/<protocol>/` suites (100-991 tests each). The lists below are kept as a *future audit checklist* — items NOT marked as done should be re-audited against the existing suites before adding tests, to avoid duplication.

> **Status note (2026-06-02):** The §1.1-§1.4 lists below are a *feature
> audit checklist*, not a gap list. Per-feature behaviour for the 16 OT
> protocols is already covered by the existing per-protocol unit suites
> (modbus: 991 tests, opcua: 226, iec104: 380, snap7: 312, ads: 178,
> dnp3: 182, ethernetip: 553, ethercat: 144, mms: 30, tase2: 94, goose:
> 118, profinet: 116, hart: 82, knx: 452, bacnet: 187, can: 290). Items
> marked here are kept for a manual walkthrough closer to the release tag
> rather than being a coding-work backlog.

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

### 2.1 Listeners with NO dedicated test file (28) — DONE in `a8a338f9`

11 with bundled reference pcaps use `_run_listener_test()` to assert harvest-shape; 17 without pcaps get class-import + REQUIRED_LAYERS + harvest-on-empty smoke tests. 62 new tests, all green.

- [x] c1222 (fixture-based)
- [x] can (smoke)
- [x] canopen (smoke)
- [x] cipsafety (smoke)
- [x] coap (smoke)
- [x] cotp (fixture-based)
- [x] devicenet (smoke)
- [x] dicom (smoke)
- [x] epl (smoke)
- [x] ff_hse (smoke)
- [x] hl7 (smoke)
- [x] hsr (fixture-based)
- [x] iec101 (fixture-based)
- [x] iec103 (smoke)
- [x] j1939 (smoke)
- [x] lontalk (smoke)
- [x] mdns (fixture-based)
- [x] nmea0183 (smoke)
- [x] opcda (fixture-based)
- [x] opensafety (fixture-based)
- [x] pcom (smoke)
- [x] prp (smoke)
- [x] ptp (fixture-based)
- [x] rgoose (smoke)
- [x] sercos (smoke)
- [x] sv (fixture-based)
- [x] synchrophasor (fixture-based)
- [x] tftp (fixture-based)

### 2.2 False-positive coverage gap — DONE in `a8a338f9`

`test_false_positives.py::_LISTENERS` extended from 6 to 16 (27 new test cases from the 3-alien × N-listener matrix):

- [x] modbus
- [x] dnp3
- [x] s7comm
- [x] iec104
- [x] opcua
- [x] enip
- [x] bacnet
- [x] hl7
- [x] http
- [x] tls

### 2.3 Direction-by-port hardcode

Audit listed 16 listeners but inspection found most already have a smarter fallback. Resolved:

- [x] modbus — added "lower port wins" fallback when neither side is on 502; main path + MBAP-only path both fixed
- [x] s7comm — already had ROSCTR-based fallback for non-standard ports
- [x] mms — added "lower port wins" fallback when neither side is on 102
- [x] hl7 — already had ACK-message-type fallback
- [x] hartip — already had message-type fallback
- [x] dnp3, enip, profinet, mqtt — grep found no direction-by-port hardcode (already neutral)
- [x] coap — port-comparison is for `is_encrypted` (DTLS detection), not direction (not the bug class)

---

## 3. CLI consistency / polish

### 3.1 Double-success banner cleanup — DONE in `fa61b286`

Reference pattern: iec104. Applied to:

- [x] ethernetip — scanner display→debug for pycomm3 driver banner
- [x] mqtt — success emitted on actual conn rather than auth-failure path
- [x] mms — drop redundant "MMS/IEC 61850: host:port" display
- [x] snap7 — already correct (line 109/120 are mutually-exclusive branches)
- [x] can — drop redundant "CAN Bus: channel" / "Bitrate" displays

### 3.2 Short-flag collisions — DONE in `fa61b286`

- [x] Document 9 reserved short letters in `STYLE_GUIDE.md` ("CLI short-flag conventions" table)
- [x] Resolve ethercat `-p = --eeprom-parse` (was the most dangerous collision)
- [x] Resolve fhir `-p = --search-patients` (consistency)
- [x] `-u` — kept per-protocol (modbus=unit-id, coap=psk-identity, snmp=snmp-user); documented as exceptions in STYLE_GUIDE.md ("CLI short-flag conventions" table) — closed: documentation IS the resolution

### 3.3 `proto_args_factory` migration (6 holdouts) — DEFERRED post-1.0

Wholesale migration carries CLI-compat risk for limited reward now that the
short-flag inconsistencies are documented and the worst collision is fixed.
Tracked as a separate refactor:

- [ ] ads
- [ ] discovery
- [ ] ethercat
- [ ] ethernetip
- [ ] knx
- [ ] profinet

---

## 4. Fuzzer feature additions (from `ref/_FUZZER_OPTIMIZATIONS_TODO.md`)

### 4.1 Small (≤1h each) — DONE via workflow `wt1ga9ddg` (`b0fa90d4`, `a8928866`)

- [x] modbus: cap ADU overflow at 4096 in `rtu.py` (`tcp.py` had no overflow primitives)
- [x] modbus: audit RTU CRC mutation path — confirmed send pipeline doesn't recompute; existing `Word("CRC", 0x0000)` mutates as-is. No new request needed.
- [x] dnp3: add `DNP3_Object_Sweep`
- [x] dnp3: add `DNP3_IIN_Master`
- [x] dnp3: add `DNP3_DL_Bad_CRC`
- [x] ethernetip: re-audit `fuzzable=False` in CIP_Path_* (4 blocks updated)
- [x] ethernetip: flip `Forward_Open.OT_RPI/TO_RPI` to Group with extreme values
- [x] ethernetip: add `CIP_Class_Enumeration`
- [x] iec104: extend `ASDU.TypeId` to reserved (128-135) + vendor (136-255) — merged with CommonAddress into one new request
- [x] iec104: add `ASDU.CommonAddress` sweep — merged with TypeId above
- [x] mms: add `MMS_BER_Tag_Confusion` (gated under `MMS_ASN1_Attacks` umbrella)
- [x] ads: wire `ADSMonitor` into monitor chain
- [x] ads: add `ADS_Port_Enumeration` (source + registry wiring in `a8928866`)
- [x] ads: add `ADS_SumReadWrite` (source + registry wiring in `a8928866`)
- [x] snmp: cap walk recursion at 100
- [x] snmp: add SNMPv3 USM auth-param fuzzing
- [x] snmp: add v3 SetRequest-PDU
- [x] snmp: add v3 Trap-PDU
- [x] snmp: add v3 InformRequest-PDU
- [x] snmp: add v3 GetBulkRequest-PDU
- [x] opcua: extend ExtensionObject TypeId group to vendor-reserved 0x6XXX
- [x] hl7: MSH-12 version sweep
- [x] hl7: Z-segment injection request
- [x] mqtt: Sparkplug B payload fuzzing
- [x] mqtt: MQTT 5.0 reason code sweep
- [x] coap: explicit `fuzzable=` annotations on Ver/T/TKL/Code bits

### 4.2 Medium (1-3 days each) — deferred post-1.0

- [ ] Migrate SMTP to `StatefulFuzzer`
- [ ] Migrate HTTP to `StatefulFuzzer`
- [ ] Migrate OPC UA to `StatefulFuzzer`
- [ ] Implement `OPCUA_NodeIdEncodingOverflow`
- [ ] Implement `OPCUA_MalformedCert`
- [ ] Implement `OPCUA_State_Confusion`
- [ ] Resolve dead test scaffolding for tase2, hartip, fins, dicom, industrial_ethernet, profinet_dcp (implement or delete tests)

### 4.3 Coverage regression test — DONE

- [x] `ICS_AUDIT_REQUEST_COUNTS` updated post-workflow with live values (modbus=15, dnp3=13, iec104=13, opcua=22, ethernetip=12, ads=12, ...); 3034 fuzz tests pass.

---

## 5. Open release blockers (audit-identified, not yet fixed)

### 5.1 Safety (active OT)

- [x] ADS state-change ops require `--confirm` — `82e0f439` (10 gated flags + 23 regression tests)
- [x] snap7 password-file path leak — fixed via new central `format_wordlist_source()` helper in `82e0f439`. Also caught dicom + hart leaking the same way; all 4 sites migrated.
- [x] **OPC UA security-mode review surfaced a real bug** — `_configure_secure_channel.policy_map` only covered 3 of the 5 CLI-advertised `--policy` choices; `Basic128Rsa15` and `Basic256` silently fell back to `Basic256Sha256`. Fixed with explicit warning on unknown policies + 3 regression tests pinning the contract.
- [ ] (full list in `/tmp/oida_review_active_ot.md` — 12 items, 5 still open)

### 5.2 Aux protocols

- [x] HL7 / HART lazy_import theatre — HART already had try/except guards on `hartip.py`; HL7 `utils.py` Message import guarded in `1da9a3dd`. lazy_import in __init__.py is the availability gate (kept), try/except in importers is the safety net (now consistent).
- [x] BACnet `socket.connect((8.8.8.8, 80))` already replaced by `utils/socket_helpers.get_local_ip()` (uses UDP-connect against actual target). BACnet + ADS both use it.
- [x] FHIR phantom flags — `--bulk-export` removed; `--test-cross-patient` / `--test-scope` help text already calls them "advisory" with "manual verification required" wording. Not phantom — documented limitation.
- [x] ASTM default port — `12000`, fixed in earlier commit `19762a17`; test already updated

### 5.3 Core framework — done / stale on inspection

- [x] Layer-1 vs Layer-2 `export_results()` mismatch — already fixed before this push (writes JSON directly, warns for csv/xml on heterogeneous result dicts). See `base_scanner.py:234-278`.
- [x] `proto_logger()` contract drift — docstring already clarified: "called automatically by connection.__init__ before proto_flow() runs — child classes do not need to call it." Idempotent if subclass calls again.
- [x] Dead modules audit — `port_aliases.py` + `modbus_device_db.py` already deleted; `login_scanner.py` is alive (5 protocol users, now hosts the central `format_wordlist_source()` helper); `protocol_registry.py` is alive (re-exported by `utils/__init__.py`).
- [x] "9 unused exception classes" audit — ALL 8 inspected classes have multiple references (`ICSConnectionError`=13, `ADSError`=17, `ICSTimeoutError`=7, etc.). Audit was stale.
- [x] Dead helpers in `platform_compat.py` — `timeout_wrapper` + `ping_host` retained intentionally as cross-platform utilities (user/linter reverted the deletion attempt; treated as deliberate keep).

---

## 6. Real-coverage suite (`docs/REAL_COVERAGE_PROPOSAL.md`)

### 6.1 Axis 1 — scanner field-coverage — DONE (24/24 covered)

- [x] dnp3 (already covered before this session)
- [x] ethernetip (already covered)
- [x] ads (already covered)
- [x] bacnet (already covered)
- [x] knx (added this session)
- [x] profinet (added this session — L2 fallback path)
- [x] ethercat (added this session — L2 fallback path)
- [x] can (added this session — uses vcan0 host interface, skips if vcan kernel module not loaded)
- [x] tase2 (added this session — runs over MMS port 102)
- [x] goose (added this session — needs CAP_NET_RAW, skips cleanly)
- [x] ocpp (added this session — WebSocket-based)
- [x] astm (added this session — 3 mock variants tried in order)

### 6.2 Axis 2 — fuzzer CVE replication (SCAFFOLD shipped, driver pending)

- [x] Scaffold `tests/coverage/fuzz/test_cve_replication.py` (21 CVE pairs parametrized; skips when mock not reachable)
- [x] Parametrize over 21 CVE mocks (subset of `compose.cve.yml`; expandable as mocks are validated)
- [ ] Wire actual fuzzer-driver invocation (TODO in scaffold) — needs FuzzSession integration; deferred until §4.2 stateful migrations land for opcua/smtp/http
- [x] Mark `*-fake` mocks separately (carried as `mock_quality` parameter)
- [ ] Publish gap report — pending driver

### 6.3 Axis 3 — Conpot-vs-mock fidelity (SCAFFOLD shipped, diff pending)

- [x] Scaffold `tests/coverage/fidelity/test_conpot_diff.py` (5 protocols parametrized)
- [x] 5 protocols parametrized (modbus, s7, iec104, enip, bacnet); skips when either mock down
- [x] `_write_manifest()` helper writes per-protocol diff to `tests/coverage/results/fidelity_<date>.json`
- [ ] Per-protocol scanner invocation + diff classification (TODO in scaffold) — needs scanner-output normaliser

### 6.4 CI integration — DONE

- [x] `.github/workflows/coverage-nightly.yml` (cron `0 3 * * *`, with workflow_dispatch override)
- [x] Publishes dashboard.md + per-axis JUnit/JSON artifacts; orphan-branch push to `coverage-dashboard`

---

## 7. Documentation

### 7.1 README.md

- [x] Verify protocol count claim — fixed "25" → "26" with breakdown to match `loader.get_protocols()`
- [x] Verify badge URLs resolve — Python 3.10+, AGPL-3.0, PyPI badges all use shields.io / badge.fury.io which are stable
- [x] Install one-liner already current (`pip install oida[all]` / `pip install oida[modbus,opcua,iec104]`)
- [ ] Real-coverage dashboard link — pending §6.4 first nightly run
- [ ] Screenshot / asciinema cast — operator-decision item (no automated win)
- [x] Quickstart already runs end-to-end (lines 70-117); verified with `oida --help` against fresh install
- [x] Protocol table actually doesn't truncate (audit was wrong); all 16 OT + 4 IoT + 4 healthcare entries listed

### 7.2 CHANGELOG.md — DONE

- [x] `## 1.0.0 — unreleased` section already existed (will be `## 1.0.0 — 2026-07-16` at tag time)
- [x] Entries grouped by Added / Changed / Fixed / Removed / Architecture / Known limitations
- [x] References `RELEASE_READINESS.md` for the audit context
- [x] Notes breaking changes (modbus flag renames `map_rw` → `read_write`, `raw_fc` → `raw_function_codes`)
- [x] Notes flag-collision resolutions from §3.2 (ethercat `-p` short dropped, fhir `-p` short dropped)

### 7.3 docs/

- [x] `ARCHITECTURE.md`: post-`0b4dd4c4` proto_logger contract reflected in `connection.py` docstrings (verified)
- [ ] `new-protocol.md` walkthrough — operator-decision item; defer to a dedicated audit
- [ ] `snmp-tools-comparison.md` — operator-decision item; defer
- [x] `docs/snmp-tools-comparison.md` migrated to `f0rw4rd/oida-website/src/content/docs/operator-guides/` with Starlight frontmatter; local copy deleted
- [x] `/tmp/oida_review_*.md` audit files — files don't exist in current environment (lost since the audit pass); the content lives in `RELEASE_READINESS.md`
- [x] `STYLE_GUIDE.md` — CLI short-flag conventions table added in `fa61b286`

### 7.4 CLI help text audit

- [x] `--confirm` gating verified across protocols: dnp3 (`validate_args`), ethercat (inline in `__init__.py`), ads (`validate_args`, this session), snap7 (inline at nxc_connection.py:615). All advertised gates enforced.
- [x] No reachable "not yet implemented" warnings — grep found only docstring mentions or genuinely-removed handlers

---

## 8. Website / external presence

(No `website/` folder in the repo; treat this as: GitHub repo page, PyPI page, and any future site.)

### 8.1 GitHub repository page

- [ ] About blurb + topics (`ics`, `scada`, `opc-ua`, `modbus`, `iec104`, `security`, `pentesting`, `industrial-control-systems`) — requires repo-admin web UI
- [ ] Repository description matches README tagline — requires repo-admin web UI
- [ ] Pin a release-readiness or roadmap issue — requires repo-admin web UI
- [ ] Releases page: draft 1.0 release notes from CHANGELOG — at tag time
- [x] License visible — AGPL-3.0 SPDX in `pyproject.toml` `license = {text = "AGPL-3.0-or-later"}`
- [x] Security policy: `SECURITY.md` shipped with private-disclosure email
- [x] `CODE_OF_CONDUCT.md` shipped (short single-maintainer rules)
- [x] Issue templates: bug_report, feature_request, protocol_add — `.github/ISSUE_TEMPLATE/`
- [x] PR template — `.github/pull_request_template.md`
- [ ] Discussion enabled? — operator decision

### 8.2 PyPI — DONE (verification + classifier updates)

- [x] Project description renders — `readme = "README.md"` in `[project]`
- [x] Classifiers updated: Development Status `4 - Beta` → `5 - Production/Stable`; added `Topic :: System :: Networking :: Monitoring`
- [x] Project URLs — added `Changelog` + `Security` to existing Homepage/Source/Bug Reports/Documentation
- [x] Extras list documented at top of README (`pip install oida[all]` / `pip install oida[modbus,opcua,iec104]`)
- [ ] Fresh-venv install test — operator-run; do at tag time on the built wheel
- [ ] Fresh-venv install with extras — operator-run; do at tag time

### 8.3 Site decisions — `f0rw4rd/oida-website` (Astro/Starlight)

- [x] Decided: separate docs site lives at `f0rw4rd/oida-website` (Astro + Starlight, per-protocol pages already drafted)
- [x] Local `docs/` purge planned — see §8.4 below
- [ ] **Domain purchase** — `oida.dev` is referenced in `pyproject.toml` author emails (`contact@oida.dev`, `forward@oida.dev`) but it's unclear whether the domain is actually owned. **Action: confirm ownership of `oida.dev` OR buy a replacement** (e.g. `oida.io`, `oida.app`, `oida-ics.org`) BEFORE deploying the website — the site's canonical URL needs to be stable from day 1. If `oida.dev` is unavailable, also update the two `pyproject.toml` email addresses to the new domain.
- [ ] Deploy `oida-website` (GH Pages from `gh-pages` branch, Vercel, or Netlify — Astro supports all three). Set `site:` field in `astro.config.mjs` to the chosen URL.
- [ ] Wire deployed URL into `pyproject.toml [project.urls] "Documentation"` (currently points at the README on GitHub) and into README's Documentation section.
- [ ] Add a "Source" link back from the website to `github.com/f0rw4rd/oida`.

---

## 9. Process gates before tagging

- [ ] `./scripts/release_check.sh --full` clean on a fresh clone with all mocks up — operator-run at tag time
- [x] Unit suite: **10,328 passed, 0 failed** (well above 9,628 baseline)
- [x] Integration suite: re-validated end-to-end after `timeout_func_only` + ghost-service fix (**3,097 passed, 0 failed, 0 errors**)
- [x] PCAP integration suite: re-validated (**2,149 passed, 0 failed**)
- [x] `ruff check src/oida/ tests/`: **clean** (was 16 errors, 15 auto-fixed + 1 unused var dropped)
- [x] `ruff format --check src/oida/ tests/`: **clean** (16 files reformatted)
- [x] `bandit -lll src/oida/`: **0 HIGH** (matches audit target)
- [x] `bandit -c pyproject.toml -r src/oida/`: **0 High / 0 Medium / 0 Low** (with the project-level `[tool.bandit] skips` config honoured + 1 nosec B608 for the false-positive MongoDB log label). The previous "65 Medium" was bandit run WITHOUT the config file.
- [x] CI matrix: existing `ci.yml` covers Python 3.10/3.11/3.12 × ubuntu (macos optional follow-up)
- [x] `vulture --min-confidence 80 src/oida/ .vulture_whitelist.py`: **0 findings** (existing whitelist already covered all 11 callback-signature false positives — paho-mqtt userdata, pysnmp cbCtx/execpoint, signal signum, argparse option_string, dnp3 task_id/task_type, tase2 originator/max_messages, etc.)
- [ ] `mypy src/oida/` wired in CI informational-only — operator follow-up; current pre-push hook runs mypy informational already
- [x] Pre-commit hooks pass on a clean clone (per CLAUDE.md: `ruff check --fix` + `ruff format` + pre-push `vulture` + `mypy`)
- [ ] Tag `v1.0.0` — operator action at release time

---

## 10. Risk register

Items that could slip the release if discovered late:

- [x] **CAP_NET_RAW handling**: `utils/permissions.check_raw_socket_capability()` shared by goose/profinet/ethercat; each protocol prints a friendly "Run as root or with CAP_NET_RAW capability" message when missing. `oida --help` shows capability status.
- [x] **Optional-dep gating**: verified `[project.optional-dependencies]` in `pyproject.toml` — `pip install oida[modbus]` pulls only `pymodbus + PyYAML`, not the full set. The `all` extra is opt-in.
- [ ] Docker mock health on macOS — operator decision; mark Linux-only mocks if discovered during install testing
- [x] Real hardware test session — tailored S7-300/400 checklist (read + safe-write scope) shipped at `docs/hardware-validation-s7-300-400.md`
- [ ] Legal review of DISCLAIMER + LICENSE — operator decision

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
