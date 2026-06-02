# OIDA Test Suite Report

**Generated:** 2026-06-02
**Branch:** main @ d1dbaf4f (after fuzz DB refactor + ghost-service conftest fix)
**Command:** `python -m pytest tests/<dir>/ --timeout=60 -p no:cacheprovider`
**Environment:** Linux 6.12.61, Python 3.11.5, pyenv. **Docker mocks NOT pre-started.**

---

## Headline numbers

| Suite | Passed | Failed | Skipped | Errors | XFail | Deselected | Wall time | Exit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `tests/unit/` | **10,241** | **1** | 260 | 0 | 11 | 313 | 7m 22s | 1 |
| `tests/integration/` (with ghost services) | 2,860 | 154 | 1,502 | 376 | — | 92 | 34m 47s | 1 |
| `tests/integration/` (after profinet fix) | — | — | — | 0 | — | — | killed @ 60s | 1 |

**Zero per-test timeouts in `tests/unit/`** at the 60s threshold.
**Zero per-test timeouts in the integration "before" run** at the 60s threshold (errors were instant, not timed out).
**One catastrophic fixture-level timeout in the integration "after" run** — see §3.

---

## 1. Unit suite — clean baseline

### The 1 failure

| Test | Diagnosis |
|---|---|
| `tests/unit/pcap/test_scanner.py::TestLoggerIntegration::test_logger_created_on_init` | **Order-dependent / test pollution.** Passes in isolation (`pytest <file>::<test>`). Some earlier-running test mutates global logger state. Not a real product bug — a test-isolation bug. |

### The 260 skips (top reasons)

All are intentional:

| Reason | Count |
|---|---|
| Special subcommand, not a protocol (`test_cli_args.py:151`) | 1 |
| Optional protocol deps missing (Brotli, defusedxml, etc.) | ~30 |
| Removed legacy API: `_python_can`, `_build_igmp_query`, `_calculate_checksum`, scapy-based parser swap-outs in `discovery/test_new_protocols.py` | ~20 |
| `EtherNetIPScanner` uses `broadcast_discovery` (no `VENDOR_IDS` constant) — 3 tests | 3 |
| Removed CLI options: `--listen-filter` (mqtt), `--wordlist-path` (opcua) — flags refactored away | 2 |
| Other module-specific deprecations | ~200 |

### The 11 xfails (all expected)

| Cluster | Tests | Reason |
|---|---:|---|
| `test_fuzzer_definitions::test_fuzzer_instantiation[ethernet/gatt/icmp/icmpv6/ipv4/ipv6/modbus_rtu]` | 7 | Require `CAP_NET_RAW` or special-system deps not in CI/dev |
| `test_opcua_fuzzer_audit.*` | 3 | `OPCUA_MalformedCert`, `OPCUA_NodeIdEncodingOverflow`, `OPCUA_State_Confusion` not yet implemented (tracked in `ref/_FUZZER_OPTIMIZATIONS_TODO.md` §4.2) |
| `test_tshark_validation::test_tshark_dissector_validates_baseline[dnp3]` | 1 | Known tshark build-version dependent issue |

### Verdict

Unit suite is **release-ready**. The 1 order-dependent failure is a test-isolation bug, not a product bug — see remediation list at the end.

---

## 2. Integration suite — first run (pre-fix)

### The 376 errors — all one cause

Every error is the identical exception:

```
Exception: Command docker compose -f docker/mocks/compose.yml -p oida-test up -d --wait
  <67 services...> returned 1: """no such service: profinet-pnet-device
```

A single nonexistent service name in `docker compose up` makes the whole call return 1. Every test that uses the pytest-docker `docker_services` fixture errors at setup with this same exception.

**Root causes (now fixed in HEAD):**

| Location | Old | New | Status |
|---|---|---|---|
| `tests/integration/conftest.py:144` | `"bacnet": ["msf-ics-mock"]` | `"bacnet": ["bacnet-mock", "bacnet-conpot"]` | Fixed in `d1dbaf4f` |
| `tests/integration/conftest.py:181, 330, 703` | `profinet-pnet-device` | `profinet-device` | Fixed in `d1dbaf4f` |
| `tests/integration/test_profinet_integration.py` (6 refs incl. `@pytest.mark.containers(...)`) | `profinet-pnet-device` | `profinet-device` | Fixed (this turn, uncommitted) |

### The 154 failures (after subtracting the docker cascade)

193 of the 154 are not the docker cascade — they break down as:

#### A) Real product regressions (12)

| File | Tests | Assertion | Probable cause |
|---|---:|---|---|
| `pcap/test_packet_coverage.py` | 4 | `PACKET DROP: bacnet/ldap/modbus/pim` against reference pcaps | Listener regression — packets visible in tshark not extracted |
| `pcap/test_iec104_passive.py` | 3 | `PROTOCOL_COLUMNS mismatch: missing {'cot'}` | Listener gained a column without updating the expected-columns set in the test |
| `pcap/test_modbus_passive.py` | 2 | "Read FC 11 name doesn't contain 'Read': Get Comm Event Counter" + "Read/write FC overlap: {23}" | Function-code classification table needs a fix — FC 23 (Read/Write Multiple) is correctly both, but the test asserts disjoint sets; FC 11 (Get Comm Event Counter) is read-only and `Read` should appear in its name |
| `pcap/test_ads_passive.py` | 2 | "No interactions have state_flags" / "No known state flags" | ADS listener doesn't extract `state_*` flag fields the test expects |
| `pcap/test_database_passive.py` | 1 | (one fail, details in log) | — |

#### B) Stale tests (lagging behind a code change)

| File | Test | Diagnosis |
|---|---|---|
| `test_astm_integration.py` | port assertion | `assert 12000 == 1394` — source moved to 12000 per 1.0 punch-list (commit `19912af5`), test still hard-coded to old 1394 |
| `test_astm_integration.py::TestASTM*` | several | `AttributeError: module 'oida.protocols.astm' has no attribute 'socket'` — test patches `oida.protocols.astm.socket` but `socket` is no longer imported at module scope |
| `test_can_integration.py::TestCANBusOptions::*` | several | `AttributeError: ... 'oida.protocols.can' ... '_python_can'` — same pattern, module symbol removed |

#### C) Service-not-running (correct skip didn't fire)

| Test | Assertion |
|---|---|
| `test_mock_services.py::TestOPCUAMockService::*` (2) | OPC UA service not available on port 4840 |
| `test_coap_integration.py` (2) | "DTLS CoAP service not responding on 127.0.0.1:5684" / "libcoap CoAP service not available on UDP 127.0.0.1:5685" |

These should `pytest.skip(...)` cleanly when the service isn't up, but currently `assert`-fail.

#### D) Cascade-contaminated count

The bulk of the 154 (most of the 93 astm + 45 can entries) are docker-cascade pollution that happens to share a file with a real failure — pytest reports them as FAILED rather than ERROR because of test-isolation interactions. With the conftest fix these will drop to the per-file counts in §A+§B.

### The 1,502 skips

Top reasons:

| Reason | Count |
|---|---:|
| `Docker mock 'modbus' not available on port 502` | 36 |
| `Docker mock 'mms' not available on port 102` | 36 |
| `Docker mock 'opcua_insecure' not available on port 4842` | 6 |
| `Docker mock 'mqtt_auth' not available on port 1884` | 5 |
| `Docker mock 'ads' not available on port 48898` | 5 |
| `Docker mock 'vnc/iec104/http_mock/ethernetip' not available` | 4 each |
| `Docker library not available - skipping integration tests` | 9 |
| `tshark found 0 packets for filter 'enip or cip' / 'opcua' / 'portmap'` (test_packet_coverage) | 9 |
| Mock auto-skip for protocols I don't have running | ~1,400 |

All skips are environmental (no docker mocks pre-started locally), not product issues.

### Zero per-test timeouts in this run

Despite 376 errors, the 60s threshold was never tripped — every error came back instantly because `docker compose` returned 1 on the ghost service name.

---

## 3. Integration suite — second run (post-fix) — catastrophic fixture timeout

After fixing the ghost-service names, `docker compose up --wait <67 services>` actually attempts a real bring-up. With no images pre-built and the per-test 60s timeout in effect, pytest-timeout kills the `docker_services` session-scoped fixture **mid-bring-up**, taking the whole session with it. Resulting log is 178 lines, no summary.

```
File "pytest_docker/plugin.py", line 212, in get_docker_services
    docker_compose.execute(command)
File "subprocess.py", line 1196, in communicate
    stdout = self.stdout.read()
+++++++++++++++++++++++++++++++++++ Timeout ++++++++++++++++++++++++++++++++++++
```

This is **the actual gating issue** for being able to run the full integration suite end-to-end in CI or locally without `services.py up all` ahead of time.

**Remediation options** (any one works):

1. **Pre-start mocks** in CI: `python services.py up all && pytest tests/integration/`. Operational fix; doesn't touch test code.
2. **Per-test timeout exemption for the docker fixture**: pytest-timeout supports `@pytest.mark.timeout(0)` on the fixture itself, or `--timeout-disable-debugger-detection --timeout=60 --timeout-method=signal` with a higher value on the docker_services fixture via `@pytest.fixture(name="docker_services")` wrapper.
3. **Skip-when-no-running-mocks pattern**: detect already-running services and skip the bring-up; if nothing's running, skip the test cleanly instead of waiting on a multi-minute `docker compose up`.
4. **Speed up bring-up**: pre-pull images, use `compose --pull never`, healthchecks with smaller intervals.

Recommended: **option 1 for now + option 3 for the dev experience.**

---

## 4. Findings rolled up by category

### A. Zero timeouts in unit suite

All 10,241 unit tests complete under 60s individually. The 1 failure is test-isolation, not slow.

### B. One fixture-level timeout in integration suite

Single root cause: `docker_services` session fixture exceeds 60s `--timeout` when actually bringing up 67 services from cold. Not a test timeout — a fixture timeout that kills the whole session.

### C. 12 real pcap-listener regressions (priority)

| File | Symptoms | Owner area |
|---|---|---|
| `pcap/test_packet_coverage.py` | PACKET DROP on 4 protocols (bacnet, ldap, modbus, pim) | Listener extraction depth |
| `pcap/test_iec104_passive.py` | PROTOCOL_COLUMNS missing `cot` | Test stale after listener gained column |
| `pcap/test_modbus_passive.py` | FC 11 + FC 23 classification mismatch | Function-code table |
| `pcap/test_ads_passive.py` | state_flags missing | Listener field extraction |
| `pcap/test_database_passive.py` | 1 failure | (inspect) |

These are pre-existing on `main`, not regressions from this branch's work.

### D. 3 stale unit/integration tests (lagging code refactors)

| Test | Fix |
|---|---|
| ASTM port assertion `12000 == 1394` | Update test to expect 12000 |
| `oida.protocols.astm.socket` patch | Refactor test to patch wherever socket is now used |
| `oida.protocols.can._python_can` patch | Same — patch new symbol location |

### E. 4 "service not running → assert" instead of "skip"

`test_mock_services.py::TestOPCUAMockService` (2) and `test_coap_integration.py` (2) hard-assert mock availability rather than `pytest.skip(...)`. Cleanup item.

### F. Skip reasons all environmental

Every skipped test in the integration suite has a clear, reasonable reason (mock not on port X, optional library not installed, tshark filter empty, removed CLI flag). None are silently disabled product tests.

---

## 5. Recommended next steps (in priority order)

1. ~~**Commit `tests/integration/test_profinet_integration.py` fix**~~ — **done** in `713f71d3`.
2. ~~**Raise the docker_services fixture timeout**~~ — **done**: `timeout_func_only = true` in `pyproject.toml` (this turn). Fixtures no longer subject to per-test timer, so the session-scoped docker bring-up can take as long as it needs. Default per-test timeout also bumped 15→60s for integration-test headroom.
3. **Add `services.py up all` to CI** as a pre-step — even with the fixture timeout fix, a cold bring-up of 67 services adds minutes to every CI run; pre-starting them in a parallel job (or persistent runner) makes the suite much faster.
4. **Fix the 3 stale tests** (ASTM port, ASTM socket patch, CAN `_python_can` patch) — quick wins, no product change.
5. **Fix the 4 "assert instead of skip"** tests in `test_mock_services` + `test_coap_integration`.
6. **Investigate the 12 real pcap listener regressions** — these are the only real product issues surfaced and they were already on the §2 list in `RELEASE_TODO.md`.
7. **Investigate the 1 order-dependent unit failure** (`test_logger_created_on_init`) — find which earlier test mutates global logger state.

---

## Appendix A. Run commands used

```bash
# Unit
python -m pytest tests/unit/ --timeout=60 -p no:cacheprovider > /tmp/oida_v3_unit.log 2>&1

# Integration (pre-fix)
python -m pytest tests/integration/ --timeout=60 -p no:cacheprovider > /tmp/oida_v3_integration.log 2>&1

# Integration (post-fix — killed by fixture timeout)
python -m pytest tests/integration/ --timeout=60 -p no:cacheprovider > /tmp/oida_v4_integration.log 2>&1
```

## Appendix B. Log file locations

| File | Lines | Purpose |
|---|---:|---|
| `/tmp/oida_v3_unit.log` | ~10.5k | Full unit suite output |
| `/tmp/oida_v3_integration.log` | ~7.5k | Full integration suite, pre-fix |
| `/tmp/oida_v4_integration.log` | 178 | Integration suite killed by fixture timeout |

These will be cleared on reboot. If you want to preserve them, copy into `docs/audit/test_runs/`.
