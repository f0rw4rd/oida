# 100k-Line Reduction Plan

**Goal:** remove ~100,000 lines from a 628,608-line repo (337,719 src + 290,889 tests) **without losing a single feature** — purely by deleting what is dead, collapsing what is duplicated, and abstracting what was written N times.

Every number below was measured, not estimated. The commands that produced them are in `scripts/quality/`. Where a number looked good but was wrong, the correction is shown — see §0.

---

> ### UPDATE 2026-07-25 — two levers shrank badly once verified
>
> Executing lever D exposed two more bad measurements. Both are corrected in §1
> and detailed in §0.4 / §0.5. **The safe target is ~39k, not ~50k.**
>
> | Lever | Plan said | Verified | Why |
> |---|---|---|---|
> | D — no-assurance tests | 656 tests / 7,250 lines | **339 tests, and they should be FIXED not deleted** | The `mock-only` detector keyed on the substring "mock" and flagged `mock_host` — this project's name for the Docker mock server. 97% false positives. |
> | E — dead code | ~5,000 lines | **64 symbols / ~947 lines** | Vulture reports suspicion, not proof. 1,139 of its 1,217 candidates are genuinely referenced. |
>
> **Done so far**
>
> | Lever | Result |
> |---|---|
> | D (partial) | 23 skip-stubs deleted, 150 lines. Collection 21,715 → 21,692. Orphaned section banners replaced with honest `NOT COVERED` notes. Detector rebuilt and validated against hand-verified ground truth. |
> | E (complete) | **62 symbols / 1,036 lines removed.** `dead_code_verify.py` now reports **0** removable — fixpoint reached. |
| B1 (partial) | F44 `PROTOCOL_CATEGORIES` done: `fuzz/protocols/__init__.py` now imports from `_metadata.py` instead of redefining the 95-line dict byte-for-byte. Verified identical at runtime before and after (13 categories, 49 protocols mapped). Remaining: F45, F46, F47. |
>
> **Running total: ~1,132 lines removed** (`src/oida` 337,719 → 336,587), all 7 gates
> green, no test regressions.
>
> Lever E took three rounds: deleting the first 59 symbols exposed 3 more that only
> the deleted code referenced, plus 2 imports that became unused. Test failures are
> identical to the pre-existing baseline (3, none new) and all 8 gates pass.
>
> The verifier also had to learn about **framework callbacks** mid-flight: its first
> run proposed deleting `_set_sqlite_pragma` (`@event.listens_for`, SQLAlchemy calls
> it), `OnOpen`/`OnClose`/`OnTaskStart` (pydnp3 `IMasterApplication`), and
> `event_notification` (asyncua). It now excludes decorated defs — except pure
> language decorators like `@staticmethod`, which it briefly and wrongly treated as
> registrations — and methods of classes whose base comes from outside the project.

## 0. Three measurements that did not survive checking

Stated up front, because a reduction plan built on the wrong numbers deletes working code.

**"24% of src is inline data" was wrong — it is 18%.** The first pass counted nested literals repeatedly, reporting 378% data for `snmpv3.py`. Nesting-corrected: **59,767 lines (18%)**.

**"95 unused classes = 58,781 removable lines" is a trap — the real figure is ~3.** 92 of those 95 are `*PassiveListener` classes loaded dynamically through `__getattr__` at `src/oida/pcap/__init__.py:135`. They are live. Deleting them on vulture's word would remove most of the PCAP subsystem. Only `APCI_Types`, `MQTTPacketTypes` (audit F31) and `ethercat` are genuinely dead. **The dead-code lever is ~5,000 lines, not 63,737.**

**"jscpd will find the duplication" — it will not.** jscpd reports 0.58% (1,167 lines) because it is token-exact and this duplication is copy-paste-then-rename. All duplication figures below come from AST-normalised structural hashing (`scripts/quality/structural_clones.py`).

### 0.4 "656 no-assurance tests / 7,250 lines" — really 339, and mostly fixable

`test_quality.py`'s original `mock-only` rule treated any variable whose name
contained "mock" as a `unittest.mock` object. This project names the Docker mock
server `mock_host` / `mock_service` / `mock_port`, so tests asserting on a **real
socket check** were flagged. It also counted `def test_worker(...)` helpers nested
inside real tests, which pytest never collects.

Rebuilt, the detector resolves `@pytest.fixture` bodies to decide whether a fixture
actually yields a Mock, propagates taint from the **receiver** of a call but never
from its **arguments** (so `scanner.scan(mock_client)` is correctly clean — that is
dependency injection, the pattern we *want*), and only counts collectable tests.

| | original | verified |
|---|---|---|
| no-assert | 181 | 178 |
| skip-stub | 23 | 23 (deleted) |
| mock-only | 452 | **150** |
| tautology | 11 | 11 |

Validated against the audit's hand-verified ground truth: it catches
`test_scanner_registers.py:431`, stays clean on `test_coap_integration.py:169`, and
stays clean on a correctly-rewritten test.

### 0.5 "~5,000 lines of dead code" — really ~947

Vulture reports suspicion. Of its 1,217 candidates, **1,139 are genuinely
referenced**, 10 are implicit dunders (`__getattr__` — the lazy-import machinery
Python calls for you), and 4 are defined in several places. The naive top-20 was
led by `__getattr__` (190 lines), the `ethercat` NXC class (113 lines, loaded by
name through `ProtocolLoader` — 155 references), and the shared CLI arg factories
`add_common_args` / `add_output_options` / `add_export_args`. Deleting any of them
breaks the tool.

`scripts/quality/dead_code_verify.py` applies the audit's own test — zero
non-definition references anywhere in `src/` or `tests/`, including string literals
so registry and `getattr()` lookups count — and converges on **64 symbols / ~947
lines**. That set is almost exactly the audit's hand-verified F23–F37: the dead
`MMSCodec` builders, the `OPCUACodec` decoder half, the dead `ASN1Builder`
builders, `MQTTPacketTypes`, `save_files`, `valid_range`, `get_sequence_info`,
`setup_osi_connection`. Two independent methods agreeing is the strongest evidence
in this document.

---

## 1. The budget

| # | Lever | Measured | Recoverable | Risk |
|---|---|---|---|---|
| A | Fuzz grammar repetition — 259 repeated `Block`/`Request` clusters inside `_define_protocol` | 18,036 dup lines | **~15,000** | Low |
| B | `src/` duplication — base-class adoption (audit F38/F39/F41/F42/F45/F46/F47/F50/F52) | ~12,000 fuzzy; 1,376 exact-structural | **~9,500** | Medium |
| C | Test structural clones — parametrization | 7,035 dup lines | **~6,000** | Low |
| D | Tests that assert nothing — 23 skip-stubs deleted; 339 remain and should be **fixed, not deleted** (§0.4) | 150 lines removed | **~150** | None |
| E | Dead code — ✅ **DONE**, 62 symbols (§0.5) | 1,036 lines | **1,036 removed** | Low |
| F | `vendor_maps.py` → JSON data file | 7,592 of 7,633 lines | **~7,500** | Low |
| | **Subtotal — deletion and abstraction only** | | **~39,100** | |
| G | Remaining fuzz grammar → declarative data | 26,793 lines | **~24,000** | High |
| H | Test-suite consolidation beyond exact clones (298 byte-identical bodies in 133 groups; 452 mock-only rewritten as ~40 parametrized real tests) | ~25,000 | **~24,000** | Medium |
| | **Total** | | **~98,000** | |

**Read this honestly:** A–F is **~39k** and is nearly all mechanical. Reaching 100k *requires* G and H, which are real engineering with real risk. If you want one number to plan against, commit to **A–F (~39k) as the safe target** and treat G+H as a second phase you decide on after A–F lands.

**And a warning the first execution pass earned:** every lever whose size came from a
tool's raw output rather than from verified references shrank by 5–15× under
scrutiny (D by 20×, E by 5×). Levers A, B and C were measured by structural
comparison rather than tool suspicion, which is why they have held. Before
committing to any number here, re-verify it the way §0.4 and §0.5 were verified.

---

## 2. Lever A — fuzz grammar repetition (~15,000 lines)

`src/oida/fuzz/protocols/` is **66,465 lines, the largest area in the repo**, and 49 `_define_protocol()` bodies account for **44,829** of them.

The grammar vocabulary is closed and regular: **29 distinct constructors, 27 distinct kwargs, 12,813 calls**. Top primitives: `Byte` (2,424), `Static` (2,272), `Word` (1,936), `Block` (1,675), `Request` (1,019), `DWord` (960).

Structural hashing finds **259 repeated fragment clusters totalling 18,036 duplicated lines**:
- **12,982 lines repeated *within* a single protocol file** — e.g. `dns.py:2282` has a 12-line fragment appearing **70 times**; `mdns.py` has a 26-copy cluster.
- **5,054 lines repeated *across* protocol files** — `snmpv1.py`/`snmpv2.py` share 90–115-line blocks in at least 7 clusters (`snmpv1.py:248` ↔ `snmpv2.py:289`, `snmpv1.py:466` ↔ `snmpv2.py:495`, …).

**Method.** These are *not* opaque — they are regular structures begging for a loop or a factory:
1. **Within-file repetition → a local helper.** `dns.py`'s 70 copies become one `_rr_block(name, rtype)` helper called 70 times. Same for the `mdns.py` and `snmpv1.py` clusters.
2. **SNMP v1/v2/v3 → a shared module.** The three files total 10,944 lines and share PDU, varbind and community blocks almost verbatim. A `snmp_common_blocks.py` with parameterised builders is the single biggest win in this lever.
3. **Keep `_define_protocol` as the extension point.** It stays one-per-protocol; only its *contents* get factored.

**Verify each protocol before and after — this is non-negotiable:** the generated wire bytes must be identical.
```bash
uv run pytest tests/unit/fuzz/ -k <proto> -x -q
uv run python scripts/quality/structural_clones.py src/oida --baseline .quality/clones.json --fail-on-new
```

---

## 3. Lever B — `src/` duplication (~9,500 lines)

Straight from the audit, in ascending risk. **Do the free ones first.**

**B1 — tables duplicated where the shared module already exists and is already imported (~1,200 lines, near-zero risk):**
- F44 `PROTOCOL_CATEGORIES` — 95 lines, **byte-identical**, `fuzz/protocols/__init__.py:125` vs `fuzz/protocols/_metadata.py:8`, same directory. `__init__.py` never imports `_metadata`. One-line fix.
- F45 `FILE_SIGNATURES` — `discovery/file_carving.py:33` vs `pcap/file_carving.py:39`. **Also fixes a real bug**: the copies drifted and only the pcap one has the GIF `min_size: 800` and trailer-anchoring fixes.
- F47 `LINK_FUNC_PRI_TO_SEC` — `pcap/iec101.py:64` vs `iec103.py:147`, *while `pcap/_iec_common.py` exists and is imported by both*.
- F46 `EIGRP_OPCODES` — verified identical by diff; `src/oida/shared/` already holds the same pattern for 5 sibling protocols.

**B2 — `UDPBroadcastProbeScanner` base class (~1,000 lines):** 21 discovery scanners, 1,070 of 1,123 lines duplicated. `infra.py:72-121` (HID) and `infra.py:219-268` (MSSQL) differ **only by the log prefix string**. Subclasses supply `PORT`, `DISCOVERY_PROBE`, `PROTOCOL_NAME`, `_parse_response()`.

**B3 — the four `pyshark_base.py` abstractions (~7,400 lines, the bulk):**
| Finding | What | Lines |
|---|---|---|
| F38 | `_update_devices` — 43 copies. **The abstraction already exists**: `_ensure_device(data_attr=, protocol_data=)` at `pyshark_base.py:1056`, used by only 22 of 179 call sites. This is adoption, not design. | ~2,015 |
| F39 | Shared `PassiveCredential` + `record_credential()` — replaces 41 `get_credentials_summary`, 13 `_record_credential`, 19 `_is_duplicate`, 36 dataclasses, 94 passthrough properties. Also fixes 67 O(n²) linear scans. | ~2,500 |
| F42 | `DiscoveredDevice` — 96 fields, 80 identically typed `Optional[Dict]`, 28 named `*_passive_data`. Collapse to one `passive_data: Dict[str, Dict]`. Removes the reason F38's manual assignments exist. | ~406 |
| F50 | `_ensure_session(key, factory)` on the base — 18 methods + 21 inline sites; `pyshark_base.py` has **zero** session support today. | ~233 |

Plus F51 `_get_ek_layer_dicts` (7 identical copies of pure PyShark plumbing, ~115) and F52 `cleanup()` (17 overrides where the base already implements it, ~110).

> **Behavioural warning for B3.** F87: there are three mutually exclusive conventions for repeat packets — 91 sites gate on `if is_new:` with no `else` (silently discarding every later packet), 44 merge, 24 write unconditionally. Unifying these **changes output**. Adopt the merging convention, and treat the diff as a bug fix, not a refactor. Do not do this one silently.

---

## 4. Levers C + D — tests (~13,250 lines, and the suite gets *better*)

**D — delete the 656 tests that cannot fail (7,250 lines). Zero risk, because they assert nothing.**

| Kind | Tests | Lines | Why deleting loses nothing |
|---|---|---|---|
| `mock-only` | 452 | 5,002 | Every assertion names a mock the test configured — validates `unittest.mock`, not `oida` |
| `no-assert` | 181 | 2,169 | No `assert`, no `self.assert*`, no `pytest.raises` |
| `skip-stub` | 23 | 79 | `@pytest.mark.skip` + docstring + `pass`; none can ever be un-skipped |

`.quality/tests.json` is the exact work list. **Caveat:** `mock-only` is a heuristic — the audit hand-verified 128 of the 452 (the `tests/unit/modbus/` cluster). Spot-check a sample per file before bulk deletion; where a mock-only test covers behaviour that genuinely matters, replace it with one real assertion rather than deleting outright. Deleting 5,002 lines of tests that test nothing is a *coverage-neutral* change, and it makes the remaining suite trustworthy.

**C — parametrize the structural clones (~6,000 lines).** 42 clusters / 3,946 lines at the strict setting, 128 clusters / 7,035 at the loose one. Biggest:
- `_make_config` — **28 byte-identical copies** across `tests/unit/fuzz/` (378 lines). Move to `conftest.py` as a fixture. This is the same helper-pasting the rewritten `integration-writer` agent now forbids.
- 14-copy and 11-copy clusters in `test_coap_integration.py` / `test_ethernetip_integration.py` / `test_hart_integration.py` — one `@pytest.mark.parametrize` each.
- F60's 23 identical fuzzer tests under 8 different names → one parametrized test.

---

## 5. Levers E + F — dead code and vendored data (~12,500 lines)

**E — delete dead code (~5,000 lines).** `.quality/vulture-baseline.txt` holds 1,217 entries; the removable ones are **232 unused methods (3,326 lines), 26 functions (766), 864 variables/attributes/properties (~864), 3 genuinely dead classes**. Audit findings F23–F37 are the verified core: 18 dead `MMSCodec` methods, 17 dead `OPCUACodec` methods, 9 dead `ASN1Builder` builders, the 100-line IEC-104 "demonstration" block (F25), the `_fuzz_mode` flag that is written twice and never read (F27).

**Do not delete the 92 `*PassiveListener` classes** (§0). Re-run `vulture_gate.py --write-baseline` after each batch so the baseline shrinks and locks in the gain.

**F — `vendor_maps.py` → JSON (~7,500 lines).** 7,592 of 7,633 lines are literal data (99%), stamped `# Update 06.11.2023` — ~2.5 years stale. Move to `src/oida/data/vendor_maps.json` (the directory `CLAUDE.md` already documents for exactly this and which currently holds one 3.6 KB file), load lazily. Ten importers to update — `ethernetip/mixins/discovery.py:18`, `ethercat/constants.py:12`, `snap7/mixins/device_info.py:27`, `profinet/__init__.py:312`, etc. Side benefit: refreshing the tables stops being a code change, and the refresh procedure currently survives only as a shell one-liner in a comment at `vendor_maps.py:1793`.

---

## 6. Levers G + H — the second 50k (higher risk, decide after A–F)

**G — remaining fuzz grammar → declarative data (~24,000).** After A, ~26,800 lines of non-repeated grammar remain. The vocabulary is closed (29 constructors / 27 kwargs), so a YAML schema maps 1:1 and a ~500-line generic builder replaces all 49 bodies. **Be clear about what this is:** the lines move from `.py` into data files rather than vanishing. Net repo reduction is smaller than the Python-LOC reduction. Do it for maintainability — grammar becomes editable without touching code — not to hit a line target. Gate it on byte-identical wire output per protocol.

**H — test-suite consolidation (~24,000).** 298 byte-identical test bodies across 133 groups (209 cross-file), whole files duplicated between `tests/unit/` and `tests/integration/` (F61), and the 452 mock-only tests rewritten as ~40 parametrized tests that actually exercise the scanner. This is where the suite stops being 290,889 lines and starts being trustworthy.

---

## 7. Sequencing

Gates are already armed (`ruff` blocking set, `vulture` at confidence 60, `bandit` with B110/B112, structural-clone and test-quality gates, CI on push/PR, hooks installed). Every step below must leave all of them green.

| Order | Work | Lines | Why here |
|---|---|---|---|
| 1 | **D** — delete no-assurance tests | 7,250 | Zero risk; shrinks the suite you must re-run for every later step |
| 2 | **E** — delete dead code | ~5,000 | Zero-reference-verified; ratchet the vulture baseline down as you go |
| 3 | **B1** — duplicated tables with an existing shared home | ~1,200 | Free, and B1's `FILE_SIGNATURES` fixes a real drift bug |
| 4 | **F** — `vendor_maps` → JSON | ~7,500 | Self-contained, 10 import sites |
| 5 | **C** — parametrize test clones | ~6,000 | Do before B3 so the suite is fast and honest when B3 changes behaviour |
| 6 | **A** — fuzz grammar repetition | ~15,000 | Biggest safe win; per-protocol, verify wire bytes each time |
| 7 | **B2** — broadcast scanner base | ~1,000 | Self-contained new base class |
| 8 | **B3** — the four `pyshark_base` abstractions | ~7,400 | Largest and riskiest of the safe tier; **F87 changes behaviour — ship it as a fix, with tests** |
| | **Safe target reached** | **~50,250** | |
| 9 | **G / H** — decide after 1–8 land | ~48,000 | Re-scope with real data from the first phase |

**The rule that keeps this honest:** every step is *deletion or extraction*, never rewriting. If a step needs new behaviour, it is not part of this plan — it is a feature, and it belongs in its own change. A green test suite plus a green `structural_clones` gate plus unchanged wire bytes is the definition of done for each step.

**And the reason the gates came first:** at the observed 29,900 LOC/day, the duplication removed here reappears in roughly three days of ungated generation. Reduction without the ratchet is a treadmill.
