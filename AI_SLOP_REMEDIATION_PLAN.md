# Remediation & Prevention Plan

**Companion to:** `AI_SLOP_AUDIT.md` (107 findings, 2026-07-24)
**Two questions this answers:** how do we clear the debt, and why did 107 findings accumulate in a repo that already has a linter config, a hooks config, a CI pipeline, and 13 quality agents?

---

## Part 0 — Root cause: the gates were never armed

This is the finding that matters most, because every remediation below is wasted if the gates stay as they are. The repo *looks* well-governed. Measured, nothing fires.

### 0.1 No automated gate runs at all

| Layer | Configured | Actually runs |
|---|---|---|
| GitHub Actions CI | `ci.yml` with lint + vulture + bandit + tests | **Never.** `on:` is `workflow_dispatch` + `workflow_call` only. The file says *"Auto push/PR triggers were removed intentionally — CI is opt-in."* `gh run list` shows no CI run on `main` — only Dependabot and release jobs. |
| pre-commit hooks | 9 hooks in `.pre-commit-config.yaml` | **Never.** `.git/hooks/` contains only `post-checkout`, `post-commit`, `post-merge`, and a `pre-push` that is **git-lfs**, not pre-commit. `pre-commit install` was never run. |

So the ruff/vulture/bandit/pytest gates described in `CLAUDE.md` are documentation, not enforcement. 628k LOC landed with no automated check.

### 0.2 The configured gates are calibrated just outside the pathology

Even armed, four of them would have missed the audit's findings — in three cases by a hair:

**Ruff has no `select`.** `[tool.ruff.lint]` sets only `ignore` and `per-file-ignores`. With no `select`, ruff runs its default `E4/E7/E9/F` set. `ruff check src/oida/` — the exact CI command — returns **zero findings today**, while a broad rule set returns **5,436**. The gate is green because it isn't looking.

**And the one exception rule that *is* default-on shaped the code around itself.** `E722` (bare `except:`) is in ruff's defaults, and the codebase is 100% clean of bare excepts — while carrying **120 `except BaseException:`** across 9 async BACnet files (finding F14), which is functionally identical and evades E722. The gate didn't prevent the pathology; it selected for a variant that survives it.

**Vulture is set one confidence band above the pathology.** The gate is `--min-confidence 80`. At 80, vulture reports only unused *variables* — 2 findings. At **60**, it reports **1,366**, including **247 unused methods** and **95 unused classes**. Every dead-code finding in the audit (F23–F37: 18 dead `MMSCodec` methods, 17 dead `OPCUACodec` methods, and the rest) lives in the 60–79 band the gate excludes. `vulture src/oida/fuzz/core/codecs/mms.py --min-confidence 80` returns **0**.

**Bandit skips the exact mechanism behind the three critical findings.** `[tool.bandit] skips` includes **`B110` (`try_except_pass`)** and **`B112` (`try_except_continue`)`** — precisely the construct in F11 (`snap7/mixins/security.py:249`), F12 (`:300`), and F13 (`bacnet/sc_tls.py:198`), where a crashed security check reports "clean".

**Nothing checks duplication.** No jscpd, no pylint `R0801`, nothing in CI or hooks.

### 0.3 The vulture gate is red on committed code right now

`vulture src/oida/ .vulture_whitelist.py --min-confidence 80` exits **3**, on `src/oida/pcap/smartinstall.py:284-285` (unused `director_port`, `switch_port`), committed in `d823fc3` and unmodified since. The CI lint job would fail today. Nobody noticed because it never ran.

### 0.4 The off-the-shelf duplication tool would not have helped

Worth knowing before buying a solution: **jscpd finds 0.58% duplication here** (1,167 lines, 75 exact clones) against the audit's ~12,000 structurally-duplicated lines. jscpd is token-exact; this codebase's duplication is copy-paste-**then-rename**. The industry-standard gate is close to blind to the AI-generated shape of the problem. This drove the tooling choice in Part 1.

### 0.5 The agents are duplication factories with weak gates

From the survey of all 13 `.claude/agents/*.md` plus `.claude/workflows/slop-check.js`:

- **`listener-quality-auditor.md`** is the single largest source. It carries **10 verbatim fix recipes at lines 428–545**, including a client/server device-tracking template at **line 455**, and is scoped to *"fix all listeners in the category"* one at a time. That template becomes the **43 near-identical `_update_devices()`** of finding F38. Its completion gate is `python -c "import ..."` — a parse check. **No test run, no lint.** It is the weakest-gated code-writing agent in the repo.
- **`integration-writer.md`** does the same for tests: a full file skeleton at **line 172**, per-file helpers (`_all_messages`, `_assert_log_has_events`) pasted into every generated file, and 8-tier fuzzer templates at **643–761** whose helpers `_has_real_traceback` (736) / `_get_request_names` (753) go verbatim into each module → finding F60 (23 identical fuzzer tests). It also **explicitly sanctions `pytest.skip("…")` bodies** at lines 649, 674, 703 as the approved fallback → finding F58 (24 skip stubs). Its doctrine *"mock data is ground truth"* (line 14) plus mock-shaped Category-A templates (line 245) → finding F53 (128 mock-only modbus tests).
- **`fuzzer-quality-auditor.md`** has a gate that loosens itself: line 265, *"if generated tests fail, adjust thresholds to match reality."*
- **`senior-dev.md`** (the general code writer, `model: opus`) instructs *"preserve existing patterns"* — which, with no counterbalancing "find the shared base class first" rule, reads as *copy the sibling module*. It also points at things that no longer exist: its stated test command **`run_tests.py` is MISSING**, its key path **`ref/{name}/` is MISSING**, and it describes the framework as **"11+ protocol scanners"** (there are 26).
- **`vuln-service-generator.md`** has **no YAML frontmatter**, so it is not registered as a selectable subagent at all.
- **`slop-check.js` is per-file.** Its Layer-2 prompts audit one file each and it defaults to the 25 largest files. A clone spread across 43 committed files never co-occurs in one window. It *counts* `except Exception` but its own calibration prompt (lines 388–393) tells reviewers **not to flag** the log-and-continue pattern, and down-weights `fuzz/protocols` density.

**Two un-owned clusters:** the 21 broadcast-probe scanners (F41) and 24 `_create_socket` overrides (F48) match no agent — F48 traces to the `fuzz-section-4.js` workflow's per-protocol fan-out with no shared-helper directive.

---

## Part 1 — Arm the gates (do this first; most of it is free)

Ordered by leverage ÷ cost. **Steps 1.1–1.4 cost zero remediation work** — measured, not assumed.

### 1.1 Turn CI on — 1 line

```yaml
on:
  push: { branches: [main] }
  pull_request:
  workflow_dispatch:
  workflow_call:
```
Fix the two `smartinstall.py:284-285` unused variables first (§0.3), or CI goes red on the first run.

### 1.2 Install the hooks — 1 command

```bash
uv run pre-commit install --install-hooks -t pre-commit -t pre-push -t commit-msg
```
Add it to the documented dev setup in `CLAUDE.md` so a fresh clone is governed by default.

### 1.3 Ruff: add a blocking `select` — **verified at 0 violations today**

Every rule below returns **zero** on the current tree, so this is adoptable immediately with no cleanup:

```toml
[tool.ruff.lint]
select = [
  "E4", "E7", "E9", "F",      # current default behaviour, now explicit
  "F821", "F811",             # undefined / redefined names
  "PLE",                      # pylint errors
  "B006", "B008",             # mutable & call-in-default args
  "S102", "S307", "S608",     # exec, eval, SQL injection
]
```
Add one new rule that is **not** currently clean but should be blocking, because it is the F14 mechanism:

```toml
"BLE001",   # blind except  → 1,864 today; see 1.6 for the ratchet
```

### 1.4 Bandit: stop skipping the critical-finding mechanism

Remove `B110` and `B112` from `[tool.bandit] skips`. These are `try/except/pass` and `try/except/continue` — F11, F12, F13. Expect ~22 hits (17 S110 + 5 S112); triage them as part of Wave 1, which you are doing anyway.

### 1.5 Vulture: drop to the band where dead code lives

Move the gate to `--min-confidence 60` **with a baseline**, not a bare threshold — 1,366 findings can't be fixed in one pass:

```bash
uv run vulture src/oida/ .vulture_whitelist.py --min-confidence 60
```
Ratchet: generate `.quality/vulture-baseline.txt` now, fail only on lines absent from it, and shrink the baseline each Wave-2 batch. Keep `.vulture_whitelist.py` disciplined — it is currently 31 lines and correctly says *"Do NOT whitelist actual dead code."* That discipline is why this ratchet is safe.

### 1.6 Ratchet the 5,436 existing lint findings instead of fixing them

Fixing 1,864 blind-excepts in one PR is not reviewable. Use `ruff --statistics` in CI against a committed baseline, or scope the strict set to changed files:

```bash
uv run ruff check --select BLE001,S110,S112,ARG,RUF012,RUF013,TRY \
  $(git diff --name-only origin/main...HEAD -- '*.py')
```
New code is held to the standard; old code is paid down in waves.

### 1.7 Add the two gates that no off-the-shelf tool provides

Both are written, tested, and committed under `scripts/quality/`, with baselines in `.quality/`.

**`scripts/quality/structural_clones.py`** — AST-normalised cross-file clone detection (identifiers and literals → positional placeholders, structure preserved). This is the gate jscpd cannot be (§0.4). Verified: it independently rediscovered F50 (`_ensure_session`, 7 copies), F51 (`_get_ek_layer_dicts`, 4 copies), F39 (`get_write_operations`, 5 copies) and the `harvest` clusters — **7 clusters, ~410 duplicated lines** on the strict setting. It excludes the legitimate per-protocol extension points (`_define_protocol`, `_format_protocol_columns`, `get_request_definitions`) by default.

```bash
python scripts/quality/structural_clones.py src/oida --baseline .quality/clones.json --fail-on-new
```

**`scripts/quality/test_quality.py`** — finds tests that pass without assurance: `no-assert`, `skip-stub`, `mock-only`, `tautology`. Verified: it independently rediscovered F55 (`test_opcua_integration.py:966`), F56 (`test_hart_mock.py:140`) and F58 (23 of the 24 skip stubs). Current counts: **181 no-assert, 23 skip-stub, 452 mock-only, 11 tautology**.

```bash
python scripts/quality/test_quality.py tests/ --baseline .quality/tests.json
```

Both were canary-tested: they exit **0** against their own baseline and exit **1** naming all three planted violations when a bad test is introduced.

> **Calibration caveat, stated honestly:** the `mock-only` heuristic reports 452 where the audit hand-verified 128 for modbus specifically. Treat `mock-only` as *report-and-ratchet*, not a hard block, until it is spot-checked. `no-assert`, `skip-stub` and `tautology` are precise enough to block on new code today.

**Note on the strict clone number:** 410 lines is the *exact-structural* cluster total. The audit's ~12,000 came from fuzzy similarity clustering, which has more false positives and belongs in a periodic audit rather than a commit gate. Gate on the 410; hunt the 12,000 in Wave 3.

---

## Part 2 — Migrate the code, in waves

Sequenced so each wave is independently shippable and reviewable. Findings reference `AI_SLOP_AUDIT.md`.

### Wave 0 — unblock (hours)
- Fix `smartinstall.py:284-285` so the vulture gate is green (§0.3).
- Decide the fate of the **45 untracked `.py` files** (F4) — 17 complete fuzz protocol modules and 27 test files sitting outside version control, alongside 262 modified files. Commit or delete; do not start Wave 1 on top of an unreviewable tree.
- `.gitignore`: collapse the 13 enumerated `.db` names to `*.db`, add `.claude/`, `.claude-work/`, `results/`, `tmp.*` (F5, F6).

### Wave 1 — correctness (days) — **do not defer any of these**
These change what the tool *reports*, and it is a security tool.
1. **F11, F12, F13** — three security checks that report "clean" when they crashed. Narrow the `except`, and default to `inconclusive`, not `safe`. `opcua/mixins/security.py:429-491` is the in-repo pattern to copy.
2. **F96** — `pip install oida[fuzz]` is broken today. Add `urllib3` and `hpack` to the `fuzz` extra. One line.
3. **F81** — `--seed` does not reproduce (`_random_seeded` never set `True`). Fuzzing results are currently unreplayable.
4. **F80** — fuzz coverage silently downgrades from 27 mutations to 10 while reporting "balanced".
5. **F14** — replace 120 `except BaseException` with `except Exception` so Ctrl-C and asyncio cancellation work.
6. **F82, F83** — `time.sleep()` inside the shared lock serialises every `-t N` scan; unsynchronised `_radamsa` singleton (the correct idiom is in `ics_logger.py:895-901`).
7. **F98, F99, F100** — remove the dead `socks` branch, drop the unused `tqdm` core dependency, resolve the empty `astm` extra.

### Wave 2 — delete dead code (days)
F23–F37: ~600 lines across `MMSCodec` (18 methods), `OPCUACodec` (17), `ASN1Builder` (9), the IEC-104 "demonstration" block (F25), `_fuzz_mode` (F27), and the rest. Deleting is safer than it looks — each was verified at 0 non-def references. Drop the vulture gate to 60 (§1.5) as you go and shrink the baseline batch by batch.

### Wave 3 — collapse duplication (weeks) — biggest payoff, do it in this order
1. **Free wins first (~1,200 lines, near-zero risk):** F44 (`PROTOCOL_CATEGORIES` duplicated byte-identically in the same directory), F46, F47 (tables duplicated while the shared module *already exists and is already imported*), F45 (`FILE_SIGNATURES` — also fixes a real drift bug where one copy kept a defect).
2. **F41** — one `UDPBroadcastProbeScanner` base removes ~1,000 lines across 21 scanners that differ only in a log prefix.
3. **The four `pyshark_base.py` abstractions — F38, F39, F42, F50 — account for ~7,400 of the ~12,000 duplicated lines.** Highest payoff, largest effort. Note F38's abstraction *already exists* (`_ensure_device(data_attr=…)`, used by 22 of 179 call sites); this is adoption, not design.
4. **F87** — pick one of the three device-enrichment conventions and apply it to all 159 sites. This is a behaviour fix, not just cleanup: 91 sites currently discard every packet after the first.

### Wave 4 — tests (weeks)
F53 (128 mock-only modbus tests), F54 (the "Category A strict" claim that isn't), F65 (341 self-skipping tests). Rule: **a test that cannot fail is worse than no test**, because it occupies the budget of a real one. Gate new tests with `test_quality.py` from day one so the pile stops growing while you drain it.

### Wave 5 — docs (one afternoon)
F68–F79. Restore `CLAUDE.md` and `README.md` to describe the system that exists: fix the broken first example (`-t` is a *global* flag), delete the 10 dead Documentation-Map rows, fix the 4 nonexistent "key test files". Preserve the two counts that are correct (26 protocols, 109 listeners).

---

## Part 3 — Adapt the agents

### 3.1 Four rules to add to every code-writing agent

The code-writing agents are `senior-dev`, `listener-quality-auditor`, `listener-field-audit`, `integration-writer`, `pcap-test-fixer`, `docker-builder`, `test-doctor`, `test-fixer`, `vuln-service-generator`. Add a shared block to each:

```markdown
## Non-negotiables

1. SEARCH BEFORE YOU WRITE. Before adding a method, constant table, or helper,
   grep for an existing one: the base class (`pcap/pyshark_base.py`,
   `fuzz/core/base_fuzzer.py`, `connection.py`, `discovery/base.py`), the shared
   modules (`src/oida/shared/`, `src/oida/utils/`), and two sibling modules.
   If a base helper exists, CALL IT. If three siblings need the same code,
   the code belongs in the base class — say so and stop, rather than writing
   a fourth copy.

2. DELETE WHAT YOU REPLACE. If you supersede a method, remove the old one in
   the same change. Never leave it "in case". Verify with:
   `grep -rn "\bNAME\b" src tests | grep -v "def NAME"` → must be empty.

3. WIRE IT OR DON'T WRITE IT. Every symbol you add must have a caller in the
   same change. A method with no caller is not a feature, it is debt. Verify
   with the same grep.

4. YOU ARE NOT DONE UNTIL THE GATES PASS. Run, and paste the output:
     uv run pytest <relevant tests> -x -q
     uv run ruff check --fix <changed files>
     python scripts/quality/structural_clones.py src/oida --baseline .quality/clones.json --fail-on-new
   Never weaken a gate to pass it: do not add `pytest.skip`, do not relax an
   assertion, do not widen an `except`, do not add to `.vulture_whitelist.py`.
   If a gate is wrong, say so and stop — do not route around it.
```

Rule 4's last clause directly overrides `fuzzer-quality-auditor.md:265` (*"adjust thresholds to match reality"*).

### 3.2 Per-agent changes

**`listener-quality-auditor.md` — highest priority.** The 10 verbatim recipes at lines 428–545 are the F38 factory.
- Replace each code template with a *directive* naming the base helper: instead of pasting the device-tracking block (line 455), say *"call `self._ensure_device(..., data_attr=…, protocol_data=…)` — see `pyshark_base.py:1056`. Do not assign `device.<proto>_passive_data` manually."*
- Same for `harvest()` (428), `_record_interaction` (468), the dedup set (522), MAC lookup (512).
- **Replace the gate.** `python -c "import"` becomes the §3.1 rule-4 block. This agent writes production listener code across dozens of files with only a parse check.
- Add: *"You are editing one of 109 sibling listeners. If your fix applies to more than three, stop and propose a base-class change instead."*

**`integration-writer.md` — highest priority for tests.**
- Move the per-file helpers (`_all_messages`, `_assert_log_has_events`, `_assert_log_event_structure`, `_has_real_traceback`, `_get_request_names`) into `tests/integration/conftest.py` and replace the templates at 172/643–761 with imports.
- **Delete the `pytest.skip("…")` template bodies at 649, 674, 703.** Replace with: *"If a tier cannot be tested, write no test and report the gap. Never commit a skipped placeholder."* This closes F58 at the source.
- Qualify the *"mock data is ground truth"* doctrine (line 14): *"Assert on values the scanner returns, not on values you configured the mock to return. If every assertion in a test names only a mock you set up, the test asserts nothing — see F53."*
- Add `python scripts/quality/test_quality.py tests/ --baseline .quality/tests.json` to the completion gate.

**`listener-field-audit.md`** — same template→directive treatment for lines 81–158; its `--fail-on-new` clone check should be in the gate.

**`senior-dev.md`**
- Fix the stale facts: **"11+ protocol scanners" → 26**; remove `ref/{name}/` from Key Paths (deleted); replace the `run_tests.py` commands — **that file does not exist**, so its entire stated verification protocol is currently unrunnable. Use `uv run pytest tests/unit/{name}/ -x -q`.
- Reframe *"preserve existing patterns"* (line 134) → *"reuse existing abstractions. Preserving a pattern means calling the same base helper the siblings call, not copying a sibling's body."*
- Add the §3.1 block.

**`fuzzer-quality-auditor.md`** — delete the self-loosening clause at line 265.

**`cli-quality-auditor.md`** — audit-only, but it has no completion gate; add rule 4 so its optional fixes are verified.

**`vuln-service-generator.md`** — add YAML frontmatter (`name`, `description`, `tools`); it is currently unregistered and unreachable.

**`docker-builder.md`** — templates here are defensible (each mock is genuinely bespoke) and it already has a build gate and an anti-duplication rule. Lowest priority; just add rule 2.

### 3.3 Fix `slop-check.js`'s structural blind spot

It is per-file, so it cannot see cross-file duplication by construction. Two changes:
- Add a Layer-1 deterministic step invoking `scripts/quality/structural_clones.py` across the whole tree, not the diff. This is the only way the 43-file spread becomes visible.
- Revisit the calibration at lines 388–393 that tells reviewers **not** to flag log-and-continue `except Exception`, and the `fuzz/protocols` down-weighting at 536–542. That guidance is why F11–F13 survived prior slop-check passes. Narrow it: log-and-continue is fine in a packet parse loop; it is **not** fine in a function whose return value is a security verdict.

### 3.4 Fix the un-owned clusters

`fuzz-section-4.js` fans out one agent per protocol with no shared-helper directive → F48. Add rule 1 to its per-agent prompt, and add `DEFAULT_PORT` / `DEFAULT_RECV_TIMEOUT` to `BaseFuzzer` so the 24 `_create_socket` overrides have somewhere to go.

---

## Part 4 — Sequencing

| When | Work | Cost |
|---|---|---|
| Day 1 | §1.1–1.4 (CI on, hooks installed, ruff `select`, bandit unskip) + Wave 0 | hours — **§1.3 is verified at 0 violations** |
| Day 1 | §1.7 clone + test gates (written and baselined already) | done |
| Week 1 | Wave 1 correctness + §3.1 rules into the 9 code-writing agents | days |
| Week 1 | §3.2 for `listener-quality-auditor` and `integration-writer` | hours — these two produce most of the duplication |
| Week 2–3 | Wave 2 dead code + §1.5 vulture ratchet | days |
| Week 3–6 | Wave 3 duplication, in the stated order (free wins → F41 → the four base abstractions) | weeks |
| Ongoing | Wave 4 tests, Wave 5 docs | — |

### The one-line version

Arming the gates costs about a day and is mostly free. Adapting two agent files stops most of the duplication at source. Everything else is paying down debt that the gates will prevent from returning — and there is no point starting the paydown until the gates are on, or the next 30k-LOC day puts it all back.
