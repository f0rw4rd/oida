# OIDA 1.0.0 — release checklist

Working checklist for the first real release. Items marked **[done]** were
completed and verified on 2026-09-23; everything else is open.

PyPI currently holds only a placeholder `oida-ics` 0.0.1 (uploaded 2026-06-10),
so 1.0.0 is the first real publish.

---

## 1. Version & changelog mechanics

- [x] **[done]** Bump `src/oida/__init__.py` → `__version__ = "1.0.0"`.
      `release.yml` verifies the tag matches this string and hard-fails on drift.
- [x] **[done]** `CHANGELOG.md` heading → `## 1.0.0 — 2026-09-23`.
- [x] **[done]** Changelog entry for the CI tshark-lane fix.
- [x] **[done]** Final read-through of the 1.0.0 Added/Changed/Fixed/Removed
      sections against `git log` since the last tag. Heading date
      (`2026-09-23`) already matched today. Diffed every commit since the last
      commit that touched `CHANGELOG.md` and found two undocumented: the
      pylint duplicate-code cleanup (internal refactor, no behavior change —
      added under Changed) and `0bab5a3` "stop protocol custom monitors from
      evicting CLI monitor extras" (real bug: `--script-monitor`/
      `--valid-case`/`--agent-monitor` were silently dropped whenever a
      protocol's `setup_custom_monitors()` replaced rather than merged the
      monitor list — added under Fixed). Both now documented.
- [ ] Decide whether the **Known limitations** block is acceptable to ship:
      mypy ungated with thousands of errors, 28 of 109 pcap listeners without
      a dedicated test file.
- [ ] Re-read the **Architecture (post-1.0)** block — confirm those refactors
      (opcua/knx parallel L1/L2, six L2-only protocols, deep MROs) are
      genuinely deferrable past a 1.0 API promise.
- [ ] `uv.lock` needs no re-run for the version bump (the editable project
      entry carries no `version =` field, and `pyproject.toml` was not
      touched). Re-check if that changes.

## 2. PyPI publishing prerequisites

- [x] **[done]** `release.yml` header comment corrected: trusted publisher is
      for PyPI project **`oida-ics`** (the GitHub repo is `oida`), and the
      example tag is now `v1.0.0`.
- [ ] Verify the PyPI trusted publisher is actually registered for `oida-ics`
      with owner `f0rw4rd`, repo `oida`, workflow `release.yml`, env `pypi`.
- [ ] Verify the `pypi` GitHub environment exists **with required reviewers** —
      that approval gate is the only thing standing between a tag push and a
      live publish.
- [ ] Dry run: `release.yml` via `workflow_dispatch` with `dry_run=true`.
- [ ] Then `test-release.yml` (GitHub-only release, no PyPI) before the real tag.

## 3. Packaging verification

- [x] **[done]** `uv build` succeeds; the wheel carries all 353 protocol data
      JSONs and the LICENSE. **Re-run after the version bump** and re-check.
- [ ] Clean-venv install of the **bare** wheel (no extras): `oida` banner,
      `oida --help`, `oida modbus --help`. A missing optional dependency must
      produce a clean message, never a traceback.
- [ ] Clean-venv install of `oida-ics[all]` on **3.10 and 3.12**, then a real
      scan against a running mock.
- [ ] `pip install dist/*.tar.gz` — the sdist path must build standalone.
- [ ] Cross-check the extras names in README against
      `[project.optional-dependencies]`.
- [ ] `[tool.setuptools.package-data]` is hand-maintained (and still carries a
      vestigial `data/*.csv` glob with no CSVs in tree) — any data directory
      added before the tag needs its own glob or it silently won't ship.

## 4. CI green on the exact release commit

- [ ] **Commit the working-tree CI fix** (`ci.yml` + `pr.yml` tshark-lane
      split). Until it lands, `ci.yml → test` is red on `main`.
- [ ] Full `ci.yml` green: `test` (3.10/3.11/3.12), `pcap` (pinned tshark),
      `integration` (docker mocks).
- [ ] Local strict run: `scripts/run-all-tests.sh` (unit + integration).
      Note: **tshark is not installed on the current dev box**, so
      `tests/unit/pcap` and the fuzz dissector test hard-fail locally until it is.
- [ ] Quality gates: `ruff check` / `ruff format --check`, bandit baseline,
      `mypy_gate.py`, `structural_clones.py`, `test_quality.py`, and the uv
      lockfile-drift contract.
- [ ] Contract suite specifically — these encode the 1.0 behavioural promises:
      `test_confirm_gate*`, `test_credential_log_leak`,
      `test_reserved_short_flags`, `test_single_dispatch_model`.
- [ ] **Resolve or explicitly accept the known flaky integration cluster**
      (from the 2026-09-23 full run: unit+contracts 18,661 passed / 1 skipped
      clean twice; integration 6,005 passed / 6 failed, different members each
      run, all passing standalone):
      - `tests/integration/test_iec104_integration.py` — one discovery test per
        run under 14-way parallelism.
      - `tests/integration/fuzz/test_definition_execution.py` — 5 tests
        (`OPCUA_Quick_Coverage`, `OPCUA_Baseline`, `IEC104_Baseline`,
        `MMS_Reports`, `MMS_Read_Operations`) assert a mutated packet was sent
        inside a real-time window that a saturated machine violates.
      Either loosen those real-time budgets, mark them `flaky`, or keep them
      out of full-parallel runs — shipping 1.0 with a lane that fails randomly
      makes every future red build ambiguous.

## 5. Standalone binaries

- [ ] Run `build-binaries.yml` on the tag: manylinux_2_28 glibc-floor gate,
      Windows SignPath signing (confirm the credential is still valid),
      per-artifact smoke test.
- [ ] Download the final Linux + Windows artifacts and actually run them
      (`oida modbus --help` plus one scan against a mock).

## 6. Docker mocks / GHCR

- [ ] `services.py` and `docker/mocks/.env.example` default to
      `ghcr.io/f0rw4rd` — verify those images are published **and anonymously
      pullable**, or a fresh clone's `python services.py up core` fails with no
      local `.env`.
- [ ] `mocks-publish.yml` is `workflow_dispatch` only — run it so the published
      images match the 1.0 compose files.
- [ ] Smoke from a scratch clone with no `.env`: `python services.py up core`
      → `status` → one scan per core protocol.

## 7. Docs & community

- [ ] README: protocol count of 26 is correct; re-check the claims that changed
      (FHIR `--bulk-export` removed, `--format xml` removed entirely,
      `oida snap7` canonical with `s7` alias).
- [ ] getoida.dev (separate repo) rebuilt for 1.0: install/quickstart,
      architecture, per-protocol pages, authorized-testing disclaimer.
- [ ] SECURITY.md disclosure channel reachable and monitored.
- [ ] CLAUDE.md doc-map drift: it points at `src/oida/configs/` (no such
      directory) and `ref/` (gitignored, absent from the repo), and omits
      `docs/CRASH_DETECTION_FIDELITY.md`.

## 8. Repo hygiene before tagging

- [x] **[done]** Removed the untracked root scratch file `TEST_REPORT.md`
      (its release-relevant findings are folded into §4 above).
- [x] **[done]** Cleared local `dist/` and `build/` artifacts (both gitignored).
- [ ] Branch `ghcr-default-registry` has **no commits over `main`** — merge or
      close it, and tag from `main`.
- [ ] License consistency: AGPL-3.0-or-later across `pyproject.toml`,
      `LICENSE`, and the trove classifiers.
- [ ] Tag list is currently `v0.9.9-rc6` and `pre-main-sync-stash` — consider
      deleting the stash tag so `v1.0.0` lands in a clean list.

## 9. Cut the release

- [ ] `git tag v1.0.0 && git push origin v1.0.0`
- [ ] Approve the `pypi` environment gate when `release.yml` pauses.
- [ ] Verify the published artifact: `pip install oida-ics==1.0.0` in a clean
      venv, confirm `oida --help` and one mock scan.
- [ ] Confirm the GitHub release carries the changelog section and the binaries.
