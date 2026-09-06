# Running the tests safely

**TL;DR:** `./scripts/run-all-tests.sh` runs all three lanes the right way (and
starts the mocks if needed). The rest of this doc is what it does and why.

`pytest tests/` in one pass **will hang** — `tests/integration` and
`tests/coverage` open real sockets to the Docker mocks, and the repo sets
`timeout_func_only = true` (the 60s timeout guards only the test body, not
fixtures/sockets). Run the suites in **lanes** instead, each with its own flags.

## 1. Unit + contracts (fast, fully parallel)

In-process and stateless — safe at max parallelism:

```bash
uv run pytest tests/unit tests/contracts -p no:randomly -n auto --dist worksteal -q
```

(For a CI-faithful run, add `--ignore=tests/unit/pcap` — those shell out to
`tshark` and are sensitive to its version.)

## 2. Integration (needs mocks; bounded + loadgroup)

```bash
python services.py status                 # mocks must be up & healthy first
uv run pytest tests/integration -p no:randomly -n 8 --dist loadgroup -q
```

- **`--dist loadgroup`, not `worksteal`** — several modules pin themselves with
  `xdist_group` (mms/snmp/hart/iec104/dicom/can) because they share a single
  mock with a low concurrent-connection cap. `worksteal` ignores those pins and
  they flake.
- **`-n 8`, not `-n auto`** — `auto` (16+ workers) OOM-kills heavy mock
  containers and trips an xdist loadscope `KeyError`.

## 3. Coverage (serial)

```bash
uv run pytest tests/coverage -p no:randomly -q   # no -n
```

The scanner-coverage tests hit stateful/UDP mocks (BACnet WhoIs discovery, the
HART hipserver's 600s session pool) that don't tolerate parallel access — run
them **serially**.

## Notes

- A flake under load is almost always mock contention, **not** a code bug.
  Re-run the single test serially before believing it (occasional offenders:
  `iec104` general-interrogation timing, BACnet UDP discovery, HART session-pool
  exhaustion).
- **Known timing-flaky tests auto-retry** (`pytest-rerunfailures`): they carry
  `@pytest.mark.flaky(reruns=2, ...)` so a contention blip self-heals instead of
  failing the lane. The marker is *only* for shared-mock timing — never use it to
  paper over a real bug. (BACnet/HART coverage instead *skip* on a discovery
  miss, since a retry can't help a missing-data case.)
- A test-body hang now **fails fast** with a traceback rather than freezing the
  run — the suite uses `timeout_method = signal`. A hang in a *fixture* or during
  *collection* is still not timed (the Docker fixture legitimately runs >60s);
  for those, add `-o timeout_func_only=false` when the mocks are already up so
  setup is just a fast health-check.
- Full lint + the 3.10/3.11/3.12 matrix runs in CI (`.github/workflows/ci.yml`,
  manual `workflow_dispatch`); PRs auto-run lint + unit/contracts on 3.12
  (`pr.yml`).
