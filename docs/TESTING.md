# Running the tests safely

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
- To make a hang **fail fast** instead of freezing:
  `-o timeout_func_only=false --timeout-method=signal --timeout=60`.
- Full lint + the 3.10/3.11/3.12 matrix runs in CI (`.github/workflows/ci.yml`,
  manual `workflow_dispatch`); PRs auto-run lint + unit/contracts on 3.12
  (`pr.yml`).
