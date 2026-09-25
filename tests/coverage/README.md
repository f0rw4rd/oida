# Real-Coverage Test Suite

Measures how much of a real target's surface OIDA actually covers, using
only the docker mock stack. Three axes:

- **`scanner/`** — Axis 1, **implemented**. Per-protocol coverage of the
  semantic surface (`results["data"]` keys) against the live mock target.
- **`fuzz/`** — Axis 2, **implemented**. Drives each fuzzer at its matching
  CVE mock (pairs discovered from `compose.cve.yml` `oida.*` labels) for a
  bounded run and records whether it triggered a crash. Writes a scorecard
  to `cve_replication_<run-id>.json`; hard-asserts only the curated
  `VERIFIED_REPRODUCTIONS` allowlist (see the module docstring).
- **`fidelity/`** — Axis 3, *scaffold*. Case table, probe, and manifest
  writer exist; the diff of scanner output Conpot-side vs. Python-mock-side
  is pending (the test skips with "Fidelity-diff harness pending").

## How to run

```bash
# Start the docker mock stack (or a subset)
python services.py up modbus
python services.py up               # everything

# Run the scanner coverage suite (axis 1)
pytest tests/coverage/ -m coverage -v

# Run the fuzzer CVE-replication suite (axis 2) — needs the CVE mock stack
python services.py up cve
pytest tests/coverage/fuzz/ -m cve_replication -v   # OIDA_CVE_CASE_CAP tunes the budget

# Results land in tests/coverage/results/{scanner,cve_replication}_<run-id>.json
cat tests/coverage/results/*.json
```

Tests skip cleanly when:
- The target container isn't reachable on the host.
- The protocol's optional Python dep isn't installed (`bacpypes3`, `yadnp3`, …).

## Skipping the suite

The `coverage` marker keeps these tests out of normal PR runs. They are
opt-in:

```bash
pytest tests/                     # runs unit + integration, NOT coverage
pytest tests/ -m coverage         # runs only the coverage suite
pytest tests/coverage/            # same thing, by path
```

## What the output looks like

Each test appends a record to `tests/coverage/results/scanner_<run-id>.json`:

```json
{
  "protocol": "modbus",
  "target": "127.0.0.1:5503",
  "target_name": "modbus-conpot",
  "semantic_coverage_pct": 42.9,
  "semantic_populated": ["connection_type", "scan_results", "server_info"],
  "semantic_missing": ["device_id", "diagnostics", "function_codes", "units"],
  "wire_coverage_pct": 0.0,
  "wire_field_count": 7
}
```

- `semantic_coverage_pct` — the headline number: % of curated
  expected keys actually populated by the scan.
- `semantic_populated` / `semantic_missing` — the diff. Gaps point
  either to a scanner that doesn't reach a feature, or to a mock that
  doesn't expose it. Use it to refine `surface.py` or fix the scanner.
- `wire_coverage_pct` — % of fields in `ref/<proto>/tshark_fields.json`
  visible in scanner output. **Reported, not yet asserted** — the
  semantic structure of scanner output doesn't 1:1 match wire field
  names for ICS protocols (the dissector exposes framing fields; the
  scanner exposes parsed PDUs).

## Adding a new protocol

1. Pick the docker container(s) that target the protocol — prefer Conpot
   where available, fall back to Python mocks.
2. Add the protocol's expected semantic surface to `scanner/surface.py`
   under `EXPECTED_SURFACE`. Generate the candidate list with:
   ```bash
   grep -rhE 'self\.results\["data"\]\["[^"]+"\]' src/oida/protocols/<proto>/ \
     | sort -u
   ```
   Prune to keys a maximal scan against a real target would actually
   exercise.
3. Add a test in `scanner/test_field_coverage.py`:
   ```python
   @pytest.mark.coverage
   def test_<proto>_coverage(coverage_results_dir):
       ensure_protocol_dep("<dep>")
       host, port, target_name = container_target(
           ("<proto>-mock", <port>),
           ("<proto>-conpot", <fallback_port>),
       )
       from oida.protocols.<proto>.nxc_connection import <proto>
       args = make_args(port=port, rhost=host, ...)
       scanner = <proto>(args, None, host)
       ...
   ```
4. Run it once locally to confirm it works:
   ```bash
   python services.py up <proto>
   pytest tests/coverage/scanner/test_field_coverage.py::test_<proto>_coverage -v
   ```

## Run identifier

Set `OIDA_COVERAGE_RUN_ID` to group multiple test results into one
manifest. The coverage workflow (manual dispatch) sets this to the GitHub run ID:

```bash
OIDA_COVERAGE_RUN_ID=nightly-2026-05-26 pytest tests/coverage/ -m coverage
# → tests/coverage/results/scanner_nightly-2026-05-26.json
```

Without the env var the file is named `scanner_manual-<today>.json`.

## Caveats

- Conpot is a simulation, not a real PLC. Coverage % is measured against
  Conpot's exposed surface, which is a subset of any real device's surface.
- The Python mocks vary in realism. `modbus-mock` in particular has been
  observed crash-looping on some hosts (pymodbus simulator config issue);
  the test falls back to `modbus-conpot` in that case.
- Above 90% probably means `EXPECTED_SURFACE` is incomplete, not that the
  scanner is perfect.
