# Real-Coverage Test Strategy

Goal: answer "how much of a real ICS target's behaviour does OIDA actually
cover" using only the docker mock suites we already maintain. Three
measurement axes, one nightly job, no real hardware required.

Status: design draft. Implementation lands incrementally.

## Three coverage axes

### Axis 1 — Scanner field-coverage %

**Question we want to answer:** for each protocol, when OIDA scans a real
target, what fraction of the fields a real frame contains does the scanner
actually extract into `self.results["data"]`?

**Approach:**

1. Pick the "most-real" target available per protocol — Conpot for the 5
   protocols Conpot supports (modbus, s7, iec104, enip, bacnet); the
   hand-written Python mock for the rest.
2. Run `oida <proto> <target> --format json -o /tmp/scan` against it.
3. Parse the JSON output, flatten to a set of `(section, field_name)` keys.
4. Read the *canonical* field set from `ref/<proto>/tshark_fields.json`
   (already exists per audit — every field tshark knows about for that
   protocol).
5. Coverage % = |extracted ∩ canonical| / |canonical|.
6. Track the per-protocol number over time in a JSON manifest committed
   nightly. Surface regressions as PR comments.

**Deliverable:** `tests/coverage/scanner/test_field_coverage.py` —
parametrised over protocols, skips when the corresponding container isn't
up. Writes `tests/coverage/results/scanner_<date>.json`.

**Expected initial baseline (rough):**

| Protocol | Estimated coverage % | Rationale |
|---|---|---|
| modbus | 70-85% | mature scanner, deep register map work |
| opcua | 60-75% | huge spec, many fields ignored intentionally |
| iec104 | 65-80% | well-modelled in scanner |
| dnp3 | 40-55% | object-group coverage gap (per fuzzer audit) |
| ethernetip | 60-75% | pycomm3 surfaces a lot |
| ads | 50-65% | port enumeration gap |
| bacnet | 55-70% | many vendor extensions |
| mms / tase2 | 40-60% | sparse implementations |
| snap7 | 70-85% | snap7 lib exposes most |

Numbers are guesses; the value of this axis is the *trendline*, not the
absolute first reading.

### Axis 2 — Fuzzer CVE-replication suite

**Question we want to answer:** for each known CVE we ship a vulnerable
mock for, does the corresponding fuzzer actually trigger a crash within
a fixed test budget?

**Approach:**

1. Inventory mapping `cve_id → (mock container, fuzzer module)`:
   - `CVE-2019-14462` → `modbus-cve-2019-14462-fake` → `modbus` fuzzer
   - `CVE-2022-0367` → `modbus-cve-2022-0367-real` → `modbus` fuzzer
   - `CVE-2024-10918` → `modbus-cve-2024-10918-fake` → `modbus` fuzzer
   - `CVE-2017-14491` → `dns-dnsmasq-cve-2017-14491` → `dns` fuzzer
   - `CVE-2017-7651` → `mqtt-cve-2017-7651` → `mqtt` fuzzer
   - `CVE-2019-19135` → `opcua-cve-2019-19135` → `opcua` fuzzer
   - `CVE-2019-19016` → `dicom-cve-2019-19016` → (no dicom fuzzer yet — gap)
   - `CVE-2019-15846` → `smtp-exim-cve-2019-15846` → `smtp` fuzzer
   - `CVE-2020-25681` → `dns-dnsmasq-cve-2020-25681` → `dns` fuzzer
   - `CVE-2020-7247` → `smtp-opensmtpd-cve-2020-7247` → `smtp` fuzzer
   - `CVE-2018-20019` → `vnc-libvncserver-cve-2018-20019` → `vnc` fuzzer
   - (full inventory in `compose.cve.yml` — **56 CVE mocks total** across modbus (5), dnp3 (3), iec104 (3), mms (3), opcua (3), ethernetip (3), bacnet (3), snmp (3), mqtt (3), dns (3), coap (2), http (3), ftp (3), smtp (3), vnc (3), ntp (3), hl7 (3), memcached (3), dicom (1))
2. For each pair: spin up the mock, run the fuzzer with N=2000 test
   cases against it, assert at least one crash event recorded in the
   fuzzer DB.
3. Test fails if no crash → either the mock is broken or the fuzzer
   doesn't cover that CVE pattern. Both are useful signals.

**Deliverable:** `tests/coverage/fuzz/test_cve_replication.py` —
parametrised over the CVE inventory. Skip when the mock container is
unhealthy.

**Failure modes to expect:**

- Some CVE mocks may be inert "fake" PoCs that return a hardcoded crash
  reply on any input. Those tests pass trivially and aren't proof of
  fuzzer competence. Mark with `@pytest.mark.fake_mock` and weight them
  lower in the scorecard.
- Some fuzzers will *not* find their advertised CVE inside N=2000 cases
  because the bug class needs a specific request type the fuzzer
  doesn't include. That's an honest finding — file it as a fuzzer gap.

**Expected outcome on first run:** 50-70% of pairs hit, 30-50% reveal
real gaps that map to entries in `ref/_FUZZER_OPTIMIZATIONS_TODO.md`.

### Axis 3 — Conpot-vs-Python-mock fidelity audit

**Question we want to answer:** when the test suite passes against a
hand-written Python mock, would it also pass against Conpot? If not,
the Python mock is teaching the scanner to expect non-real behavior.

(This replaces the "mock-vs-real-hardware" idea since we don't have real
hardware.)

**Approach:**

1. For the 5 protocols Conpot covers (modbus, s7, iec104, enip, bacnet):
2. Run the scanner against the Conpot container → output A.
3. Run the scanner against the Python mock container → output B.
4. Diff A and B at the `self.results["data"]` level.
5. For each disagreement, classify:
   - **Both wrong, differently** — both mocks are simulations; scanner
     reads what each provides. No bug.
   - **Python mock returns something Conpot doesn't** — Python mock is
     "lying" — scanner has been trained on fiction.
   - **Conpot returns something Python mock doesn't** — Python mock is
     incomplete; integration tests against it under-test the scanner.
6. Surface the diff as a manifest. Conpot is treated as the
   ground-truth proxy.

**Deliverable:** `tests/coverage/fidelity/test_conpot_diff.py` writes
`tests/coverage/results/fidelity_<date>.json` with the diff per
protocol.

**Caveat to document loudly:** Conpot is itself a simulation. It is
*more honest* than our Python mocks because it tries to mimic real
vendor behavior (Siemens S7-1200, Schneider Modicon, Triconex), but it
is not a real device. The audit catches Python-mock invention, not
absolute correctness.

## CI integration plan

```
.github/workflows/coverage-nightly.yml
  schedule: cron '0 3 * * *'
  jobs:
    coverage:
      timeout: 30 min
      steps:
        - checkout
        - pip install -e .[dev,all]
        - python services.py up all
        - python services.py status (wait for all healthy)
        - pytest tests/coverage/ -v -q --junitxml=results.xml
        - publish results/scanner_<date>.json + fidelity_<date>.json
        - python services.py down
```

PR runs do **not** include `tests/coverage/`. They stay fast.

The nightly publishes a single artefact: `tests/coverage/results/latest.json`
with three sections (scanner / fuzz / fidelity). A small `dashboard.md` is
regenerated at the end of the job and committed to a `coverage-dashboard`
branch — that way the trendline is visible in the GitHub UI without
needing external infra.

## Implementation order

1. **Field-coverage scaffold** — `tests/coverage/scanner/`, one test case
   per protocol, single protocol (modbus) first to prove the pattern.
   Uses existing `tshark_fields.json` files. 1 day.
2. **CVE-replication scaffold** — `tests/coverage/fuzz/`. Pick one
   well-known pair (`modbus-cve-2022-0367-real` × modbus fuzzer). Get
   one assertion green. 1 day.
3. **Fidelity scaffold** — `tests/coverage/fidelity/`. One protocol
   (modbus, both python-mock and conpot-modbus). Diff written. 1 day.
4. **Parametrise across all protocols** — fan out the three scaffolds
   over every protocol the docker stack has. 1 day per axis.
5. **Nightly workflow** — `.github/workflows/coverage-nightly.yml` +
   dashboard generation. 0.5 day.

Total to a working nightly: ~5-7 days focused work.

## What the dashboard reads like (sketch)

```
OIDA Real-Coverage Dashboard — 2026-05-26

SCANNER FIELD-COVERAGE
  modbus      ████████████████░░░░  82% (was 78%, +4)
  iec104      ███████████████░░░░░  74%
  opcua       ███████████░░░░░░░░░  56%
  dnp3        █████████░░░░░░░░░░░  44%
  ...

FUZZER CVE REPLICATION
  CVE-2022-0367 (modbus)    HIT in 412 test cases
  CVE-2024-10918 (modbus)   HIT in 1893 test cases
  CVE-2017-14491 (dns)      HIT in 22 test cases
  CVE-2019-19135 (opcua)    MISS in 2000 test cases — GAP
  CVE-2018-20019 (vnc)      MISS in 2000 test cases — GAP
  ...

FIDELITY (vs Conpot)
  modbus    3 disagreements (PCAP capture vendor_id, exception_status, mei_object)
  iec104    1 disagreement
  enip      7 disagreements — Conpot returns 7 CIP objects the Python mock doesn't
  s7        0 disagreements
  bacnet    4 disagreements
```

## Honesty caveats to write into every output

- Conpot is a simulation, not a real PLC. Coverage % is measured against
  Conpot's exposed surface, which is a subset of any real device's surface.
- The 30 CVE mocks vary in realism. "Real" mocks (`*-real`) replicate the
  actual vulnerable library. "Fake" mocks (`*-fake`) return a canned
  crash response on any input — those pass the test cheaply.
- Scanner field-coverage % above 90% probably means the canonical field
  set (`tshark_fields.json`) is incomplete, not that the scanner is
  perfect.

## Questions for follow-up brainstorming

- **Where does fuzzer effectiveness intersect with scanner coverage?**
  A scanner that fails to extract a field can still be fuzzed against
  that field by the fuzzer — but the fuzzer can't *check* it found a
  bug there. Could a unified "field discovery" metric span both?
- **What's the right test budget for CVE replication?** N=2000 is a
  guess. Some CVEs need state setup that takes most of the test budget.
  Per-CVE budgets might be better than a flat number.
- **Can we ingest external pcap corpora?** ICS-CERT, Netresec, GICS have
  public capture sets. Adding them as fixtures pushes "real coverage"
  further toward "real" without hardware.
