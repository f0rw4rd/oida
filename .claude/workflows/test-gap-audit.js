// Test-gap audit: for the 12 CRITICAL + 48 HIGH findings in CODE_REVIEW.md,
// identify (a) why the test suite missed each one — clustered by gap class
// — and (b) search the WHOLE codebase for more bugs of each class. Output:
// TEST_GAP_AUDIT.md with per-gap-class "why missed", "more like it" lists,
// and the new test categories needed to prevent regression.
//
// Token estimate: ~14 analysis agents + 1 synthesiser ≈ 1.0-1.5M output.
// Wall-clock ~20-30 min.

export const meta = {
  name: 'test-gap-audit',
  description: 'For each CRITICAL/HIGH finding in CODE_REVIEW.md: why did tests miss it? Find more of the same class.',
  whenToUse: 'After a large review pass surfaces many bugs, before fixing, to understand the systemic test gaps and find more latent bugs of the same shape.',
  phases: [
    { title: 'Cluster', detail: 'Group the 60 CRITICAL+HIGH findings into ~10 gap classes' },
    { title: 'Why-missed', detail: 'Per gap class: what test category was missing? Reproduce with a unit test that would catch the class.' },
    { title: 'Latent-search', detail: 'Per gap class: grep the whole src/oida/ for more instances of the pattern.' },
    { title: 'Synthesise', detail: 'Write TEST_GAP_AUDIT.md with the systemic fixes' },
  ],
}

// ---------------------------------------------------------------------------
// Gap classes — derived from CODE_REVIEW.md CRITICAL + HIGH sections.
// Each class names the bug pattern and points at the canonical example.
// ---------------------------------------------------------------------------
const GAP_CLASSES = [
  {
    name: 'import-depth-crash',
    description: 'Module-level or function-level `from ...utils.X import Y` with wrong dot count (3 instead of 4). Crashes the first time the importing function is called; passes module-import tests because the import is inside a function body.',
    examples: [
      'src/oida/protocols/dicom/mixins/reporting.py:312 — from ...utils.export_utils (3 dots)',
      'src/oida/protocols/knx/mixins/properties.py:130 — from ...utils.fuzzer (3 dots)',
    ],
    search_pattern: 'function-body relative imports with mismatched dot count vs. file location',
  },
  {
    name: 'runtime-kwarg-mismatch',
    description: 'Call site passes a kwarg the callee no longer accepts (e.g. pymodbus 3.12 removed `slave=` → `device_id=`). Mocked tests stub the call signature; only a real-library invocation crashes.',
    examples: [
      'src/oida/protocols/modbus/{register_io,nxc_connection,mixins/read_write,mixins/writes,mixins/fuzz}.py — slave= vs device_id=',
      'src/oida/protocols/ethernetip/nxc_connection.py:163-169 — cleanup() calls scanner.disconnect() with no args; required connection param',
    ],
    search_pattern: 'kwargs / positional args at call sites that diverge from the current callee signature',
  },
  {
    name: 'callee-not-defined',
    description: 'Method call to `self.scanner._foo(...)` where `_foo` does not exist. AttributeError at runtime; mocked self.scanner sails through.',
    examples: [
      'src/oida/protocols/modbus/mixins/canopen.py — calls self.scanner._send_mei_canopen (does not exist)',
      'src/oida/protocols/hl7/mixins/master_file.py + financial.py — calls SegmentBuilder.build_mfi / build_bar / build_dft / build_pra (none exist)',
      'src/oida/protocols/hl7/mixins/pharmacy.py:202-310 — pharmacy builders use unknown kwargs (silent fallback)',
    ],
    search_pattern: 'method calls where the target method is not defined on the receiver class',
  },
  {
    name: 'confirm-gate-missing',
    description: 'CLI flag whose help text says or implies dangerous behaviour, but `validate_args()` / inline check / dispatcher never enforces `--confirm`. Catches: flags that write, fuzz, brute-force, modify state, or send unsolicited messages.',
    examples: [
      'src/oida/protocols/coap/nxc_connection.py:285-294 — --methods fires DELETE',
      'src/oida/protocols/hl7/mixins/probe.py:15-49 — --probe-ops sends ADT merge/discharge',
      'src/oida/protocols/hl7/__init__.py:507-515 — enum_host_info sends ADT^A01 on every scan',
      'src/oida/protocols/snap7/...:... — --audit runs writes + brute-force',
      'src/oida/protocols/opcua/... — --call-method / --test-subscription-limits without --confirm',
      'src/oida/protocols/bacnet/... — --assess / --test-write / --enumerate-writable on BAC0 path',
      'src/oida/protocols/can/nxc_connection.py:388-436 — --id-scan floods TesterPresent',
    ],
    search_pattern: 'CLI flags that touch network / state / writes / fuzzers without a confirmable enforcement gate; default-scan paths that emit writes',
  },
  {
    name: 'credential-log-leak',
    description: 'Cleartext credential or wordlist content written to stdout / JSON log at INFO/display. Survives because tests do not grep test output for `password=`/`:pass` patterns.',
    examples: [
      'src/oida/cli.py:974 — debug-logs full Namespace incl. credentials/TLS keys',
      'src/oida/utils/login_scanner.py:215 — every failed username:password at INFO',
      'src/oida/protocols/fhir/mixins/security.py:179-184 — brute-force loop INFO',
      'src/oida/pcap/passive/mssql.py:523 — Login7 cleartext password at INFO',
      'src/oida/pcap/passive/fins.py:662 — FINS password= at INFO',
    ],
    search_pattern: 'logger.info/display/print of values that came from --password / --credentials / parsed cred fields',
  },
  {
    name: 'dataclass-kwarg-drift',
    description: 'Code constructs a dataclass with kwargs whose names diverged from the dataclass definition (renames, removals). TypeError at runtime; tests do not construct the result type.',
    examples: [
      'src/oida/protocols/discovery/netmanage.py:442-463 — DiscoveredDevice(ip=, mac=, hostname=, vendor=, protocol=, metadata=) — none exist',
    ],
    search_pattern: 'dataclass / pydantic / NamedTuple constructors at call sites that diverge from current field set',
  },
  {
    name: 'async-sync-misuse',
    description: 'await on a sync function (TypeError "object NoneType cannot be used in await"), or sync call on a coroutine (returns coroutine object, not result). Mock unit tests do not actually run the loop.',
    examples: [
      'src/oida/protocols/opcua/nxc_connection.py — await client.set_user(...) — set_user is sync setter',
    ],
    search_pattern: 'await on calls whose target is sync; sync call on async helpers',
  },
  {
    name: 'timeout-as-success',
    description: '`if response is None: ... # success` predicates that turn a socket timeout / no-reply into a positive security finding. Pollutes every report on noisy networks.',
    examples: [
      'src/oida/protocols/bacnet/mixins/security.py:63-68 — DCC brute-force / TestReinit / TimeSync / BBMD',
      'src/oida/protocols/bacnet/mixins/network.py:438-449 — BBMD foreign-device-registration',
    ],
    search_pattern: 'is None / except Timeout: pass branches that lead to a security_finding() emit',
  },
  {
    name: 'inverted-classifier',
    description: 'Multi-branch classifier (request vs response, master vs backup, success vs failure) inverted by a flipped condition. Tests do not assert classification against an authoritative ground-truth.',
    examples: [
      'src/oida/pcap/passive/vrrp.py — master/backup inverted (RFC 5798 §6.2: only masters advertise)',
      'src/oida/protocols/modbus/mixins/raw_function_codes.py — handlers consume wrong dict keys, exceptions = success',
    ],
    search_pattern: 'classification logic where the predicate could be inverted without a test asserting the correct direction',
  },
  {
    name: 'parser-unbounded-or-hang',
    description: 'Parser loop with no upper bound on input size, no progress requirement per iteration, or that consumes attacker-supplied length without sanity check. DoS class.',
    examples: [
      'src/oida/protocols/snap7/... — SZL parser hangs on record_len=0',
      'src/oida/protocols/coap/helpers.py:275-311 — coap_get_blockwise unbounded assembled payload',
      'src/oida/fuzz/monitors/... HL7Monitor — unbounded recv loop',
    ],
    search_pattern: 'while-loops over response bytes with no cap; recv loops with no max_len; length fields read from peer without sanity check',
  },
  {
    name: 'config-and-default-drift',
    description: 'Configuration plumbing that quietly drops user-provided values (e.g. argparse defaults shadow config-file values; aliased flags break export filenames).',
    examples: [
      'src/oida/cli.py:107-121 — merge_config_with_args ignores config-file values',
      'src/oida/connection.py:349-353 — NetworkConnection only copies args when port unset',
    ],
    search_pattern: 'getattr-based "is set" detection on argparse Namespaces; merge functions that compare to None instead of parser.get_default',
  },
  {
    name: 'garbled-log-string',
    description: 'Refactor artefact — debug log strings that read like pasted source lines (`f"Failed to get s: {e}"` where `s` was the local variable name). 30+ sites in the original report.',
    examples: [
      'src/oida/protocols/discovery/enrich.py, infra.py, core.py, ntp.py, stats.py, dhcp.py, fins.py',
      'src/oida/protocols/hart/, mms/, ethercat/, iec104/, goose/',
    ],
    search_pattern: 'logger.debug(f"Failed to get [a-z]{1,4}: {e}") and other suspicious one-letter / mid-refactor names',
  },
]

const SCHEMA_WHY = {
  type: 'object',
  required: ['gap_class', 'why_missed', 'reproducing_test', 'missing_test_category'],
  additionalProperties: false,
  properties: {
    gap_class: { type: 'string' },
    why_missed: {
      type: 'string',
      description: '2-4 paragraphs: what kind of test would have caught this class? Why did existing tests not? What assertion is missing?',
    },
    reproducing_test: {
      type: 'string',
      description: 'A concrete pytest test (10-30 lines) that would catch the canonical example finding. Write the test like you would commit it — file path, imports, asserts.',
    },
    missing_test_category: {
      type: 'string',
      description: 'Name of the new test category needed (e.g. "end-to-end CLI-flag exercise", "log-grep negative test", "spec-conformance ground-truth fixture")',
    },
    coverage_hint: {
      type: 'string',
      description: 'Where in the repo this category should live (tests/integration/X/, tests/contracts/, etc.)',
    },
  },
}

const SCHEMA_LATENT = {
  type: 'object',
  required: ['gap_class', 'latent_findings'],
  additionalProperties: false,
  properties: {
    gap_class: { type: 'string' },
    latent_findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'file', 'title', 'description'],
        additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          file:     { type: 'string', description: 'file:line of the new finding' },
          title:    { type: 'string' },
          description: { type: 'string' },
        },
      },
    },
    grep_commands_used: {
      type: 'array',
      items: { type: 'string' },
      description: 'The actual grep/grep -r / regex queries you ran. Lets the next reviewer reproduce or extend.',
    },
  },
}

// ---------------------------------------------------------------------------
// Phase 1: per gap class — why missed + reproducing test
// ---------------------------------------------------------------------------
phase('Why-missed')

const whyPrompt = (gc) => `
You are auditing the OIDA test suite to understand WHY a class of bugs
slipped past CI. The bug class is:

  ${gc.name}
  ${gc.description}

CANONICAL EXAMPLES (from CODE_REVIEW.md):
${gc.examples.map(e => '  - ' + e).join('\n')}

JOB:
1. Read the existing test surface (\`tests/unit/\` + \`tests/integration/\`)
   for the protocols / modules where these examples live. Spot-check the
   files; you don't need to read every test.
2. Identify the SHAPE of the missing test. Examples of test shapes:
   - "end-to-end run with --flag-X, assert no exception"
   - "grep the test log output for /password=/, assert no matches"
   - "instantiate the dataclass with the same kwargs the code uses,
      assert no TypeError"
   - "mock the network response as None, assert no security_finding is emitted"
3. Write a CONCRETE reproducing test that would catch the canonical
   example. Don't propose; write the actual pytest function — imports,
   fixtures, asserts. 10-30 lines is fine.
4. Name the missing test category and propose where it should live in
   the test tree.

PRINCIPLES:
- Don't propose adding "more unit tests" — be specific about the
  ASSERTION that was missing, not just "needs more coverage".
- The reproducing test should fail against current code and pass once
  the bug is fixed. Verify that by reading the canonical example.
- If a category of test category-specific tooling is needed (e.g. a
  fixture that asserts no log line contains credentials, or a
  spec-conformance harness for protocols with RFC ground truth),
  describe it.

Return the structured result via schema.
`.trim()

const whyResults = await parallel(
  GAP_CLASSES.map(gc => () =>
    agent(whyPrompt(gc), {
      label: `why:${gc.name}`,
      phase: 'Why-missed',
      agentType: 'review',
      schema: SCHEMA_WHY,
    })
  )
)

// ---------------------------------------------------------------------------
// Phase 2: per gap class — find more like it across the WHOLE codebase
// ---------------------------------------------------------------------------
phase('Latent-search')

const latentPrompt = (gc) => `
You are hunting for LATENT bugs of a specific class across the OIDA
codebase. The class is:

  ${gc.name}
  ${gc.description}

ALREADY KNOWN INSTANCES (don't re-report these):
${gc.examples.map(e => '  - ' + e).join('\n')}

SEARCH HINT: ${gc.search_pattern}

JOB:
1. Construct grep / grep -r / regex queries that match the pattern.
2. Run them against \`src/oida/\` (NOT tests/). Report the actual
   commands you used.
3. For each match, OPEN the file and assess whether it's a real
   instance of the gap class. False positives are fine — just don't
   include them in the result.
4. Return each NEW finding via the schema: severity, file:line, title,
   1-2 paragraph description with the actual code snippet that proves
   the bug.

CALIBRATION:
- Most gap classes will yield 2-10 latent findings. If you find 0,
  great — say so in the result (empty array). If you find 50, you're
  probably matching too loosely; tighten the predicate.
- Severity: if the pattern matches but the consequence is benign in
  context, mark LOW. CRITICAL/HIGH only when the consequence parallels
  the canonical examples.
- Don't repeat findings already in CODE_REVIEW.md (read it first if
  you're unsure).

Return the structured result via schema.
`.trim()

const latentResults = await parallel(
  GAP_CLASSES.map(gc => () =>
    agent(latentPrompt(gc), {
      label: `latent:${gc.name}`,
      phase: 'Latent-search',
      agentType: 'review',
      schema: SCHEMA_LATENT,
    })
  )
)

const newFindings = latentResults
  .filter(Boolean)
  .flatMap(r => (r.latent_findings || []).map(f => ({ ...f, gap_class: r.gap_class })))

log(`Latent search complete: ${newFindings.length} NEW findings across ${GAP_CLASSES.length} gap classes`)
const sevCount = {}
for (const f of newFindings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1
log(`Severity: ${JSON.stringify(sevCount)}`)

// ---------------------------------------------------------------------------
// Phase 3: synthesise TEST_GAP_AUDIT.md
// ---------------------------------------------------------------------------
phase('Synthesise')

const synthPrompt = `
You are writing /home/feb/pro/oida/TEST_GAP_AUDIT.md from two inputs:

INPUT A — per-gap-class "why missed" analyses:
\`\`\`json
${JSON.stringify(whyResults.filter(Boolean), null, 2).slice(0, 60000)}
\`\`\`

INPUT B — per-gap-class latent-bug search results:
\`\`\`json
${JSON.stringify(latentResults.filter(Boolean), null, 2).slice(0, 120000)}
\`\`\`

WRITE the file with this structure:

    # Test Gap Audit

    *Why did the test suite miss the bugs found in CODE_REVIEW.md, and how
    many more bugs of the same shape exist?*

    ## Executive summary
    - <2-3 paragraphs> What systemic test-category gaps does the OIDA suite
      have? Rank them by blast radius (most-missed bug class first).
    - **Headline finding:** <highest-severity / most-pervasive new bug>

    ## Per-gap-class breakdown

    For each gap class (12 total):

    ### <gap-class-name>

    **Why tests missed it:** <paragraph from input A>

    **Missing test category:** <name + repo location>

    **Reproducing test:**
    \`\`\`python
    <code from input A>
    \`\`\`

    **Latent findings (N new):**
    - <severity> <file:line> — <title>
      <description>
    - ...

    **Grep queries used (for future maintainers):**
    \`\`\`bash
    <commands>
    \`\`\`

    ## Recommended test infrastructure to add

    Bulleted list of the new test categories that should land BEFORE
    or ALONGSIDE the bug-fix push. Each item: name, repo location,
    estimated effort, which gap classes it closes.

    ## All new latent findings, by severity

    Quick-reference cross-cut sorted by CRITICAL → HIGH → MEDIUM → LOW.

PRINCIPLES:
- Be specific. "Add integration tests" is useless; "tests/integration/cli/
  test_default_scan_emits_no_writes.py: pytest.parametrize over every
  protocol; assert outbound packets contain no write/state-change PDUs"
  is useful.
- Don't pad — keep the report under ~800 lines.
- Preserve every NEW CRITICAL and HIGH latent finding. MEDIUM may be
  aggregated by class if there are >10. LOW may be summarised.

Return the full path of the file you wrote plus a one-paragraph
summary of the most pressing systemic gap.
`.trim()

const synth = await agent(synthPrompt, {
  label: 'synthesise',
  phase: 'Synthesise',
  agentType: 'review',
})

return {
  gap_classes: GAP_CLASSES.length,
  latent_findings: newFindings.length,
  severity_breakdown: sevCount,
  audit_report: synth,
  per_class_why: whyResults,
  per_class_latent: latentResults,
}
