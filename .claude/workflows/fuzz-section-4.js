// Workflow: implement RELEASE_TODO.md §4.1 fuzzer optimizations.
//
// Fans out one agent per protocol across the 11 protocols with open §4.1
// items. Each agent edits ONLY its protocol's fuzzer file(s) so the parallel
// runs don't conflict. A final reconciliation step rewrites
// tests/unit/fuzz/test_fuzzer_coverage.py::ICS_AUDIT_REQUEST_COUNTS in one
// place from the per-agent reported counts, then runs the unit fuzz suite.
//
// Token estimate: ~11 implementation agents × ~80-120k each + 1 reconcile
// + 1 verify ≈ 1.2-1.6M output tokens. Wall-clock ~15-25 min on the cap of
// 16 concurrent (so all 11 implementation agents run together).

export const meta = {
  name: 'fuzz-section-4',
  description: 'Implement the 26 RELEASE_TODO §4.1 fuzzer optimizations, one agent per protocol.',
  whenToUse: 'Run when ready to land the small (≤1h) fuzzer additions across §4.1. Run from a clean git tree.',
  phases: [
    { title: 'Implement', detail: 'Per-protocol agents edit fuzzer source + their tests' },
    { title: 'Reconcile', detail: 'Update ICS_AUDIT_REQUEST_COUNTS from collected counts' },
    { title: 'Verify', detail: 'Run full unit fuzz suite, report regressions' },
  ],
}

// ---------------------------------------------------------------------------
// Per-protocol work assignments. Each entry is exactly the set of §4.1
// bullets for that protocol from ref/_FUZZER_OPTIMIZATIONS_TODO.md.
// ---------------------------------------------------------------------------
const ASSIGNMENTS = [
  {
    protocol: 'modbus',
    files: ['src/oida/fuzz/protocols/modbus/tcp.py', 'src/oida/fuzz/protocols/modbus/rtu.py'],
    items: [
      'Cap ADU overflow: add max_len=4096 to the boofuzz String/Bytes overflow primitives in both modbus/tcp.py and modbus/rtu.py to stop multi-MiB OOM frames.',
      'Audit RTU CRC mutation path at modbus/rtu.py:252,272,295,314,331. The current Word("CRC", 0x0000, endian="<") will be recomputed by the send pipeline if the pipeline auto-fixes CRC. Inspect the send path. If CRC IS recomputed post-mutation, add a new RTU_Bad_CRC request that uses Static for the CRC bytes so an invalid CRC actually reaches the wire.',
    ],
  },
  {
    protocol: 'dnp3',
    files: ['src/oida/fuzz/protocols/dnp3.py'],
    items: [
      'Add DNP3_Object_Sweep request: iterate Group("Group", values=range(1,90)) × Group("Variation", values=range(0,17)) against a Read function code. See ref/dnp3/cve_patterns.json#dnp3-object-group-sweep.',
      'Add DNP3_IIN_Master request: master-emulation mode; fuzz the 16-bit IIN flags field. See ref/dnp3/cve_patterns.json#dnp3-iin-flags-master.',
      'Add DNP3_DL_Bad_CRC request: DL block CRC is auto-recomputed, so use Static for invalid CRC bytes to actually test peer validation.',
    ],
  },
  {
    protocol: 'ethernetip',
    files: ['src/oida/fuzz/protocols/ethernetip.py'],
    items: [
      'Re-audit fuzzable=False in CIP_Path_*: the path-length header byte should stay non-fuzzable, but class/instance/attribute VALUE bytes should flip to default-fuzzable. See ref/ethernetip/cve_patterns.json#enip-cip-path-encoding.',
      'Flip Forward_Open.OT_RPI and Forward_Open.TO_RPI to default-fuzzable; extreme RPI values (0, 1, 0xFFFFFFFF) hit timer crashes. See ref/ethernetip/cve_patterns.json#enip-forward-open-rpi.',
      'Add CIP_Class_Enumeration request: Group("ClassID", values=[0x01, 0x02, 0x04, 0x06, 0xF4, 0xF5, 0xF6, 0xAC, 0x100, 0x101, 0x110]). See ref/ethernetip/cve_patterns.json#enip-class-enumeration.',
    ],
  },
  {
    protocol: 'iec104',
    files: ['src/oida/fuzz/protocols/iec104.py'],
    items: [
      'Reserved type-ID coverage: extend the Group("ASDU.TypeId", ...) to include 128-135 (reserved) and 136-255 (vendor) ranges. Single-line change. See ref/iec104/cve_patterns.json#iec104-asdu-type-id-reserved.',
      'Common Address sweep field: add Group("ASDU.CommonAddress", values=[0, 1, 65534, 65535, 32767, 32768]) to the existing IEC104_ASDU_TypeId request. See ref/iec104/cve_patterns.json#iec104-common-address-sweep.',
    ],
  },
  {
    protocol: 'mms',
    files: ['src/oida/fuzz/protocols/mms.py'],
    items: [
      'Add MMS_BER_Tag_Confusion request: take a valid MMS PDU template, replace the outer SEQUENCE tag (0x30) with Group([0x30, 0x31, 0x80, 0xA0, 0xA1, 0xC0, 0xE0]). High-yield ASN.1 parser bug class. See ref/mms/cve_patterns.json#mms-asn1-tag-confusion.',
    ],
  },
  {
    protocol: 'ads',
    files: ['src/oida/fuzz/protocols/ads.py'],
    items: [
      'ADSMonitor integration: wire the existing ADSMonitor class into the fuzzer\'s monitor chain. Single-line registration. Promotes ADS-side error codes (e.g. 0x70A) to crash events. Audit S6.',
      'Add ADS_Port_Enumeration: Group("AMS.TargetPort", values=[100, 110, 200, 350, 400, 500, 851, 852, 853, 900]) on the ADS_Read request. See ref/ads/cve_patterns.json#ads-port-enumeration.',
      'Add ADS_SumReadWrite request: Beckhoff-specific bulk operation, missing from current request set. See ref/ads/cve_patterns.json#ads-sumcommand.',
    ],
  },
  {
    protocol: 'snmpv2',
    files: ['src/oida/fuzz/protocols/snmpv2.py'],
    items: [
      'Cap walk recursion at depth 100. The WALK_XFAIL is from unbounded GetNext recursion. See ref/snmp/cve_patterns.json#snmpv2c-walk-recursion.',
    ],
  },
  {
    protocol: 'snmpv3',
    files: ['src/oida/fuzz/protocols/snmpv3.py'],
    items: [
      'Add SNMPv3 USM auth-param fuzzing: the 12-byte AuthenticationParameters and 8-byte PrivacyParameters fields need explicit Group() mutation (currently treated as derived). See ref/snmp/cve_patterns.json#snmpv3-usm-auth-params.',
      'Add the four missing SNMPv3 Request types: SetRequest-PDU, Trap-PDU, InformRequest-PDU, GetBulkRequest-PDU. Audit S8.',
    ],
  },
  {
    protocol: 'opcua',
    files: ['src/oida/fuzz/protocols/opcua.py'],
    items: [
      'Extend ExtensionObject TypeId Group: current group covers common TypeIds; add vendor-reserved range (0x6XXX). See ref/opcua/cve_patterns.json#opcua-extension-object-typeid.',
    ],
  },
  {
    protocol: 'hl7',
    files: ['src/oida/fuzz/protocols/hl7.py'],
    items: [
      'HL7 v2.x version sweep on MSH-12: single Group() over version strings 2.3/2.4/2.5/2.6/2.7/2.8. See ref/hl7/fuzzer.md recommendation 1.',
      'Z-segment injection request: inject a malformed Z segment mid-message. Catches parsers that don\'t skip vendor segments gracefully.',
    ],
  },
  {
    protocol: 'mqtt',
    files: ['src/oida/fuzz/protocols/mqtt.py'],
    items: [
      'Sparkplug B payload fuzzing: separate Request that wraps a fuzzed protobuf payload inside MQTT PUBLISH. See ref/mqtt/fuzzer.md.',
      'MQTT 5.0 reason code sweep: Group() over all 256 byte values.',
    ],
  },
  {
    protocol: 'coap',
    files: ['src/oida/fuzz/protocols/coap.py'],
    items: [
      'Add explicit fuzzable= annotations on Ver/T/TKL/Code header bits. Mechanical clarity pass — no behaviour change, just makes the existing default explicit so future contributors can see what is and isn\'t mutated. See ref/coap/fuzzer.md.',
    ],
  },
]

// ---------------------------------------------------------------------------
// Schemas for structured agent results.
// ---------------------------------------------------------------------------
const IMPL_RESULT_SCHEMA = {
  type: 'object',
  required: ['protocol', 'items_attempted', 'items_completed', 'new_request_count', 'tests_pass'],
  additionalProperties: false,
  properties: {
    protocol: { type: 'string' },
    items_attempted: { type: 'integer', minimum: 0 },
    items_completed: { type: 'integer', minimum: 0 },
    new_request_count: {
      type: 'integer',
      minimum: 0,
      description: 'Total request-class count for this fuzzer after the edits — read by counting Request() instantiations in the fuzzer file.',
    },
    files_modified: { type: 'array', items: { type: 'string' } },
    tests_pass: { type: 'boolean' },
    tests_run: { type: 'string', description: 'pytest command(s) executed for verification' },
    notes: {
      type: 'string',
      description: 'Free-text per-item summary: what was done, what was skipped and why.',
    },
  },
}

const VERIFY_RESULT_SCHEMA = {
  type: 'object',
  required: ['passed', 'failed', 'skipped', 'overall_pass'],
  additionalProperties: false,
  properties: {
    passed: { type: 'integer' },
    failed: { type: 'integer' },
    skipped: { type: 'integer' },
    overall_pass: { type: 'boolean' },
    failure_summary: { type: 'string' },
  },
}

// ---------------------------------------------------------------------------
// Phase 1: per-protocol implementation
// ---------------------------------------------------------------------------
phase('Implement')

const implPrompt = (a) => `
You are implementing the §4.1 fuzzer-optimization items for protocol "${a.protocol}".

REPO: /home/feb/pro/oida (already cwd). Branch is clean. Make your edits, run
the corresponding protocol's tests, and report structured results.

YOUR FILES (edit ONLY these — no shared-state files):
${a.files.map(f => '  - ' + f).join('\n')}

YOUR ITEMS (apply each in order):
${a.items.map((it, i) => `  ${i + 1}. ${it}`).join('\n')}

REFERENCE MATERIAL:
- ref/_FUZZER_OPTIMIZATIONS_TODO.md — source of these items (verify your edits match)
- ref/${a.protocol === 'snmpv2' || a.protocol === 'snmpv3' ? 'snmp' : a.protocol}/cve_patterns.json — line/byte-level guidance for several items
- ref/${a.protocol === 'snmpv2' || a.protocol === 'snmpv3' ? 'snmp' : a.protocol}/fuzzer.md — protocol-specific notes

CODING STANDARDS (CLAUDE.md):
- Ruff format / 100 char line length
- Lazy import boofuzz primitives where the existing file does
- Match the existing Request() / Group() patterns in the file you're editing
- Do NOT add unrelated changes — only the items above

DO NOT TOUCH:
- tests/unit/fuzz/test_fuzzer_coverage.py — the reconcile phase handles ICS_AUDIT_REQUEST_COUNTS
- Any file outside your "YOUR FILES" list
- pyproject.toml, README, etc.

VERIFICATION YOU MUST RUN (and report tests_pass = true ONLY if all pass):
- pytest tests/unit/fuzz/test_${a.protocol}_fuzzer.py -q  (if exists)
- pytest tests/unit/fuzz/test_fuzzer_definitions.py -q -k "${a.protocol}"
- pytest tests/unit/fuzz/test_fuzzer_coverage.py -q -k "${a.protocol}" (will likely FAIL on the count check until the reconcile phase; report that as a known-expected failure and do NOT modify the counts file to "fix" it)

For new_request_count: run a quick grep to count Request( instantiations
in the file(s) after your edits. Format: \`grep -c "Request(" <file>\`.

When done, return the structured result. Be precise about what's completed
vs skipped — the orchestrator uses this directly. If you cannot complete an
item (e.g. the referenced cve_patterns.json key is missing), explain in
"notes" and leave the file untouched for that item.
`.trim()

const results = await parallel(
  ASSIGNMENTS.map(a => () =>
    agent(implPrompt(a), {
      label: `impl:${a.protocol}`,
      phase: 'Implement',
      schema: IMPL_RESULT_SCHEMA,
      agentType: 'senior-dev',
    })
  )
)

const succeeded = results.filter(Boolean)
const failed_agents = results.filter(r => !r).length

log(`Implementation phase: ${succeeded.length}/${ASSIGNMENTS.length} agents returned a result; ${failed_agents} did not respond.`)
log(`Per-protocol completion: ${succeeded.map(r => `${r.protocol}=${r.items_completed}/${r.items_attempted}`).join(', ')}`)

// ---------------------------------------------------------------------------
// Phase 2: reconcile ICS_AUDIT_REQUEST_COUNTS
// ---------------------------------------------------------------------------
phase('Reconcile')

const countsByProtocol = succeeded
  .filter(r => r.new_request_count > 0)
  .map(r => ({ protocol: r.protocol, count: r.new_request_count }))

const reconcilePrompt = `
Update tests/unit/fuzz/test_fuzzer_coverage.py::ICS_AUDIT_REQUEST_COUNTS so
each protocol below has its new request count. DO NOT lower any existing
count that isn't in this list (preserve unrelated entries verbatim).

NEW COUNTS (from the implementation agents):
${countsByProtocol.map(c => `  ${c.protocol}: ${c.count}`).join('\n')}

NOTES:
- snmpv2/snmpv3 may map to a single "snmp" key in ICS_AUDIT_REQUEST_COUNTS or
  separate keys — match whatever the file currently uses. If it uses
  separate keys, set each. If it uses a single "snmp" key, set it to the
  SUM of snmpv2 + snmpv3 counts.
- After editing, run \`pytest tests/unit/fuzz/test_fuzzer_coverage.py -q\`
  and report whether it passes.
- Edit ONLY test_fuzzer_coverage.py; no other files.

Return a one-paragraph summary of what was changed and whether the suite passes.
`.trim()

const reconcileResult = await agent(reconcilePrompt, {
  label: 'reconcile-counts',
  phase: 'Reconcile',
  agentType: 'senior-dev',
})

log(`Reconcile: ${reconcileResult}`)

// ---------------------------------------------------------------------------
// Phase 3: full verification
// ---------------------------------------------------------------------------
phase('Verify')

const verifyResult = await agent(`
Run the full unit fuzz suite and the unit fuzz-coverage test:

  pytest tests/unit/fuzz/ -q --tb=line

Return structured JSON with passed/failed/skipped totals from pytest's
final summary line. Set overall_pass = true ONLY if failed == 0. If
failed > 0, include a one-paragraph failure_summary listing which tests
failed and any obvious root-cause patterns (e.g. "3 tests in coverage
suite still expect old counts" or "DNP3_Object_Sweep raises ImportError").
`.trim(), {
  label: 'verify',
  phase: 'Verify',
  schema: VERIFY_RESULT_SCHEMA,
  agentType: 'senior-dev',
})

return {
  implementation: succeeded,
  reconcile_summary: reconcileResult,
  verification: verifyResult,
  total_items_completed: succeeded.reduce((sum, r) => sum + r.items_completed, 0),
  total_items_attempted: ASSIGNMENTS.reduce((sum, a) => sum + a.items.length, 0),
}
