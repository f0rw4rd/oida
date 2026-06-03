// Gap follow-up to code-review-full (wxt77w8kq): cover the 22 files
// not assigned to any reviewer + deep-dive the 8 largest protocol dirs
// where the original per-protocol agent had to sample. Findings get
// appended into CODE_REVIEW.md under a "Gap follow-up" section.
//
// Token estimate: ~13 review agents + 1 appender ≈ 800k-1.2M output.
// Wall-clock ~15-25 min.

export const meta = {
  name: 'code-review-gap',
  description: 'Cover files missed by code-review-full + deep-dive 8 largest protocol dirs; append findings into CODE_REVIEW.md.',
  whenToUse: 'Run after code-review-full when you want to close gaps in the original fan-out coverage.',
  phases: [
    { title: 'Missed-areas', detail: 'shared/, hooks/, fuzz/monitors/, 4 listeners' },
    { title: 'Deep-protocols', detail: '8 largest protocol dirs (modbus, discovery, ethernetip, hl7, opcua, knx, bacnet, snap7)' },
    { title: 'Append', detail: 'Append findings into CODE_REVIEW.md under a Gap follow-up section' },
  ],
}

const REVIEW_SCHEMA = {
  type: 'object',
  required: ['target', 'files_reviewed', 'findings'],
  additionalProperties: false,
  properties: {
    target: { type: 'string' },
    files_reviewed: { type: 'integer', minimum: 0 },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'category', 'title', 'file', 'description'],
        additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
          category: { type: 'string', enum: ['bug', 'security', 'correctness', 'performance', 'maintainability', 'style', 'docs'] },
          title:    { type: 'string' },
          file:     { type: 'string' },
          description: { type: 'string' },
        },
      },
    },
    summary: { type: 'string' },
  },
}

// ---------------------------------------------------------------------------
// Missed-area assignments
// ---------------------------------------------------------------------------
const MISSED_AREAS = [
  {
    name: 'shared',
    paths: ['src/oida/shared/'],
    hint: '7 .py files under src/oida/shared/ — common helpers used cross-protocol. Look for thread-safety, mutable global state, and helpers that should be in utils/ but ended up here.',
  },
  {
    name: 'hooks',
    paths: ['src/oida/hooks/'],
    hint: '1 .py file. Probably an installable hooks integration point — verify it actually does what its docstring claims.',
  },
  {
    name: 'fuzz-monitors',
    paths: ['src/oida/fuzz/monitors/'],
    hint: '10 .py files. Monitor implementations that detect crashes/anomalies in fuzzed targets. Look for: monitors registered with FuzzSession that never observe a check; race conditions between fuzz iteration and crash detection; protocol-specific monitors (e.g. ADSMonitor) that swallow exceptions.',
  },
  {
    name: 'listeners-missed',
    paths: [
      'src/oida/pcap/passive/fins.py',
      'src/oida/pcap/passive/knx.py',
      'src/oida/pcap/passive/mssql.py',
      'src/oida/pcap/passive/mysql.py',
    ],
    hint: 'Four pcap listeners my original cluster list missed. Apply the same review criteria as the listener clusters in code-review-full (greedy listener / silent drops / direction-by-port hardcode / pyshark EK quirks / credential disclosure).',
  },
]

// ---------------------------------------------------------------------------
// Deep-dive: 8 largest protocol dirs (had to sample in the original run)
// ---------------------------------------------------------------------------
const DEEP_PROTOCOLS = [
  { name: 'modbus',     files: 34, subdirs: ['mixins/', 'scanner_mixins/', 'register_maps/'] },
  { name: 'discovery',  files: 32, subdirs: ['mixins/'] },
  { name: 'ethernetip', files: 21, subdirs: ['mixins/'] },
  { name: 'hl7',        files: 19, subdirs: ['mixins/'] },
  { name: 'opcua',      files: 17, subdirs: ['mixins/'] },
  { name: 'knx',        files: 16, subdirs: ['mixins/'] },
  { name: 'bacnet',     files: 15, subdirs: ['mixins/'] },
  { name: 'snap7',      files: 14, subdirs: ['mixins/'] },
]

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

const missedAreaPrompt = (a) => `
You are doing a code review of an OIDA area that the original review fan-out
(workflow wxt77w8kq) missed. This is a gap follow-up.

SCOPE: ${a.paths.length} target(s):
${a.paths.map(p => '  - ' + p).join('\n')}

CONTEXT FOR THIS AREA:
${a.hint}

GENERAL CONTEXT:
- OIDA is a defensive ICS security-testing CLI framework.
- Already reviewed (don't re-flag): see CODE_REVIEW.md at repo root —
  410 raw findings deduped to ~135. Skip anything that's already in there.
- Layer-1/Layer-2 facade pattern documented in docs/ARCHITECTURE.md.
- Logger contract: ICSLogger / get_module_logger; NO print statements.
- --confirm gating on dangerous ops is enforced via validate_args() in
  dnp3/ads and inline in ethercat/snap7.
- format_wordlist_source() in utils/login_scanner.py replaces full paths
  with basenames in user-facing logs (privacy).

WHAT TO LOOK FOR:
1. Bugs / correctness (off-by-one, wrong type, swallowed exceptions,
   race conditions, resource leaks).
2. Security: credential / engagement-context leaks; missing --confirm
   gates; unbounded reads from attacker-controlled responses; trust of
   peer-supplied data.
3. Cross-protocol consistency: does this code disagree with the
   reference patterns?
4. Layer-contract violations.
5. Style / maintainability: dead code, contradictory docstrings,
   garbled refactor-artefact debug strings (the original review found
   ~30 of these).

DO NOT FLAG:
- Issues already listed in CODE_REVIEW.md.
- Missing tests (separate scope).
- "Could be more Pythonic" nits.

CALIBRATION:
- These areas are smaller / more peripheral than the protocols. Expect
  0-5 findings per area. Honest severity — CRITICAL means "would crash
  / leak creds / drive state change without confirm".

Return the structured result via schema.
`.trim()

const deepProtocolPrompt = (p) => `
You are doing a DEEP code review of OIDA protocol \`src/oida/protocols/${p.name}/\`,
which contains ${p.files} files (largest in the codebase). The original
review agent for this protocol had to sample; your job is to cover the
files / paths it may have missed.

SCOPE: every Python file under \`src/oida/protocols/${p.name}/\`,
particularly the subdirs the original agent likely skipped:
${p.subdirs.map(s => '  - src/oida/protocols/' + p.name + '/' + s).join('\n')}

CONTEXT:
- See CODE_REVIEW.md at repo root for findings the original ${p.name}
  reviewer already produced. DO NOT re-flag them. Focus on what was
  likely missed: deep mixins, helper modules, register maps, vendor-
  specific code paths.
- Layer-1/Layer-2 facade pattern; format_wordlist_source helper for
  wordlist privacy; --confirm enforcement via validate_args() pattern.

WHAT TO LOOK FOR (same criteria as the original review, applied to the
files the first pass didn't reach):
1. Bugs / correctness (off-by-one, wrong type, swallowed exceptions,
   race conditions, broken error paths).
2. Security (defensive-tool concerns): credential leaks, --confirm
   missing, unbounded reads, trust of attacker-controlled data, hard-
   coded defaults surfacing.
3. Cross-protocol consistency.
4. Layer-contract violations.
5. Style / maintainability: dead code, garbled refactor-artefact log
   strings, mis-named flags, contradictory docstrings.

DO NOT FLAG:
- Anything already in CODE_REVIEW.md (read it first).
- Missing tests.
- Style nits.

CALIBRATION:
- A "deep" pass on ${p.name} should yield 5-15 NEW findings on average
  (i.e. ones not in the original report). If you find fewer, that means
  the original agent was thorough — fine.

Return the structured result via schema, including file:line in each
finding so they can be added to CODE_REVIEW.md.
`.trim()

// ---------------------------------------------------------------------------
// Phase 1: missed areas
// ---------------------------------------------------------------------------
phase('Missed-areas')
const missedResults = await parallel(
  MISSED_AREAS.map(a => () =>
    agent(missedAreaPrompt(a), {
      label: `missed:${a.name}`,
      phase: 'Missed-areas',
      agentType: 'review',
      schema: REVIEW_SCHEMA,
    })
  )
)

// ---------------------------------------------------------------------------
// Phase 2: deep protocol re-review
// ---------------------------------------------------------------------------
phase('Deep-protocols')
const deepResults = await parallel(
  DEEP_PROTOCOLS.map(p => () =>
    agent(deepProtocolPrompt(p), {
      label: `deep:${p.name}`,
      phase: 'Deep-protocols',
      agentType: 'review',
      schema: REVIEW_SCHEMA,
    })
  )
)

const allResults = [...missedResults, ...deepResults].filter(Boolean)
const allFindings = allResults.flatMap(r =>
  (r.findings || []).map(f => ({ ...f, target: r.target }))
)

log(`Gap pass: ${allResults.length} areas reviewed; ${allFindings.length} new findings`)
const sevCount = {}
for (const f of allFindings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1
log(`Severity breakdown: ${JSON.stringify(sevCount)}`)

// ---------------------------------------------------------------------------
// Phase 3: append to CODE_REVIEW.md
// ---------------------------------------------------------------------------
phase('Append')

const appendPrompt = `
Take the gap-review findings below and APPEND them to /home/feb/pro/oida/CODE_REVIEW.md
under a new top-level section:

    ---

    # Gap follow-up (workflow code-review-gap)

    ## Summary
    - Areas covered: <list>
    - New findings (post-dedup vs. original report): N
    - Breakdown by severity: ...

    ## CRITICAL
    ### <file:line> — <title>
    <description>

    ## HIGH
    (etc.)

    ## Areas with zero NEW findings
    <comma-separated list>

JOB:
1. Read the existing /home/feb/pro/oida/CODE_REVIEW.md so you don't
   duplicate findings already there. Cross-reference by file:line and
   title.
2. For each finding below, decide: is it a new issue, or a duplicate /
   variant of something already in the existing report? Drop duplicates.
3. Group surviving findings by severity and append the new section.
4. Use Edit / Write to actually modify CODE_REVIEW.md. Return the
   final path + a one-paragraph executive summary of what's new.

RAW GAP FINDINGS (JSON):

\`\`\`json
${JSON.stringify(allFindings, null, 2).slice(0, 200000)}
\`\`\`

PRINCIPLES:
- Dedup ruthlessly. Most "new" findings on a deep-reviewed protocol
  will overlap with the original agent's findings.
- Preserve every NEW CRITICAL and HIGH. MEDIUM may be aggregated.
- Keep file:line precise so each finding is actionable.
- Don't rewrite the existing CODE_REVIEW.md content; only append.
`.trim()

const appendResult = await agent(appendPrompt, {
  label: 'append-to-report',
  phase: 'Append',
  agentType: 'review',
})

return {
  areas_reviewed: allResults.length,
  raw_findings: allFindings.length,
  severity_breakdown: sevCount,
  append_summary: appendResult,
  per_area_results: allResults,
}
