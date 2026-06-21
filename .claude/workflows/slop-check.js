// slop-check.js — Detect AI-slop in code (existing files OR a diff).
//
// Two-layer design:
// - Layer 1: deterministic checks (vulture@60, ruff F401/F841, try/except
//   density, slop comment phrasings, lockfile/PyPI registry checks).
// - Layer 2: parallel LLM agents per file — API hallucination, cargo-cult /
//   over-engineering, dead-write detection across method boundaries.
//
// Diagnostic only — produces a prioritized markdown report; never blocks CI.
//
// Invocation:
//   /slop-check                     uncommitted working tree (default)
//   /slop-check HEAD~3..HEAD        explicit git range
//   /slop-check #42                 GitHub PR via gh
//   /slop-check src/oida/foo.py     a specific file (or several, space-sep)
//
// Token estimate: ~3 agents per file + 1 scope + 1 layer-1 + 1 synthesis.
// 1 file ≈ 200-400k output. 25-file diff ≈ 2-4M output. Wall-clock 3-10 min.

export const meta = {
  name: 'slop-check',
  description: 'Hunt AI-slop in code: dead scaffolding, hallucinated APIs, cargo-cult patterns, dead writes. Pass a path, git range, or PR number; default is the uncommitted working tree.',
  whenToUse: 'Run on suspect files or before merging an AI-authored branch. Diagnostic only — does not block CI.',
  phases: [
    { title: 'Scope', detail: 'resolve target files from args' },
    { title: 'Layer-1', detail: 'deterministic: vulture@60 + ruff F401/F841 + try/except + fluff + PyPI' },
    { title: 'Layer-2', detail: 'per-file LLM: API hallucination + cargo-cult + dead-writes' },
    { title: 'Report', detail: 'synthesize prioritized markdown report' },
  ],
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const SCOPE_SCHEMA = {
  type: 'object',
  required: ['files', 'scope_mode'],
  additionalProperties: false,
  properties: {
    files: { type: 'array', items: { type: 'string' } },
    scope_mode: { type: 'string', enum: ['diff', 'range', 'pr', 'paths'] },
    skipped_count: { type: 'integer', minimum: 0 },
    diff_stats: {
      type: 'object',
      additionalProperties: false,
      properties: {
        lines_added: { type: 'integer' },
        lines_removed: { type: 'integer' },
        files_touched: { type: 'integer' },
      },
    },
    notes: { type: 'string' },
  },
}

const LAYER1_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['vulture', 'ruff', 'defensive', 'fluff'],
  properties: {
    vulture: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          kind: { type: 'string' },
          name: { type: 'string' },
          confidence: { type: 'integer' },
        },
      },
    },
    ruff: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          code: { type: 'string' },
          msg: { type: 'string' },
        },
      },
    },
    defensive: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        properties: {
          file: { type: 'string' },
          try_count: { type: 'integer' },
          except_count: { type: 'integer' },
          bare_count: { type: 'integer' },
          exception_catchall: { type: 'integer' },
          loc: { type: 'integer' },
          density_pct: { type: 'number' },
        },
      },
    },
    fluff: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          text: { type: 'string' },
        },
      },
    },
    diff: { type: ['object', 'null'] },
    deps: { type: 'array' },
    notes: { type: 'string' },
  },
}

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['target', 'findings'],
  additionalProperties: false,
  properties: {
    target: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'category', 'title', 'location', 'description'],
        additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'] },
          category: {
            type: 'string',
            enum: [
              'api-hallucination',
              'cargo-cult',
              'dead-write',
              'dead-code',
              'fluff',
              'defensive-slop',
              'oversized',
              'slopsquat',
            ],
          },
          title: { type: 'string' },
          location: { type: 'string' },
          description: { type: 'string' },
          suggested_fix: { type: 'string' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

// ---------------------------------------------------------------------------
// Phase 1: resolve target files
// ---------------------------------------------------------------------------

phase('Scope')

const scopePrompt = `
Resolve the slop-check target files from this argument:
\`\`\`
${JSON.stringify(args || '')}
\`\`\`

Working directory is /home/feb/pro/oida.

Resolution rules (apply in order, FIRST match wins):

1. Empty/null argument → run:
     git -C /home/feb/pro/oida diff --name-only HEAD
   scope_mode = 'diff'.

2. Matches a git range (regex /^[^ ]+\\.{2,3}[^ ]+$/) → run:
     git -C /home/feb/pro/oida diff --name-only <range>
   scope_mode = 'range'.

3. Matches /^#?[0-9]+$/ → treat as GitHub PR number, run:
     gh pr view <N> --json files --jq '.files[].path'
   scope_mode = 'pr'.

4. Otherwise → treat as a space-separated path list (relative to /home/feb/pro/oida).
   For any directory, recurse:
     find <dir> -name '*.py' -not -path '*/.*'
   scope_mode = 'paths'.

Filter the resulting list:
- Keep only paths ending in .py.
- Keep only files under src/, tests/, or top-level scripts (services.py etc).
- DROP anything under ref/, docker/mocks/, .venv/, .git/, build/, dist/, __pycache__/.
- DROP files that don't exist.

Cap:
- If the filtered list >25 files, keep the 25 LARGEST by LOC (use wc -l).
- Record the dropped count as skipped_count.

For scope_mode in ('diff','range','pr'), also capture diff_stats:
  lines_added / lines_removed / files_touched via 'git diff --shortstat <range>'
  or equivalent. For scope_mode='paths', set diff_stats to null/empty.

Return STRICT JSON matching the schema. No prose.
`.trim()

const scope = await agent(scopePrompt, {
  label: 'scope',
  phase: 'Scope',
  schema: SCOPE_SCHEMA,
})

if (!scope || !scope.files || scope.files.length === 0) {
  log('No Python files in scope — nothing to check.')
  return {
    error: 'No Python files in scope.',
    args,
    scope,
  }
}

log(`Scope: ${scope.files.length} file(s), mode=${scope.scope_mode}, skipped=${scope.skipped_count || 0}`)

// ---------------------------------------------------------------------------
// Phase 2: Layer-1 deterministic checks
// ---------------------------------------------------------------------------

phase('Layer-1')

const layer1Prompt = `
Run Layer-1 deterministic slop checks against these files (cwd = /home/feb/pro/oida):

${scope.files.map(f => '  - ' + f).join('\n')}

Use Bash for every check. Capture output literally. Do NOT summarize away
findings.

CHECK 1 — Dead scaffolding (vulture at confidence 60, lower than the project's
pre-push hook threshold of 80; the slop-check intentionally surfaces the
attribute and nested-function cases the hook drops):

  uv run vulture --min-confidence 60 <files>

Parse each line: 'path:line: <kind> <name> (NN% confidence)'.

CHECK 2 — Unused imports / locals (ruff):

  uv run ruff check --select F401,F841 <files> --output-format concise

Parse 'path:line:col: CODE message'.

CHECK 3 — Try/except density per file:

  For each file, compute:
    loc                = wc -l
    try_count          = grep -cE '^\\s*try:' file
    except_count       = grep -cE '^\\s*except' file
    bare_count         = grep -cE '^\\s*except\\s*:' file
    exception_catchall = grep -cE '^\\s*except\\s+Exception' file
    density_pct        = 100 * except_count / loc

  Add an entry per file to defensive[]. ALWAYS include every file (the
  reviewer needs the baseline numbers even when nothing crosses a threshold).

CHECK 4 — Slop comment phrasings: for each file, grep -nE for comment lines
matching any of:
  '^\\s*#\\s*This (function|class|method|module) '
  "^\\s*#\\s*Here'?s "
  '^\\s*#\\s*(We need to|Note:|Simply |Just |In order to )'
  '^\\s*#\\s*(First|Then|Finally), '
  '^\\s*#\\s*(Implements|Handles|Manages|Processes) the '

Each match is a fluff[] entry with the line text trimmed.

CHECK 5 — Diff stats:
  If scope_mode in ('diff','range','pr'), the scope agent already captured
  diff_stats — include here as 'diff'. Otherwise diff = null.

CHECK 6 — New dependencies (slopsquat probe):
  If uv.lock was changed in the diff (only relevant for diff/range/pr modes):
    git diff <range> -- uv.lock | grep -E '^\\+name = ' | awk -F'"' '{print $2}'
  For each new package, curl 'https://pypi.org/pypi/<name>/json' (1s timeout)
  and capture:
    - info.author / info.maintainer (or releases[].uploaded_by)
    - first release date (min of releases[*][0].upload_time)
    - download stats (use /pypi/<name>/json; if absent, leave 0)
  Flag suspicious = true when EITHER:
    - first_release within the last 60 days, OR
    - maintainer/author info empty.
  For scope_mode='paths', skip CHECK 6 entirely (no diff context).

If a tool is missing (vulture/ruff not installed in the venv), return
[] for that check and add a 'notes' entry explaining. Don't fail.

Return STRICT JSON matching the layer-1 schema. No prose outside JSON.
`.trim()

const layer1 = await agent(layer1Prompt, {
  label: 'layer-1',
  phase: 'Layer-1',
  schema: LAYER1_SCHEMA,
})

const l1Counts = {
  vulture: (layer1?.vulture || []).length,
  ruff: (layer1?.ruff || []).length,
  fluff: (layer1?.fluff || []).length,
  defensive_flagged: (layer1?.defensive || []).filter(d => d.bare_count > 0 || (d.density_pct || 0) > 4).length,
  deps_suspicious: (layer1?.deps || []).filter(d => d.suspicious).length,
}
log(`Layer-1: vulture=${l1Counts.vulture} ruff=${l1Counts.ruff} fluff=${l1Counts.fluff} defensive_flagged=${l1Counts.defensive_flagged} deps_suspicious=${l1Counts.deps_suspicious}`)

// ---------------------------------------------------------------------------
// Phase 3: Layer-2 per-file LLM judgment (3 sub-agents in parallel per file)
// ---------------------------------------------------------------------------

phase('Layer-2')

const apiPrompt = (file) => `
You are auditing /home/feb/pro/oida/${file} for HALLUCINATED EXTERNAL APIS —
calls to methods/classes/attributes on third-party libraries that DO NOT
EXIST or are deprecated. This is the #1 AI-slop defect class.

Working directory: /home/feb/pro/oida. The venv is at .venv (use 'uv run').

Method:
1. Read the file's imports. List external (PyPI) libraries used. IGNORE
   first-party imports (anything under 'oida.*' or starting with '.').
2. Find every external call site — attribute access (lib.X.Y), instantiation,
   method call on an instance of a third-party class, and getattr/hasattr
   patterns with string attribute names.
3. For each, verify the symbol exists in the INSTALLED version. Use:
     uv run python -c "import LIB; print(hasattr(LIB, 'NAME'))"
   For nested attrs:
     uv run python -c "import LIB; import inspect; print(inspect.signature(LIB.X.Y))"
   For getattr-with-string-name patterns, check whether the attribute actually
   exists on the target class — these are the classic silent-fallback typos.
4. Flag with severity:
     HIGH   — symbol does not exist or signature mismatch crashes at call time
     MEDIUM — getattr() / hasattr() with a default that silently masks the typo
              (e.g., getattr(conn, "server_nonce", b"") when the real attr is
              "remote_nonce" — code "works" but always uses the default)
     LOW    — deprecated-but-still-exists API where a replacement is documented

DO NOT flag internal/first-party calls. DO NOT speculate; verify every claim
by actually running the python check.

Return findings via the schema. target = '${file}'. If clean, findings: [].
`.trim()

const cargoCultPrompt = (file) => `
You are auditing /home/feb/pro/oida/${file} for CARGO-CULTED PATTERNS and
OVER-ENGINEERING.

CONTEXT — apply these as judgment criteria. /home/feb/pro/oida/CLAUDE.md says:
  - "Don't add features, refactor, or introduce abstractions beyond what the
    task requires."
  - "Don't add error handling, fallbacks, or validation for scenarios that
    can't happen."
  - "Three similar lines is better than a premature abstraction."

For every construct below, ask: WHAT NAMED FAILURE MODE DOES THIS ADDRESS?
Look in the surrounding code AND, if relevant, in /home/feb/pro/oida/ref/<protocol>/
(e.g., ref/opcua/cve_patterns.json, ref/opcua/fuzzer.md). If you cannot find
a real failure mode, flag it:

  - retry decorators, circuit breakers
  - wrapper-around-wrapper, single-call helper functions
  - factory functions used at exactly one call site
  - abstract classes with one concrete subclass
  - nested functions defined but never called (real defect — confirm by grep)
  - parameters with defaults no caller overrides
  - dead try/except guarding no real exception path
  - duplicated helpers across the diff (3+ near-identical functions)

CRUCIAL CALIBRATION — these patterns are LEGITIMATE in this codebase; do not
flag them blindly:

  - Files under src/oida/fuzz/protocols/ — dispatch tables and primitive
    builders that LOOK repetitive ARE the point of a fuzzer. Only flag
    fuzzer constructs that are truly unused (vulture-confirmed dead).
  - Files under src/oida/protocols/*/nxc_connection.py or */mixins/*.py —
    the documented NXC pattern is "log + continue" (see docs/ARCHITECTURE.md).
    try/except around individual protocol operations is INTENTIONAL — not
    defensive slop. The pattern is:
        except Exception as e:
            self.logger.debug("X failed: %s", e)
            self.logger.fail("Error X: %s", e)
    DO NOT flag this. Flag only catches with NO debug AND NO fail (pure swallow).

Adversarially verify each candidate before flagging: "could this be inlined?"
If yes, flag. If it has a real reason (consistency across many call sites,
hot path, documented invariant), drop the finding.

Severity:
  HIGH   — definitively dead (nested function with zero callers, etc.)
  MEDIUM — over-abstraction with no named failure mode
  LOW    — speculative / borderline

Return findings via schema. target = '${file}'. If clean, findings: [].
`.trim()

const deadWritePrompt = (file) => `
You are auditing /home/feb/pro/oida/${file} for DEAD WRITES — values that
get assigned/stored but no other code ever reads.

This catches the slop class vulture cannot: cross-method / cross-file
string-keyed writes where the key never appears as a reader anywhere.

Method:
1. Read the file. Identify potentially dead writes:
     self.X = ...                      (attribute write)
     ctx.set("key", ...)               (string-keyed write API)
     dict["key"] = value               (state-dict write)
     module-level constants exported but maybe unused
2. For each candidate, grep the repo for any READER:
     grep -rn 'self\\.X\\b' src/ tests/
     grep -rn 'ctx\\.get("key")\\|"key"' src/ tests/
3. If the only matches are the write site itself, the write is DEAD.
   Docstring examples and comments DO NOT count as readers.

CALIBRATION — do NOT flag:
- Writes whose key is consumed by reflection / config-driven code that
  scans __dict__ or string-matches names (look for getattr(self, ...),
  vars(self), to_dict, asdict patterns).
- __init__ attributes that are part of a public dataclass-like API
  consumed by external callers (verify via grep — if external callers
  read self.X, it's not dead).
- Writes that are intentionally part of an external library protocol
  (e.g., asyncua client state).

Severity:
  HIGH   — large block of writes nobody reads (e.g., 4 ctx.set calls in a
           row, all keys absent from any reader)
  MEDIUM — a single dead self.X attribute or ctx key
  LOW    — borderline (the reader exists but only as commented-out code)

Return findings via schema. target = '${file}'. If clean, findings: [].
`.trim()

// Reviewer subagent type (no dedicated 'review' agent in this environment).
const REVIEW_AGENT = 'general-purpose'

const perFile = await pipeline(
  scope.files,
  (file) => agent(apiPrompt(file), {
    label: `api:${file.split('/').pop()}`,
    phase: 'Layer-2',
    agentType: REVIEW_AGENT,
    schema: FINDINGS_SCHEMA,
  }).then(r => ({ file, api: r })),
  (prev) => agent(cargoCultPrompt(prev.file), {
    label: `cargo:${prev.file.split('/').pop()}`,
    phase: 'Layer-2',
    agentType: REVIEW_AGENT,
    schema: FINDINGS_SCHEMA,
  }).then(r => ({ ...prev, cargo: r })),
  (prev) => agent(deadWritePrompt(prev.file), {
    label: `dead:${prev.file.split('/').pop()}`,
    phase: 'Layer-2',
    agentType: REVIEW_AGENT,
    schema: FINDINGS_SCHEMA,
  }).then(r => ({ ...prev, dead: r })),
)

const allLayer2 = perFile.filter(Boolean).flatMap(p =>
  [p.api, p.cargo, p.dead]
    .filter(Boolean)
    .flatMap(r => (r.findings || []).map(f => ({ ...f, target: f.target || p.file })))
)

const sevCount = { HIGH: 0, MEDIUM: 0, LOW: 0 }
for (const f of allLayer2) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1
log(`Layer-2: ${allLayer2.length} findings (HIGH=${sevCount.HIGH} MEDIUM=${sevCount.MEDIUM} LOW=${sevCount.LOW})`)

// ---------------------------------------------------------------------------
// Phase 4: synthesize markdown report
// ---------------------------------------------------------------------------

phase('Report')

const reportPrompt = `
Synthesize a SLOP-CHECK report from these inputs.

SCOPE:
\`\`\`json
${JSON.stringify(scope, null, 2)}
\`\`\`

LAYER-1 SUMMARY (deterministic):
\`\`\`json
${JSON.stringify({ ...layer1, counts: l1Counts }, null, 2).slice(0, 80000)}
\`\`\`

LAYER-2 FINDINGS (per-file LLM):
\`\`\`json
${JSON.stringify(allLayer2, null, 2).slice(0, 80000)}
\`\`\`

OUTPUT — a markdown report with EXACTLY this structure:

# /slop-check report — <scope summary>

<one-line stats: files reviewed, total findings, severity counts. include
diff_stats if present.>

## HIGH — likely real defects

For each HIGH finding (Layer-2) AND high-confidence Layer-1 hits (vulture
confidence 100, ruff F401/F841, bare except, slopsquat with suspicious=true):

- **\`file:line\`** — title
  description. *Suggested fix:* one-line.

## MEDIUM — review and confirm

Same shape. Include Layer-2 MEDIUM + vulture@60-80 + comment fluff with
density >2/100 LOC + defensive-density >4%.

## LOW — calibration / cleanup

Same shape. Include all remaining low-severity items, and per-file fluff
samples (just one or two examples per file, not every match).

## Skipped

- vendored / out-of-scope counts (skipped_count from scope).
- any files Layer-2 errored on (null entries in the per-file pipeline).
- mention Layer-1 checks that were skipped because their tool was missing.

## Calibration notes

1-3 sentences on signal quality. Specifically flag:
- Fuzzer files (src/oida/fuzz/protocols/) where high comment density turned
  out to be section labels — not a real signal.
- NXC connection / mixin files where high try/except density is the
  documented "log + continue" pattern, not defensive slop.
- Any other false-positive cluster the reviewer should weight DOWN.

PRINCIPLES:
- DEDUP: if Layer-1 and Layer-2 both report the same defect, mention it ONCE
  under the higher severity.
- CITE file:line on every finding. No file:line → don't include it.
- NO emojis. NO marketing language. Terse, specific.
- If literally nothing was found, output:
    # /slop-check report — <scope summary>
    No slop detected across <N> file(s). <one-line layer-1 stats.>
  Don't pad.

Return ONLY the markdown body. No surrounding JSON, no preamble.
`.trim()

const report = await agent(reportPrompt, {
  label: 'synthesize',
  phase: 'Report',
  agentType: REVIEW_AGENT,
})

return {
  scope,
  layer1_summary: l1Counts,
  layer2_findings: allLayer2.length,
  severity: sevCount,
  report,
}
