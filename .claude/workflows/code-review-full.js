// Full code review: fan out the `review` subagent across the codebase,
// grouped by logical module (one agent per protocol, listener cluster,
// fuzzer area, and framework area). A final aggregator agent merges all
// findings into a single priority-ranked report.
//
// Token estimate: ~42 review agents × ~80-100k each + 1 aggregator
// ≈ 3.5-4.5M output tokens. Wall-clock ~25-40 min on the cap of 16
// concurrent (so several waves).
//
// Output: writes a consolidated review to /tmp/code-review-<run-id>.md
// (path returned by the final aggregator).

export const meta = {
  name: 'code-review-full',
  description: 'Full multi-agent code review: 1 reviewer per protocol + listener cluster + fuzzer area, then one aggregator to merge findings.',
  whenToUse: 'Run pre-release for a wide-net code review. Expensive; only run when ready to act on the output.',
  phases: [
    { title: 'Framework', detail: 'Review core (cli, loader, connection, utils, base scanners)' },
    { title: 'Protocols', detail: 'One reviewer per protocol scanner (26 agents)' },
    { title: 'Listeners', detail: 'Pcap-listener clusters grouped by category (~12 agents)' },
    { title: 'Fuzzer', detail: 'Fuzzer core + protocol modules (4 agents)' },
    { title: 'Aggregate', detail: 'Merge all findings into one priority-ranked report' },
  ],
}

// ---------------------------------------------------------------------------
// Group definitions
// ---------------------------------------------------------------------------

const PROTOCOLS = [
  'ads', 'astm', 'bacnet', 'can', 'coap', 'dicom', 'discovery', 'dnp3',
  'ethercat', 'ethernetip', 'fhir', 'goose', 'hart', 'hl7', 'iec104',
  'knx', 'mms', 'modbus', 'mqtt', 'ocpp', 'opcua', 'pcap', 'profinet',
  'snap7', 'snmp', 'tase2',
]

// Listener clusters — 109 listeners grouped by category for ~10-12 reviews.
const LISTENER_CLUSTERS = [
  {
    name: 'ot-industrial-core',
    files: ['modbus.py', 'dnp3.py', 'iec104.py', 'iec101.py', 'iec103.py', 's7comm.py', 'enip.py', 'bacnet.py', 'mms.py', 'cotp.py'],
  },
  {
    name: 'ot-fieldbus-realtime',
    files: ['ethercat.py', 'profinet.py', 'goose.py', 'rgoose.py', 'sv.py', 'opensafety.py', 'epl.py', 'sercos.py', 'cipsafety.py', 'devicenet.py', 'canopen.py', 'can.py', 'ff_hse.py', 'opcua.py', 'opcda.py'],
  },
  {
    name: 'ot-misc',
    files: ['ads.py', 'pcom.py', 'hartip.py', 'lontalk.py', 'synchrophasor.py', 'c1222.py', 'nmea0183.py', 'j1939.py'],
  },
  {
    name: 'network-routing',
    files: ['bgp.py', 'ospf.py', 'eigrp.py', 'rip.py', 'pim.py', 'igmp.py', 'hsrp.py', 'vrrp.py', 'glbp.py', 'bfd.py', 'stp.py', 'vtp.py', 'cdp.py', 'lldp.py', 'dtp.py', 'hsr.py', 'prp.py', 'ptp.py'],
  },
  {
    name: 'network-discovery',
    files: ['dhcp.py', 'dns.py', 'mdns.py', 'ssdp.py', 'wsdiscovery.py', 'netbios.py', 'msrpc.py', 'rpcbind.py', 'smartinstall.py'],
  },
  {
    name: 'credentials-mgmt',
    files: ['ldap.py', 'kerberos.py', 'radius.py', 'tacacs.py', 'ntlm.py', 'pap.py', 'snmp.py'],
  },
  {
    name: 'remote-access',
    files: ['telnet.py', 'rdp.py', 'vnc.py', 'x11.py', 'socks.py', 'ipsec.py', 'tls.py'],
  },
  {
    name: 'file-transfer',
    files: ['ftp.py', 'tftp.py', 'smb.py', 'nfs.py', 'rsync.py', 'iscsi.py'],
  },
  {
    name: 'web-app',
    files: ['http.py', 'http2.py', 'ajp.py', 'rmi.py', 'jboss.py', 'tns.py'],
  },
  {
    name: 'messaging-mail',
    files: ['smtp.py', 'imap.py', 'pop3.py', 'mqtt.py', 'amqp.py', 'sip.py', 'rtsp.py', 'irc.py', 'ibmmq.py', 'memcached.py', 'redis.py', 'mongodb.py', 'pgsql.py'],
  },
  {
    name: 'healthcare-printing',
    files: ['hl7.py', 'dicom.py', 'pjl.py', 'ipp.py'],
  },
  {
    name: 'iot-misc',
    files: ['coap.py', 'ntp.py', 'ipmi.py'],
  },
  {
    name: 'pcap-infra',
    files: ['pyshark_base.py', 'interactions.py', 'file_carving.py'],
  },
]

const FUZZER_AREAS = [
  { name: 'fuzz-core',      paths: ['src/oida/fuzz/core/', 'src/oida/fuzz/__init__.py', 'src/oida/fuzz_cli.py'] },
  { name: 'fuzz-protocols-ics', paths: ['src/oida/fuzz/protocols/modbus/', 'src/oida/fuzz/protocols/iec104.py', 'src/oida/fuzz/protocols/dnp3.py', 'src/oida/fuzz/protocols/ads.py', 'src/oida/fuzz/protocols/mms.py', 'src/oida/fuzz/protocols/opcua.py', 'src/oida/fuzz/protocols/ethernetip.py', 'src/oida/fuzz/protocols/snmpv2.py', 'src/oida/fuzz/protocols/snmpv3.py', 'src/oida/fuzz/protocols/snmp_common.py'] },
  { name: 'fuzz-protocols-net', paths: ['src/oida/fuzz/protocols/dns.py', 'src/oida/fuzz/protocols/dns_common.py', 'src/oida/fuzz/protocols/dhcp.py', 'src/oida/fuzz/protocols/ntp.py', 'src/oida/fuzz/protocols/ftp.py', 'src/oida/fuzz/protocols/smtp.py', 'src/oida/fuzz/protocols/http_protocol.py', 'src/oida/fuzz/protocols/http2.py', 'src/oida/fuzz/protocols/tftp.py', 'src/oida/fuzz/protocols/coap.py', 'src/oida/fuzz/protocols/mqtt.py', 'src/oida/fuzz/protocols/hl7.py', 'src/oida/fuzz/protocols/vnc.py', 'src/oida/fuzz/protocols/echo.py', 'src/oida/fuzz/protocols/daytime.py'] },
  { name: 'fuzz-protocols-l2',  paths: ['src/oida/fuzz/protocols/ethernet.py', 'src/oida/fuzz/protocols/ipv4.py', 'src/oida/fuzz/protocols/ipv6.py', 'src/oida/fuzz/protocols/tcp.py', 'src/oida/fuzz/protocols/tcp_state_integration.py', 'src/oida/fuzz/protocols/icmp.py', 'src/oida/fuzz/protocols/icmpv6.py', 'src/oida/fuzz/protocols/mdns.py', 'src/oida/fuzz/protocols/gatt.py', 'src/oida/fuzz/protocols/mutation.py'] },
]

const FRAMEWORK_AREAS = [
  { name: 'cli-entry',      paths: ['src/oida/cli.py', 'src/oida/loader.py', 'src/oida/connection.py', 'src/oida/targets.py', 'src/oida/__init__.py', 'src/oida/__main__.py'] },
  { name: 'utils-core',     paths: ['src/oida/utils/'] },
  { name: 'pcap-scanner',   paths: ['src/oida/pcap/scanner.py', 'src/oida/pcap/__init__.py', 'src/oida/pcap/passive/__init__.py'] },
]

// ---------------------------------------------------------------------------
// Result schema — keep findings comparable across reviewers.
// ---------------------------------------------------------------------------
const REVIEW_SCHEMA = {
  type: 'object',
  required: ['target', 'files_reviewed', 'findings'],
  additionalProperties: false,
  properties: {
    target: { type: 'string', description: 'Module / cluster name being reviewed' },
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
          title:    { type: 'string', description: 'One-line summary' },
          file:     { type: 'string', description: 'file:line or file:line-line' },
          description: { type: 'string', description: '1-3 paragraph explanation: what is wrong, why it matters, suggested fix' },
        },
      },
    },
    summary: { type: 'string', description: 'One paragraph overall assessment of the module' },
  },
}

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

const protocolPrompt = (proto) => `
You are doing a code review of the OIDA protocol module: \`src/oida/protocols/${proto}/\`.

CONTEXT:
- OIDA is a defensive ICS security-testing CLI framework. The protocol you're
  reviewing is part of a fleet of 26 protocol scanners that all follow the
  same Layer-1 (BaseScanner) / Layer-2 (NetworkConnection) facade pattern.
- See \`docs/ARCHITECTURE.md\` for the contract, \`STYLE_GUIDE.md\` for naming,
  \`CLAUDE.md\` for the codebase orientation.

SCOPE:
- All Python files under \`src/oida/protocols/${proto}/\` (recursively).
- Tests under \`tests/unit/${proto}/\` (read for context — don't review them).
- The corresponding fuzzer at \`src/oida/fuzz/protocols/${proto}.py\` IF the
  protocol has one (review there is handled by a separate agent — skip).

WHAT TO LOOK FOR:
1. **Bugs / correctness**: off-by-one, wrong type, missing await, swallowed
   exceptions, race conditions, resource leaks, broken error paths.
2. **Security** (defensive-tool concerns): silent credential leaks into logs,
   --confirm gates missing on dangerous ops, parser-level OOM / unbounded reads,
   trust of attacker-controlled response data without validation, hard-coded
   default credentials surfacing into output.
3. **Layer contract violations**: subclass that breaks the Layer-1/Layer-2
   pattern in ways that confuse the facade.
4. **Style / maintainability**: dead code, mis-named flags, contradictory
   docstrings, magic constants that should be named.
5. **Cross-protocol consistency**: does this protocol disagree with iec104 /
   modbus / dnp3 reference patterns where the audit said they should align?

DO NOT FLAG:
- Things the codebase explicitly accepts (read \`RELEASE_TODO.md\` and
  \`CHANGELOG.md\` first — do not re-discover already-known issues).
- "Could be more Pythonic" nits.
- Missing tests (tests/ exists separately; out of scope here).
- Documentation polish unless the docstring is actively misleading.

CALIBRATION:
- Most protocols will yield 0-5 findings; some will yield 10+. Set severity
  honestly — CRITICAL means "would crash a target / leak creds / drive a
  state change without confirm". Don't grade-inflate.

Return the structured result via the schema. \`file\` should be
\`src/oida/protocols/${proto}/<file>:<line>\` or \`<file>:<start>-<end>\` for
multi-line findings.
`.trim()

const listenerClusterPrompt = (cluster) => `
You are doing a code review of an OIDA passive pcap-listener cluster:
${cluster.files.map(f => '  - src/oida/pcap/passive/' + f).join('\n')}

CONTEXT:
- OIDA's pcap subsystem replays saved packet captures through 109 dissectors
  (one per protocol family) to surface devices, credentials, and protocol
  interactions found in the wire. Listeners inherit from
  \`PySharkListenerBase\` (\`src/oida/pcap/passive/pyshark_base.py\`).
- See \`docs/ARCHITECTURE.md\` and \`CLAUDE.md\` for orientation. Read
  \`pyshark_base.py\` to know what the contract is before reviewing
  the listeners in this cluster.

SCOPE: only the files listed above. Other listeners are reviewed by other
agents in this workflow.

WHAT TO LOOK FOR:
1. **Greedy listener / false positives**: REQUIRED_LAYERS too loose, code
   paths that record an interaction even when the packet doesn't actually
   belong to the protocol. (See \`tests/integration/pcap/test_false_positives.py\`.)
2. **Silent drops**: paths that early-return without recording an interaction
   AND without an explanatory debug log. The audit found 4 of these
   (pim/bacnet-arcnet/modbus/ldap) — make sure these listeners don't have
   the same bug class.
3. **Direction-by-port hardcode**: \`if dst_port == <STANDARD>\` without a
   fallback for non-standard ports. iec104/modbus/mms have the
   "lower port wins" pattern; check others.
4. **Pyshark EK quirks**: \`packet.<layer>.field\` returning None silently
   when \`_fields_dict\` is a list (encapsulated headers). \`pyshark_base.get_ip_info\`
   has a fallback for this — listeners that bypass it may regress.
5. **Credential / device-info disclosure into logs at the wrong level**
   (info/display vs debug).
6. **Tshark field name typos / outdated names** that would silently fail.

DO NOT FLAG:
- Listeners that just don't emit much info — many wire protocols are sparse.
- Missing tests (separate scope).
- Style nits.

Return the structured result via the schema.
`.trim()

const fuzzerPrompt = (area) => `
You are doing a code review of OIDA fuzzer code in:
${area.paths.map(p => '  - ' + p).join('\n')}

CONTEXT:
- OIDA wraps boofuzz with protocol-specific Request definitions for ~30
  protocols. The base is \`BaseFuzzer\` / \`StatefulFuzzer\` in
  \`src/oida/fuzz/core/base_fuzzer.py\`.
- See \`ref/<proto>/cve_patterns.json\` for the CVE patterns each request
  targets — many findings will compare current code against those refs.

WHAT TO LOOK FOR:
1. **Request registration drift**: \`Request()\` objects defined in source
   but never \`session.connect()\`'d, OR connected but missing from
   \`get_request_definitions()\` (which powers \`--list-requests\`). A finding
   in either direction is a real bug — workflow \`wt1ga9ddg\` already had this.
2. **Fuzzable-flag misuses**: \`fuzzable=False\` on bytes that SHOULD mutate
   (per cve_patterns.json), or fuzzable=True on structural bytes that break
   the frame before reaching the parser.
3. **Mutation primitives over-broad**: \`String()\` / \`Bytes()\` without
   \`max_len=\` cap when targeting a length-prefixed protocol — can OOM
   the target before the network stack drops.
4. **CRC / checksum drift**: Static placeholder fields that get auto-recomputed
   by the send pipeline (defeating the test), OR Checksum() primitives in
   protocols where you want to test the validator with a bad CRC.
5. **State machine reachability**: StatefulFuzzer subclasses where a state
   has no edge connecting it from the initial state.
6. **Monitor wiring**: protocol-specific Monitor subclasses defined but never
   registered with the FuzzSession.

DO NOT FLAG:
- "Could add more Request types" — out of scope; see \`ref/_FUZZER_OPTIMIZATIONS_TODO.md\`.
- Test scaffolding under tests/unit/fuzz/.
- Style nits.

Return the structured result via the schema.
`.trim()

const frameworkPrompt = (area) => `
You are doing a code review of OIDA framework code in:
${area.paths.map(p => '  - ' + p).join('\n')}

CONTEXT:
- This is the framework layer that every protocol scanner depends on.
  Bugs here affect ALL 26 protocols.
- See \`docs/ARCHITECTURE.md\` for the canonical Layer-1/Layer-2 facade
  contract and \`CLAUDE.md\` for orientation.

WHAT TO LOOK FOR:
1. **Cross-protocol leaks**: anything that lets one protocol's state pollute
   another (the audit caught the Namespace-mutation bug — confirm no others).
2. **Logger / privacy**: paths that write engagement-sensitive data to JSON
   logs, screen output, or shared global state. The \`format_wordlist_source\`
   helper exists in \`utils/login_scanner.py\` — find other places that
   should use it but don't.
3. **Error paths that swallow exceptions** without a debug log or context.
4. **--confirm enforcement**: framework helpers that should enforce the gate
   centrally rather than per-protocol.
5. **Dependency injection / lazy_import**: protocols that bypass
   \`utils/lazy_import\` and import an optional dep at module load.
6. **Thread/concurrency safety**: shared mutable state without locks, esp.
   in caches (logger cache in ics_logger).

DO NOT FLAG:
- Tests, scripts, docs.
- Style nits.
- Already-deferred refactor targets listed in \`RELEASE_TODO.md\` §3.3 / §4.2.

Return the structured result via the schema.
`.trim()

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

phase('Framework')
const frameworkResults = await parallel(
  FRAMEWORK_AREAS.map(a => () =>
    agent(frameworkPrompt(a), {
      label: `framework:${a.name}`,
      phase: 'Framework',
      agentType: 'review',
      schema: REVIEW_SCHEMA,
    })
  )
)

phase('Protocols')
const protocolResults = await parallel(
  PROTOCOLS.map(p => () =>
    agent(protocolPrompt(p), {
      label: `proto:${p}`,
      phase: 'Protocols',
      agentType: 'review',
      schema: REVIEW_SCHEMA,
    })
  )
)

phase('Listeners')
const listenerResults = await parallel(
  LISTENER_CLUSTERS.map(c => () =>
    agent(listenerClusterPrompt(c), {
      label: `listeners:${c.name}`,
      phase: 'Listeners',
      agentType: 'review',
      schema: REVIEW_SCHEMA,
    })
  )
)

phase('Fuzzer')
const fuzzerResults = await parallel(
  FUZZER_AREAS.map(a => () =>
    agent(fuzzerPrompt(a), {
      label: `fuzz:${a.name}`,
      phase: 'Fuzzer',
      agentType: 'review',
      schema: REVIEW_SCHEMA,
    })
  )
)

const allResults = [...frameworkResults, ...protocolResults, ...listenerResults, ...fuzzerResults].filter(Boolean)
const allFindings = allResults.flatMap(r => (r.findings || []).map(f => ({ ...f, target: r.target })))

log(`Reviewed ${allResults.length} areas; collected ${allFindings.length} findings before dedup.`)
const sevCount = {}
for (const f of allFindings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1
log(`By severity: ${JSON.stringify(sevCount)}`)

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------
phase('Aggregate')

const aggregatePrompt = `
You are aggregating the findings from ${allResults.length} parallel code-review
agents on the OIDA codebase. Total raw findings: ${allFindings.length}.

YOUR JOB:
1. Read the findings array below.
2. Dedup: collapse findings that describe the same underlying issue but
   were noticed by multiple reviewers (e.g. "format_wordlist_source not used
   in HL7" might appear from both the HL7 reviewer and the framework
   reviewer).
3. Re-calibrate severity: reviewers were per-module and may have been
   high-confidence locally but the issue is global (or vice versa).
4. Group by severity: CRITICAL → HIGH → MEDIUM → LOW → INFO.
5. Within each severity bucket, sort by file path so related issues are
   adjacent.
6. Write the consolidated report to ./CODE_REVIEW.md in markdown:

   # OIDA Code Review (workflow code-review-full / <run-id>)

   ## Summary
   - N areas reviewed: ...
   - N findings (post-dedup): ...
   - Breakdown by severity: ...
   - Highest-blast-radius findings: top 3-5 bulleted

   ## CRITICAL
   ### <file:line> — <title>
   <description>

   ## HIGH
   (same format)

   ... etc.

   ## Areas with zero findings
   <comma-separated list>

7. Return the FULL path to the file you wrote ("/home/feb/pro/oida/CODE_REVIEW.md")
   plus a one-paragraph executive summary.

RAW FINDINGS (JSON):

\`\`\`json
${JSON.stringify(allFindings, null, 2).slice(0, 200000)}
\`\`\`

(Truncated to 200kB; if there's more, the agents over-produced and you
should note that in the report's Summary.)

PRINCIPLES:
- Be ruthless about dedup. 30 reviewers each noticing "uses bare except"
  isn't 30 findings; it's one project-wide issue + 1 example pointer.
- Don't lose any CRITICAL or HIGH finding. MEDIUM may be deduped more
  aggressively. LOW / INFO can be batched.
- Preserve enough file:line context that someone can act on each finding.
`.trim()

const aggregated = await agent(aggregatePrompt, {
  label: 'aggregate-findings',
  phase: 'Aggregate',
  agentType: 'review',
})

return {
  areas_reviewed: allResults.length,
  raw_findings: allFindings.length,
  severity_breakdown: sevCount,
  consolidated_report: aggregated,
  per_area_results: allResults,
}
