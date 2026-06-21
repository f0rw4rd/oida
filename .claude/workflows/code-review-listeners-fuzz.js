export const meta = {
  name: 'code-review-listeners-fuzz',
  description: 'Follow-up: review pcap listener clusters + fuzzer areas (the slice rate-limited in the full run). Returns raw findings; no file write.',
  phases: [
    { title: 'Listeners', detail: 'Pcap-listener clusters grouped by category (~13 agents)' },
    { title: 'Fuzzer', detail: 'Fuzzer core + protocol modules (4 agents)' },
  ],
}

const REVIEW_AGENT = 'general-purpose'

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
2. **Security** (defensive-tool concerns): --confirm gates missing on dangerous
   ops, parser-level OOM / unbounded reads, trust of attacker-controlled
   response data without validation.
3. **Layer contract violations**: subclass that breaks the Layer-1/Layer-2
   pattern in ways that confuse the facade.
4. **Style / maintainability**: dead code, mis-named flags, contradictory
   docstrings, magic constants that should be named.
5. **Cross-protocol consistency**: does this protocol disagree with iec104 /
   modbus / dnp3 reference patterns where the audit said they should align?

DO NOT FLAG:
- Things the codebase explicitly accepts (read \`RELEASE_TODO.md\` and
  \`CHANGELOG.md\` first — do not re-discover already-known issues).
- Cleartext logging/export/console-display of discovered or supplied
  credentials. OIDA is an operator-run tool; surfaced credentials are the
  operator's own deliverable, not a leak. No "redact creds" findings.
- "Could be more Pythonic" nits.
- Missing tests (tests/ exists separately; out of scope here).
- Documentation polish unless the docstring is actively misleading.

CALIBRATION:
- Most protocols will yield 0-5 findings; some will yield 10+. Set severity
  honestly — CRITICAL means "would crash a target / corrupt results / drive a
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
5. **Tshark field name typos / outdated names** that would silently fail.

DO NOT FLAG:
- Listeners that just don't emit much info — many wire protocols are sparse.
- Cleartext logging/display of credentials or device info surfaced from the
  capture. Surfacing wire-observed data is the tool's job, not a leak.
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

// Throttled runner: small sequential batches (peak `size` concurrent) instead
// of firing all 16 at once — the burst is what trips the server-side rate
// limiter. A second fully-serial pass retries any null (rate-limited) areas.
async function runThrottled(items, label, makePrompt, phaseName, size) {
  const results = new Array(items.length).fill(null)
  for (let i = 0; i < items.length; i += size) {
    const idx = []
    const thunks = []
    for (let j = i; j < Math.min(i + size, items.length); j++) {
      const item = items[j]
      idx.push(j)
      thunks.push(() => agent(makePrompt(item), {
        label: label(item), phase: phaseName, agentType: REVIEW_AGENT, schema: REVIEW_SCHEMA,
      }))
    }
    const r = await parallel(thunks)
    r.forEach((v, k) => { results[idx[k]] = v })
    log(`${phaseName}: batch done, ${results.filter(Boolean).length}/${items.length} so far`)
  }
  // serial retry pass for stragglers that got rate-limited
  for (let i = 0; i < items.length; i++) {
    if (results[i]) continue
    results[i] = await agent(makePrompt(items[i]), {
      label: `${label(items[i])}:retry`, phase: phaseName, agentType: REVIEW_AGENT, schema: REVIEW_SCHEMA,
    })
  }
  return results
}

phase('Listeners')
const listenerResults = await runThrottled(
  LISTENER_CLUSTERS, c => `listeners:${c.name}`, c => listenerClusterPrompt(c), 'Listeners', 3
)

phase('Fuzzer')
const fuzzerResults = await runThrottled(
  FUZZER_AREAS, a => `fuzz:${a.name}`, a => fuzzerPrompt(a), 'Fuzzer', 3
)

const allResults = [...listenerResults, ...fuzzerResults].filter(Boolean)
const allFindings = allResults.flatMap(r => (r.findings || []).map(f => ({ ...f, target: r.target })))
log(`Reviewed ${allResults.length} areas; ${allFindings.length} findings.`)
return { areas_reviewed: allResults.length, raw_findings: allFindings.length, per_area_results: allResults }
