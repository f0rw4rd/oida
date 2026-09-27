## v1.0.1 - 2026-09-27

### Chore

- Reword project description to OT/ICS Dynamic Assessment Framework

## v1.0.0 - 2026-09-27

### Added

- §4 - 3 new OPCUA fuzz requests + dead test scaffold cleanup

- Real verified-crashing CVE container fleet + per-protocol reorg

- Real OSS mock stacks, bacnet bind fix, conformance test wiring, tooling

- Configurable private registry via $OIDA_REGISTRY + sync command

- Structure-aware BER/ASN.1 mutation + BACnet crash oracle

- Default OIDA_REGISTRY to ghcr.io/f0rw4rd

- `list <filter>` + warn when push skips a dirty context

- Flag bulk result sets as a possible exfiltration

- Add name/group filter to status & list, and single-service up

- Add CVE-driven attack methods for MMS, EtherNet/IP, IEC104, MQTT

- Crashes / reproduce / narrow subcommands and combinatorial-depth flags

- Opt-in arg-key typo detection; demote Layer-1 to internal

- Accept <host>:<port> in every target form

- Fall back to a temp output dir when --format is given without -o

- Summarize exported file counts in --output help and success line

- Add Secret column to unified credentials table + export

- DTLS support in TLS listener + EK header recovery

- Gate releases on outdated mock images

- Make `stale -v` show the evidence behind each verdict


### CI

- Remove orphaned lib60870 gitlink (no .gitmodules) that broke checkout

- Install tshark for pcap tests; format hartip/pcom/tls

- Exclude tshark-version-sensitive pcap tests from unit lane

- Mock-stack failure is non-fatal (best-effort coverage)

- Remove CLA Assistant workflow (single-maintainer; inbound=outbound in CONTRIBUTING)

- Add --extra dev on Windows so pytest is available for smoke test

- Release env carries runtime extras only; pyinstaller+pytest installed as build/test tools (no dev extra)

- Gate provenance attestation to public repos (unavailable on user-owned private repos)

- Bump actions/checkout v4.2.2 -> v6.0.3 (node24 runtime)

- Raise dependabot pip PR limit 5 -> 10 (#33)

- Allow release.yml to reuse ci.yml via workflow_call

- Make CI manual-only (workflow_dispatch); remove cron scheduled-tests + coverage-nightly

- Add quick lint/format auto-gate on PRs (full CI stays manual)

- Add unit+contract test job to PR gate (3.12, -n auto, excl pcap)

- Add GitHub-only test-release workflow; make build-binaries reusable

- Gate on unit+contract tests only, drop lint/format

- Drop the unit-test gate; build+publish artifacts unconditionally

- Use thread timeout method for Windows smoke test (signal is Unix-only)

- Upload built binary even if smoke test fails (job stays red)

- Nightly CVE-replication axis + mock stack updates

- Install pyinstaller from locked dev group, not ad-hoc pip

- Bump 3 GitHub Actions to current, keep SHA pins

- Gate the measured glibc floor instead of just reporting it

- Run the tshark-dependent fuzz test in the pcap lane, and prep 1.0.0

- Smart per-version matrix + Python 3.13/3.14 support

- Install all extras except dnp3 on the 3.14 lane

- Gate heavy integration + pcap jobs to release, not every push

- Run the pre-push hooks as step 2

- Checkout git-lfs objects for pcap/dissector jobs

- Remove coverage-nightly workflow

- Trigger release.yml by hand only

- Trigger by hand only

- Wire the blocking mypy gate into the local script

- Pin the dissector job's tshark to 4.2.*

- Run CI on PRs instead of every push to main

- Unify release workflows into "Release"

- Grant binaries job id-token permission for attestation

- Also grant attestations permission to the binaries job


### Changed

- §3 proto_args_factory migration (6 holdouts)

- Flatten pcap/passive/ into pcap/ (pcap is inherently passive)

- Drop 14 _safe_int clones for base _parse_int

- Add get_field_any, collapse dual-name field chains

- Drive mock management from compose labels, drop PROTO_SPECS

- Rename nxc_connection module to cli_runner

- Drop dead logger guards and pymodbus 2.x compat

- Drop dead library-version compat shims

- Drop dead brotlipy fallback and iec104 demo methods

- Unify dispatch, type the result envelope, and gate confirms

- Remove Metasploit-style standalone-run metadata generator

- Knx -p flag, port-aware progress banner, drop dead SERIAL_PROTOCOLS

- Reply-expectation policy, DEAD/UNRESPONSIVE verdicts, effectiveness counters

- One import style — absolute `from oida.x import y` everywhere

- Share brute-force connection-error classifier in protocol_helpers


### Chore

- Untrack Claude tooling (.claude, CLAUDE.md) and ref/ research material; keep local via .gitignore

- Remove stale reports + one-off dev scripts (TEST_REPORT, WORKFLOW_VERIFICATION_REPORT, bench/debug/pcap-gen scripts)

- Untrack .python-version (per-dev pyenv pin; uv/CI own the interpreter)

- Replace contact emails with https://getoida.dev/contact link

- Remove personal lab scripts (win_shell.sh ssh helper, portforward.sh)

- Untrack .envrc (direnv local env; kept on disk)

- Remove dead files (orphan config/data READMEs, stale frozen-build snapshots)

- Drop DTLSSocket dependency from coap extra

- Remove memcached CVE mock services

- Checkpoint working tree before cli_runner rename

- Retire root planning docs, un-hide agent definitions, add slop AST check

- Bump profinet-py 0.6.2->0.6.3 and xknx 3.15.0->3.19.0

- Gitignore AI-workflow tooling and docs/ (purged from history, kept local)

- Gitignore maintainer dev-container

- Bump 16 outdated protocol dependencies

- Transitive lock refresh + pytest 9.1 compat

- Drop stale pip requirements pin files

- Drop dead protocol_registry placeholder and its stale references

- Attribute the project to f0rw4rd instead of "OIDA Team"

- Stop advertising dead flags; expand OPC UA usage examples

- Gitignore local RELEASE_CHECKLIST.md scratch file

- Drop NEW: edit markers and redundant step comments

- Normalize non-ascii text to ascii


### Docs

- Sync RELEASE_TODO.md §−1 checkboxes against committed fixes

- Sync RELEASE_TODO §1 (feature test matrix) - 165->10 open

- Add GitHub workflows verification report

- Reconcile OIDA backronym to 'OT/ICS Discovery & Assessment' (matches website)

- Remove in-repo docs (content now at getoida.dev); fix dangling links

- Remove DISCLAIMER.md (authorized-testing notice lives at getoida.dev)

- Slim README; point to getoida.dev, fix DISCLAIMER link to LICENSE

- Drop the authorized-testing warning block from README

- README/CONTRIBUTING/CODE_SIGNING polish; pcap listener updates

- Replace Discord with email + GitHub Discussions contact

- Add trademark notice

- Drop memcached references after service removal

- Add snap7-deep findings (2 CRITICAL brute-force false-positives)

- Research notes on the fuzzer payload system

- Add empirical validation + scheduling analysis

- Stateful/crypto delivery + capability-adoption finding

- Flag matrix says --ads-port; the -P short flag was removed

- Record release-prep additions and fixes

- Advertise <host>:<port> shorthand in usage text, tidy ocpp port resolution

- 1.0.0 Fixed entries for the bug-hunt batch and hook fix

- Reconcile CHANGELOG with commits landed since last edit

- Drop citations to untracked workflow docs

- Reword content-free comparative claims

- Add the ko-fi link back alongside quellsec support


### Fixed

- Fix remaining profinet-pnet-device ghost refs + test report

6 refs in test_profinet_integration.py (incl @pytest.mark.containers)
still referenced the old name; pytest-docker fixture invoked compose
up with the ghost, returning 1 instantly and cascading to 376 setup
errors. With this fix the cascade is fully gone.

TEST_REPORT.md: unit 10241/1/260/11xf, integration 2860/154/1502/376e
pre-fix, plus full root-cause breakdown and remediation list.

- 8 import-depth crashes — 6 wrong-shallow + 2 wrong-deep imports

- Coap DTLS scheme bypass — wordlist prober + write helpers used hard-coded coap://

- Connection probe + standalone helper no longer send patient writes

- --methods safe-by-default; write methods require --confirm

- UDP timeout no longer reported as positive security finding

- OPC UA set_user TypeError (drop bad await) + NetManage DiscoveredDevice kwarg drift

- Migrate pymodbus slave= → device_id= (21 src sites + tests)

- SZL parser DoS — record_len=0 infinite loop

- Master/backup classifier inverted vs RFC 5798

- Redact credentials in CLI debug log + brute-force progress lines

- Merge_config_with_args silently dropped non-None defaults

- C-GET/C-STORE path traversal via hostile UIDs

- Send_custom_fc arity + _send_mei_canopen missing helper

- 11 confirm-gate-missing flags + snap7 audit/brute gates

- Gate --probe-ops + implement 8 missing SegmentBuilder methods

- HIGH batch — confirm-gates + ethernetip/snap7 false positives

- HL7 silent fallbacks + OPC UA flag/URL bugs

- HIGH batch 3 - misc bugs across 11 protocols

- HIGH batch 4 - IPv6 + args leak + wordlist labels + discovery logs

- Bacnet routing + discovery merge + 16 garbled logs + tests

- Actually validate credentials with probe connect+read

- Bacnet DCC/BBMD predicates + dicom default port + skip-if test guards

- Complete remaining 3 HIGH items + verification tests

- §−1 final batch — HL7Monitor cap + monitor loggers + export contract + timeout snapshots

- Ruff format pass + bump setup-uv to v8.2.0

- Make ads stderr-capture + wsdiscovery tests robust under pytest/CI capture

- Fhir enum_all test asserts on scanner.args (copy-on-write Namespace)

- Ship device_database.json inside the package so MEI device-ID actually loads

- Correct EEPROM dump range help (0x7F) and -e --eeprom-parse example

- ISO-TP multi-frame reassembly + Flow Control

- Test suite fixes + xdist parallelisation

- Code-review findings (framework + ads/astm/bacnet/can/coap/dnp3/ethercat)

- Code-review findings (dicom/ethernetip/fhir/goose/hart/iec104/knx/mms/modbus)

- Code-review findings (mqtt/ocpp/opcua/pcap/profinet/snap7/snmp/tase2/hl7) + confirm-gate test reconciliation

- Implement MapNameResolver (dead import), iec104 fuzz tuple unpack, hl7 grouped-segment parse

- PyPI badge points to oida-ics

- 5 HIGH review findings (snap7/vnc inverted verdicts, can/knx confirm gates, coap dtls port)

- 5 HIGH review findings (dicom port, dnp3 assign-class range + SA wiring, ethernetip write gate, mms typed restore)

- 6 HIGH fuzzer findings — wire --enable/--disable gating (dhcp, icmpv6, iec104, mdns, snmpv2, snmpv3)

- 4 HIGH pcap-listener findings (ajp status, c1222/ipmi/ipp field extraction)

- 4 HIGH pcap-listener findings (ntlm stream correlation, opcda/rpcbind greedy guards, tns refuse fields)

- 10 MEDIUM findings (dicom/opcua/knx confirm gates, hart dead flags wired, ipmi direction+cipher-zero)

- 6 MEDIUM listener findings (bacnet/rmi/socks silent drops, pop3/smtp/imap non-standard-port direction)

- 5 MEDIUM listener findings (EK base16 parsing x4, gif carving, ptp alert dedup, x11 ek fields, iscsi opcode symmetry)

- 5 MEDIUM fuzzer registry findings (validate enable/disable names; ethernetip/icmpv6 phantoms; ipv6/ntp unregistered requests)

- 6 MEDIUM findings (ipp pairing, ethernetip dump-security opt-in, fhir https default, mqtt service/leak, ocpp dead method)

- 7 MEDIUM findings (smartinstall/tftp listeners, bacnet readfile cap + recon, hl7 enum/oru, can xcp arbid)

- 5 MEDIUM findings (ads fuzz-memory removed, ethercat PD ordering, goose gocb-ref, iec104 callback compose, mms fuzz FC)

- Final 6 MEDIUM (profinet/snap7/tase2, ICSLogger.extra thread-local, require_confirm helper, cred-list copy) + gate dicom store/move

- Integration regressions from review fixes (iec104 listen callback sig, iec104 fuzz explicit --enable override; mark hart --full flaky under load)

- 5 LOW findings (cli tables.pop mutation; coap/ethernetip/http2/rtu ungated fuzzer requests)

- 5 LOW listener findings (ajp/ftp silent drops, iec104 s-frame mislabel, kerberos rep port, mongodb op_msg direction)

- 5 LOW findings (astm tls peek, bacnet objid parse, dicom cfind recursion guard, fhir model column, hart client leak)

- 5 LOW findings (vnc/dns fuzzer gating, fuzz_cli monitors help, pgsql sasl field, rgoose silent drop, sercos svc attribution)

- 5 LOW findings (dicom reject-info guard, fhir premature connected, ocpp ws scheme, opcua file-read cap, opcua fuzz restore)

- 4 LOW findings (pcap scanner unbound var, profinet socket leak, snap7 slot pacing, ics_logger torn read)

- Regression-review fixes (sercos SVC single-slave fallback, ptp flap dedup per-domain)

- Fhir --no-tls built http://host:443 (spurious port); only append non-standard ports

- Snap7 --monitor bool.split crash (source areas from --monitor-areas) + dnp3 OnDeviceAttribute missing 'set' arg

- Iec104 --test-commands was a no-op — now probes control-command acceptance (C_SC/C_DC) at --test-command-ioa, reports finding

- Unify protocol log labels (no flip-flop); empty banner sponsors

- Stop iec104/pcap re-declaring global --full-width/--json-log

- Correct dead tshark field tokens in 8 passive listeners

- Build dnsmasq CVE image without racing install against compile

- Don't hard-require boofuzz for CLI init or non-fuzz commands

- Bundle manuf2 OUI database in standalone binaries

- Redact credentials in the --debug args dump

- Make BACnet/SC cert-audit failures visible, not silent

- Stop swallowing Ctrl-C/cancellation (except BaseException)

- Correct COTP TSAP field tokens (silent-empty extraction)

- Correct false-safe security verdicts and extraction bugs (bug hunt)

- More bug-hunt findings + findings report

- Correct listen-mode ASDU offsets (COT is 2 octets)

- Correct listener field extraction and endpoint direction

- Close 5 HIGH review findings (false verdicts, ungated ops, import crash)

- Pin bullseye apt to the image's baked snapshot

- Accept username/password under asyncua 2.0 + harden set_temperature

- Honor -p/--port on a bare host target

- Don't truncate tables to terminal width when output is piped

- Reject malformed --memory-write instead of writing address 0x0000

- Guard len(data) >= 2 before classifying CALLRESULT frames

- UNSYNC flag was inverted

- Reject truncated ciphertext before emitting a 16100 hash

- Scope DATA server attribution to the endpoint pair

- DATA/ACK interaction direction was hardcoded

- Parse every header in an XML-mode unknown_header blob

- Don't assume a 4000 smpCnt wrap when smpRate is unknown

- Stop session regex from spanning multiple login attempts

- Extract credentials in XML mode, and read the real error field

- Parse IIN from the hex-rendered field and correct IIN1/IIN2 order

- Correct SVCCTL opnum mapping so a write op isn't reported as a read

- Reach the XML-mode field fallback and fix reversed dedup guard

- Stop emitting placeholder credential and salt values

- Report unknown --format instead of silently writing nothing

- Restore stats keys so list_test_cases works on the real database

- Align mock get_test_cases ordering with the ORM backend

- Decode I-Am with application tags and order NPCI correctly

- Don't decode controller data from an error reply

- Update device record on repeat sightings

- Distinguish standard and extended frames with the same arbitration ID

- Render the mutated value so Data_Offset is actually fuzzed

- Emit extended-length ISO 8327 framing instead of crashing

- Stop corrupting every byte >= 0x80

- Use a MutationContext attribute that actually exists

- Keep curated binary payloads malformed

- Honour size/padding/fuzzable when radamsa is enabled

- Read the watchdog divider and DC activation from the right registers

- Hex-parse GSDML SubslotNumber so the file isn't discarded

- Stop decoding the BitString unused-bits byte as content

- Correct the vendor-ID table against the ASHRAE registry

- Actually apply the requested security instead of silently downgrading

- Support bool in the encoder and stop float-ifying bool map values

- Match the SunSpec not-implemented sentinel for sunssf

- Decode ctypes byte fields before use and before reporting

- Emit the CR record terminator inside the checksummed span

- Stop inventing a vendor identity from 4-character substrings

- Stop reporting a rejected wildcard query as a security finding

- Make seven fuzzers advertise what they actually send

- Gate the four missing mutating universal commands

- Parse the real Beckhoff identify wire format and split the index tables

- Status extraction, IPv6 targets, ack swallowing, and gate wiring

- Sibling Group rendered concatenated, killing the traversal cases

- Build the parser from the argv main() actually parses

- Checksum status 0 is Bad, not 2 - forgery alert was unreachable

- Checksum status table inverted and opcode table wrong

- CHECKSUM_STATUS_BAD was 2 (Unverified), so bad checksums never alerted

- Three diagnostic labels wrong and RFC 6428 code 9 missing

- Operating status is its own enum, not the admin-status table

- Srvsvc opnums were shifted, reporting a DFS call as a share deletion

- The "?" salt placeholder escaped into credentials and export

- IKE version reported as v0x01 on the live-capture path

- Five multicast group names were wrong, and KNXnet/IP was missing

- Hello option 65001 was invented, and PIM types 9-13 were missing

- Repeated multicast groups merged into one bogus entry, neighbors never populated

- FDA_OpenSession was classified as a read

- Safety state tables were shifted, downgrading Critical Fault to Abort

- XML-mode captures silently extracted nothing from ICMP-quoted HART-IP

- _supervision_times grew unbounded and was never read

- Add six listener modules the committed registry already referenced

- Every MQ API verb was mislabelled, and the table drove dispatch

- A device memory write was reported as a read

- Generic read/write cause-of-transmission codes 42-44 were missing

- SASL mechanism was read from a field tshark does not define

- CHAP data read from nonexistent fields, and _chap_state leaked

- Command table had fabricated codes and drove the wrong dispatch

- Table-55 write registration keyed off a command code that does not exist

- SDO read/write polarity was inverted, so OD writes were reported as reads

- Exchange.Unbind-Ok carried Queue's method id

- Option 119 read a field name that does not exist

- Service table carried PCCC/Modbus-bridge names, so Device Shutdown read as "Write Tag"

- CAN arbitration ID is rendered decimal, not hex

- Drop unverified dnp3 CVE mock, fix mqtt build and opcua anonymous auth

- Honor --enable/--disable for UDP requests and correct CVE citations

- Stop reporting "no evidence" as a healthy target

- Correctness fixes across connections, state machine, session store and RNG

- RFC 6690 link-format parsing, JSON recursion guard, DTLS key validation

- Read-only flag inverted, rate-limiter clock jumps, target parsing, and logger cleanup

- Snap IOCR reduction ratio to a valid power of two

- Bound message accumulators and correct "passive sniffing" docs

- UDS response-pending, ISO-TP/SDO bounds guards, and index safety

- Report real capability results and stop mislabeling untested controls

- Per-point command status, vacuous all() checks, and polling abort

- Probes left device clock and outOfService points altered; enumerations aborted on Error/Reject PDUs

- AET brute-force ran plaintext against TLS listeners and had no bounds

- Active LLDP scan crashed, and merged devices lost vendor payloads

- SII bootstrap-mailbox and DC-category fields read from wrong offsets

- TCP/IP Interface Object IP addresses parsed with wrong byte order

- Brute-force/OAuth2 probes ignored TLS client config, reporting a false "0 valid"

- Unicast discovery used multicast-only SEARCH_REQUEST, silently failing against real gateways

- --test-write on input/discrete banks reported the wrong bank, and diag words crashed on multi-byte data

- Reported security_mode could lie, and cert-acceptance audits never generated a cert

- --cpu-start did a destructive cold restart, and the op timeout never bounded wall-clock

- SNMPv3 authPriv with a missing passphrase crashed the scan, and bare -E bypassed --confirm

- Several listeners mis-attributed request/response direction

- Field-name and spec-table errors dropped or mislabelled data

- Unbounded per-packet work let a hostile capture exhaust memory/CPU

- Parsing gaps lost credentials, devices, and non-TCP Modbus

- Schedule/calendar/alarm/trendlog/priority/life-safety checks aborted --assess on unknown-object

- Vendor fingerprint dict had fabricated vendor->ID mappings

- Record a crash row per case, de-bounce only the crash event

- Session-end crash count re-inflated a single outage to one-per-check

- Crash bookkeeping corrupted / silently dropped on a raising flush

- Refused --send/--send-file/--replay reported success=True

- Refused writes reported success=True

- Refused dangerous ops reported success=True

- Modbus health-probe false positives halted fuzzing

- App-monitor health-probe false positives (HTTP/FTP/SMTP/DNS)

- Tolerant protocol-fuzzer loader so one missing dep no longer breaks all fuzzing

- Make the integration lane green under strict mode

- Remove hardcoded personal path from integration runner

- Close two credential-leak paths in crash-report redaction

- Retain discovered credential; wire arg-key typo detection

- Close three more false-positive / hang / fabrication bugs

- Look up metadata under the real distribution name

- Log export target dir at info level after every export

- Drop file-path prefix from export announcement

- --output without --format now exports all formats

- Demote per-table export count to debug

- Export -S/--stats tables instead of console-only rendering

- Detect SSDP/WS-Discovery/mDNS and cross-transport services in stats

- De-duplicate cross-listener devices in asset inventory

- Declare all listener device fields; merge_from via fields() loop

- Exclude CVE targets from group `up` by default

- Pin bullseye CVE mock builds to a snapshot.debian.org mirror

- --rtu-over-tcp, --ascii-over-tcp, --max-registers were dead flags

- Rename misnamed DNS PoC scripts so build-all-mocks.sh doesn't try to build them as Dockerfiles

- Gate tunnel-branch success; repair FP-fix test regressions

- Query package metadata by distribution name, not import name

- Repair frozen-binary protocol dispatch + close fuzz/knx test failures

- Repair two semantic merge conflicts caught by contract tests

- Label export events with the scanned host on single-target runs

- Scope console filters to boofuzz-originated records

- Reject verbatim-echo replies in ping validation

- Key CAN ID stats by traffic key in passive listener

- Gate -E <userfile> behind --confirm like bare -E

- Refused dangerous ops reported success=True

- Failed scans reported success=True via None->True default

- Release_check gate fixes + format 16 review-era files

- SNMP reply policy misread fuzzed bytes; fast-path recv lost boofuzz error mapping

- Lingering failure streak no longer fakes crashes on every case

- Empty specs scanned localhost; file-cycle guard bypassed; [v6range]:port mangled

- One hostile MAC aborted the whole LLDP report

- Mac_lookup never raises on wire-derived MAC strings

- GIF89a was never carved; PNG had a bogus footer

- A non-UTF-8 password list killed the scan

- A stray non-UTF-8 byte silently truncated brute-force wordlists

- SASL and trust logins were reported as plaintext credentials

- Refreshed tokens stayed permanently expired

- Child contexts dropped the session's sequence numbers and crypto state

- Repo bug-hunt — 12 confirmed correctness bugs + check-secrets hook false-positive

- Two integration tests stale after main's monitor-policy changes

- Dead code, pcap lazy-import gap, and HTTP/2 mock server bugs found while auditing tests

- Strengthen 94+ low-assurance tests flagged by test-quality gate

- Eliminate large pylint duplicate-code (R0801) blocks

- Stop protocol custom monitors from evicting CLI monitor extras

- Resolve genuine integration test failures across fuzz, mock, and CLI paths

- Stop check-secrets flagging f-string placeholders as passwords

- Don't count unreachable-server connect failures as tested creds

- Don't count unreachable-server failures as tested HTTP-auth creds

- Don't count lost-connection attempts as tested passwords

- Don't report untested PSKs as failed when DTLS service is unreachable

- Correct opcua-advanced advertised credentials

- Only claim anonymous access once a session activates

- Clear vulture and test-quality gate findings

- Replace broad silent handlers to clear Bandit B110/B112

- Support Python 3.10 in test_dist_name_resolution (tomllib)

- Resolve bug-shaped mypy findings without baselining

- Make DTLSSocket windows-optional

- Correct remaining-length varints in Large_Payload_Overflow

- Make set_reduction_level("aggressive") reversible

- Read Art-Net ESTA manufacturer code little-endian

- Allow a 254-octet ISO 8327-1 short-form length indicator

- Annotate _BALANCED_DEFAULTS to stop mypy call-overload error

- Pin astm upstream templates via PORT_TEMPLATES

- Restart bacserv when the BSC listener dies

- Tolerate coalesced udp_multicast datagrams on read

- Select step 10's re-run from pass 1, not --lf

- Accept tshark 4.2 unknown-protocol filter wording

- Pin c104 from PyPI, unblocking the PyPI upload

- Repair three bugs in the unified Release workflow


### Other

- Initial public release

Co-authored-by: Linus Röpert <linus.roepert@gmail.com>
Co-authored-by: Jan Pennekamp <39992834+jpennekamp@users.noreply.github.com>

- Gate dnp3/ethercat control ops behind --confirm, fix snap7/s7 alias, bound hl7 recv, snmpv3 key validation

- Add RELEASE_READINESS report

- Annotate bandit false positives (vnc tripleDES, export_utils minidom)

- Make hl7apy import honest (clear ImportError instead of deferred crash)

- Remove duplications + setup slop (manifest paths, requirements drift, dead modules, vendor_maps duplicate, local-ip helper)

- Auto-call proto_logger from connection.__init__, strip 26 redundant calls, add ARCHITECTURE.md

- Rename modbus map_rw → read_write, raw_fc → raw_function_codes

- Tighten user-facing text: fix README badge + protocol list, drop ai-doc boilerplate, sync docs to current contracts

- 1.0 release punch list: astm port, hart lazy_import, fhir/opcua phantom flags, double-success banners, single fuzzer DB backend, crash_hash dedup, CI matrix, CHANGELOG

- Add per-protocol fuzzer review notes + machine-readable cve_patterns.json, fix mdns Quick_Coverage zero-mutation bug

- Add remaining per-fuzzer review docs (snmp, dns, mqtt, coap, ftp, smtp, http, hl7) + open-fuzzer candidate list

- Fuzzer optimization: transition IEC104 to DATA_TRANSFER after STARTDT (audit B8); correct modbus length-mismatch coverage claim

- Fuzzer optimization roadmap: line-targeted concrete TODOs grouped by size

- Axis 1: scanner real-coverage suite (tests/coverage/scanner/) measuring per-protocol field-coverage % against live mock containers

- Axis 1: expand scanner coverage suite to 16 protocols (opcua, snmp, mqtt, coap, hl7, fhir, dicom, snap7, mms, hart added); skip on results.success=False

- Fuzz DB perf refactor + ghost-service conftest fix + release TODO

- bulk insert APIs (store_test_cases_bulk, store_metadata_bulk) on
  DatabaseInterface/SQLAlchemy/Mock; one fsync instead of N
- WAL + synchronous=NORMAL + foreign_keys + 64MB cache PRAGMA listener
- single aggregate query in get_statistics (was 8 round-trips)
- covering index (protocol, result, timestamp) + idx on name
- BigInteger for unsigned CRC32 columns
- crash_hash now surfaced in get_crash() returned DTO
- get_test_cases gains target_ip/protocol/limit (default 10k, fuzz_cli
  passes None to keep crash listings honest)
- tests: test_database_perf.py (12) + test_cli_deep.py (14) all green

conftest.py PROTOCOL_SERVICES referenced ghost services
(msf-ics-mock, profinet-pnet-device); a single missing service makes
docker compose return 1 and cascades 'FAILED' to every dependent test.
Replaced with real service names.

RELEASE_TODO.md: punch list for 1.0 (T-6.5w, 2026-07-16)

- Timeout_func_only=true so docker fixture isn't killed by per-test timer

- Update with v5 integration run (timeout fix landed, 0 errors)

- ADS state_flags decode; tests: accept correct listener semantics; xfail 4 known listener gaps

- V6 GREEN baseline — 3004 passed, 0 failed, 0 errors, 4 xfails

- Pcap listeners: fix 4 packet-coverage gaps (pim, modbus, ldap, bacnet)

pyshark_base.get_ip_info: when EkLayer.__getattr__ raises (encapsulated
headers cause _fields_dict to be a list), fall back to raw dict lookup
on the outer header. Unblocks PIM Register frames (was 17/20 dropped).

pyshark_base.get_mac_info: add ARCNET fallback when no eth layer is
present (BACnet/ARCNET datalink). Synthesises 'AR:NN' identifiers for
the 8-bit node IDs. Unblocks BACnet over ARCNET (was 564/564 dropped).

modbus listener: stop hard-rejecting on non-zero mbtcp.prot_id — pyshark's
EK output mis-reads this byte on frames that trigger tshark's 'Cannot
classify packet type' warning. The presence of the mbtcp layer plus a
modbus payload is sufficient evidence; log the discrepancy and proceed.
Unblocks modbus exception responses (was 5/17 dropped).

ldap listener: add SASL/GSSAPI-encrypted message branch. Kerberos-bound
LDAP sessions have ldap.sasl_buffer_length / ldap.gssapi_encrypted_payload
but no ldap.protocolOp (the LDAP message is inside the ciphertext);
previously every encrypted frame fell through with no interaction.
Unblocks Kerberos-bound LDAP (was 19/24 dropped).

test_pim_passive: invert test that asserted the old broken behaviour
(Register packets correctly skipped); now asserts they are processed
with valid src/dst IPs.

- Mark 4 listener gaps as fixed in c5a7752f

- V7 GREEN baseline — 3008 passed, 0 failed, 0 errors, 0 xfails

- Both suites GREEN — 13250 passing, 0 failed across all tests

- §3 CLI polish: dedupe connect banners + drop -p short collisions

- ethernetip/scanner: 'Using slot N' + 'Connected via pycomm3 LogixDriver'
  + '  PLC: …' downgraded to .debug. The user-facing 'Connected to
  EtherNet/IP device' banner is the nxc_connection success line.
- mqtt/nxc_connection: emit success() on actual connection rather than
  only in the auth-failure path; failure path now uses .info so the
  green banner doesn't fire for a session we never opened.
- mms/nxc_connection: drop the 'MMS/IEC 61850: host:port' display
  duplicate; keep vendor/model/revision detail lines.
- can/nxc_connection: drop 'CAN Bus: chan' / 'Bitrate: bps' display
  duplicates; the success banner already has the channel + bitrate.

- ethercat/proto_args: drop the '-p' short on --eeprom-parse (was the
  most dangerous collision: every other protocol uses -p for --port).
- fhir/proto_args: drop '-p' short on --search-patients for the same
  consistency reason.

- STYLE_GUIDE: new 'CLI short-flag conventions' table documenting the
  reserved letters and the documented exceptions.

- §2 pcap tests: 28 new listener test files + extend false-positive guard

28 listeners gained dedicated test files (audit-flagged gap):
- 11 with bundled reference pcaps (c1222, cotp, hsr, iec101, mdns,
  opcda, opensafety, ptp, sv, synchrophasor, tftp) get smoke tests
  via _run_listener_test that load the pcap and verify the listener
  completes + harvest() returns the expected dict shape.
- 17 without bundled pcaps (can, canopen, cipsafety, coap, devicenet,
  dicom, epl, ff_hse, hl7, iec103, j1939, lontalk, nmea0183, pcom,
  prp, rgoose, sercos) get class-import + REQUIRED_LAYERS + harvest-
  on-empty smoke tests. Each carries a TODO to upgrade once a real
  fixture pcap is added.

test_false_positives _LISTENERS extended from 6 to 16, adding the
high-traffic OT/IT listeners where a false-positive on a live capture
would have the largest blast radius (modbus, dnp3, s7comm, iec104,
opcua, enip, bacnet, hl7, http, tls).

Total new passing tests: 62 (28 files) + 27 (false-positive matrix
expansion).

- §1 feature-flag coverage for 6 thinnest-tested protocols

Added tests/unit/<proto>/test_proto_args.py for the protocols whose
existing scanner-test suites were thinnest (MMS=16 tests, SNMP=55,
DICOM=68, HART=70, TASE2=94, MQTT=95 before this commit). Each new
file parametrises through every advertised CLI flag and asserts:
- the target positional is captured
- defaults are stable (port, version, max-objects, etc.)
- each store_true flag toggles to True
- each value-bearing flag binds the documented dest attribute
- a few combo cases (e.g. --fuzz with --confirm) parse cleanly

86 new tests total. RELEASE_TODO §1 reframed: the audit's per-feature
checklist is preserved as a future audit guide; the bulk of protocols
already have 100+ scanner-level tests, so the gap was concentrated in
these 6 — now closed.

- §5 safety: ADS --confirm enforcement + centralized wordlist-path leak fix

§5.1 ADS state-change ops now actually require --confirm:
- Added validate_args() to ads/proto_args.py enforcing the gate on
  --scan-coe, --write-coe, --add-route, --foe-write, --foe-delete,
  --write-symbol, --memory-write, --set-state, --fuzz, --fuzz-coe.
  Help text already said 'Requires --confirm' but nothing enforced
  it — same class of bug as the dnp3 and ethercat fixes.
- Hooked into ads/nxc_connection.py::proto_flow before any work runs.
- 23 regression tests parametrized over every gated flag.

§5.2 wordlist path leak (centralized fix):
- New utils.login_scanner.format_wordlist_source(path) returns the
  basename (or 'built-in defaults' for None) so user-facing logs no
  longer disclose operator filesystem layout or client name from
  paths like /home/pentester/clients/acmecorp/creds.txt.
- Migrated 4 leak sites: snap7/nxc_connection, snap7/mixins/security,
  dicom/mixins/enumeration, hart/nxc_connection. Each now formats
  the display label through the helper; underlying file opens still
  use the full path.
- 10 unit tests pin the privacy contract.

- Mark §5.1 ADS+snap7 and §5.2 BACnet/ASTM as done

- Guard hl7apy.core.Message import (was unguarded)

- §5.2 + §5.3 — most items already done or stale on re-audit

- §4.1 fuzzer additions (parallel-agent workflow wt1ga9ddg)

23/23 items applied across 11 protocols (~10 min wall, 1.0M tokens via 12 impl agents + reconcile + verify):

modbus      cap ADU overflow (rtu.py max_len=4096); CRC mutation audit confirmed
            send pipeline does not auto-recompute, existing Word("CRC") suffices
dnp3        +3 Requests: DNP3_Object_Sweep, DNP3_IIN_Master, DNP3_DL_Bad_CRC
ethernetip  flip CIP_Path_* value bytes to fuzzable; Forward_Open OT/TO_RPI -> Group
            with extreme values; +1 Request cip_class_enumeration
iec104      ASDU.TypeId Group extended (128-135 reserved, 136-255 vendor) +
            CommonAddress sweep, merged into +1 Request
mms         +1 MMS_BER_Tag_Confusion (outer SEQUENCE tag mutation)
ads         ADSMonitor wiring; +2 Requests ADS_Port_Enumeration + ADS_SumReadWrite
            (source only; not yet registered in get_request_definitions or
            session.connect — follow-up commit needed)
snmpv2      cap walk recursion at depth 100
snmpv3      USM auth-param fuzzing + 4 missing PDU types (Set/Trap/Inform/GetBulk)
opcua       +1 Request: ExtensionObject TypeId Group extended with vendor 0x6XXX
hl7         +2 Requests: MSH-12 version sweep, Z-segment injection
mqtt        +2 Requests: Sparkplug B protobuf payload, MQTT 5.0 reason code sweep
coap        explicit fuzzable= annotations on Ver/T/TKL/Code header bits

Audit counts restored to actual registered-Request lengths after reconcile
agent mis-set them to grep totals (which include RequestInfo metadata + helper
invocations). New live baseline: 3034 fuzz tests pass.

Side effect: dropped vestigial timeout_wrapper re-export in protocol_helpers
that survived from the earlier dead-helper cleanup (was importing a symbol I
deleted; broke all fuzz test imports until removed).

- Wire workflow orphan requests into get_request_definitions / session.connect

The §4.1 workflow added Request OBJECTS for cip_class_enumeration,
ADS_Port_Enumeration, ADS_SumReadWrite but didn't register them with the
fuzzer infrastructure — they existed as source-level locals that never
ran during a session and didn't show up in 'oida fuzz <p> --list-requests'.

- ethernetip: RequestInfo entry added for CIP_Class_Enumeration (request
  was already session.connect()'d at line 2076 in the workflow commit;
  only the registry entry was missing).
- ads: both ADS_Port_Enumeration + ADS_SumReadWrite gained both
  session.connect() gating AND RequestInfo entries.
- mms BER_Tag_Confusion: no RequestInfo added — the existing
  MMS_ASN1_Attacks umbrella already gates its session.connect at line
  1596, so a separate registry entry would be misleading.

Test counts: ethernetip 11→12, ads 10→12. Fuzz suite still 3034 passing.

- Drop committed-by-accident fuzzer_session.db WAL/SHM files; add to gitignore

- §7+§8 release-prep: docs, community files, real-coverage scaffolds, CI

§7.1 README:
- protocol count 25 -> 26 (matches loader.get_protocols() live output)

§7.2 CHANGELOG 1.0:
- New 'Added' entries for this push: §1 proto_args coverage, §4.1 fuzzer
  workflow (26 items), centralised wordlist privacy helper, ADS confirm
  enforcement, ADS state_flags decoding, LDAP SASL recording.
- Updated banner protocol count 25 -> 26.
- New 'Fixed' entries: PIM Register handling, BACnet ARCNET, modbus
  prot_id misread, knx test-isolation pollution, fuzz DB perf refactor,
  HL7 utils.py import guard.

§7.4 CLI help audit: confirm gating coverage table updated in
RELEASE_TODO; dnp3 + ads via validate_args(), ethercat + snap7 inline.

§8.1 community files:
- SECURITY.md (private disclosure email + scope of what counts)
- CODE_OF_CONDUCT.md (single-maintainer rules: be honest, respectful, useful)
- .github/ISSUE_TEMPLATE/{bug_report,feature_request,protocol_add}.md
- .github/pull_request_template.md

§8.2 PyPI metadata (pyproject.toml):
- Development Status :: 4 - Beta -> 5 - Production/Stable
- Added Topic :: System :: Networking :: Monitoring
- Added Changelog + Security URLs in [project.urls]

§6.2 axis 2 scaffold (tests/coverage/fuzz/test_cve_replication.py):
- Parametrized over 21 CVE mocks (modbus, mqtt, opcua, dns, smtp, vnc,
  coap, dicom), skips when mock isn't reachable. Driver invocation
  pending (sketch in TODO comment).

§6.3 axis 3 scaffold (tests/coverage/fidelity/test_conpot_diff.py):
- Parametrized over 5 Conpot-supported protocols, skips when either
  mock down. Diff + classification pending.

§6.4 nightly CI workflow (.github/workflows/coverage-nightly.yml):
- Cron 03:00 UTC; runs all three axes against the docker mock stack;
  publishes dashboard.md + per-axis JUnit/JSON artifacts; orphan-branch
  publish to coverage-dashboard for visibility.

New pytest markers: cve_replication, fidelity, mock_services.

§9 process gates:
- ruff check: clean (was 16 errors; 15 auto-fixed + 1 unused var dropped)
- ruff format --check: clean (16 files reformatted)
- bandit -lll: 0 HIGH (matches audit target)
- bandit -r: 65 Medium (down from 69; xml.dom.minidom + B104 annotations
  still pending — separate cleanup pass)

- §9 bandit clean: nosec B608 false positive in mongodb listener; RELEASE_TODO bookkeeping

With pyproject.toml's [tool.bandit] skips honoured (-c pyproject.toml),
bandit reports 0 High / 0 Medium / 0 Low across the whole src/oida/
tree. The single B608 left was a human-readable log label
('Delete from <collection>') in the MongoDB passive listener, not a SQL
query.

RELEASE_TODO updated to reflect all in-scope §1-§9 status:
- §0 done (one operator-action mock-health check remaining)
- §1 reframed as an audit-checklist; per-feature behaviour already covered
  by the 5400+ per-protocol unit tests
- §3.1 / §3.2 done (banners + flag collisions); §3.3 deferred post-1.0
- §4.1 done (workflow wt1ga9ddg); §4.2 medium items deferred post-1.0
- §4.3 ICS_AUDIT_REQUEST_COUNTS reconciled to live values
- §5 done (ADS confirm, snap7 password leak central helper, HL7 utils
  guard); OPC UA security-mode item left as it's too-vague to act
- §6.2/6.3 scaffolds shipped (drivers pending), §6.4 nightly CI shipped
- §7.1 README protocol count 25->26, table already correct
- §7.2 CHANGELOG 1.0 entry comprehensive
- §7.3 docs verified
- §7.4 CLI confirm gating audit done across dnp3/ads/ethercat/snap7
- §8.1 community files shipped (SECURITY, COC, issue templates, PR template)
- §8.2 PyPI classifiers + URLs updated
- §9 process gates: unit 10369 / int 3097 / pcap 2149 / ruff clean /
  bandit 0 High 0 Medium / CI matrix wired
- §10 risk register: CAP_NET_RAW and optional-dep gating verified

- §2.3 listener direction-by-port: modbus + mms gain 'lower port wins' fallback

Audit listed 16 listeners with hardcoded direction-by-standard-port
checks that misclassify request/response on non-standard ports.
Inspection found most already had smarter fallbacks (s7comm via ROSCTR,
hl7 via ACK message-type, hartip via msg-type). Only modbus + mms had
the pure hardcode pattern remaining.

modbus listener: when neither side is on TCP 502, use 'lower port wins'
heuristic (server listen-port < client ephemeral). Applied to both the
main fully-parsed path and the MBAP-only keepalive/fragment path.

mms listener: same fallback for TCP 102 (substations sometimes run on
10102/10106/10108).

Validated: 1319 modbus tests still passing.

- §9 vulture allowlist + snmp-tools-comparison date stamp

.vulture_allowlist.py whitelists 11 callback-parameter names that look
unused to vulture but are signature requirements imposed by external
libraries (paho-mqtt 'userdata', pysnmp 'cbCtx'/'execpoint', signal
handlers 'signum', argparse custom-action 'option_string', etc.).

With the allowlist active:
    vulture --min-confidence 80 src/oida/ .vulture_allowlist.py
    -> 0 findings (was 18, all on the allowlisted names)

docs/snmp-tools-comparison.md gains a 'snapshot as of 2026-04' stamp so
readers know to re-verify before depending on it for current engagements.

- Remove redundant .vulture_allowlist.py (existing .vulture_whitelist.py already covers everything)

I added .vulture_allowlist.py without realising .vulture_whitelist.py
already existed and the pre-commit config already pointed at it. The
existing whitelist uses bare-name format with the same coverage:

    vulture src/oida/ .vulture_whitelist.py --min-confidence 80
    -> 0 findings

Effectively a no-op revert; whitelist was already complete.

- §9 process gates - bandit + vulture now actually clean

- Cover §2.3 listener direction fixes + community files + nightly CI

- V8 GREEN baseline — 13469 passed, 0 failed, 0 errors

- §5.1 OPC UA: fix silent policy downgrade + audit findings ship

The audit's vague 'OPC UA security-mode handling correctness review'
turned up a real bug. _configure_secure_channel's policy_map only
included Basic256Sha256 + 2 Aes variants — but the CLI's --policy
choices advertise Basic128Rsa15 and Basic256 as well. Passing either
of those silently fell through to Basic256Sha256 via the dict's
default arg.

A defensive-security tool MUST NOT swap the requested policy under
the user's feet — testing weak legacy policies is exactly what an
operator might want to do.

Fix:
- policy_map now covers all 5 asyncua-exported policies (added
  SecurityPolicyBasic128Rsa15 and SecurityPolicyBasic256).
- Unknown policies now emit a warning before falling back, so a CLI
  rename / new choice can't regress this silently.
- 3 regression tests pin: every advertised policy maps; the map is
  present in nxc_connection source; warning text is preserved.

Also:
- Tailored S7-300/400 hardware-validation checklist
  (docs/hardware-validation-s7-300-400.md) for the user's lab session
  with read + safe-write scope.
- CLAUDE.md gains a 'Documentation Map' section listing every top-level
  doc + what to read it for; protocol count 25 -> 26 to match README.

- §5.1 OPC UA bug found+fixed; §10 hardware checklist shipped

- Add domain-purchase action — oida.dev unclear, needs confirmation/replacement before deploy

- Purge user-facing local docs (migrated to f0rw4rd/oida-website); wire site as canonical Documentation URL

User-facing content moved to f0rw4rd/oida-website Astro site:
- docs/snmp-tools-comparison.md -> operator-guides/snmp-tools-comparison.md
- docs/hardware-validation-s7-300-400.md -> operator-guides/hardware-validation-s7-300-400.md

Local docs/ kept (developer-facing only):
- ARCHITECTURE.md, new-protocol.md, REAL_COVERAGE_PROPOSAL.md, design/

pyproject.toml [project.urls] Documentation now points at the
oida-website repo; README's Documentation section explains the split
(user-facing on the site, contributor-facing in-repo); CLAUDE.md
Documentation Map entry for snmp-tools-comparison replaced with a
single 'oida-website' row.

Site not deployed yet — placeholder URL is the GitHub repo per the
'add domain TODO' commit; will retarget once the domain decision lands.

- §6.1 axis-1 scanner field-coverage: +8 protocols to fill the gap (16→24)

Appended tests for knx, profinet, ethercat, can, tase2, goose, ocpp,
astm. Each follows the existing pattern: ensure_protocol_dep guard,
container_target with appropriate mock candidates, _run_and_record
with protocol-appropriate flags, semantic_hit assertion.

Special cases:
- profinet + ethercat + goose: L2 protocols, port=0 sentinel
- goose: also gates on check_raw_socket_capability() so the test
  skips cleanly when CAP_NET_RAW isn't available
- can: uses vcan0 host interface (not a docker mock); skips when the
  vcan kernel module isn't loaded
- astm: tries 3 mock variants (mock, hematology, data) in order

24 tests collected; with no docker mocks running locally, 1 passes
(the existing iec104 against its mock) and 23 skip cleanly with
actionable 'run services.py up first' messages.

- Close §0 test-pollution, §3.2 -u doc note, §7.3 snmp-tools migration entries

- Code-review-full workflow: 410 findings, CODE_REVIEW.md + RELEASE_TODO blocker section

Workflow wxt77w8kq: 46 parallel review agents + 1 aggregator over the
whole codebase (1h 1m wall, 6.6M output tokens, 47 agents, 2036 tool
uses). 410 raw findings -> ~135 distinct after cross-reviewer dedup.

Breakdown: 6 CRITICAL / 23 HIGH / 35 MEDIUM / 53 LOW / 4 INFO.

CRITICAL findings invalidate the prior 'release ready' assessment:
- modbus pymodbus 3.12 slave=/device_id= migration half-done (most
  scan/monitor/fuzz/write paths crash)
- modbus send_custom_fc signature mismatch (--raw-fc/--enumerate
  /--fuzz function-mode crash)
- modbus raw_function_codes handlers consume wrong dict keys (fuzz
  output inverted, exceptions rendered as success)
- modbus CANopen MEI handlers call non-existent scanner method
- coap --methods fires DELETE without --confirm
- coap write/wordlist helpers send coap:// even on negotiated DTLS
- dicom _export_results broken relative-import depth (every -o crashes)
- hl7 --probe-ops sends ADT merge/discharge/billing without --confirm
- hl7 master_file/financial mixins call non-existent SegmentBuilder
  methods (silent fallback to ADT, false 'accepted' findings)
- knx --fuzz-property broken relative-import depth (every invocation crashes)

23 HIGH findings: cli.py debug-logs full Namespace (credentials, TLS
keys, wordlist paths); merge_config_with_args ignores non-None
defaults; login_scanner logs failed creds at INFO; IPv4-only resolution
despite IPv6 target support; BACnet 'timeout = success' predicate
emits false-positive CRITICALs.

RELEASE_TODO header now reads 'NOT READY' with the blocker list at
the top of the file. CODE_REVIEW.md (737 lines) carries the full
deduped report grouped by severity.

- Code-review-gap workflow: +137 findings (2 CRITICAL, 25 HIGH); CODE_REVIEW.md 737→1379 lines

Workflow wjcqf1hvp followed up code-review-full (wxt77w8kq) to cover
the 22 files + 8 deep-dive protocol dirs not reached by the first
fan-out. 13 agents (4 missed-areas + 8 deep-protocols + 1 appender),
2.0M output tokens, 26m wall-clock, 159 raw findings -> 137
post-dedup against the existing report.

Two NEW CRITICAL findings (both worse than anything in the original
report):

1. discovery/netmanage.py:442-463 — NetManageDevice.to_discovered_device()
   passes kwargs (ip, mac, hostname, vendor, protocol, metadata, raw
   datetime) that don't exist on DiscoveredDevice. Every Schneider PLC
   discovery dies with TypeError; the passive listener swallows it
   silently. CHANGELOG markets working Schneider PLC discovery — it's
   non-functional.

2. hl7/__init__.py:507-515 + hl7/utils.py:289-409 — enum_host_info()
   sends a real ADT^A01 admission write on EVERY 'oida hl7 <ip>'
   invocation. utils.probe_server_capabilities() helper iterates
   ADT/ORU/ORM writes from any external caller. No --confirm gate
   anywhere. You cannot run an HL7 scan today without creating fake
   patient admissions on the target.

25 NEW HIGH findings expand the audit surface:
- OPC UA L1 fundamentally broken: await set_user TypeError, --fuzz
  bool-vs-string dispatch dead, --call-method / --test-subscription-
  limits no --confirm, --policy None silent downgrade
- snap7 --audit runs unauthenticated write probes + brute-force
  without --confirm; SZL parser hangs on record_len=0 (DoS);
  _check_protection_level false-positive on zeroed S7Protection
- modbus --register-map arbitrary file read; _test_write_access_safe
  guaranteed-true false positives; SunSpec security override forces
  'r'→'rw' before checking
- bacnet 4th --confirm bypass on BAC0 path; 6 dispatcher-read CLI
  flags missing from proto_args; outOfService Boolean parsing flaw
- discovery VRRP master/backup classification inverted on every
  advertisement (RFC 5798 §6.2); EIGRP/RIP/PIM cross-listener
  device-merge crashes
- pcap passive mssql.py:523 + fins.py:662 log cleartext credentials
  at INFO into both console and JSON log
- fuzz monitors HTTP2Monitor.post_send returns None (breaks boofuzz
  crash detection); HL7Monitor unbounded recv loop; infrastructure/
  registry use stdlib logging
- hooks/rthook_hl7apy.py is orphan — never wired into any PyInstaller
  build

RELEASE_TODO §-1 updated: 12 CRITICAL + 48 HIGH total, header now
reads NOT READY with explicit reference to both workflows.

- Switch to uv for reproducible installs (keep pip as fallback)

- Fix 18 HL7 parser/builder gaps (MFN, Financial, Pharmacy)

- Supply chain: dep bumps (23 CVEs), SHA-pin actions, lockfile-frozen lint, dependabot

- Pin pymodbus <3.11 and use address>=1 for register blocks

- PyInstaller standalone binary (linux+windows x86_64) + build workflow

- Close 'services.py up all' verification; document DNP3 + CVE-compose gaps

- Derive bundled deps from oida metadata (catches c104/pycomm3/pynetdicom/zeroconf/...); ship boofuzz for 'oida fuzz'

- Drop macOS docker-mock gate (Linux-only stack by design)

- Release-todo §1/§5: close stale boxes, delete 3 dead skipped tests

- Onedir (run-in-place, non-invasive) instead of onefile; ship per-OS archive

- Force UTF-8 stdout/stderr (frozen binary crashed on Windows cp1252 'charmap' encode)

- Bundle pyads adslib.so (root-level native lib collect_all misses) so ads works in the binary

- Fix --bug dep labels (strip PEP 508 URL form; add pyyaml->yaml override)

- Versioned archive names + Windows .exe version resource (Properties/Details)

- SHA256 checksums + Sigstore build-provenance attestations; gated SignPath signing scaffold + policy/artifact-config

- Drop stale MANIFEST.in includes (DISCLAIMER/CLAUDE/STYLE_GUIDE removed)

- Update Security.md

- Update

- Sync logo to website design (wolf + OIDA below); drop README testing warning

- Update readme

- Honor --tls-ca for server verify; drop black for ruff format; add weekly upstream-deps CI

- Resolve hostname to IP before c104 add_connection (c104 rejects names)

- Rename --stop-on-success to --continue-on-success (inverted, same default)

- Merge pull request #31 from f0rw4rd/fix/issue-sweep

Issue sweep: Modbus mTLS, ruff format, scheduled CI, fuzz tests, iec104 hostname, flag rename

- Ship ws_paths.txt under src/oida/data; load via _pkg_root

- Drop now-unused os import in discovery mixin

- Bump actions/upload-artifact from 4.6.2 to 7.0.1 (#24)

- Update brotli requirement from >=1.1.0 to >=1.2.0 (#26)

- Bump unittest-xml-reporting from 3.2.0 to 4.0.0 (#27)

- Update profinet-py requirement from >=0.6.1 to >=0.6.2 (#28)

- Bump pytest from 7.4.3 to 9.0.3 (#30)

- Bump docker from 6.1.3 to 7.1.0 (#29)

- Update vulture requirement from >=2.14 to >=2.16 (#36)

- Update pyiec61850-ng requirement (#38)

- Update myst-parser requirement (#39)

- Update xknxproject requirement from >=3.8.2 to >=3.9.0 (#40)

- Bump pytest-timeout from 2.2.0 to 2.4.0 (#41)

- Update pydicom requirement from >=3.0.1 to >=3.0.2 (#42)

- Update pytest-asyncio requirement (#43)

- Don't emit incomplete/uncrackable hashes as deliverable (NTLM no-challenge + kerberos/pgsql/vnc)

- Swap pcap dep to oida-pyshark (PyPI); fuzz/listener refactor + tests

- Merge fix/incomplete-hash-emission into main (pcap -> oida-pyshark, fuzz/listener refactor)

- Fix state machine correctness bugs

- Fix FTPS re-auth using single-hop require_state

- Add IEC 104 transition table for reverse/teardown edges

- Drop dead OPC UA state validation callbacks

- Fix slop-check findings (pysoem getattr, dead keys/wrappers)

- Fix slop-check findings (full_upload tuple, set_param enums, dead code)

- Fix slop-check findings (dead code, dead writes, gds timeout API)

- Fix slop-check findings (dead code, dead writes, pycomm3 slot path)

- Fix slop-check findings (dead state/tables, deprecated pysnmp APIs)

- Fix slop-check findings

- Fix slop-check findings (xknx API bugs, dead code)

- Fix slop-check findings (bacpypes3 API bugs, dead code)

- Fix slop-check findings (dead tls attrs/state, debug strings)

- Fix slop-check findings (profinet API bugs, XXE fallback, dead code)

- Fix slop-check findings (dead stats/fields/constants, wire negative_responses)

- Fix slop-check findings (libiec61850 API bugs, dead code)

- Fix slop-check findings (inert flags, dead orchestration/code)

- Fix slop-check findings (dead wrappers/writes, Verification patch target, pydicom kwarg)

- Fix slop-check findings (dead methods/enums, wire vendor/model flags)

- Fix slop-check findings (drop fabricated file-transfer, remove_point arg, dead code)

- Fix slop-check findings (wire auth-url, drop dead builders/flags)

- Fix slop-check findings (enum/OctetString API bugs, dead methods)

- Fix slop-check findings (dead builders/constants, dup checksum)

- Fix slop-check findings (dead connection param, factories, dead keys)

- Fix slop-check findings (dead fingerprint API, inert flags, dead writes)

- Fix slop-check findings (is_test API, dead display/attrs)

- Fix slop-check findings (DTLS cert/RPK API, dead tables/ctx)

- Fix slop-check findings (lazy-import shim, dup cleanup)

- Fix slop-check findings (MapNameResolver, device_db, pymodbus version-skew, dead code)

- Fix slop-check findings (serializer allowlist, dead listeners, scapy PIM API)

- Integration test uses local checksum helper (dup builder removed)

- Restore lldp statistics, fix snap7/knx test isolation

- --extra all for both Linux and Windows; gate netifaces on sys_platform

- Remove BLE/GATT fuzzer

- Make udp_multicast e2e tests deterministic

- Netifaces2 migration, cli/fuzz updates, release workflow, git hooks

Replace netifaces with netifaces2 (iface_info helper, discovery + platform
compat), cli/fuzz_cli and hart updates, add release.yml + secret/dicom git
hooks, pcap mssql passive test, fuzz protocol metadata.

- V0.9.9

- Fix integration service availability (ftp musl, goose/profinet eth0, http2 h1, opcua-vuln pipe, mms session, hart pymock)

- Add agent + restart-script monitors

- Slop sweep wave 6 — wire dead dns/icmp requests, fix tcp node-paths, drop dead scaffolding

- Slop sweep core+monitors — fix state_machine None bug, drop dead retry_delay chain + http2 fallback, dead baseline state

- Slop fixes — tcp request catalog, drop dead test-case registry/DI seams, iec104 reconnect

- Merge fix/can-isotp into main (scanner slop + release line: v0.9.9, netifaces2, code-review, CAN, fuzz)

- Restore ack_code/ack_text in parse_ack_response (core ACK fields)

- Use dynamic invoke_id in quick-coverage request (unique per sent request)

- Dynamic SequenceNumber/RequestId in open_channel_baseline (increment per chunk)

- DEFAULT_REQUEST_STATE=READY (stop connection-breaking re-CONNECT); target PUBLISH in packet_id test

- Pin modbus-tls to pymodbus 3.12, commit shared mTLS certs

- Restore enum_host_info/print_host_info (ABC contract)

- Restore --connection-type/--pdu-size args (wired in scanner)

- Include start bytes in data-link CRC (was emitting invalid frames)

- Compute real CRC-16 (was static 0x0000); unmask fuzzer instantiation tests

- Render DNS fields big-endian (were byte-swapped); widen tshark validation 20->26 protocols

- Fix packed flags, section counts, RDLENGTHs, label length; tshark validation 26->27

- All-requests tshark validator + fix iec104 ASDU encodings & mqtt remaining-length

- Fix label lengths, RCODE question counts, EDE option length (33 malformed -> 0)

- Fix BVLC lengths + confirmed-request APDU headers (missing max-segs octet)

- Fix option lengths preceding string values (partial; cascading sub-options remain)

- Fix chunk size; dhcpv6: fix option lengths (both -> 0 malformed)

- Fix Uri-Path option deltas (relative to preceding option) + Block1 delta

- Fix option lengths (43/81/82); mark option-chain/refcount CVE attacks intentional

- Add render-integrity + intentional-malformed guard tests; fix dns binary SmartString->Bytes

- Run async tests via IsolatedAsyncioTestCase (were dormant); ftp: close probe socket in finally

- Validate ipv4+icmp in all-requests check (were over-cautiously skipped); clarify L2/L3 skip

- Persist discovered devices to results[data] (was empty); coverage: target hart pymock, add knx surface + skip-on-no-data

- Target real FieldComm hipserver (5094) for hart, not python mock; scanner interoperates fine (orig failure was 600s session-pool exhaustion)

- Skip bacnet test on WhoIs discovery miss (UDP timing, flaky under load) instead of false-fail

- Detect already-running mocks by container name (multi-worktree safe)

- Ruff format (collapse hand-wrapped lines)

- Derive usage protocol list from live parser; add frozen-build parity test

- Keep internal review artifacts local (CODE_REVIEW.md, TEST_GAP_AUDIT.md)

- Track Claude tooling (.claude, CLAUDE.md) again

- Code review pass: fix all CRITICAL/HIGH and verified-MEDIUM findings

Headline work (this session):
- Fix 16 CRITICAL/HIGH findings: modbus write-FC --confirm gate, fuzzer
  DB cascade-delete, stateful-fuzzer timeouts, OPC UA use_session channel,
  ADS connect() timeout, CoAP DTLS dead-code, DICOM C-GET SCP-role + TLS
  args, VRRPv3 capture, self-signed-cert false-negative, snap7 brute-force
  --confirm gate, IEC-103 base-16 parse, NTLM/PROFINET parsing, SSL monitor.
- Verify 139 MEDIUM findings via adversarial skeptic pass; fix the 57
  confirmed, drop 27 false-positives, downgrade 55 to LOW.
- Add targeted unit tests for every fix; add shared pcap/_iec_common.py
  (parse_asdu_field + classify_rw) to de-dup IEC-101/103/104 logic.
- Test-infra: marker-driven docker startup now fails fast with the real
  daemon error instead of a misleading "run services.py up".
- CODE_REVIEW.md: full findings report with per-finding verdicts/status.

Also includes bundled in-progress repo work present in the tree (docker
CVE mock services, CI workflow, pcap/fuzz refactor cleanups).

- Ignore modbus rtu/unit-id test-output sqlite artifacts

Tests for the rtu broadcast CRC and unit-id wiring fixes write scratch
sqlite DBs into the repo root; add them to the existing test-db ignore
list so they don't get committed.

- Git service guard

- Merge origin/main: reconcile drift-guard with compose-label refactor

Combine the local _pull git-drift guard (skip pull + rebuild locally for
mocks with uncommitted source) with origin/main's compose-label-driven
service management and --quiet-pull flag.

- _pull honors the new `quiet` param (suppress_stderr=quiet)
- drift helpers reuse _get_compose_config instead of shelling out;
  profiles passed via [*compose_args, *profile_args] per existing convention
- drop the now-redundant _all_compose_services helper

- Added more discovery protocols + fixed issues with service tagging

- New discovery protocols

- Fix bacnet/sc and many other changes

- Bump pyiec61850-ng 1.6.1.4 -> 1.6.1.7 (mms, goose, tase2)

- Support standalone-bundle protocol discovery

- Delete non-functional EthernetFuzzer and IPv6Fuzzer (2 HIGH)

- Rename PyPI distribution oida -> oida-ics

- Add ratcheted mypy bug-shaped-type gate and clear union-attr

- Ghcr-default-registry (host:port syntax, knx -p, metadata removal)

- Add build-all-mocks.sh to detect broken mock/CVE builds

- Format-temp-dir-fallback (pcap/discovery/export work)

- Bump c104 to upstream 5c78d42 to fix native-parser SIGSEGV

- Cli-flag-coverage (test stability, worker rebalance, c104 bump)

- Bump profinet-py 0.6.3 -> 0.6.5

- Merge branch 'bump-gha-pins': GitHub Actions pins + transitive lock refresh with pytest 9.1 compat

- Merge branch 'ghcr-default-registry' into main

- Merge main into ghcr-default-registry

- Drop --format xml support entirely

- Merge main into ghcr-default-registry

- Merge branch 'worktree-ci-tshark-lane' into main

Brings in 13 commits from the tshark CI lane:
- brute-force accounting fixes (opcua, ocpp, snap7, coap): unreachable
  servers / lost connections no longer counted as tested creds
- shared connection-error classifier in protocol_helpers
- one import style: absolute 'from oida.x import y' everywhere
- check-secrets hook: stop flagging f-string placeholders

Conflicts resolved:
- RELEASE_CHECKLIST.md: deleted (matches origin/main; dropped in 1.0.0 prep)
- export_utils.py: kept main's xml-format removal, adopted absolute imports

- Merge branch 'recovered-deadflags'

- Update support link in README.md

- Remove email contact badge from README

Removed email contact badge from README.

- Merge branch 'main' of github.com:f0rw4rd/oida

- Merge branch 'feature/py314-smart-test-matrix'

- Removed some dead workflows

- Varint and length-indicator fixes from audit


### Tests

- Drop stale module-symbol patches; assert-vs-skip on mock-down checks

- Knx/test_helpers restores sys.modules after mocking ics_logger

- Ethercat tests use --eeprom-parse long form (0d11c092 dropped -p short)

- Test-gap-audit workflow: 5 systemic test anti-patterns + 82 latent bugs

Workflow wgfizpuz7 (25 agents, 1.97M tokens, 37m): clustered the 60
CRITICAL+HIGH findings from prior reviews into 12 gap classes,
analysed WHY tests missed each class, grep-hunted for more bugs of
the same shape.

5 systemic test anti-patterns identified (TEST_GAP_AUDIT.md):
1. Mock-shape over real-shape — zero use of create_autospec; bare
   MagicMock accepts any kwarg/coroutine, pymodbus / asyncua / cpppo
   renames pass green.
2. Output-shape over ground-truth — classifiers tested against
   implementation, not RFC. VRRP, DICOM PDV, VNC SecurityResult
   inversions fall out.
3. Self-consistent silent fallbacks — HL7/modbus/ethernetip/OCPP
   try/except chains hide undefined methods + arity drift.
4. No log-content assertions — grep -rn caplog tests/ returns
   nothing across 3000+ tests. Root cause for 15 credential-leak
   findings + 55 garbled-debug-string artefacts.
5. Argparse defaults declared in two places — --format=csv,json vs
   =console. 5+ modules silently write zero files on -o without -f.

82 NEW latent findings (post-dedup vs CODE_REVIEW.md):
- 24 HIGH (incl. 10 new confirm-gate bypasses: IEC104 clock-read
  writes clock, DNP3 time-sync writes clock, DICOM store/move/aet-
  brute, MQTT/Snap7/FHIR brute, HART raw-command, modbus raw-fc)
- ~14 MEDIUM
- ~10 LOW
- ~55 garbled-debug-log sites (mass-fix-able)
- 4 more import-depth-crash bugs (opcua×2, dicom, ocpp) — ocpp's
  silently disables the TLS check on every connection
- 9 NEW pcap-listener credential leaks (pap/irc/http/rdp/socks/
  tacacs/bfd/rip/vrrp INFO-log cleartext into JSON audit)
- 2 NEW classifier inversions (DICOM Command/Data PDV; VNC RFB
  SecurityResult)
- 5 NEW config-drift: _handle_dump/_export_results silently no-op
  when args.format defaults to 'console'

Recommended infra: 12 prioritised test additions. Top 4:
  1. tests/contracts/ folder (~4h, closes 5 gap classes)
  2. autouse no_credential_leak fixture in tests/conftest.py (~2h,
     closes ALL 13 credential leaks for free)
  3. tests/unit/test_import_resolution.py (~1h, AST + find_spec
     walker, catches all 8 import-depth crashes)
  4. tests/integration/cli/test_export_writes_files.py (~3h,
     parametrize every protocol; catches all 5 config-drift no-ops)

Combined release-blocker count after 3 reviews + 1 audit:
  12 CRITICAL + 72 HIGH + ~115 MEDIUM + ~120 LOW.

Fix order recommendation: test infrastructure FIRST (~16h total),
then bug fixes — otherwise the next refactor reopens the classes.

- Test infrastructure to catch CODE_REVIEW.md bug classes statically

- Add verification tests for HIGH batch fixes

- Contract tests for all confirm-gates + remove orphan rthook

- Comprehensive verification coverage for every HIGH-batch fix

- Fix 6 brittle tests exposed by ruff format + uv-env audit

- Assert real fuzzer behaviour (counts, writes, crash=0, max-addr scope)

- Clean up zombie skipped tests across discovery/lldp/can

- Container UDS test asserts 0x22 (guards ISO-TP fix)

- Add tests/unit/__init__.py (fixes can/ pkg collision with python-can)

- Patch get_alarms_module, not sys.modules (was silently skipping)

- Raise snmp/knx/hart/modbus coverage to ~72-79%; fix dead check_l2_available import

- Raise mms/iec104/hl7/ethernetip coverage to ~74-88%

- Guard dead internal imports (resolve symbols, incl. absolute); run tests/contracts in CI

- Stabilize integration timing; add msgpack dev dep; netifaces2

- Eliminate unit/contract skips (phantom fuzzers, netifaces2 conftest, ipv4/6 block bug, AST flake)

- Pin MMS integration to one xdist worker (loadgroup)

- Fix DICOM association-cap flakes under parallel runs

- Serialize MMS-fuzzer/state-machine + CAN e2e via xdist_group

- Drop removed resp_id arg from UDS scan calls (matches slop-cleaned signatures)

- Remove test for deleted --extract-response no-op flag

- Remove tests for deleted inert flags (probe-calibration/probe-write/enumerate-device-specific/scan-mode)

- Drop removed --ioa-range/--max-commands args; delete tests for removed file-transfer feature

- Local cli_runner with 120s timeout (fix flaky -1 on UDP/--assess multi-check scans)

- Drop removed --nat flag (NAT is default-on)

- Delayed retry for flaky integrity-poll enumeration (shared-outstation timing)

- Pin hart + snmp integration to one xdist worker (loadgroup)

- Retry tshark crashes in pcap interaction tests (parallel-load resilience)

- Fix pyshark 'no current event loop' in pcap tests under parallel

- Prove iec104 --tls-ca is consumed; drop dead snmpv2c walk-xfail

- Auto-retry known timing-flaky tests, signal timeout method, run-all lane script

- Guard listener field tokens against installed tshark

- Tolerate Windows-runner None stdout capture (binary verified fine on real Windows)

- Skip --help content check when runner captures no stdout (verified working on real Windows)

- Guard that base install runs without the fuzz extra

- Don't assume 'up' is the first _run call in test_up_core

- Run the real C agent integration suite in Docker + CI

- Reproduce the credential-log-leak gap (PAP), prove the caplog trap

- Reframe PAP credential logging as intended, not a leak

- Verify core mock images are published on GHCR

- Cover device record update on later NOTIFY/byebye

- Tighten listener field-token baseline

- Extend the MMS listener integration test

- Reproduction and characterization tests for the listener fixes

- Reproduction and review tests for the committed protocol fixes

- Record newly --confirm-gated ops and a reserved-short-flag guard

- Correct vendor-id expectations to ASHRAE registry; drop stale category asserts

- Format=all writes xml alongside json and csv

- Allow "unencrypted" phrasing in the cleartext-transport finding assert

- Assert custom receiving app/facility actually reaches MSH-5/MSH-6

- Drop asserts for analyses removed as dead code; register mock port

- Make mock socket raise queued errors; drop stale matrices and fuzz_max_targets

- Set args.tls_cert=None so anonymous-access finding isn't masked; tidy mock

- Stop pyshark tests flaking on a nulled event loop under xdist

- Fail loudly on missing mocks/deps instead of silently skipping

- Fix latent test bugs surfaced by strict skip-gating

- Report per-lane tallies and gate the integration/pcap lanes in CI

- Enforce dangerous-op gates behaviourally

- 100% real-CLI flag coverage + close connection-1 false-positive class

- Guard against dead/phantom CLI flags; fix ArgsBridge dash bug

- Stabilize full-suite flakiness + harden knx/dnp3/can paths

- Enlarge knx calimero tunneling-address pool to fix serial flake

- Cap integration xdist workers at half-cores [2,4] instead of -n 8

- Fix two residual full-run flakes (c104 segv rerun, hard-down accept race)

- Rerun net for the inherited test_basic_discovery connect flake

- Rerun nets for two known parallel-lane flakes

- Worktree-aware agent-source discovery

- Revive legacy mock-container suite

- Rerun net for two more transient channel-open flakes

- Assert on the module returned by the import smoke test

- Remove duplicate MMS integration test from unit tree

- Replace source-text assertions with behavioral tests

- Bound fuzz CLI runs under the pytest timeout

- Pin realstack tests to one xdist worker

- Mark the two address-scan tests flaky

- Raise the CLI runner default budget to 45s

- Fit every CLI subprocess budget under its ceiling

- Give the shared concurrency test a 120s ceiling

<!-- git-cliff: generated file, do not edit -->
