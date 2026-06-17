# OIDA Code Review (workflow code-review-full / aggregated)

## Summary

- **Areas reviewed:** 46 parallel review agents covering the framework core
  (`cli.py`, `loader.py`, `connection.py`, `targets.py`), the shared utils layer
  (`utils/ics_logger.py`, `utils/export_utils.py`, `utils/proto_args_factory.py`,
  `utils/login_scanner.py`), the pcap passive-listener pipeline, and the
  individual protocol modules: ads, astm, bacnet, can, coap, dicom, discovery,
  dnp3, ethercat, ethernetip, fhir, goose, hart, hl7, iec104, knx, mms, modbus,
  mqtt, ocpp, opcua, pcap, profinet, snap7, snmp, tase2.
- **Findings (post-dedup):** 118 distinct findings consolidated from 265 raw
  reviewer findings. Heavy dedup applied to three cross-cutting classes:
  (a) the shared-logger / shared-`_config` concurrency leak (raised by ~5
  reviewers as one root cause), (b) the `--confirm` enforcement gap (one
  framework root cause + ~10 per-protocol instances), and (c) the
  "CLI flag declared but never consumed" dead-flag pattern (1 root cause + ~25
  per-protocol instances).
- **Breakdown by severity:** CRITICAL 1 · HIGH 19 · MEDIUM 23 · LOW 56 · INFO 19.
- **Input note:** The raw findings JSON was truncated mid-stream (the tase2 HIGH
  finding was cut off and any findings after it were lost). Reviewers
  over-produced relative to the prompt's expected volume; this report reflects
  all findings received up to the truncation point. The tase2 section is
  therefore partial and that module should be re-reviewed.

### Highest-blast-radius findings (top 5)

1. **Shared cached `ICSLogger` corrupts/leaks findings across concurrent scans**
   (`utils/ics_logger.py:168-192`) — affects every protocol under the
   ThreadPoolExecutor multi-target path; can cross-attach findings between
   engagement targets and lose data under duplicate-target / hostname-vs-IP key
   collisions.
2. **JSON/CSV result export is not credential-redacted**
   (`cli.py:265-359`) — every protocol that records a discovered/supplied
   secret writes it in cleartext to the operator's deliverable on disk;
   redaction was only finished at the screen-debug boundary.
3. **No central `--confirm` enforcement; gate re-implemented at ~117 per-protocol
   sites** (`utils/proto_args_factory.py`) — a single protocol that forgets the
   check performs an unconfirmed state-changing OT operation. Concretely
   realized as ungated destructive writes in modbus, ethercat, ethernetip,
   bacnet, hart, snmp, iec104, can, and others.
4. **Multiple `--test-write` / write-probe flags are dead or ungated**
   (mms, snap7, profinet, modbus, dnp3, tase2) — operators believe write-testing
   ran when it silently no-ops, OR live writes fire without `--confirm`.
5. **Multiple `--tls` paths connect to the wrong port and/or never verify the
   server cert** (astm, dicom, dnp3, coap-DTLS) — operators get a false sense of
   encryption/assurance against PHI/OT endpoints.

---

## CRITICAL

### src/oida/protocols/hl7/ (module-wide) — Test coverage 52% below 70% gate
The code_review.sh coverage gate reports 52% line coverage (1417/2979 statements
missed), a merge blocker per the review contract. Gaps concentrate in the
operationally important write/probe/enum/query paths: device.py 6%, enum.py 4%,
fuzz.py 4%, query.py 11%, utils.py 19%, __init__.py 43% — exactly the paths that
touch a live clinical endpoint. Add unit tests exercising the message builders
against a mock MLLP server / hl7apy round-trip and the proto_flow dispatch table.

> Note: several other modules were flagged `<70%` by the script (ethernetip 55%,
> iec104 40%, mms 32%, modbus 40%, snmp 14%, hart 25%, knx 19%). Reviewers
> calibrated most of these to MEDIUM/INFO because the script measures aggregate
> tree coverage during a per-module run rather than module-local coverage, and
> tests were declared out of scope. They are listed in their severity buckets
> below. hl7 and snmp are the genuine low-coverage outliers tied to uncaught
> functional bugs.

---

## HIGH

### src/oida/cli.py:265-359 — JSON/CSV result export is not credential-redacted
`_redact_sensitive_args()` (cli.py:76-85) is applied only to the single
`logger.debug("CLI args: ...")` line (cli.py:1080). The persisted artifacts —
`export_results()` writing `{protocol}.json`/`.csv` and `_export_tables()` —
dump `results` verbatim via `json.dump`/`csv.DictWriter`. Any protocol that
echoes a supplied or harvested password/community/PSK/token into `result['data']`
(login/bruteforce protocols record the winning credential) lands in cleartext in
the operator's output directory, and the `--json-log` stream is likewise
unredacted. Redact at the export boundary: walk nested dicts with the
`_SENSITIVE_ARG_PATTERNS` key matcher inside `export_results`/`_export_tables`
before serialization, or never write raw secrets into `results`.

### src/oida/protocols/astm/nxc_connection.py:127-137 — --tls-ca / --tls-insecure advertised but silently dropped; --tls never verifies cert
proto_args adds the full TLS group (`--tls-ca`, `--tls-insecure`) but
`create_conn_obj()` forwards only `tls_cert`/`tls_key` to
`create_tls_tcp_connection()`; the CA path and insecure flag are never read.
`build_tls_context()` defaults to `check_hostname=False`/`CERT_NONE` and only
upgrades to `CERT_REQUIRED` when it sees a `tls-ca` key, which astm never
supplies. So `oida astm <host> --tls --tls-ca ca.pem` is unauthenticated and
MITM-able while carrying PHI. Thread `--tls-ca`/`--tls-insecure` through to the
TLS context, or remove the flags. (Underlying helper gap shared with hl7.)

### src/oida/protocols/bacnet/mixins/state.py:117-129 — --dump with default --format silently writes nothing but reports success
`_handle_dump` reads `getattr(self.args, "format", "json")` but the real parser
default is `"console"` (cli.py:444). The file is only written in the json/yaml
branches, so the documented `oida bacnet <host> --dump -o backup` writes NO file
yet line 129 unconditionally logs `"Dump saved to {dump_file}"`. `--format
csv/xml/all` hit the same silent-no-write-but-claim-success path. Data-loss /
false-assurance on a backup feature. Normalize console/unknown to json, or only
log success inside a branch that actually wrote.

### src/oida/protocols/coap/helpers.py:40-65 — single process-wide asyncio loop shared across all scan threads
`_EventLoopHolder` is a process-global singleton holding ONE event loop;
`run_async()` calls `loop.run_until_complete()` on it. CoAP scans run under
`ThreadPoolExecutor` (default 10 workers), each funneling aiocoap traffic through
`run_async`. The `_lock` only guards loop creation, not `run_until_complete`.
Concurrent targets (`oida coap 192.168.1.0/24`) raise `RuntimeError: This event
loop is already running` and corrupt aiocoap context state. Make the loop
thread-local (`threading.local()`) or use a per-call loop like ocpp/opcua.

### src/oida/protocols/coap/nxc_connection.py:128-141 — DTLS scans without explicit -p enumerate wrong port (5683 instead of 5684)
After a successful DTLS handshake on 5684, the scan work runs through
`self.scanner`, whose port comes from `get_target_info()` = `rport or
get_default_port()` = 5683 (because `args.port` is None and `rport` is never
set). The code sets `scanner._scheme='coaps'` but keeps port 5683, so every
post-handshake request builds `coaps://host:5683/...` against a DTLS session
negotiated on 5684 — discovery/writes silently fail. Inject `rport`=dtls_port
into the args dict after a successful handshake.

### src/oida/protocols/dicom/nxc_connection.py:522 — --tls does not switch to advertised TLS port (2762); connects to 104 over TLS
`add_tls_options(dicom_parser, default_tls_port=2762)` renders "--tls (changes
default port to 2762)", but `create_conn_obj()` reads `port = getattr(self.args,
'port', self.default_port)` which always resolves to the `--port` default of 104.
So `oida dicom HOST --tls` does a TLS handshake against port 104. Mirror the
modbus pattern (`self.port or 2762` when TLS requested and no explicit port), or
drop the `default_tls_port` hint.

### src/oida/protocols/discovery/file_carving.py:134-146 — file-carving listener has no per-stream / dict size cap (unbounded memory + O(n²) CPU)
`process_packet()` does `stream.data.extend(payload)` with no size limit and
grows `self._streams` with no eviction; it calls `_try_extract_files()` on every
packet, which `data.find()`-scans the entire growing buffer per signature
(O(n²)). A stream with no matching footer OOMs the process. The sibling
`pcap/passive/file_carving.py:147-165` already enforces `stream.capped`,
`_STREAM_BUFFER_MAX`, and `_CARVE_INTERVAL`; the discovery variant diverged and
lost the cap. Mirror the pcap variant and bound live-stream count.

### src/oida/protocols/dnp3/mixins/file_transfer.py:306 — --file-auth gated and documented but never invoked; file auth is dead
`_authenticate_file()` is fully implemented but never called — `discover()` has
no `self.file_auth` branch. Consequently `self._file_auth_key` is never set, so
the `getattr(self, '_file_auth_key', None)` checks in `_read_file`/`_write_file`
always None and `ReadFileWithAuth`/`WriteFileWithAuth` are dead. An operator
targeting an outstation that requires file auth sees read/write fail with no
indication credentials were ignored. Add `if self.file_auth:
self._authenticate_file(results)` before the file-op branches in `discover()`.

### src/oida/protocols/ethercat/coe_ops.py:151-153,334-345 — --scan-coe (-C) silently writes to live slaves without --confirm
The CoE dictionary scan (dispatched at `__init__.py:567` with no `--confirm`
gate) calls `_test_sdo_write_access()` which performs `slave.sdo_write(...)`,
writing the just-read value back to every readable object on every slave during
a nominally read-only scan. On objects with write side effects (control words,
command/trigger objects, store/restore 0x1010/0x1011) a same-value write can
latch a state change. The write-only probe `_test_sdo_write_only()` IS gated
(coe_ops.py:357) but the RW probe is not. CHANGELOG says the ADS scanner
"refuses --scan-coe without --confirm" and "mirrors the dnp3/ethercat pattern" —
ethercat does NOT mirror it. Gate the RW write-back behind `self.confirm`
(degrade to read-only classification when unconfirmed).

### src/oida/protocols/ethernetip/mixins/advanced_parsers.py:264-320 — file download accumulates attacker-controlled total_size into memory with no real cap
`_download_file()` checks attr-6 size against `max_size` BEFORE downloading, but
the loop `while len(file_data) < total_size` is driven by `total_size` from the
device's Initiate-Upload response, never bounded against `max_size`. If attr-6 is
unreadable the pre-check is skipped entirely; even with a benign attr-6 a
malicious/buggy PLC can report a huge `total_size` and OOM the scanner (data held
fully in memory then base64-encoded). Use `effective_max = min(total_size,
max_size)` and break with a warning; apply the guard when `size_data is None`.

### src/oida/protocols/hart/scanner.py:237 — --tcp flag is dead; transport always UDP (reads args['protocol'] = subcommand name 'hart')
`self.transport = args.get("protocol", "udp").lower()` — but `protocol` is the
argparse subparser dest, so `args.protocol` is always the literal `"hart"`. The
`--tcp` flag lands on `args.tcp` and is never translated. hartip-py branches `if
self.protocol == "tcp"` so `"hart"` always takes the UDP else-branch; `oida hart
HOST --tcp` silently uses UDP while the banner (computed from `args.tcp`
separately) prints "(TCP)". Derive transport from `args.tcp`.

### src/oida/protocols/hart/mixins/security.py:254-310 — --security-analysis fires dangerous write/calibration commands (Cmd 42 Master Reset, Trim 45/46) without --confirm
`security_analysis()` actually transmits write commands (6/17/18/19/35/44/45/46/
50) and "dangerous_commands" (42 Master Reset, 43, 45/46 trim) with empty
payloads to the live device, with NO `--confirm` gate — unlike `--fuzz`,
`--write-*`, `--master-reset`, `--raw-command` which all require it. Sending
Master Reset / calibration trim to production instrumentation is exactly the
class the safety policy gates. Gate the dangerous_commands probes behind
`--confirm`, or restrict the unconfirmed path to non-mutating reachability
checks (Cmd 48 / Cmd 0).

### src/oida/protocols/iec104/proto_args.py:110 — CLI --asdu-address default=1 disables CA auto-discovery
`-a/--asdu-address` declares `default=1`, so the scanner branch
`self.asdu_address != -1` is always true: it pins `common_address=1` and sets
`_ca_explicit=True`, defeating the deliberate CA-discovery logic
(`protocol_options['asdu-address']` defaults to -1; `_best_common_address`
falls back to discovered stations/CA=0 only when `_ca_explicit` is False).
Devices not on CA 1 (common in real RTUs) get UNKNOWN_CA rejections for
interrogation/reads/writes. Set the CLI default to -1 (or None).

### src/oida/protocols/knx/mixins/security.py:234,290 — read/write access tests read wrong attribute (resp.data) and silently no-op
`_test_read_access` and `_test_write_access` do `data = resp.data`, but
`p2p.request()` returns a `Telegram` whose APCI response is `resp.payload` —
every other call site correctly uses `resp.payload.data`. `resp.data` raises
AttributeError on the first read, caught by the surrounding `except Exception`,
so `--test-read`/`--test-write` always return empty readable/writable lists
regardless of what the device exposes. `_analyze_security` then under-reports
write access. Change both to `resp.payload.data if resp and resp.payload else
None`.

### src/oida/protocols/mms/__init__.py:248 — --test-write CLI flag is inert; read_only defaults True and is never toggled off
`discover()` gates writes on `if self.test_write and not self.read_only` and
`_test_write_access()` re-checks `if self.read_only: return`. `read_only`
defaults True from base_scanner and there is NO `--read-only`/`--write` flag
anywhere for MMS, so `--test-write` silently does nothing. Wire `--test-write` to
clear `read_only` (behind `--confirm`), or drop the flag. (Same dead-write-flag
shape appears in snap7 `--test-write`, snap7 `-T`, and tase2 — see LOW/HIGH.)

### src/oida/protocols/modbus/nxc_connection.py:346-349 — --test-write-thorough performs destructive live writes (writes 42/43, toggles coils) with no --confirm gate
`--test-write` and `--test-write-thorough` both call `_handle_test_write()` with
no `--confirm` check, while every other modbus write path is gated.
`--test-write-thorough` resolves to mode='destructive', which writes a DIFFERENT
value (42, or 43) into live holding registers and flips coils, then best-effort
restores — a failed restore only sets `result['restored']=False` and continues,
so registers/coils can be left permanently changed. Require `--confirm` for the
destructive mode (the safe same-value mode may stay ungated by deliberate
decision).

### src/oida/protocols/mqtt/mixins/auth.py:35-39 — report_vulnerability() called with wrong positional args; TypeError crash when anonymous auth succeeds
`_test_anonymous_auth` calls `report_vulnerability("Anonymous Authentication",
"CRITICAL", "Broker allows...")` but the inherited signature is
`report_vulnerability(self, host, vuln_name, **kwargs)`, so the third positional
has no parameter and raises `TypeError`. Reachable via the connect-times-out-
then-anonymous-reconnect-succeeds path; aborts the scan. The very next
`security_finding(...)` already reports the same fact through the working API, so
the broken call can simply be removed (or fixed to pass `self.host, "Anonymous
Authentication", severity=..., description=...`).

### src/oida/protocols/opcua/mixins/credentials.py:61-62 — post-construction client.timeout = … is a no-op in brute-force / RBAC / GDS / L1 paths
asyncua's `Client` accepts `timeout` only as a constructor arg; assigning
`client.timeout` afterward creates a dead attribute and the library 4s default
stays. The main flow was fixed (nxc_connection.py:426-429) but four secondary
paths were not: credentials.py:61-62 (brute force), credentials.py:184-185
(RBAC), discovery.py:48-49 (GDS find-servers), scanner.py:201-202 (L1 connect).
`-t/--timeout` is ignored there; during brute force every wrong cred blocks on
the default timeout. Pass `Client(url=url, timeout=...)` and drop the assignment.

### src/oida/protocols/profinet/mixins/rpc.py:582-586 — --write-index permanently dead; gated on non-existent --no-read-only flag
`_write_single_index()` blocks on `if self._arg("read_only", True): ... "use
--no-read-only to enable writes"`, but no `--read-only`/`--no-read-only` argument
exists anywhere, so `_arg("read_only", True)` is always True and every
`--write-index` aborts even with `--confirm`. Inconsistent with the rest of the
module which gates on `--confirm` only. Drop the read_only check and rely on the
existing `--confirm` gate (rpc.py:537), or register the flag.

### src/oida/protocols/snmp/mixins/host_enumeration.py:1164-1167,1187-1190 — security_finding() title/category args swapped for H3C and Brocade credential findings
Signature is `security_finding(title, category="", detail="")`. The H3C
(line 1164) and Brocade (1187) calls pass `(credential-sentence,
"Credential disclosure")`, i.e. the leaked username/password lands in the
`title` slot (and is persisted/exported as the finding title) while the category
label lands in `category` — the reverse of every sibling call. Swap to
`security_finding("Credential disclosure", f"H3C credential found: ...")`.

### tests/unit/snmp — Test coverage 14%; protocol logic mixins almost entirely untested
Script reports 14% (host_enumeration.py 6%, write_access.py 8%,
version_detection.py 9%, raw_queries.py 8%, v3_enumeration.py 13%,
brute_force.py 18%, scanner.py 29%). Both snmp functional findings above (the
arg swap and the ungated SET) live in single-digit-coverage mixins, which is why
neither was caught. Add tests over `_enum_credentials` finding emission and
`_set_probe`/`_check_write_access` (assert confirm-gated and idempotent).

### src/oida/protocols/tase2/proto_args.py:312-318 — scanner read_only hardwired True; --confirm-gated write/control/tag ops silently no-op
(Partial — finding truncated in source feed.) The tase2 scanner's `read_only` is
hardwired True (scanner.py:499; mixins/control.py:159,249;
mixins/enumeration.py:199,226; mixins/info_messages.py:280), so `--confirm`-gated
write/control/tag operations silently no-op. Same dead-write-flag class as MMS
and snap7. Reconcile the read_only/confirm story for the tase2 write paths.
Re-run the tase2 review — its findings were cut off in the aggregation feed.

---

## MEDIUM

### src/oida/cli.py:1184, src/oida/connection.py:363 — shallow arg copy allows mutable-attribute cross-target/cross-protocol leakage
The scalar `args.port` leak was fixed with `copy.copy(args)` (connection.py:363)
and a per-target `argparse.Namespace(**vars(args), ...)` (cli.py:1184), but both
are SHALLOW. Any list/dict/set attribute remains a shared reference across
per-target copies and across the two Layer-2 protocols in one process; in-place
mutation (`args.scan_range.append(...)`) is visible to every other concurrent
target (ThreadPoolExecutor → data race). Use `copy.deepcopy(args)` at the
per-target fan-out, or treat `args` as immutable framework-wide.

### src/oida/utils/export_utils.py:262-286,230-260 — get_export_path()/export_table() build paths from unsanitized name (path-traversal latent)
Both construct `_config['output_dir'] / f"{name}.{ext}"` with no sanitization,
while `common_types.safe_output_path()` exists for exactly this. All current
in-tree callers pass static literals (latent, not exploitable), but this is the
framework file-output chokepoint; any future caller deriving `name` from device/
remote data inherits a traversal write. Route `name` through `safe_output_path()`
(or `os.path.basename`).

### src/oida/utils/proto_args_factory.py:346-419,892-925 — --confirm gate declared centrally but enforced at ~117 per-protocol sites with no helper
`add_dangerous_options()`/`add_control_options()` declare `--confirm`/`--fuzz`/
`--write`/etc. and put "requires --confirm" in help text, but no framework
function enforces the gate — ~117 hand-written `if args.confirm` checks under
`protocols/`. A single protocol that forgets (or checks the wrong flag) performs
an unconfirmed dangerous OT op. Add a central `require_confirm(args, operation)`
helper that logs a uniform refusal and returns False when unset. This is the root
cause behind the modbus/ethercat/ethernetip/bacnet/hart/snmp/iec104/can
"ungated write" findings.

### src/oida/protocols/ads/ethercat_ops.py:1027-1031 — CoE write-only scan: range_found/name used outside `if wo_ok:` → NameError aborts port scan
In `_scan_coe_via_ads`, lines 1029-1030 (`range_found += 1`, debug log using
`name`) are de-indented under `if test_access:` instead of `if wo_ok:`. When
`wo_ok` is False, `name` is unbound → `NameError`, swallowed by the broad
`except Exception` (line 1165), which silently aborts the whole CoE scan for that
port. Secondary: `range_found` is wrongly incremented. Indent into the `if
wo_ok:` block (mirror lines 1106-1110).

### src/oida/protocols/astm/proto_args.py:45 — --tls help claims default port switches to 1395, but create_conn_obj always uses 12000
`add_tls_options(astm_parser, default_tls_port=1395)` makes help read "changes
default port to 1395", but `create_conn_obj()` reads port unconditionally (=
12000) and never adjusts for `--tls`. Implement the switch (default 1395 when
`--tls` and no explicit `--port`) or drop `default_tls_port=1395`.

### src/oida/protocols/astm/mixins/security.py:61 — fuzz case list truncated to fuzz_iterations, dropping most record-type cases
`_fuzz_records()` builds frame cases (8) + 5 per record type but iterates
`fuzz_cases[:iterations]` (default 10). With `--fuzz-frame` only 2 of 30
record-level cases run; across all 6 record types only the first 10 (H, P) run
and O/R/Q/C are never fuzzed. Loop the full case list (optionally repeating
across rounds) or document/order so coverage is representative.

### src/oida/protocols/bacnet/nxc_connection.py:350-354 — --brute-force and --test-dcc send password-guessing DCC requests with no --confirm gate
In the bacpypes3 path, `--brute-force` and `--test-dcc` dispatch without a
`--confirm` check, while less-intrusive `--test-reinit-pass`,
`--test-priority-writes`, `--test-time-sync`, `--test-bbmd-injection` all require
it. The code itself warns these "may trigger alarms or lockouts". Add a
`--confirm` gate and honor `--safe`.

### src/oida/protocols/can/nxc_connection.py:331-333 — OBD-II supported-PIDs parser reads data[6] after only guarding len(data) >= 6
`_handle_obd2` accepts `if len(data) >= 6 ...` then reads `data[6]` →
IndexError on 6/7-byte frames; no surrounding try/except so it aborts the whole
`proto_flow()` for that target. Change the guard to `len(data) >= 7`.

### src/oida/protocols/dicom/nxc_connection.py:381 — CLI default port 104 contradicts documented/commented default of 11112
`self.default_port = 11112` (with a comment explaining 11112 is the de-facto
PACS default) is only used in programmatic construction; `add_network_options`
registers `--port` with `default_port=104`, so the CLI path always uses 104 and a
bare `oida dicom HOST` misses every PACS on 11112. Align proto_args to 11112 or
fix the comment/docstrings.

### src/oida/protocols/dicom/nxc_connection.py:523 — create_conn_obj timeout fallback of 30s is dead; real timeout 2s applied to ACSE/DIMSE
`timeout = getattr(self.args, 'timeout', 30)` but `--timeout` defaults to 2; the
attribute always exists so 30 is dead. 2s is then assigned to dimse_timeout,
which is aggressive for C-FIND/C-GET against a busy PACS (bulk export can
spuriously abort). Remove the misleading dead default and consider a larger
DICOM-specific default.

### src/oida/protocols/dnp3/scanner.py:340 — -s/--save-file parsed and documented but never writes the downloaded file
`self.save_file` is stored but never read; `_read_file()` only logs a preview and
stores `data_hex`. `--read-file ... --save-file ./x` creates no local file
(recoverable only from JSON `data_hex`, and only when size ≤ 65536). Write `data`
to the path via `get_export_path`/pathlib in `_read_file`.

### src/oida/protocols/dnp3/scanner.py:749 — --tls without --tls-cert/--tls-key silently downgrades to plaintext TCP
TLS channel is created only when `use_tls and tls_cert and tls_key`; otherwise
the chain falls through to `_connect_tcp()` over cleartext with no warning, and
`validate_args()` doesn't enforce cert+key. Silent confidentiality downgrade.
Raise `ConfigurationError` when `--tls` lacks cert+key, or log loudly on
fallback.

### src/oida/protocols/discovery/lldp.py:994-999 — LLDPPassiveListener references self.logger which is never defined → AttributeError on every parse-error path
`LLDPPassiveListener` doesn't inherit `PassiveListenerBase` and never sets
`self.logger`, yet calls `self.logger.debug(...)` in five exception handlers on
attacker-controlled-TLV paths. The except meant to swallow the parse error
instead raises AttributeError out of `process_packet()`. Largely dormant in the
main flow (served by `LLDPScanner`) but live for direct/pipeline use. Add a
module-level logger (matching the rest of discovery) or inherit the base and
accept a logger.

### src/oida/protocols/ethernetip/scanner.py:811-814 — --write performs live Set_Attribute_Single writes without --confirm
`--write` flips `read_only=False` and `_test_write_with_status()` issues real
Set_Attribute_Single (0x10) to every readable attribute (writing the value
back), gated only on `test_write`, never `confirm` — while `--fuzz` IS confirm-
gated. The protocol's own help says "might cause DoS". Gate the write-test path
on `--confirm`.

### src/oida/protocols/ethernetip/scanner.py:1-941 — test coverage 55% below 70% gate
Script reports 55% CRITICAL. Thinly-covered areas (cip_objects,
advanced_parsers, write_test) overlap exactly with the two ethernetip findings
above, so added tests would also guard the OOM/confirm fixes. (Calibrated to
MEDIUM: process gate, not a runtime defect.)

### src/oida/protocols/fhir/mixins/security.py:410-418 — _analyze_security() relabels ALL accumulated logger findings as CERTIFICATE and double-counts
The "Add certificate findings from logger" loop iterates the whole per-scan
`logger.findings` accumulator (which already contains every finding) and
re-appends each with hard-coded `category='CERTIFICATE'`. Result: every non-cert
finding (anonymous access, default creds, etc.) is duplicated and mislabeled. The
modbus SunSpec mixin (sunspec.py:699,870) solves this correctly by snapshotting
`len(logger.findings)` before and slicing afterward. Adopt the start-index slice
and stop forcing the category.

### src/oida/protocols/iec104/scanner.py:1-1665 — test coverage 40% below 70% gate
Untested surface is the command/write/parameter/file-transfer and raw-ASDU
parsing paths most prone to struct-offset bugs (the two iec104 parsing findings
below). Calibrated MEDIUM (process gate).

### src/oida/protocols/iec104/scanner.py:879-884 — writes gated only on --confirm, not read_only, contradicting --no-read-only guidance
`discover()` gates test-commands on `test_commands and not read_only` and
`_test_commands` tells users it "requires --no-read-only", but `_write_value`,
`_write_parameter`, `_reset_process`, file upload/delete are gated ONLY on
`--confirm` (base `read_only` defaults True). So state-changing commands run in
nominal read-only mode while harmless capability detection honors read_only —
the inverse posture. Reconcile: standardize on `--confirm` and correct the
misleading `--no-read-only` message.

### src/oida/protocols/iec104/scanner.py:427-497 — non-sequence multi-object IOA parser lacks bounds check; incomplete INFO_ELEMENT_SIZES yields bogus values
`_extract_value` relies solely on `(struct.error, IndexError)` catch (swallowing
out-of-bounds reads to None) and `INFO_ELEMENT_SIZES` omits types 17-19/38-40
etc., defaulting `ie_size` to 0 so per-index offset math collapses to a constant
and emits duplicate/bogus IOA values. Bounds-check each `unpack_from` and skip
value extraction when `type_id not in INFO_ELEMENT_SIZES`.

### src/oida/protocols/mms/__init__.py:632-708 — --test-write issues real IedConnection_writeObject calls with no --confirm gate (Layer-1 path)
`_test_write_access()` → `_write_data_object()` calls `IedConnection_writeObject`
(cycling FC_CO/FC_SP/FC_MX) gated only on `not self.read_only`, no `--confirm` —
unlike `_handle_fuzz()`. Currently masked by the inert-read_only HIGH above; will
surface when that is fixed. Gate behind `--confirm` like `--fuzz`.

### src/oida/protocols/mms/proto_args.py:34-51 — dead CLI options: -i/--identify, -l/--get-name-list, -r/--variable, --wordlist-path
None of `args.identify`/`get_name_list`/`variable` is read; identify is always
done in `_get_server_info`, no single-variable-read path exists, and
`wordlist_path` (the "object name fuzzing" it describes doesn't exist) is never
referenced. Implement or remove.

### src/oida/protocols/mms/__init__.py:272-273 — native MmsError handle leaked on every _get_server_info call
`MmsError_create()` is never `MmsError_destroy`-ed; `_get_server_info()` runs ≥2×
per scan, leaking a native allocation per call across a sweep. Add the destroy in
the finally block (the module is otherwise careful about SWIG memory).

### src/oida/protocols/mqtt/proto_args.py:144-151 — --listen-time / -T declared but never read; listen mode uses --timeout (default 2s)
`add_listen_options(..., default_duration=60)` registers `--listen-time` but
nothing reads it; listen logic uses `self.timeout`, and mqtt doesn't override
`default_timeout` so the effective value is 2s. `oida mqtt host --listen`
captures ~2s and `--listen-time 60` is a no-op. Wire `--listen-time` into the
listen path or drop it and bump the listen default.

### src/oida/protocols/ocpp/__init__.py:146-148 — TLS certificate check probes wrong port for non-default wss:// URLs
For `wss://`, __init__ forces `args.port = 443` whenever the port is falsy or
9000 (the argparse default), so `wss://host:8443/...` rewrites `args.port` to 443.
The WS connection works (uses embedded `_target_url`) but
`_check_tls_certificate()` reads `args.port` and probes 443 instead of 8443,
reporting misleading/empty cert results. Parse the real port from the URL via
urlparse.

### src/oida/protocols/profinet/mixins/rpc.py:79-80 — --no-read-im silently ignored in DCP discovery mode
In `_rpc_operations()` `_read_im_data(...)` is called unconditionally ("Always
read I&M0"); `read_im` is only honored in the RPC-only path. `oida profinet eth0
--no-read-im` still issues I&M0/I&M1 reads against every discovered device.
Honor `read_im` here or document that I&M0 is always read.

### src/oida/protocols/snap7/mixins/block_operations.py:622-631 — enumerate_dbs_action prints raw dicts instead of DB numbers
`-e/--enumerate-dbs` dispatches `enumerate_dbs_action()`, which iterates a
`List[Dict]` as `for db_num in dbs:` and prints `DB{'number': 1, 'size': 88,
...}` instead of `DB1`. The stored `{"data_blocks": dbs}` is fine but the main
user-facing output of `-e` is garbled. Pull `db['number']`.

### src/oida/protocols/snmp/scanner.py:526-529 — --test-write issues an active SET without the --confirm gate that --set/--walk-write require
`--set` and `--walk-write` are gated on `confirm_brute`; `--test-write` is not —
it calls `_check_write_access` → `_set_probe`, issuing a real `set_cmd` PDU
against sysContact.0. Engineered idempotent (read/write-same/restore) but still
an unsolicited write PDU on a permissive agent, inconsistent with the other two
SET paths. Gate `--test-write` behind `--confirm`.

---

## LOW

### src/oida/cli.py:508-516,575-621,723,1144 — raw print() for banner/usage/progress/interrupt/proto_args warnings
Several emissions use bare `print()`/`print(file=sys.stderr)`. Banner/usage are
defensible framework chrome, but the proto_args registration failure notices
(508-516) are error reporting that should go through `logger.warning`/`error` so
they honor `-q/--quiet` and the JSON-log stream — currently they print regardless
of `--quiet`.

### src/oida/loader.py:178-182 — stray FROZEN_DIAG print + traceback to stdout in frozen builds
`_discover_frozen()` emits `print(f"FROZEN_DIAG: ...")` and
`traceback.print_exc()` per protocol whose optional dep is missing — floods
stdout in frozen distributions before any scan, polluting machine-readable
output. Sibling probe paths (loader.py:196,204) correctly use `logger.debug`.
Replace with `logger.debug` and drop the unconditional traceback.

### src/oida/utils/export_utils.py:214,616 — export_table reads back a shared-global truncation flag another thread may have overwritten
`print_table()` writes `_config['_last_table_truncated']` (line 616) and
`export_table()` reads it (line 214); `_config` is shared across workers, so the
truncation hint can cross over between targets. Impact is only a misleading
console message. Return the flag from `print_table()` instead of round-tripping
through the global.

### src/oida/utils/ics_logger.py:857-883,784-794 — lazy singletons _mac_parser and _cli_instance initialized without a lock
`mac_lookup()` builds `_mac_parser` and `_get_cli()` builds `_cli_instance` under
no lock; workers can race the `if _x is None` check and each construct an
instance (MacParser re-parses a vendor DB — wasteful, not corrupting). The file
already uses dedicated locks for other caches; guard these two with
double-checked locks for consistency.

### src/oida/protocols/ads/ethercat_ops.py:1908-1935 — FoE write chunk-ack RuntimeError swallowed; failed write still reports success
`_foe_write_via_ads` catches every `RuntimeError` on the chunk ack (intended for
benign short-reads) then unconditionally `bytes_written += len(chunk)`, returning
`success: True` even on a genuine write rejection. Inspect the error string for
the short-read pattern (as `_read_coe_sdo` does) and treat other RuntimeErrors as
a failure that aborts and returns `success: False`.

### src/oida/protocols/ads/proto_args.py:482-496 — --scan-coe-access confirm gate enforced only in NXC wrapper, not central validate_args()
`--scan-coe-access` performs real device writes (`_test_coe_write_access` /
`_test_coe_write_only`) but is missing from `_CONFIRM_REQUIRED_FLAGS`; gated only
by an inline check in `_scan_coe_access_nxc`. Behavior is currently correct but a
future dispatch refactor could drop the inline check. Add `"scan_coe_access"` to
the map for uniform enforcement.

### src/oida/protocols/ads/ethercat_ops.py:714-755 — attacker-controlled EtherCAT slave_count drives unbounded per-slave network loop
`_scan_ethercat` uses the device-reported slave count unvalidated to build
`range(first_port, first_port + slave_count)`; a device reporting 65535 slaves
forces up to 65535 multi-round-trip iterations (self-inflicted DoS on the
scanner). Sanity-clamp the count with a warning (mirroring the existing 256
discovery cap and the XML-length bound).

### src/oida/protocols/astm/mixins/records.py:82-86 — _send_patient_record records no security finding on acceptance, unlike order/result paths
A forged Patient (P) record accepted sets `patient_accepted=True` but appends
nothing to `security_findings`, while `_send_order_record`/`_send_result_record`
both append a CRITICAL finding. A confirmed patient-demographic injection is
missing from the exported report. Add an equivalent HIGH finding.

### src/oida/protocols/astm/mixins/framing.py:51-54 — duplicate _calculate_checksum in ASTMRecordBuilder and FramingMixin can drift
Identical mod-256 checksum implemented twice (records.py:65-79 appears dead).
Consolidate or delete the unused builder copy.

### src/oida/protocols/bacnet/mixins/monitoring.py:534-600 — COV subscription created but never cancelled, leaking subscriber state on the device
`_bacpypes3_subscribe_cov` subscribes with `lifetime=300s`, listens ~30s, returns
without cancelling; subscriptions persist for the full lifetime, consuming COV
slots and potentially exhausting constrained controllers. Unsubscribe in a
`finally`, or document the intentional expiry.

### src/oida/protocols/bacnet/mixins/state.py:183-190 — --diff baseline parser assumes dump-format objects, crashes on export-format objects
`_handle_diff` does `obj.get("instance")` assuming dict entries (dump shape), but
`_export_results` writes bare ints; diffing against a `-o/--format json` export
raises AttributeError, swallowed and reported as a confusing scan failure. Pick a
canonical on-disk shape or tolerate both.

### src/oida/protocols/bacnet/mixins/export.py:58-75 — _export_results silently no-ops for xml/all/console formats it advertises
Only json/csv handled; `xml`/`all`/`console` with `-o` set write nothing and log
nothing (less severe than the dump case — no false success). Route through the
shared `export_results` helper or handle the formats explicitly.

### src/oida/protocols/can/proto_args.py:185-193 — --uds-services defined but never consumed
`_enumerate_uds_services` always iterates the full `UDS_SERVICES`; `--uds-services
0x10,0x22` silently has no effect, giving a false sense of having scoped the
footprint. Wire it in or remove.

### src/oida/protocols/can/mixins/isotp.py:120-135 — ISO-TP consecutive-frame reassembly ignores sequence numbers despite docstring
The CF loop checks only the frame-type nibble and appends `cf[1:]`, never
validating the 4-bit SN in `cf[0] & 0x0F`; out-of-order/dropped CFs concatenate
in arrival order producing silent corruption rather than the documented None.
Implement the SN check or soften the docstring.

### src/oida/protocols/coap/helpers.py:80-98 — stale raw-socket coap_ping ignores DTLS (TODO to use aiocoap Context.ping())
`coap_ping` hand-builds a raw UDP packet; with `-D` set, liveness probes
cleartext UDP for a coaps:// scan, so a DTLS-only server reports "not alive" and
forces the GET fallback. Route liveness through the aiocoap context respecting
scheme, or skip the raw ping when DTLS is requested.

### src/oida/protocols/dicom/mixins/operations.py:404-421 — C-MOVE sub-operation counters only captured on Pending; final-only responses report 0 transferred
`NumberOfCompletedSuboperations` is read only in the Pending (0xFF00) branch; an
SCP that sends counts only in the terminal response reports "0 transferred", the
results store records 0, and the "Open transfer" finding (gated on completed>0)
never fires — masking a real successful exfiltration. Also read the counters from
the terminal 0x0000/0xB000 status.

### src/oida/protocols/dicom/mixins/cfind.py:131-135 — duplicate "Unrestricted query access" finding emitted twice for the same wildcard C-FIND
`_cfind_query()` emits it inline and `_analyze_security()` re-derives the same
condition and emits it again; every wildcard `--find` records it twice. Drop the
inline emission (keep `_analyze_security` as the single source).

### src/oida/protocols/dicom/mixins/reporting.py:329-350 — C-FIND export rows pull STUDY-level keys that PATIENT-level results never contain
`_export_results()` hard-codes StudyDate/Modality/StudyInstanceUID headers, but
the default PATIENT level produces PatientName/ID/BirthDate/Sex/StudyCount; a
normal `--find -o out` exports blank study columns and drops the data actually
retrieved. Select export headers/rows based on `cfind['query_level']`.

### src/oida/protocols/dicom/mixins/enumeration.py:312-329 — device/time enumeration uses Study-Root C-FIND at SERIES level with empty StudyInstanceUID unique key
`_enum_devices()` issues a SERIES-level C-FIND with empty StudyInstanceUID; under
Study Root, that unique key is required to descend, so strict SCPs return nothing
("No device information found" on a populated PACS). Descend study-by-study (as
`_recursive_bulk_export` does) if strict servers are in scope.

### src/oida/protocols/discovery/lldp.py:436-454 — _format_chassis_id / _format_port_id fall through to implicit None despite -> str
The no-attribute success path returns None instead of a string; masked downstream
by `device.chassis_id or 'Not provided'` but breaks any str-assuming consumer.
Add an explicit `return ''` (or 'Unknown') at the end of both methods.

### src/oida/protocols/dnp3/proto_args.py:214 — --probe-objects help claims "(requires --confirm)" but never enforced
`validate_args()` never adds `probe_objects` to `control_ops`. The probe is
read-only so not gating is defensible, but the help text is contradictory. Drop
the clause or gate it.

### src/oida/protocols/dnp3/scanner.py:410 — -n/--no-ack flag has no effect despite "stealth mode" help text
`self.no_ack_mode` is stored but never referenced; only `-N/--freeze-no-ack`
actually selects NR variants (freeze only). Dead flag misleading operators. Wire
it into control paths or remove.

### src/oida/protocols/dnp3/mixins/control.py:214-262 — --deadband-type uint16/uint32 selections silently ignored
`_write_dead_bands()` always builds a G34V3 float deadband regardless of
`--deadband-type`; uint16/uint32 are only echoed into results. Map the type to
the correct variation or remove the choices.

### src/oida/protocols/dnp3/scanner.py:720-785 — opendnp3 manager (and worker threads) leak when connect() fails
`connect()` creates `DNP3Manager(4, ...)` before channel/open; on failure it
raises without `Shutdown()`. In the NXC path `self.conn` stays None so
`cleanup()` skips teardown — threads leak per failed connect (accumulates under
range scanning). Wrap `connect()` to shut down `_manager`/`_channel` on any
exception before re-raising.

### src/oida/protocols/ethercat/proto_args.py:126-131 — --timeout (default 2000.0 ms) is dead; scanner hard-codes timeouts
`args.setdefault('timeout', 5)` never fires (CLI always supplies 2000.0) and
nothing reads `self.timeout` for pysoem ops (hard-coded 50000/10000/2000/etc.).
The documented `--timeout` flag has no effect. Wire it in or drop it.

### src/oida/protocols/ethercat/advanced_ops.py:13-15,50 — advanced_ops uses module-level logging.getLogger instead of self.logger
`_dump_esc_registers`'s `read_reg()` logs FPRD failures via the stdlib
module logger inside an instance method where `self.logger` is available,
breaking the single-logger contract (the script's "logging module usage" flag).
Pass/use `self.logger`.

### src/oida/protocols/ethernetip/scanner.py:293-295 — heavy CIP-Security dump (cert + password-auth reads) runs by default with no flag
`check_security` and `dump_security` both default True, so a plain `oida
ethernetip <host>` reads CIP Security (0x5D/0x5E), Certificate Mgmt (0x5F) —
downloading every cert — and Password Authenticator (0x61) without being asked,
adding heavy CIP traffic per host in a sweep. Default `dump_security` to False
(keep lightweight `check_security`).

### src/oida/protocols/ethernetip/mixins/fuzz.py:287-325 — contradictory pycomm3 flags connected=True + unconnected_send=True in fuzz writes
The fuzzer passes a contradictory combination (everywhere else uses one or the
other), so a fuzz "crash"/"accept" may not be reproducible via the documented
connected path. Align to `connected=True, unconnected_send=False` unless routed
fuzzing is intended (then pass an explicit route_path).

### src/oida/protocols/ethernetip/scanner.py:301-304 — stale TODO: --route-path accepted but routed CIP object reads never wired in
`route_path_str` is parsed/warned but never threaded into
`_discover_cip_objects()`; `--route-path 1/2` is a no-op for its advertised
CVE-2024-6242-style use case. Wire it in or downgrade the docstring.

### src/oida/protocols/fhir/mixins/security.py:174-177 — plaintext brute-forced creds embedded in security-finding detail, re-exported via the CERTIFICATE relabel loop
`detail=f"Valid Basic Auth: {username}:{password}"` puts the cleartext pair into
`logger._findings`, which the buggy relabel loop then copies into exported
`security_findings`. Keep the secret out of the human-readable detail (e.g.
"Valid Basic Auth for user '<user>'") and rely on the structured
`brute_force.valid` record.

### src/oida/protocols/fhir/mixins/search.py:203-212 — Observation date-range builds a list value for the 'date' param that may not round-trip through fhirclient .where(struct=)
When both `--date-from`/`--date-to` are supplied, `search_params['date']` is a
two-element list; fhirclient's `where(struct=)` expects scalar strings, and if it
str()-coerces the list the server ignores the filter and returns unfiltered
results. Verify against the pinned fhirclient or build the range via the search-
param chaining API.

### src/oida/protocols/goose/__init__.py:530-533 — dead VLAN/dst_mac display branches + wrong dict key (vlan_prio vs vlan_priority)
`_display_goose_message` reads `msg['vlan_id']`/`vlan_prio`/`dst_mac` which
`_goose_message_to_dict()` never populates (only the MMS GoCB path does), and
uses key `vlan_prio` while the rest of the file uses `vlan_priority`. Populate the
fields from the GooseMessage or remove the dead branches; rename to
`vlan_priority`.

### src/oida/protocols/goose/__init__.py:323,395 — copy-pasted debug log messages are source-code fragments + module logger instead of self.logger
Debug logs read `f"if sub._subscriber is not None:: {e}"` and
`f"self._goose_subscriber.stop(): {e}"`, and use the module-level `logging`
logger inside a method where `self.logger` is used everywhere else. Replace with
descriptive text via `self.logger.debug`. *(Consolidated: the goose
debug-message-quality and goose module-logger findings are the same two lines.)*

### src/oida/protocols/goose/proto_args.py:76-87 — R-GOOSE auth/key CLI flags advertised but non-functional
`--rgoose`/`--rgoose-port`/`--rgoose-auth`/`--rgoose-key` are parsed but R-GOOSE
itself hard-fails ("not yet supported"); the epilog even advertises a working
example. Hide the flags until R-GOOSE lands or mark them unimplemented and remove
the example.

### src/oida/protocols/hart/nxc_connection.py:27-90 — eleven CLI flags defined in proto_args but never consumed by proto_flow()
`--read-id/-pv/-current/-tag/-output/-status`, `--enumerate-device-specific`,
`--probe-calibration/--probe-write`, `--scan-mode` are silent no-ops; the
corresponding mixin methods (read_primary_variable, etc.) exist and are tested
but never wired to a flag. Wire or remove. *(MEDIUM in source; calibrated to LOW
as a dead-flag instance under the framework dead-flag root cause.)*

### src/oida/protocols/hart/mixins/fuzz.py:210 — copy-paste-broken debug log messages misdescribe the failing operation
`f"if date:: {e}"` for a Cmd-18 failure; `f"Failed to get code_padded: {e}"` for
unlock/lock send failures (security.py:86,117). Replace with operation-named
messages.

### src/oida/protocols/hart/mixins/enumeration.py:18-20 — enumeration.py and fuzz.py use stdlib logging.getLogger instead of self.logger
Module-level `logger = logging.getLogger(__name__)` used in instance methods
where `self.logger` is available (the script's check #4). Use `self.logger.debug`;
for the `probe_address` nested closure, capture/pass `self`.

### src/oida/protocols/iec104/serial.py:106-112 — IEC 101 ASDU/IOA truncated to 1-byte CA and 2-byte IOA regardless of configured sizes
`_build_asdu_101`/`_process_asdu_101`/`_poll_serial_data` hardcode 1-octet CA and
2-octet IOA; IEC 60870-5-101 allows configurable widths. Against a 2-octet CA /
3-octet IOA station every parsed CA/IOA is wrong. At minimum name the constants
and document the limitation.

### src/oida/protocols/iec104/constants.py:462-467 — orphan 'confirm-upload' protocol option never read; --confirm is the real gate
Nothing reads `confirm-upload`; all dangerous ops gate on `self.confirm`. Remove
the dead/misleading entry or wire it.

### src/oida/protocols/iec104/file_transfer.py:240-322 — --query-log triggers a device-side archive operation with no --confirm gate
`_query_log` (Type 127) dispatches with no `--confirm` while surrounding ops are
gated; some RTUs spin up a file-transfer session / write audit entries. Gate it
or document the device-side request.

### src/oida/protocols/iec104/serial.py:126-167 — _receive_serial_frame default timeout=None typed as float; only restores when truthy
Default None against a `float` annotation; `if timeout:` skips override AND
restore for `timeout=0` (valid non-blocking). Tighten to `Optional[float]` and
use `if timeout is not None`.

### src/oida/protocols/knx/ets.py:410 — crack_knxproj() calls logger.debug() unguarded though logger defaults to None
The future-result except handler calls `logger.debug(...)` directly while every
other use is guarded by `if logger:`; with the function's own default
`logger=None`, a worker exception raises AttributeError aborting the crack run.
Latent (only caller passes a logger). Wrap in `if logger:`.

### src/oida/protocols/knx/mixins/security.py:20 — three async mixin methods defined but never dispatched (dead code)
`_test_bcu_auth`, `_read_device_info`, `_discover_group_addresses` are superseded
by live equivalents and never referenced from the dispatcher or tests (~120 lines
mirroring live code). Delete or wire to a flag.

### src/oida/protocols/knx/nxc_connection.py:240 — _parse_search_response hardcodes port 3671, ignores HPAI-advertised control endpoint port
A gateway on a non-default port (NAT/port-forward) is reported as 3671, which is
misleading for follow-up tunnels built from output. Decode the HPAI port instead
of hardcoding.

### src/oida/protocols/mms/__init__.py:589-590 — MMS_UNSIGNED extracted via signed toInt32; large unsigned values misread
Unsigned values above 0x7FFFFFFF return negative in JSON/CSV. Use
`MmsValue_toUint32()` (or mask) for the unsigned case.

### src/oida/protocols/mms/nxc_connection.py:12-14 — nxc_connection uses logging.getLogger instead of self.logger
Module-level stdlib logger used in nested closures where `self` is in scope
(script check #4). Route through `self.logger.debug`.

### src/oida/protocols/mms/__init__.py:726 — copy-paste garbage in several debug log messages
`f"if isinstance(value, bool):: {e}"` (__init__.py:726),
`f"if re.match(rule.domain_pattern...: {e}"` (fingerprint.py:175), and generic
"Return value computation failed"/"Failed to get result/value" in nxc fuzz
closures. Replace with operation-describing text.

### src/oida/protocols/modbus/nxc_connection.py:622-639 — scale_factor_register lookup uses incrementally-built dict; wrong when SF register follows the value register
`_read_and_display_map_registers()` looks up the SF register in a dict built as
the loop progresses, so an SF register placed AFTER the value register (common in
SunSpec, e.g. value 40083 / SF 40084) is missing and the value is silently off by
a power of ten. The batch decoder path doesn't have this bug. Pre-populate
`all_registers` in a first pass (the docstring already claims this).

### src/oida/protocols/modbus/mixins/writes.py:94 — --no-restore referenced but never defined as a CLI argument
`_handle_write()` computes `restore_on_exit=not getattr(self.args, 'no_restore',
False)` — no such flag exists, so single-register writes always restore-by-
default via a non-existent flag, while coil/multi writes default to no-restore via
the real `--restore-on-exit`. Pick one model and align.

### src/oida/protocols/modbus/nxc_connection.py:454-463 — map default unit ID silently overrides an explicit `-u 1`
The guard `if user_unit_id is None or user_unit_id == 1` can't distinguish "unset"
from "explicitly 1" (default=1), so `-u 1` is silently redirected to the map's
default_unit_id (e.g. 255) — retargeting a different live slave than typed. Set
the argparse default to None and treat None as unset.

### src/oida/protocols/modbus/mixins/sunspec.py:70 — garbled auto-refactored debug log strings + standalone logging module usage
Debug calls emit the source line as the message
(`f"with open(json_file, r) as f:: {e}"`; validate_maps.py:834,890), and
sunspec.py creates a module-level stdlib logger (lines 28,30 used at 70,167) in
module-level helpers with no `self`. Clean up message text; flagged for the
logging-contract consistency (these helpers have no `self` so are partially
exempt). *(Consolidated: the two modbus log-quality/logging findings.)*

### src/oida/protocols/mqtt/mixins/auth.py:53-56 — plaintext password echoed into debug logs during single-credential test
`_test_credentials` logs `pass='{password}'` and `{username}:{password} -> ...`,
while the brute-force finding masks the secret (`{user}:***`); every brute
candidate's cleartext password lands in the debug stream. Mask consistently.

### src/oida/protocols/mqtt/scanner.py:479-484 — three conflicting defaults for timeout (10 / 5 / 2)
`protocol_options` says 10, `__init__`/`connect` fall back to 5, the real CLI
default is 2 (add_network_options not overridden). Root of the short
enumeration/listen windows. Pick one default via `add_network_options(
default_timeout=...)` and align the description + fallbacks.

### src/oida/protocols/mqtt/nxc_connection.py:185-190 — anonymous-access finding reported up to four times for one broker
`print_host_info`, `_test_anonymous_auth` (a `report_vulnerability` + a
`security_finding`), and `_analyze_security` all surface the same fact;
duplicated banner and overlapping result entries. Consolidate ownership into
`_analyze_security`.

### src/oida/protocols/ocpp/scanner.py:256-280 — event loop left open after a failed connect()
`connect()`'s finally sets `self._event_loop = loop` even on failure; the outer
except returns None, `self.conn` stays None so `cleanup()` skips `disconnect()`
(the only place that closes `_event_loop`). Every unreachable host in a sweep
leaks an open loop. Close `loop` in the except and only assign `_event_loop` on
success.

### src/oida/protocols/ocpp/proto_args.py:108-159 — four CLI options defined but never read (--ws-path, --firmware-info, --vendor, --model)
`--firmware-info` promises BootNotification firmware gathering but does nothing;
`--vendor`/`--model` are ignored ('SecurityAudit'/'OIDA-Scanner' hardcoded);
`--ws-path` unused. Implement or remove (at minimum `--firmware-info`).

### src/oida/protocols/ocpp/scanner.py:163-169 — auto version negotiation never offers OCPP 2.1
`_get_subprotocols()` returns `['ocpp2.0.1','ocpp1.6']` for `auto`, omitting
`ocpp2.1` though 2.1 is supported/advertised; a 2.1-only charger fails
negotiation under default auto. Add `'ocpp2.1'` (newest-first).

### src/oida/protocols/ocpp/__init__.py:261-308 — -s --confirm fires the most destructive 2.0.1 probes (rogue-CA install, CSMS redirect, WS hijack) in one shot
`_dispatch_security_probes` runs the full list including `test_install_cert`,
`test_network_profile`, `test_ssrf_extended`, `test_ws_hijack` under one switch.
Probes attempt cleanup and `--confirm` is enforced, so by-design — but consider
gating the most invasive subset behind an extra `--aggressive` flag.

### src/oida/protocols/opcua/mixins/writes.py:78-82 — _convert_value does not range-check integer/byte types, silently wraps on write
Every int/byte width maps to bare `int(value_str)` with no bounds check; a
`--write-value 99999` into a UA Byte node either raises deep in encoding or
encodes mod 2ⁿ silently — a footgun on a `--confirm`-gated live write. Validate
against the target width before `write_value`.

### src/oida/protocols/opcua/mixins/history.py:36-53 — --history-start/--history-end accept naive datetimes compared against UTC-aware default
`fromisoformat` yields naive datetimes; mixing with the UTC-aware default in
`read_raw_history` raises `TypeError` or sends a wrong-offset timestamp,
surfaced only as a generic error. Normalize parsed times to UTC-aware (assume UTC
when no offset).

### src/oida/protocols/opcua/nxc_connection.py:230-233 — __import__('asyncua.ua', ...) inline import instead of the lazy ua accessor
`_configure_secure_channel` uses a raw `__import__` + `getattr` on operator-
controlled `requested_mode`, bypassing the `_get_ua_module()` lazy path and the
test-patching seam. Use `ua_mod = _get_ua_module(); getattr(ua_mod.
MessageSecurityMode, requested_mode)` and validate `requested_mode`.

### src/oida/protocols/pcap/scanner.py:66-70,120,169 — full pcap file path leaks engagement context into JSON export and screen output
`results['pcap_file']` / `statistics['pcap_file']` and the screen line echo the
raw caller path (e.g. `/home/pentester/clients/acmecorp/internal-capture.pcap`),
disclosing filesystem layout and client name to screen and a shareable JSON
artifact. `utils/login_scanner.format_wordlist_source` exists for exactly this.
Route display + the JSON value through it (basename); keep the full path for the
actual file open. *(MEDIUM in source; calibrated to LOW — operator-supplied path,
not remote data, but inconsistent with the module's own privacy contract.)*

### src/oida/protocols/pcap/scanner.py:515-583 — unguarded per-listener harvest loop lets one protocol's failure abort all others' results
The harvest loop (`_collect_credentials`/`_collect_hashes`/`harvest`) has no
per-iteration try/except, unlike the feed_packet loop above it; one listener
raising aborts harvest/export and the device-merge for EVERY protocol, losing
already-extracted credentials. Wrap the loop body (and the device-merge loop at
661) in try/except with a debug log. *(MEDIUM in source; calibrated to LOW —
backs all 109 listeners but requires a buggy listener to trigger.)*

### src/oida/pcap/passive/pyshark_base.py:413,575,594 — copy-paste debug messages use source code as the log text
`self.logger.debug(f"if hasattr(packet, tcp):: {e}")` etc. in get_port_info /
get_flow_id / get_stream_id. Replace with operation-named messages.

### src/oida/protocols/pcap/scanner.py:768-784 — --hashcat ignores -o/--output and always prints to stdout
`_export_hashcat` reads `self.args.get("output_dir")` but the CLI dest is
`output`; no code sets `output_dir` for pcap, so `oida pcap capture.pcap
--hashcat -o results` dumps hashes to the console instead of results/hashcat.txt.
The sibling `_write_asset_files` correctly checks `get("output") or
get("output_dir")`. Mirror it. *(MEDIUM in source.)*

### src/oida/protocols/pcap/scanner.py:468-505 — truncated-pcap re-raise discards all already-harvested listener intel
A mid-iteration tshark "cut short" crash re-raises before the harvest/export
block, so credentials/interactions extracted from the valid prefix are lost (the
close()-time truncation path is handled gracefully). For a forensics tool on
partial/rotated captures this is a meaningful loss. On the is_truncated branch,
fall through to harvesting instead of raising. *(MEDIUM in source.)*

### src/oida/protocols/pcap/scanner.py:176-177 — -e/--extract-all functionally identical to -E/--extract-files
`-e` only does `setdefault("extract_files", True)`; help implies a superset that
doesn't exist. Collapse the flags or make `-e` genuinely enable every extraction
sub-flag.

### src/oida/protocols/pcap/scanner.py:162-164 — device serialization drops legitimate falsy values (0 / False)
`{k: v for ... if v is not None and v != [] and v != ""}` filters out integer 0 /
boolean False (e.g. unit id 0, `secure=False`) because `0 == False == 0.0`
(repeated at 963, 1044-1046). Use `v not in (None, "", [], {}, ())`.

### src/oida/protocols/profinet/gsdml_parser.py:10-13 — GSDML parser silently falls back to non-hardened xml.etree if defusedxml absent
`--gsdml FILE` (possibly attacker-supplied) is parsed with the stdlib parser when
defusedxml is missing, silently disabling XXE/billion-laughs protection.
defusedxml ships in the same extra, so unlikely — but drop the fallback (hard-
fail) or warn when stdlib is used.

### src/oida/protocols/profinet/proto_args.py:99-107 — -p/--rpc-port (default 34964) parsed but never used to connect
No code reads `rpc_port`; the endpoint comes from the DCP/mock description and
`default_port = 0`. `-p 12345` has no effect. Remove or thread into RPCCon.

### src/oida/protocols/profinet/proto_args.py:268-272 — -i short flag reused for --set-ip instead of project-standard interface meaning
`--set-ip` binds `-i`; the convention reserves `-i` for interface. No argparse
conflict (interface is positional for profinet) but cross-protocol-surprising for
a destructive write op. Drop the short form or pick another letter.

### src/oida/protocols/snap7/proto_args.py:264-268 — --test-write parsed but never wired to any action
`--test-write` and `_test_write_access()` exist but `test_write` is absent from
`_has_action`/dispatch; `oida s7 HOST --test-write` falls through to a normal
scan. Wire it (gated by `--confirm`) or remove. *(Same dead-write-flag class as
MMS/tase2.)*

### src/oida/protocols/snap7/proto_args.py:75-90 — --connection-type and --pdu-size parsed but never consumed
`-C/--connection-type` and `-N/--pdu-size` are never read; the connection uses
snap7 defaults. `-C OP -N 960` changes nothing. Plumb into
`set_connection_type()`/`set_param()` or drop.

### src/oida/protocols/snap7/mixins/memory.py:118-131 — -T/--test-memory-areas never reports writable areas (scanner defaults read_only=True)
The write-back probe runs only `if not self.read_only`, but snap7 exposes no
read-only/write toggle, so `area_info['writable']` is always False and the
WRITABLE finding is unreachable from `-T` (only --audit detects it). Document or
gate the probe on `--confirm`.

### src/oida/protocols/snap7/mixins/block_operations.py:438-474,601-620 — dead public methods get_order_code_action, get_cp_info, get_pdu_length
Implemented but never reached from the CLI (not in `_has_action`/dispatch, not
exported/tested); `info_action` inlines its own logic. `get_order_code_action`
even references a non-existent `Code` fallback. Remove or wire to flags.

### src/oida/protocols/snmp/mixins/host_enumeration.py:1 — host_enumeration.py exceeds 1000-line guideline (1749 lines)
Cleanly groups into network/host-resource/Windows/credential/IPv6 concerns
sharing only `_walk_table`. Split into sibling mixins without changing the public
surface.

---

## INFO

### src/oida/connection.py:44-135, src/oida/utils/export_utils.py:77 — no central --confirm enforcement at the framework layer
Design/hardening recommendation (the root cause of the per-protocol `--confirm`
findings). `add_common_args()` defines no `--confirm` and `connection` provides no
gating hook; each protocol re-implements its own `getattr(args, 'confirm',
False)`. Add `--confirm` to `add_common_args` and a `self.require_confirm(action)`
helper. Verify against RELEASE_TODO 3.3/4.2 before acting.

### src/oida/cli.py:181-182 — config-merge equality test can mis-classify a user value identical to the default
`merge_config_with_args` infers "was it set" from `current ==
defaults.get(attr)`, so an explicit CLI value equal to the default lets the config
file win — inverting the documented CLI-precedence contract for that one case.
Edge case; the docstring acknowledges the trade-off. A robust fix tracks which
dests actually fired on argv.

### src/oida/utils/login_scanner.py:24-51 — format_wordlist_source() exists but several protocol callers still log full wordlist/credential file paths
`bacnet/mixins/security.py:300`, `snap7/mixins/security.py:226`,
`fhir/mixins/security.py:268` interpolate the raw path into display output,
leaking the operator's filesystem layout / client name. Wrap each interpolated
path in `format_wordlist_source()` at the display call (keep the full path for
the file open).

### src/oida/protocols/ads/nxc_connection.py:709-723 — --memory-read size is unbounded; allocates a ctypes buffer of that size
`int(parts[2], 0)` with no upper bound passed to `_read_raw` (allocates
`ctypes.c_byte * size`); a typo like `0xFFFFFFFF` attempts a 4 GB allocation
before any I/O. Operator-supplied/read-only, but add a sane cap (as `_read_file`
already has a 100 MB cap).

### src/oida/protocols/astm/nxc_connection.py:244-276 — _receive_server_response can over-merge frames and only ACKs after STX
The 1024-byte read loop treats the whole buffer as one frame and only ACKs inside
the STX branch, so multi-frame analyzer responses aren't individually ACKed —
can stall a strict analyzer that waits per-frame. Bounded by timeouts. Benign for
fingerprinting.

### src/oida/protocols/can/mixins/xcp.py:94-118 — --xcp-scan / --ccp-scan flood the full ID/station range like --id-scan but are not --confirm-gated
`--id-scan` is confirm-gated for bus load; `scan_xcp` (0x000-0x7FF CONNECT) and
`scan_ccp` (0-255 stations) are comparable load but ungated. CONNECT is a
handshake (less state-changing). For parity, gate both or document the exemption.

### src/oida/protocols/coap/scanner.py:487 — redundant exception tuple + non-standard short flag -cf
`except (asyncio.TimeoutError, Exception)` is redundant (collapse to `except
Exception`); `-cf` (proto_args.py:191-194) is a two-char short flag inconsistent
with the single-char convention. Drop the `-cf` alias.

### src/oida/protocols/dicom/nxc_connection.py:456 — dead getattr default: called_aet fallback 'ANY' never used; real default 'ANY-SCP'
`getattr(self.args, 'called_aet', 'ANY')` but `--called-aet` defaults 'ANY-SCP';
the 'ANY' fallback is dead and misleading. Drop or align.

### src/oida/protocols/discovery/ssdp.py:16-23 — script-flagged "CRITICAL fallback import" is an intentional hard-fail (false positive)
The try/except ImportError re-raises with an install message making defusedxml a
hard dependency (documented in CHANGELOG as an XXE-closing fix). Also: base.py:17
`from logging import DEBUG as _DEBUG` (level constant only) and core.py:853
("Print interface status" in a docstring) are script false positives. Do not
action.

### src/oida/protocols/ethercat/eeprom_ops.py:172-181 — EEPROM dump aborts the entire 128-word read on the first word-read exception
`_dump_full_eeprom()` and `_parse_eeprom_esi()` (257-262) `break` on any read
exception, conflating "reached end of device" with "one read failed" — a flaky
bus yields a quietly short dump. Consider continuing past a single failure or
recording the failed address. Best-effort diagnostic output.

### src/oida/protocols/fhir/proto_args.py:67-71 — script-reported missing CLI options (--port, --output, --confirm) are false positives
`--port` is intentionally absent (FHIR targets are URLs); `--output`/`--confirm`
come from the shared factory parents. The 4 Bandit hits (B105/B106 on True/True
dict values, a test token, a help string) are also false positives.

### src/oida/protocols/fhir/mixins/search.py:153-160 — heuristic ">10 patients = unrestricted access" magic threshold may mislead on small datasets
Bare `10` conflates large result set with broken access control; an authorized
token routinely returns >10. Name the threshold and gate the finding on the
absence of supplied auth.

### src/oida/protocols/goose/__init__.py:346 — AppID help/example implies decimal but capture display prints hex
`--appid 1000` (decimal) is shown as `0x03E8`, which can read as a
misinterpretation. Note in help that `--appid` is decimal (or accept 0x input).

### src/oida/protocols/hart/hartip.py:32-103 — script-flagged CRITICALs are pre-accepted / false positives
The hartip.py:32 fallback import is the intentional "honest import" (CHANGELOG);
coverage 25% is a measurement artifact (82 tests pass); Bandit B105 at
security.py:139 ('(already unlocked)') is a status sentinel; --timeout/--output
"missing" come from the shared parent parser. Do not action.

### src/oida/protocols/hl7/segments.py:21-28, utils.py:17-20 — two try/except ImportError fallback imports flagged by the gate (accepted design)
CHANGELOG records HL7's "honest import" design; `__init__.py` gates the module
behind the lazy_import availability check and these leaf modules surface a clear
ImportError for transitive paths. To make the gate pass cleanly, route through
the lazy_import wrapper or add a suppression. *(MEDIUM in source; downgraded —
known/accepted, not a latent bug.)*

### src/oida/protocols/hl7/segments.py:1-2042 — segments.py is 2042 lines, over the 1000-line split threshold
Builder + parser logic (not a data table). Split into segments/builder.py and
segments/parser.py. __init__.py (932) and proto_args.py (931) are under the hard
limit.

### src/oida/protocols/hl7/__init__.py:304-314 — --hl7-version 2.5 silently discarded when a server version was auto-detected
`_get_version()` treats the literal default '2.5' as "unset"
(`user_version != "2.5"`), so an explicit `--hl7-version 2.5` against a server
advertising 2.7 is dropped in favor of detection. Set the argparse default to
None and treat None as "fall through". *(LOW in source; batched.)*

### src/oida/protocols/hl7/mixins/financial.py:208 — DFT FT1 transaction description populated from transaction_code (copy-paste)
`transaction_description=getattr(self.args, "transaction_code", ...)` reads the
code arg, not a description. Cosmetic (confirm-gated test message). Add a real
description arg or hardcode the literal default.

### src/oida/protocols/hl7/proto_args.py — add_common_args/--output reported missing by the CLI-options gate (false positive)
proto_args composes modular helpers rather than `add_common_args()`;
`_export_results()` reads `output`/`format`. No action; confirm consistency with
the other 25 protocols if desired.

### src/oida/protocols/knx (module-wide) — review-script headline "coverage 19% CRITICAL" is a framework-wide measurement artifact, not a KNX defect
547 KNX tests pass; 19% is whole-tree coverage during the KNX run. Fallback/print/
global all clean; 3 Bandit are Low/benign or false positives. The only
substantive KNX bug is the security.py `resp.data` HIGH. *(Also subsumes the
parallel Layer-1/Layer-2 divergence note at nxc_connection.py:5, an accepted
documented refactor target.)*

### src/oida/protocols/modbus/device_db.py:44 — script CRITICALs (global keyword, 40% coverage) are calibrated false-criticals
`global _device_db` is a load-once memoization of a read-only JSON DB (idempotent,
no mutable shared scan state) — cosmetic linter hit. 40% is aggregate tree
coverage dominated by offline map tooling. Bandit B311 (fuzzer random), E402
(lazy_import pattern), and custom file writes (map tooling / explicit
--save-response paths) are all acceptable.

### src/oida/protocols/mms/__init__.py:241 — script reports 3 CRITICALs; 2 false positives, 1 real
The 2 "print()" CRITICALs match the substring inside `self._report_fingerprint(`
(no real print calls); the "missing --port/--timeout/--output" warnings are
factory-helper false positives. Genuine: coverage 32% (tests out of scope).

### src/oida/protocols/opcua/mixins/discovery.py:7-9 — module-level logger in discovery/browse/security mixins instead of self.logger
Inconsistent within the same files (some handlers use `self.logger.debug`,
adjacent ones the module logger), splitting debug output across two channels.
Standardize on `self.logger.debug` inside instance methods.

### src/oida/protocols/opcua/nxc_connection.py:356-388 — --dump-namespaces mutual-exclusivity not actually enforced
`dump_namespaces` isn't in `dump_mode_map`, so `--dump-namespaces --dump` runs
namespaces AND the fast dump, and `--dump-history --dump` runs whichever appears
first in dict order — contradicting the per-flag help and the "Mutually
exclusive" comment. Make exclusivity explicit (argparse group) or document that
namespace dump co-runs. *(MEDIUM in source; calibrated INFO — confusing dispatch,
not data loss.)*

### src/oida/protocols/opcua/mixins/credentials.py:70-93 — plaintext discovered passwords written into results dict / JSON export
`brute_force.valid` stores `{username, password}` cleartext and
`security_finding(... {username}:{password})` prints it; L1 scanner does the same.
Surfacing recovered creds is an accepted cross-protocol norm, but mask the
password in the human-facing finding/display line (the adjacent debug lines
already use `:***`) and rely on the structured record. *(This is the same class
as the cli.py export-redaction HIGH; the framework-level fix there covers the
on-disk leak.)*

### src/oida/protocols/profinet/mixins/enumeration.py:139-147 — --enum-range with start > end silently scans nothing
Transposed bounds produce an empty `range()` and report zero probes with no
error, looking like the device exposed nothing. Add a `start > end` guard with a
`self.logger.fail`.

### src/oida/protocols/snmp/constants.py:614 — script eval/exec CRITICAL is a verified false positive
A precise grep finds only the comment `# exec(1) or shell(2)` and the identifiers
`_v3_observer(... execpoint ...)` / `exec_type` — no `eval`/`exec` builtin calls.
The "missing 2 CLI options" warning is a heuristic miss (`add_network_options`
supplies --port/--timeout). Optionally rename the comment to stop tripping the
linter.

---

## Cross-cutting themes (for triage planning)

- **Concurrency / shared mutable global state** (HIGH ics_logger findings + LOW
  export_utils `_config`/`_mac_parser`/`_cli_instance` + MEDIUM shallow-copy
  args): the framework reuses process-global state across ThreadPoolExecutor
  workers in several places. A single audit of "what mutable state is shared
  across the per-target fan-out" would close ics_logger, export_utils, and the
  Namespace shallow-copy findings together. Note: the dedicated
  `utils/ics_logger.py:168-192` shared-cached-`ICSLogger` finding (raised by
  ~5 reviewers, the top blast-radius item) is the root of this theme — see the
  Summary's #1 highest-blast-radius entry; fix it once at the cache layer.
- **`--confirm` enforcement** (1 framework root cause + ~10 per-protocol
  instances across modbus, ethercat, ethernetip, bacnet, hart, snmp, iec104,
  can, mms, ads, tase2): implement the central `require_confirm()` helper first,
  then the per-protocol fixes become one-line conversions.
- **Dead / inert CLI flags** (1 framework gap + ~25 instances): a tree-wide pass
  asserting "every declared arg is read somewhere" would surface all of these
  mechanically (hart 11, ocpp 4, mms 4, snap7 4, can, dnp3, profinet, mqtt,
  ethercat, iec104).
- **`--tls` wrong-port / no-verify** (astm, dicom, dnp3, coap-DTLS): a shared
  helper that (a) switches to the TLS default port when `--tls` and no explicit
  `--port`, and (b) actually threads `--tls-ca`/`--tls-insecure` into the SSL
  context would fix the class.
- **Copy-paste debug log messages** (source-line-as-message): goose, hart, mms,
  modbus, pcap/pyshark_base — all artifacts of an automated except-body rewrite;
  a mechanical sweep for `logger.debug(f"<code fragment>: {e}")` finds them all.

## Areas with zero findings

None. Every reviewed area produced at least one finding (the lowest-yield areas
were the framework `targets.py` and `__main__.py`, which surfaced only as part of
the cli.py / connection.py framework findings rather than standalone issues).
The tase2 module review was truncated in the source feed, so its coverage here is
partial and should be re-run.
