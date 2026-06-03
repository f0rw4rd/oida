# OIDA Code Review (workflow code-review-full / aggregated)

## Summary

- **Areas reviewed:** 46 parallel reviewers across framework layer (cli/loader/connection/targets), utils (login_scanner, ics_logger, base_scanner, lazy_import, proto_args_factory, socket_helpers, serial_detection, protocol_helpers, etc.), pcap/passive pipeline, and 20+ protocol modules (ads, astm, bacnet, can, coap, dicom, discovery, dnp3, ethercat, ethernetip, fhir, goose, hart, hl7, iec104, knx, mms, modbus + portions of more).
- **Findings (raw → post-dedup):** 410 raw → ~135 distinct findings after cross-reviewer dedup (notably for `format_wordlist_source` leaks, `slave=`/`device_id=` pymodbus migration, garbled refactor-artefact debug strings, `is None == success` BACnet pattern, dead/phantom CLI flags, and `--confirm` gate inconsistencies, each of which surfaced from multiple reviewers).
- **Breakdown by severity:** CRITICAL 6 · HIGH 23 · MEDIUM 35 · LOW 53 · INFO 4.
- **Status:** FAIL — multiple CRITICAL correctness/security failures across modbus, coap, dicom, hl7, knx, and the discovery refactor; HIGH-severity false-positive security findings in BACnet that will pollute every customer report; HIGH-severity credential/path leaks throughout the logging surface.

**Highest-blast-radius findings (top 5):**
- *(framework)* `merge_config_with_args` discards every config-file value whose argparse default is non-None — `format`, `threads`, `timeout`, `verbose`, `output`, etc. silently fall back to CLI defaults regardless of YAML/JSON config. Defeats the entire `-c/--config` feature.
- *(framework)* `cli.py:974` debug-logs the entire argparse `Namespace`, leaking `--password`, `--credentials`, `--wordlist`, TLS keys, OCPP tokens, etc. into stdout and the structured JSON audit log.
- *(framework)* `login_scanner.py:215` logs every failed `username:password` at INFO; wordlist contents end up in the audit log that operators often share back to clients.
- *(modbus)* pymodbus 3.12 removed the `slave=` kwarg; many call sites in `register_io.py`, NXC mixins, fuzz, and writes still pass `slave=`. Every scan/monitor/fuzz/test-write/map-read path crashes at runtime.
- *(bacnet)* `_is_success_response` treats UDP timeouts as success for confirmed services (DCC brute-force, ReinitializeDevice, TimeSync, OOS-writable, BBMD foreign-device injection). On any noisy/filtered network, the first candidate is reported as a CRITICAL vulnerability and brute-force terminates. Pollutes every BACnet engagement report with false-positive criticals.

---

## CRITICAL

### src/oida/protocols/coap/nxc_connection.py:285-294 — `--methods` fires PUT/POST/DELETE/PATCH/IPATCH on every discovered resource without `--confirm`
The `_execute_features` dispatcher gates `--methods` only on the flag's presence; never checks `--confirm`. Once triggered, `_test_methods` iterates `[GET, PUT, POST, DELETE, FETCH, PATCH, IPATCH]` against every resource discovered via `/.well-known/core`. DELETE can wipe live actuator/sensor state. The `proto_args.py` group header at line 153 declares write methods as `--confirm`-gated and the example at line 29 shows `-M --confirm`, so the intent was clearly to require confirmation. The implementation forgot the check.
**Fix:** mirror the pattern used a few lines below for `--put` etc.; or restrict the methods list to safe verbs when `--confirm` absent.

### src/oida/protocols/coap/nxc_connection.py:504,571 — Write helpers and wordlist prober hard-code `coap://`, bypassing DTLS
Both `_probe_paths_wordlist` and `_do_write` build URIs with literal `"coap://%s:%s%s"`. If the user established DTLS (`--dtls-cert`, `--dtls-rpk`, `--psk`, `-D`), every other code path uses `f"{self._scheme}://..."` correctly. The consequence: `oida coap host -D -P key --put /actuator/led 1 --confirm` sends the PUT unencrypted on UDP/5683 instead of over the negotiated DTLS context on UDP/5684. Payload (which may itself carry credentials) leaks in cleartext.
**Fix:** use `f"{self.scanner._scheme}://..."` in both locations; add a DTLS-active write test.

### src/oida/protocols/dicom/mixins/reporting.py:312 — Broken relative-import depth in `_export_results`
`from ...utils.export_utils import export_data` (3 dots) resolves to non-existent `oida.protocols.utils.export_utils`. Sibling import on line 22 of `enumeration.py` correctly uses 4 dots. Every `oida dicom <host> -o results` invocation raises `ModuleNotFoundError` late in `proto_flow()`, after a successful scan.
**Fix:** change to `from ....utils.export_utils import export_data`. Add a regression test that runs `proto_flow()` with `-o /tmp/x`.

### src/oida/protocols/hl7/mixins/probe.py:15-49 — `--probe-ops` sends dangerous write messages without `--confirm`
`_probe_operations()` iterates every type returned by `_get_fuzz_message_types()` and sends each via `_send_mllp_message`. The list includes ADT^A40 (patient merge), ADT^A03 (discharge), ORM^O01 (lab order), RDE/RAS/RGV/RDS^O17/O15/O13 (pharmacy administer/give/dispense), BAR^P01 (billing account), DFT^P03 (financial transaction), MFN^M01/02/04 (master-file modification). Every other `_send_*` handler in this module rejects these without `--confirm`; probe has no gate. A permissive HL7 server processes them — creating fake admits, discharges, merges, bills, and medication records during what help text describes as "Probe supported message types".
**Fix:** filter to read-only message types (QRY/QBP/MFQ/ACK), or gate dangerous half behind `--confirm` with clear warning.

### src/oida/protocols/hl7/mixins/master_file.py:87-134, src/oida/protocols/hl7/mixins/financial.py:154-215 — MFN/BAR/DFT call non-existent `SegmentBuilder` methods → silent fallback to generic test messages
`HL7SegmentBuilder` only defines builders for pid/pv1/obx/obr/orc/sch/txa/rxo/rxe/rxa/rxd/rxg/dg1/pr1/mrg. Mixins invoke `build_mfi`, `build_mfe`, `build_stf`, `build_pra`, `build_prc`, `build_gt1`, `build_in1`, `build_ft1` — none exist. Each raises `AttributeError`, swallowed by `try/except Exception`; control falls through to `_create_test_message(...)` producing a generic ADT-shaped stub. Every documented invocation of `--send-mfn`, `--send-bar`, `--send-dft` sends a useless minimal message; resulting security findings are also wrong (ack-handling marks `Billing Account Creation Accepted` based on an ACK to an ADT).
**Fix:** implement missing builders in `segments.py`, or replace each call with raw `Segment("…")` construction (mirror QPD/RCP in special_query.py).

### src/oida/protocols/knx/mixins/properties.py:130 — Wrong relative-import depth in `_fuzz_property` (`ModuleNotFoundError` on every invocation)
`from ...utils.fuzzer import fuzz` resolves to `oida.protocols.utils.fuzzer` (does not exist; actual module at `oida.utils.fuzzer`). Sibling imports at file top correctly use 4 dots. Every `--fuzz-property` invocation raises immediately; outer `try` reports `Error fuzzing property: No module named 'oida.protocols.utils'`. Feature is entirely broken in shipped code.
**Fix:** `from ....utils.fuzzer import fuzz`. Consider hoisting to module top.

### src/oida/protocols/modbus/{register_io.py, nxc_connection.py, mixins/read_write.py, mixins/writes.py, mixins/fuzz.py} — pymodbus 3.12 `slave=` → `device_id=` migration incomplete; many runtime paths crash
pyproject.toml pins `pymodbus>=3.12.0`; 3.12 made the device-id kwarg keyword-only as `device_id=` — old `slave=` removed. Scanner mixins (write_ops, identification, discovery, file_ops, diagnostics, comm_events, custom_fc) already migrated; the NXC-side, register_io batched reader, writes, and fuzz still pass `slave=`. Every call routed through `read_registers_batched` (scan, monitor, fuzz, test-write, map read; SunSpec block reads route through it too) and every map-read/write/broadcast/fuzz hits this. Test `test_writable_access_security_finding` (test_modbus_integration.py:1152) literally documents the regression and weakens its assertion as a band-aid.
**Fix:** rename all `slave=` to `device_id=`; update mock-call assertions in `tests/unit/modbus/test_register_io.py` and `test_scanner_batched_reads.py`.

### src/oida/protocols/modbus/scanner_mixins/custom_fc.py:23 — `send_custom_fc()` requires `unit_id`; every caller omits it (--raw-fc / --enumerate-functions / --fuzz function-mode crash)
Signature is `send_custom_fc(self, client, fc, payload, unit_id)`. Callers in `mixins/raw_function_codes.py:42,132` and `mixins/fuzz.py:153` pass three args. `TypeError: send_custom_fc() missing 1 required positional argument: 'unit_id'`. No test coverage (raw_function_codes.py 42%, fuzz.py 8%).
**Fix:** pass `self.scanner.unit_id` (or `getattr(self.args, 'unit_id', 1)`); or make `unit_id` keyword default 1.

### src/oida/protocols/modbus/mixins/raw_function_codes.py:47-58,135-141; src/oida/protocols/modbus/mixins/fuzz.py:156-160 — Handlers read keys `send_custom_fc` never returns
`send_custom_fc` returns `{is_exception, exception_code, exception_name, response_payload, ...}`. Handlers consume `result.get('exception')` (always False; branch never fires) and `result.get('data')` (always None/empty). Exceptions silently rendered as success in `--raw-fc`; fuzz output is *inverted* — every success treated as 'unsupported', every exception treated as 'supported'.
**Fix:** rename consumer keys to match `is_exception` / `response_payload`, or rewrite `send_custom_fc` return shape.

### src/oida/protocols/modbus/mixins/canopen.py:34,68,140 — CANopen MEI handlers call non-existent `self.scanner._send_mei_canopen()`
`_handle_canopen_info`, `_handle_canopen_read`, `_handle_canopen_write` all dispatch through `self.scanner._send_mei_canopen(self.conn, request_data)`. Repo-wide grep finds zero definitions. Every CiA-309-2 flag (`--canopen-info`, `--canopen-read`, `--canopen-write`) raises `AttributeError`. Entire CANopen MEI feature documented in `-h` is non-functional. `--canopen-write` also clears `--confirm` gate before reaching the broken call — latent footgun.
**Fix:** implement the missing scanner helper (build MEI Type 13 frame via `client.execute()` with custom PDU, mirroring `send_custom_fc`); or hide the CLI group + warn at parse time.

---

## HIGH

### src/oida/cli.py:107-121 — `merge_config_with_args` ignores config-file values whenever argparse default is non-None
Only writes a config-file value when attribute does not exist OR is None. Global parser sets concrete defaults for nearly every common flag: `--verbose=0`, `--threads=10`, `--timeout=5`, `--debug/--quiet/--full-width=False`, `--format=console`. None of those compare equal to None, so YAML/JSON config values for `threads`/`timeout`/`verbose`/`debug`/`quiet`/`format` are silently discarded. Privacy hazard: operator sets `format: json` and `output: /tmp/engagement-acme` in config to avoid stdout mass-print; results still dump to console because `args.format == 'console'` by default.
**Fix:** compare against `parser.get_default(attr_name)` (or use SUPPRESS sentinel) so values matching parser default are treated as "not set on command line".

### src/oida/cli.py:974 — `cli.py` debug-logs the entire argparse `Namespace` including credentials, TLS keys, and wordlist paths
`logger.debug("CLI args: %s", vars(args))` writes the entire parsed namespace — including `--password`, `--credentials`, `--wordlist`, `--knxproj-password`, `--tls-key`, OCPP API tokens — to debug. With `--debug` enabled (common during engagements), every secret on the command line ends up in the structured JSON log and console. Framework-level bypass of `format_wordlist_source` and of operator expectation that the JSON log can be shared.
**Fix:** filter `vars(args)` through redaction allowlist (mask keys matching `*password*`, `*secret*`, `*token*`, `*key*`; shorten wordlist/credentials paths to basenames) before logging; or only dump keys (no values) at debug.

### src/oida/connection.py:149-164, 355-376 — `_resolve_host` and `NetworkConnection.test_connection` are IPv4-only despite IPv6 target support
`targets.py` advertises and implements IPv6 parsing (CIDR, `[::1]-[::ff]` ranges, hostnames). `_resolve_host` calls `socket.gethostbyname(host)` (A records only); AAAA-only hostnames silently "fail to resolve" and the raw string is fed back. `test_connection` hardcodes `socket.AF_INET`; IPv6 self.ip raises `socket.gaierror` in connect_ex, swallowed by bare `except Exception`, returns False → every IPv6 probe appears closed.
**Fix:** use `socket.getaddrinfo(host, None)` and `socket.create_connection((self.ip, port), timeout=...)`. Inherited by every Layer-2 protocol → framework-wide impact.

### src/oida/connection.py:349-353 — `NetworkConnection` only copies `args` when port is unset; user-supplied `-p` still leaks across protocols
Defensive copy is conditional on the port being unset. If operator passes `-p`, or any earlier protocol wrote `args.port`, the branch is skipped and `self.args` is the SAME Namespace the next protocol will receive. Not theoretical: `src/oida/protocols/hl7/__init__.py:336-344` does eight writebacks on `self.args` (`enum_providers`, `enum_apps`, ..., `extract_response`); with `-p` set these mutations escape into the caller Namespace and contaminate any follow-up protocol invocation in a multi-protocol dispatcher run.
**Fix:** always `args = copy.copy(args)` (or `deepcopy` for nested) at the top of `connection.__init__`, regardless of `default_port`.

### src/oida/protocols/ads/proto_args.py:475 — `--scan-coe` gated behind `--confirm` contradicts its read-only documentation
`_CONFIRM_REQUIRED_FLAGS` lists `scan_coe`, so `validate_args()` raises `ConfigurationError` unless `--confirm` is set. But `--scan-coe`'s help text is `"Scan CoE object dictionary on EtherCAT slaves (via ADS bridge)"` with no mention of `--confirm`, and the underlying `_scan_coe_via_ads()` is called with `test_access=False` (read-only enumeration). The sibling `--scan-coe-access` correctly gates and advertises it. Other read-only EtherCAT scans (`--scan-soe`, `--scan-fsoe`, `--eeprom-dump`, `--esc-registers`) are NOT gated.
**Fix:** remove `"scan_coe": "--scan-coe"` from `_CONFIRM_REQUIRED_FLAGS`.

### src/oida/protocols/bacnet/mixins/security.py:63-68 — Timeout treated as successful auth in DCC brute-force / test-dcc / test-reinit
`_is_success_response()` is `response is None or not isinstance(response, (ErrorPDU, Error, AbortPDU, RejectPDU))`. DCC and ReinitializeDevice are CONFIRMED services — `None` means timeout, not accepted password. On any minimally filtered network the very first password is reported as the working password and brute-force terminates. Produces false-positive CRITICAL findings in pentest reports.
**Fix:** separate timeout from success; only treat non-None reply as success for confirmed services.

### src/oida/protocols/bacnet/nxc_connection.py:459-460 — `--dump` and `--diff` silently produce empty output on bacpypes3 (raw / remote) path
`_async_raw_scan` dispatches `--dump`/`--diff` to `_handle_dump`/`_handle_diff` which call `_read_property` → `self.bacnet.read(...)`. In the raw / `--device-id` path, `self.bacnet` is never assigned (stays `None`), so every read raises `AttributeError`, swallowed by bare-Exception, returns `None`. Dump file written to disk containing only `{name: null, presentValue: null, ...}` per object, but CLI prints `Dump saved to ...` as if successful. `--diff` against saved baseline reports "no changes" for everything.
**Fix:** route `--dump`/`--diff` through the bacpypes3 RPM helpers on the raw path (or refuse the flag combo with a clear error); have `_read_property` log a fail when `self.bacnet` is None.

### src/oida/protocols/bacnet/mixins/network.py:438-449 — BBMD foreign-device-registration false positive on UDP packet loss
`_bacpypes3_test_bbmd_injection` runs `RegisterForeignDevice` over BVLC/UDP; on `response is None` warns CRITICAL "Foreign device registration ACCEPTED" and records `Foreign device registration accepted without authentication`. Same `is None == success` pattern at line 472 for WriteBroadcastDistributionTable. On UDP, `None` dominates when target is not a BBMD or upstream firewall drops the packet. Every non-BBMD target reported as a CRITICAL "BBMD injection accepted" vulnerability.
**Fix:** BVLC Register-Foreign-Device returns `BVLC-Result`; only treat `bvlciResultCode == 0` as accepted. Timeout → "no response (target may not be a BBMD)".

### src/oida/protocols/bacnet/nxc_connection.py:111-117 — BAC0 vs bacpypes3 dispatch misroutes 172.0.0.0/8 and feature-asymmetric
Two bugs: (1) `host.startswith('172.')` covers entire `172.0.0.0/8`; RFC1918 only reserves `172.16.0.0/12`. Public IPs like `172.32/217/65.x` (Google/Cloudflare) treated as "local", forcing BAC0 broadcast path. (2) Paths are not feature-equivalent: `_async_raw_scan` (bacpypes3) handles `vendor_scan`, `deep_enum`, `enum_programs`, `enum_loops`, `discover_mstp`, `rpm`, `read_range`, `cov`, `check_bacnet_sc`, `test_bbmd_injection`, `test_time_sync`, `test_oos`, `test_priority_writes`, `who_has`; none wired into `_async_proto_flow` (BAC0). User pointing at `192.168.1.100` with `--deep-enum` or `--vendor-scan` gets nothing.
**Fix:** use `ipaddress.ip_address(host).is_private`; unify on one path or dispatch missing helpers in `_async_proto_flow`.

### src/oida/protocols/can/nxc_connection.py:388-436 — `--id-scan` floods every standard CAN ID with TesterPresent; no `--confirm` gate
`_handle_id_scan` iterates full 0x000-0x7FF arbitration-ID range and injects ISO-TP TesterPresent on every ID. On a real automotive/industrial bus this is an active write racing real ECUs for arbitration, ~50% bus load for the scan duration, triggers TesterPresent semantics on any ECU using a non-standard request ID. Other destructive ops (`--uds-reset`, `--xcp-memory-read`, `--fuzz`) are `--confirm`-gated; `--id-scan` is louder than a single ECUReset.
**Fix:** add `--confirm` gate (or `--aggressive` flag).

### src/oida/protocols/coap/helpers.py:275-311 — `coap_get_blockwise` has no upper bound on assembled payload
Block2 reassembly loop is `while True:`, terminates only when server clears `more` bit. Malicious server can return blocks with `more=True` forever, growing in-process `bytearray` until OOM. No per-call timeout, no max-blocks counter, no max-bytes cap. `/.well-known/core` block-wise GET runs automatically against every CoAP target — reachable in default scans against attacker-controlled endpoint.
**Fix:** cap by total bytes (e.g. 4 MiB) and/or block count (e.g. 4096); bail with `truncated` status if exceeded.

### src/oida/protocols/dicom/nxc_connection.py:367-394 — Path traversal in C-GET/C-STORE via attacker-controlled `PatientID`/`SOPInstanceUID`
`_handle_store_for_cget` sanitizes via `Path(raw).name` which handles `/` and `\\` but not literal `..` (`Path('..').name == '..'`). Hostile DICOM responder controls returned UIDs; setting `PatientID='..'` and `StudyInstanceUID='..'` makes the handler `mkdir(parents=True, exist_ok=True)` and write a `.dcm` two directory levels above output dir. Scanner is victim (not target) — matters for hostile-target OT pentest scenarios.
**Fix:** reject names in `{'', '.', '..'}`; assert `resolved_path.is_relative_to(output_path)` before `save_as`/`mkdir`.

### src/oida/protocols/dicom/mixins/cfind.py:29,48 — `--find` with no `--patient-name` sends `PatientName=None` instead of wildcard
`proto_args.py:130` declares `--patient-name` with no `default=`. `_cfind_query()` does `patient_name = getattr(self.args, 'patient_name', '*')` — but the attribute exists set to `None`, so `'*'` fallback never fires; code then executes `ds.PatientName = None`. Documented `oida dicom <host> --find` example does NOT run a wildcard query; either errors or sends empty/null PatientName that many PACS reject. Wildcard security-finding (`if patient_name == '*'`) never trips.
**Fix:** set `default="*"` or normalize: `patient_name = getattr(self.args, 'patient_name', None) or '*'`. Sweep other `getattr(self.args, X, default)` sites with same issue.

### src/oida/protocols/discovery/{enrich,infra,core,ntp,stats,dhcp,fins}.py (21 sites) — Garbled exception-log messages from broken refactor
A regex refactor turned 21 `except ... as e: logger.debug(f"...: {e}")` sites into nonsense. Examples: `f"hostname, _, _  socket.gethostbyaddr(ip): {e}"` (enrich.py:211), `f"if len(data)  57:: {e}"` (enrich.py:338), `f"if isinstance(ref_id, bytes):: {e}"` (ntp.py:292), `f"if offset  2  len(data):: {e}"` (infra.py:1077), `f"for part in parts:: {e}"` (core.py:258), and 16 `f"Failed to get <localvar>: {e}"` where `<localvar>` is just an assignment target (latency, time_part, is_ipv6, hostname, decoded, id_str, netmask, clean, network, ts_str, src_port, flags_val). Doesn't crash (valid f-strings) but obliterates real error context. Full list:
- `enrich.py:74, 119, 124, 179, 211, 338`
- `dhcp.py:381`
- `infra.py:517, 634, 1077, 1372`
- `ntp.py:292`
- `core.py:258, 1369, 1377`
- `fins.py:154`
- `stats.py:413, 719, 726, 867, 876`
**Fix:** replace each with a meaningful contextual message (e.g. `logger.debug("NBSTAT response parse failed (len=%d): %s", len(data), e)`).

### src/oida/protocols/dnp3/mixins/file_transfer.py:524-558 — `--read-octet` ignores user-specified index range (reads ALL objects)
Parses `start_idx`/`end_idx` from `--read-octet 110:0-4` but then issues `master.ScanAllObjects(...)` fetching every octet-string object. Collected items not filtered by index before display. `validate_args` (proto_args.py:723-743) validates the range, so user believes bounds are honored. On outstations with large octet payloads, can pull megabytes of data the operator did not authorize.
**Fix:** swap to `ReadHeader`/`Range` reads (Group 110 with parsed range), or drop entries outside `[start_idx, end_idx]` before recording.

### src/oida/protocols/ethercat/__init__.py:482-488 — `UnboundLocalError` in `disconnect()` inner-except shadows outer exception
Outer `except Exception as e:` is shadowed by inner `except Exception as e:` — Python 3 rebinds and unbinds at end-of-block, so final `self.logger.debug(f"Error during EtherCAT cleanup: {e}")` raises `UnboundLocalError`. Swallowed by callers but masks real cleanup error and tags log as debug NameError.
**Fix:** rename inner variable (`except Exception as e2:`).

### src/oida/protocols/ethernetip/nxc_connection.py:163-169 — `cleanup()` calls `scanner.disconnect()` with no args; required `connection` parameter raises TypeError
`EtherNetIPScanner.disconnect(self, connection: Any)` requires `connection`. TypeError caught by broad `except Exception`, only debug-logged. pycomm3 driver's `connection.close()` never called from NXC path, cached `_pycomm3_driver` reference never cleared, and the pycomm3 logger level lowered to CRITICAL during `connect()` is never restored — the host process's `pycomm3` logger is permanently silenced after any NXC-flow scan. The CHANGELOG specifically claims this was fixed.
**Fix:** pass `self.conn` (`self.scanner.disconnect(self.conn)`) or change `disconnect`'s signature.

### src/oida/protocols/fhir/mixins/security.py:179-184 — Brute-force loop logs every failed `username:password` at INFO/display
Every 401/403 triggers `self.logger.display(f"Failed: {username}:{password}")`. Writes entire wordlist to stdout, scan logs, and any `--json-log`. 5000-line wordlist dumps every plaintext password into operator logs frequently shared via tickets/screenshots. Healthcare passwords leaking into incident reports is exactly the audit's target failure mode.
**Fix:** drop to `debug`, log running counter only; never display failed credential lines.

### src/oida/protocols/dicom/mixins/cfind.py:29,48 + src/oida/utils/login_scanner.py:147,151,212,215,223 — `login_scanner` logs every attempted password
`make_scanner()`/`make_password_scanner()` log every failed credential at debug (147, 151) and at info (`"Failed: {username}:{password}"`, 215). With `--json-log` (engagement default), every wordlist password ends up in the audit-log file that gets shared back to clients. Bypass of `format_wordlist_source` — that helper hides the path; this leaks the contents.
**Fix:** drop failed-attempt password from the message (log counter or hash); downgrade to debug-only with explicit opt-in flag. Successful credentials (138/212) are legitimate.

### src/oida/protocols/{coap,fhir,bacnet,knx,dicom}/... — `format_wordlist_source` helper exists but many call sites still emit raw wordlist/credentials paths
Helper exists exactly to strip engagement-sensitive paths like `/home/pentester/clients/acmecorp/internal-creds.txt`. Only `snap7`, `hart`, and one DICOM call use it. Unsanitised sites:
- `coap/nxc_connection.py:490, 493` (`Wordlist file not found: %s`, `Loaded %d paths from wordlist: %s`)
- `fhir/mixins/security.py:243, 257, 290` (`Loaded {len(usernames)} usernames from {user_file}`, etc.)
- `bacnet/mixins/security.py:241` (`Loaded {len(passwords)} passwords from {password_file}`)
- `knx/ets.py:353, 359` (`crack_knxproj: wordlist={wordlist}`, exception text containing path)
- `src/oida/utils/socket_helpers.py:80` (`Using client certificate: {tls_cert}`)
Each is `self.logger.display/info/warning/fail` → also written verbatim into structured JSON log via `ICSLogger._json_log`. Customer who receives the audit log gets operator's filesystem layout *and* often the previous client's name.
**Fix:** wrap each interpolation in `format_wordlist_source(...)`; strip path from exception text; add lint-style check in `scripts/code_review.sh` for raw path interpolation into logger calls when var matches `*wordlist*|*password_file|*user_file|userpass`.

### src/oida/utils/base_scanner.py:89-93, 341 — `BaseScanner.__init__` calls `.get()` on raw Namespace input
`_normalize_args(args)` returns a `_ArgsBridge` with `.get()`, stored only in `self.args`. Lines 89-93 (and 341 in `SerialScanner`) call `args.get(...)` on the **raw** parameter not the wrapped form: `args.get("debug", False)`, etc. Verified: `argparse.Namespace.get(...)` raises `AttributeError`. Masked today because Layer-1 scanners are invoked from Layer-2 NXC wrappers that call `_convert_args_to_dict()` first; `cli.py:1086` passes raw Namespace, so any Layer-1-only protocol or direct script invocation crashes on init.
**Fix:** rename param to `raw_args`, then `self.args = _normalize_args(raw_args)` and call `self.args.get(...)`.

### src/oida/utils/lazy_import.py:66-93 — `LazyModule._load()` races: second thread sees `_loaded=True` before `_module` is set
Sets `self._loaded = True` *before* calling `importlib.import_module`. Two simultaneous threads (e.g. ThreadPoolExecutor workers both touching `_pyshark.is_available`) can observe `_loaded == True` and `_module is None` and raise spurious `DependencyError`. CPython import lock protects import itself, not the surrounding flag. The pcap orchestrator (`scanner.py:258, 766`) reads `_pyshark.is_available` on every scan; dispatcher runs scans in threads. Reachable in normal usage.
**Fix:** guard with per-instance `threading.Lock()`; set `_loaded=True` after `try`/`except`. Better: fold into `_module: Any = _UNSET` switched on identity inside the lock.

### src/oida/protocols/goose/__init__.py:527,596 — `is_test` flag never populated; security analysis and TEST/SIMULATION warning unreachable
`_display_goose_message()` checks `msg.get('is_test')`; `_analyze_security()` filters messages by it. `_goose_message_to_dict()` (403-436) never writes the key. Underlying `GooseMessage` exposes no attribute that the code reads. The TEST/SIMULATION-flag concern — one of the headline GOOSE security checks — can never fire.
**Fix:** extract StNum-13/Test bit via `_pyiec61850_raw` (the same way `GooseSubscriber_getSrcMac` is used at line 322); populate `info['is_test']`. Or delete dead checks and the README claim.

### src/oida/protocols/hart/mixins/fuzz.py:253-266 — `perform_master_reset()` runs a self-test before the master reset
First calls `client.perform_self_test(...)` unconditionally; result is thrown away. Any exception from `perform_self_test` is caught by outer except → master reset looks like a failure even when accepted (or never sent). The debug-log f-string `f"self.client.perform_self_test(self.po...: {e}"` is also a copy/paste artefact. For cheap field devices a spurious self-test on top of master-reset is exactly the kind of state churn this tool should avoid.
**Fix:** drop the `perform_self_test` call entirely; send `HARTCommand.PERFORM_MASTER_RESET`.

### src/oida/protocols/hl7/mixins/pharmacy.py:202-310 — Pharmacy RAS/RGV/RDS use unknown kwargs on builders → silent fallback
`build_rxa(... completion_status=...)`, `build_rxg(give_code=..., give_amount=..., give_units=..., give_dosage_form=...)`, `build_rxd(dispense_code=..., actual_amount=..., actual_units=..., prescription_number=..., refills_remaining=...)`. None of these kwargs exist on the respective signatures. Every call raises `TypeError`, caught by outer try/except → fallback to `_create_test_message("RAS","O17")` etc. `--send-ras`, `--send-rgv`, `--send-rds` never produce the medication record; always send a generic test stub. "Pharmacy Give Accepted" findings based on ack to the stub.
**Fix:** align kwargs (`give_code` → `drug_code`, `actual_amount` → `actual_dispense_amount`, etc.); drop or implement `completion_status` as real RXA-20 override.

### src/oida/protocols/hl7/mixins/master_file.py:196-243 — Master-file result extraction reads parser keys that don't exist
Reads `mfi.get("MasterFileID")` but `HL7SegmentParser.parse_mfi` returns `MasterFileIdentifier`. STF: code checks `stf.get("StaffIDCode")` / `ActiveInactive`; parser returns `StaffID` / `ActiveStatus`. PRC `ActiveInactiveFlag` also absent from `parse_prc` output. Even when server returns valid MFR/MFK, no rows appended to `master_files` or `staff_entries`; no table displayed; user sees no enumerated master-file content.
**Fix:** align keys (`MasterFileIdentifier`, `StaffID`, `ActiveStatus`) or change parsers to emit names the mixin expects.

### src/oida/protocols/hl7/mixins/response.py:206-240 — `_extract_order_status` reads non-existent parser key `"orders"`
`orders = parsed["orders"]` on a dict that only initialises `patients`, `observations`, `medications`, `segments`. Raises `KeyError`, swallowed by outer try/except, debug-only. `--query-orders` returns a real OSR response but operator sees nothing — no table, no `order_status_results` in `self.results['data']`, no security finding. Feature silently no-ops on success.
**Fix:** parse ORC/OBR into `orders` list in `parse_message`, or use `parsed.get("orders", [])` and emit warning.

### src/oida/protocols/iec104/commands.py:621-634 — `_fuzz_commands` sends nothing because `conn.send_raw` does not exist in c104
Loop guards send behind `if hasattr(conn, 'send_raw'):`; fallback is literal `pass`. Verified: c104 `Connection` class has no `send_raw` (only `on_send_raw` callback registration). Loop iterates `fuzz_iterations` times, increments tested counter, logs `[i/N] ... payload=...`, but never writes a single byte. Pentester runs `--fuzz --confirm`, sees clean "Fuzzing complete: Commands tested: 100", concludes device is robust — nothing was sent. Same dead `hasattr` branches in `_reset_process` (332) and `_write_parameter` (498) are unreachable but at least have working c104 fallbacks.
**Fix:** route fuzz payloads through c104's `point.transmit()` + value-injection (same path `_write_value` uses); or fail loudly at top of `_fuzz_commands`.

### src/oida/protocols/modbus/proto_args.py:232; src/oida/protocols/modbus/scanner_mixins/diagnostics.py:33,82-86,162-170 — `--diag clear` and advertised `--diag restart` mutate device state without `--confirm`; 'restart' silently no-ops
`--diag` advertises `clear` and `restart` as valid subtests. FC 8 sub 0x0A clears device's diagnostic registers/comm event log/overrun counters; FC 8 sub 0x01 restarts slave's communication (wipes event log, can force full reboot). No confirm check, no security finding emitted. `restart` is advertised but `_run_diagnostics` doesn't dispatch it (accepts only echo/counters/clear/register) → silent no-op while user believes a restart was triggered.
**Fix:** gate `clear` and any future `restart` behind `--confirm`; implement `restart` (FC 8 sub 0x01) or drop from help/choices.

### src/oida/protocols/modbus/nxc_connection.py:201-209; src/oida/protocols/modbus/mixins/writes.py:127-197 — `--broadcast` accepted on TCP/TLS/UDP transports despite being serial-RTU-only
Forces `args.unit_id = 0` and routes writes through `_handle_broadcast_write*` with `slave=0`, reports success unconditionally ('no confirmation possible'). Help text says 'serial RTU only' but nothing enforces it. On TCP, unit-ID 0 has no special meaning per MBAP semantics; device ignores or responds, code logs `[Broadcast] Write sent` as if successful. Gives false confidence that a write went out 'to all slaves' when on TCP it's a single non-broadcast write to a non-existent unit ID. Also bypasses `--confirm` gate entirely.
**Fix:** refuse `--broadcast` when transport is not RTU/ASCII; keep `--confirm` requirement on serial.

### src/oida/protocols/knx/cemi_handler.py:113-185 — Intercepting cEMI handler restored inside try block — exception during scan leaves xknx permanently hooked
`CustomCEMIHandler.fast_bus_discovery` swaps `self.xknx.cemi_handler` to intercepting subclass at line 113, registers `register_telegram_received_cb` at 133, restores handler at 168 *inside* try. Any exception between 113 and 168 leaves xknx using intercepting subclass forever; callback never unregistered (no matching `unregister_*`). Both `parse_bus_ranges` raising `ValueError` for `MAX_BUS_ADDRESSES` and a cancelled `asyncio.sleep` leak the hooks.
**Fix:** move handler restore and callback unregister into the existing `finally` block at 182.

### src/oida/protocols/astm/mixins/framing.py:135-143 — Frame checksum silently skipped when buffer is too short
`_receive_frame` only validates checksum when `len(data) > end_pos + 3`. Recv loop returns frame whose CR/LF is only thing after ETX → missing/truncated checksum case treated as 'frame OK, ACK it' instead of NAK. Non-compliant server can have arbitrary content ACKed and decoded as a record. Recv loop breaks as soon as `CR + LF in data` → can fire on partial frame.
**Fix:** invert guard — if not exactly 2 hex bytes between ETX/ETB and CR/LF, log debug + NAK (or do not ACK).

---

## MEDIUM

### src/oida/cli.py:631-642 — Scan results dropped when `future.result()` itself raises
`_execute_scans` increments `failed` on `future.result()` exceptions but never appends a synthetic result dict for the dead target. Downstream `export_results` omits those targets entirely from JSON/CSV/XML even though counted in failure tally. Real auditability gap: pentester greps JSON for missing host, no record of why absent.
**Fix:** append `{'host': target, 'protocol': protocol_name, 'success': False, 'error': str(e)}` in except branch.

### src/oida/connection.py:117-124 — Top-level proto_flow exception logged without traceback; root cause lost in debug mode
Catch-all in `connection.__init__` records `str(e)` into `self.results['error']` and emits `self.logger.fail(...)`. Original traceback discarded. In debug/verbose mode operator has no way to see *where* failure came from.
**Fix:** when verbose/debug is on, also emit `self.logger.debug('proto_flow traceback', exc_info=True)`.

### src/oida/loader.py:177-182 — `_discover_frozen` prints to stdout/stderr and unconditionally dumps tracebacks
Frozen-bundle discovery path uses `print(...)` and `traceback.print_exc()` directly to stderr — not via `logger`, not gated on debug/verbose. Violates logger contract, spams stderr in the produced binary with stack traces that may include absolute paths from PyInstaller staging dir (privacy leak), runs even when `--quiet` is passed.
**Fix:** replace with `logger.error(...)` + `logger.debug("traceback", exc_info=True)`.

### src/oida/utils/serial_detection.py:18-24 — Bypasses `lazy_import` — pyserial loaded at module import time
Uses legacy `try: import serial / except ImportError: PYSERIAL_AVAILABLE = False` fallback pattern (one of the patterns audit specifically flagged). `utils/serial_detection.py` is imported transitively by protocols — every CLI startup eagerly imports `pyserial` even for IP-only protocols.
**Fix:** `_serial = lazy_import('pyserial', 'serial')`; use `_serial.tools.list_ports`; drop `PYSERIAL_AVAILABLE` (call `_serial.is_available`).

### src/oida/utils/protocol_helpers.py:143, src/oida/utils/permissions.py:58, src/oida/utils/default_credentials.py:451, src/oida/utils/platform_compat.py:294, src/oida/utils/security_findings.py:81,257,266,343,348,756 — Auto-generated debug messages contain code text instead of human context
Multiple `logger.debug()` calls have machine-mangled context strings inserted by a refactor tool reading surrounding source. Examples: `_logger.debug(f"with socket.create_connection((host, ...: {e}")`, `logger.debug(f"if hasattr(socket, AF_PACKET):: {e}")`, `logger.debug(f"with open(value, r) as f:: {e}")`, `logger.debug(f"if value.encipher_only:: {e}")`, `logger.debug(f"with warnings.catch_warnings():: {e}")`, `_logger.debug(f"Return value computation failed: {e}")`. Won't help operator when real bug fires. Strongly suggests AI-generated boilerplate.
**Fix:** rewrite each as a short, human-readable description of what was being attempted.

### src/oida/utils/proto_args_factory.py:339-412,710-764,885-918 + src/oida/connection.py — No central `require_confirm()` helper despite framework-wide opt-in
`add_dangerous_options()`, `add_file_transfer_options()`, `add_control_options()` all advertise `(requires --confirm)` in help text and register the flag, but framework never enforces it. Grep finds ~30 sites reading `args.confirm` directly with four different shapes; some protocols only declare the option but never check it (silently unsafe). snap7 has `_require_confirm` (`snap7/nxc_connection.py:259`) but nobody else uses it. New protocol authors can easily forget the gate; no `super().require_confirm()` boilerplate failure; inconsistent audit-log when gate trips. **Affected protocols (offenders):** dnp3, snap7, opcua, profinet, dicom, knx, ads, bacnet (see also HIGH/CRITICAL findings below for specific dangerous flags missing the gate).
**Fix:** add `connection.require_confirm(op: str) -> bool` returning the gate state, calling `self.logger.fail(...)` + `self.logger.log_security('confirm_blocked', op)`. Route every offender through it. Add `scripts/code_review.sh` check flagging raw `args.confirm` outside `connection.py`.

### src/oida/utils/ics_logger.py:170-189 + src/oida/connection.py:82-84, 228-237 — `ICSLogger.extra` mutated outside `_logger_cache_lock` — concurrent scans of same triple see torn writes
`get_logger()` caches one `ICSLogger` per `protocol:host:port` triple and synchronises read/insert. Every caller mutates `logger.extra` directly (host/hostname/port) *outside* the cache lock. Two threads scanning same triple (e.g. same IP appearing twice in target file) get the SAME ICSLogger; concurrent mutation produces interleaved log prefixes. `update_logger_host` (219-228) deletes + reinserts under new key while another thread may still hold the old key reference.
**Fix:** make each `connection` instance get its OWN logger (cache only dedupes expensive setup); or wrap every `self.logger.extra[...] = ...` in `_logger_cache_lock`.

### src/oida/utils/ics_logger.py:769-779, 843-868 — `_mac_parser` and `_cli_instance` singletons initialised without a lock
`_get_cli()` and `mac_lookup()` use classic check-then-set singleton with no synchronisation. Two threads can both pass `is None` check, both import/initialize, both assign — loser's handler chain silently discarded. For `manuf2.MacParser()` the cost is worse: loads multi-MB OUI file → duplicate work measurable on multi-threaded scan startup. Codebase already has `_logger_cache_lock`/`_json_log_lock` next door.
**Fix:** module-level `_cli_lock`/`_mac_parser_lock` + double-checked locking.

### src/oida/protocols/pcap/listener_registry.py:811-839 — `create_listeners()` swallows ALL listener-import failures at debug level
If passive listener has syntax error, raises at class body, or lazy dependency fails to import, exception caught, appended to `failed`, only debug-level message. Default verbosity: operator sees `PyShark pipeline: N listeners` (silently smaller than requested) — no indication OPC UA listener crashed on `from cryptography import x509`. Pcap brief explicitly calls out this anti-pattern.
**Fix:** when `failed` is non-empty, emit `logger.warning(...)` (not debug) listing names, count, and first exception's `repr(e)`.

### src/oida/protocols/ads/nxc_connection.py:2294-2310 — `--fuzz memory` mode silently does nothing
`--fuzz` declared with `choices=["symbols", "memory", "all"]` and advertises `"memory=memory areas, all=both"`. `_handle_fuzz()` only dispatches on `if mode in ["symbols", "all"]:` — both route to symbol fuzzing. `--fuzz memory --confirm` passes validation, prints `Fuzzing mode: memory (10 iterations)`, exits with zero work done.
**Fix:** add `_fuzz_memory()` implementation, or drop `memory` from choices and fix help text.

### src/oida/protocols/ads/scanner.py:132-137 — AMS Net ID construction silently produces invalid IDs for hostname targets
When `--ams-netid` not passed: `self.ams_netid = f"{self.host}.{netid_ext}"`. For hostname target (`plc01.example.com`), result is `plc01.example.com.1.1` — `_validate_ams_netid` raises `ValueError("Invalid AMS Net ID 'plc01.example.com.1.1'...")` from `__init__` with no actionable hint. Error says "Check -n/--netid-ext value" but that's not the fix.
**Fix:** resolve `self.host` to IP first, or detect hostname case and instruct to pass `--ams-netid` explicitly.

### src/oida/protocols/astm/proto_args.py:45 — `default_tls_port=1395` is fabricated (FireWire confusion residue)
Only place in project where 1395 appears. No IANA-registered ASTM-over-TLS port; 1395 is `1394 + 1` — the IEEE-1394/FireWire misread CHANGELOG.md explicitly called out as wrong for cleartext default. Surfaces in `--help` as 'changes default port to 1395', misleading operators.
**Fix:** drop `default_tls_port=` or use 12000.

### src/oida/protocols/bacnet/mixins/security.py:935-943 — `_bacpypes3_test_oos` reports timeout as 'writable outOfService' (false positive)
Same `None == success` pattern. WriteProperty is confirmed; `None` is timeout, not accepted write. On slow/filtered target every probed object reported as having writable outOfService flag.
**Fix:** require non-None, non-error response; map timeout to inconclusive.

### src/oida/protocols/bacnet/mixins/security.py:818-840 — TimeSynchronization 'accepted' inference is unsound
TimeSync is UNCONFIRMED — by spec device never replies on success. Code does `wait_for(app.request(request), timeout)`, then on `None` warns 'Device accepted unauthenticated TimeSynchronization', catches `TimeoutError` warns 'No rejection received (unconfirmed service)'. Both branches → 'accepted'. Every reachable device — including those that silently dropped the BVLC packet — reported as accepting unauthenticated time sync.
**Fix:** spec-correct validation is follow-up readback of `localDate`/`localTime`; without that, note 'TimeSync sent (unconfirmed; no protocol-level confirmation possible)'.

### src/oida/protocols/bacnet/nxc_connection.py:340-345 — Destructive password / brute-force tests not gated on `--confirm`
`--test-reinit-pass`, `--test-priority-writes`, `--test-time-sync`, `--test-bbmd-injection` correctly gate on `args.confirm`. `--brute-force` (340), `--test-dcc` (343), `--test-oos` (369) do NOT. Brute-force sends DCC 'enable' requests with up to ~50 candidates; on real installs WILL trip account-lockout/SIEM and can disable BACnet comms if any password is accepted (DCC 'enable' is itself state change). `--safe` (212-216) clears `write/test_write/check_reinit/check_oos` but NOT these flags — contradicts its name.
**Fix:** add `--confirm` gates to `--brute-force` and `--test-dcc`; expand `--safe` shortcut.

### src/oida/protocols/bacnet/mixins/security.py:217-232 — `_handle_check_oos` only reads, never tests write — but docstring and assess() imply otherwise
Docstring says 'Check if Out-of-Service flag can be set'; `_handle_security_assessment` calls it as OOS coverage in BAC0 path. Body only reads property and warns 'Out-of-Service readable on …'. No write attempt. BAC0 assessment silently omits actual OOS-writability check the bacpypes3 path performs.
**Fix:** rename and update warning, or perform non-destructive write-back via `_write_property`.

### src/oida/protocols/bacnet/mixins/objects.py:1076-1083 — `enum_programs` infers writability from readability
After enumerating programs: `writable_count = sum(1 for p in programs if p.get('programChange') is not None)`. Comment explicitly says "writability is inferred from the property being present and accessible" — incorrect. BACnet property readability has no relationship with writability. Emits `security_finding('Writable access', ...)` on every device with program objects.
**Fix:** perform non-destructive write-back (write current value) like `_handle_enumerate_writable`, or downgrade to informational `display()`.

### src/oida/protocols/bacnet/mixins/security.py:77-83 — `_handle_security_assessment` reports anonymous-read vuln based solely on device presence
`if self.devices: self.logger.security_finding('Anonymous access', ...)`. `self.devices` populated by any discovery path including Who-Is broadcast — receiving I-Am does NOT prove anonymous ReadProperty allowed. Actual probe lives in `_bacpypes3_check_auth`. BAC0 path collapses 'device exists' and 'anonymous read allowed' → guaranteed-true 'Anonymous read access enabled' on every successful discovery.
**Fix:** attempt a no-side-effect ReadProperty (e.g. objectName on device object); only emit finding when it succeeds.

### src/oida/protocols/can/mixins/xcp.py:94-156 — XCP CONNECT scan can leave slave in connected state
`scan_xcp` sends XCP CONNECT to every arb ID; only sends XCP_DISCONNECT when positive response received within 50ms timeout. If slave accepted CONNECT but response delayed past 0.05s (slow ECU, bus contention), slave is left in connected XCP state. XCP CONNECT grabs the resource lock; can block legitimate calibration tools.
**Fix:** fire-and-forget DISCONNECT for every probed ID at end-of-scan; or send DISCONNECT in no-response branch as best-effort cleanup.

### src/oida/protocols/can/mixins/xcp.py:322-356 — XCP scan accepts any frame starting with 0xFF/0xFE as response (false positive)
`_recv_xcp_response` called with `expected_id=None` from `scan_xcp`. Loop returns FIRST frame on bus whose `data[0]` is 0xFF/0xFE regardless of arb ID. On noisy bus (J1939, PDOs, CAN error frames with all-1s payload), scanner reports non-existent XCP slave on wrong arb ID, then tries `xcp_get_info`/`xcp_memory_read` against that ID.
**Fix:** constrain scan to response window relative to probed req_id.

### src/oida/protocols/can/mixins/uds.py:519-523 — Seed-randomness analysis false 'ALL-ZERO seeds' warning when seed bytes are empty
`sum(1 for s in seeds if all(b == 0 for b in s))` — Python's `all(...)` over empty iterable returns True. Any empty seed entry (positive SecurityAccess response with no payload, which parser at uds.py:473 produces via `seed_data = resp_data[3:3+max(0,pci_len-2)]` when pci_len <= 2) triggers `WARNING: ALL-ZERO seeds: X/N (security bypass may be possible)`.
**Fix:** filter empty seeds before analysis; or `len(s) > 0 and all(b == 0 for b in s)`.

### src/oida/protocols/coap/scanner.py:361 — `security.dtls_available` is self-reported, not probed
`findings["dtls_available"] = self._scheme == "coaps"` reflects whether client uses DTLS, not whether target exposes one. `nosec` security finding ("NoSec mode (DTLS available)") fires only when DTLS was negotiated this run; the interesting case (LwM2M reports NoSec but device ALSO listens on coaps:5684) never detected.
**Fix:** send UDP probe to 5684 when scanning over plain CoAP; or rename to `dtls_in_use`.

### src/oida/protocols/coap/nxc_connection.py:266 — Dead second `getattr(args, 'lwm2m-full', ...)` check (argparse never produces hyphenated names)
Second clause permanently False — argparse normalises to `lwm2m_full`. Suggests author confusion.
**Fix:** drop second clause.

### src/oida/protocols/dicom/mixins/cfind.py:124-129 + src/oida/protocols/dicom/mixins/reporting.py:391-396 — Wildcard-query security finding fires twice
`_cfind_query()` emits `security_finding('Unrestricted query access', ...)` when wildcard returns >0 results; `_analyze_security` re-checks stored `cfind_results.query.PatientName == '*'` and emits same finding again. Every security report double-counts it.
**Fix:** pick one site (preferably `_analyze_security`); drop the other.

### src/oida/protocols/dicom/mixins/operations.py:388-417 — C-MOVE pending sub-operation counters reset on each pending response
Initialises `completed = failed = warning = 0` outside loop, then on each Pending overwrites with `status.NumberOfCompletedSuboperations`. Per DICOM PS3.7 C.4.2.1.4 those are cumulative — overwriting OK during Pending statuses. But final Success/Warning often omits the sub-op attributes; result dict (line 411) records last-snapshot. Hard reject with sub-op-counts in final status is ignored. Also: success log fires inside loop → 'C-MOVE completed' printed more than once for multi-Success transfers.
**Fix:** move success/warning logging outside loop; aggregate final counts.

### src/oida/protocols/dicom/nxc_connection.py:500-596 — `create_conn_obj` registers 50+ presentation contexts per probe — risks 128-context limit
2 (C-FIND) + 2 (C-GET) + 50 (storage subset) + 2 (C-MOVE) + ~40 (probe extras) ≈ 96. With `--probe-ops --get --move --store`, the 50-context cap on storage is reused but `--store` adds full StoragePresentationContexts (~120) — total well over 128. pynetdicom silently drops excess; user gets misleading 'operation not supported'.
**Fix:** track running context count, or merge insertion into one place that respects cap regardless of flag combinations.

### src/oida/protocols/dicom/mixins/enumeration.py:95-123 — AET brute force purely serial; 100+-AE wordlists take minutes
Single for-loop, fresh AE/TCP/DICOM association per candidate. 76-entry wordlist × 5s timeout = 5-10 min on slow target. Headline use case for this module; current behavior discourages real-world use.
**Fix:** thread with `ThreadPoolExecutor`; or document limitation in help.

### src/oida/protocols/discovery/enrich.py:113-121 — Exception handler drops successfully-parsed latency on parse error
Inside `_ping_host` parsing loop, `except (IndexError, ValueError) as e: ... return 0.0` *inside* for-loop. Single malformed `time=` line returns 0.0 instead of trying next. Returning 0.0 indistinguishable from successful ping < 0.5 ms (rounded). Downstream stores `device.ping_data[ip]["latency_ms"] = 0.0` and `alive_ips[ip] = 0.0` as-if-alive when parsing actually failed.
**Fix:** `continue` on parse failure; `return None` after loop if nothing parsed.

### src/oida/protocols/discovery/proto_args.py:37-43 — `-P` short flag for `--no-passive` collides with cross-protocol `-P=password` convention
Other protocols use `-P` for password/PSK (ads, snap7, dnp3, coap). Pipelined commands across protocols (`for p in modbus discovery snap7; do oida $p $tgt -P ...`) get silent semantic drift.
**Fix:** rebind to `-N`/`--no-passive` or drop short form.

### src/oida/protocols/discovery/base.py:62-65, igmp.py:75-81 — `PROTOCOL_NAME` class attribute not enforced
Subclass forgetting class attribute → debug logs say `": Listening on eth0 for 30s"` (empty prefix); abstract intent lost.
**Fix:** `__init_subclass__` check or `assert self.PROTOCOL_NAME` in `__init__`.

### src/oida/protocols/discovery/{scanner,core,stats,infra,network,lldp}.py — Six files exceed 1000-line threshold
scanner.py (2622), core.py (2168), stats.py (2031), infra.py (1414), network.py (1359), lldp.py (1178). None are constants files. Listed on §3 release-prep list.
**Fix:** suggested splits: `scanner_registry.py` for `_SCANNER_CONFIGS`; `models.py`/`interfaces.py` from `core.py`; split EK vs raw-scapy in `stats.py`.

### src/oida/protocols/dnp3/mixins/control.py:214-262 — `--deadband-type` parsed but ignored — always writes float
`proto_args.py:350-356` advertises `choices=['uint16', 'uint32', 'float']`. `_write_dead_bands` reads `db_type`, logs it, includes in result dict — but hardcodes `dnp3.AnalogInputDeadband()` (float) for every entry. `--deadband-type uint16` silently produces G34V3 write that outstation expecting integer may reject or accept with truncation.
**Fix:** build deadband object based on `db_type`; or remove choices and help text.

### src/oida/protocols/dnp3/scanner.py:340 — `--save-file` advertised but never writes to disk
`proto_args.py:300-306` registers `-s/--save-file` with help text "Save downloaded file to local path". Stored on `self.save_file`, referenced nowhere. `_read_file` only puts `data_hex` into result dict. User invoking `oida dnp3 host -R /config.txt -s /tmp/out.bin` sees "File read SUCCESS" but no file on disk and no warning.
**Fix:** in `_read_file`, when `self.save_file` truthy and read succeeded, write `data` via `pathlib.Path(self.save_file).write_bytes(data)`.

### src/oida/protocols/dnp3/scanner.py:410 — `--no-ack` flag is dead — no code path reads `self.no_ack_mode`
`proto_args.py:436-442` advertises `-n/--no-ack` with help "Use no-acknowledgment variants for control operations (stealth mode)". Stored on `self.no_ack_mode`; grep finds only the assignment. Always goes through standard `DirectOperate`/`SelectAndOperate`. Misleading when operator expects unconfirmed sends.
**Fix:** wire through (use `*NoResponse` opendnp3 variants mirroring `freeze_no_ack`); or remove the flag.

### src/oida/protocols/dnp3/mixins/polling.py:136-201 — `_perform_class_read` / `_perform_variation_read` swallow failures — no entry in `results['operations']`
`_perform_integrity_poll` records both success and failure (127/131). Companions don't: on success only `_collect_data` + log; on failure log warning but never set `results['operations']['class_<n>_read']`. Consumers scanning `results['operations']` see class/variation reads as if never happened. iec104, modbus follow always-record pattern.
**Fix:** add standard `results['operations']['class_<n>'] = {'success': bool, 'error': str?}` in both methods.

### src/oida/protocols/ethercat/coe_ops.py:151-204 — `--scan-coe` issues SDO writes to every readable object without `--confirm`, contradicting 'scan' framing
Advertised as 'Scan CoE object dictionary' with no write semantics. `_scan_coe_dictionary` calls `_test_sdo_write_access` for every successfully-read object — issues real `slave.sdo_write(index, subindex, data)`. CiA-301 strict objects benign because trigger on magic signature; manufacturer-specific 0x2000-0x5FFF default range and vendor 0x7xxx/0x8xxx config objects may have side effects. Sister `_test_sdo_write_only` IS gated.
**Fix:** gate `_test_sdo_write_access` behind `self.confirm`; or update help to state scan emits SDO writes.

### src/oida/protocols/ethercat/proto_args.py:113-118 — `--timeout` unit mismatch (ms vs seconds)
proto_args declares ms with default 2000.0. `__init__.py:147` defaults to 5 (seconds, per inline comment). `BaseScanner.__init__` does `int(args.get("timeout", 2))` then uses in `socket.create_connection(..., timeout=self.timeout)`. User following help text and passing `--timeout 2000` ends up with 2000 seconds (33 min) interpretation. EtherCAT currently doesn't consume `self.timeout` (latent bug).
**Fix:** pick one unit; convert ms→s if proto_args stays in ms.

### src/oida/protocols/ethernetip/mixins/enip_commands.py:48 — ENIP encapsulation header parser reads `options` as UINT (2 bytes) instead of UDINT (4 bytes)
`_parse_enip_header` unpacks 24-byte ENIP header with `"<HHIIQH"` — `options` should be `I`. `_build_enip_packet` correctly packs as `I` — writes and reads disagree. Mostly cosmetic (payload slice uses hardcoded 24), but anything consulting `header["options"]` sees wrong value.
**Fix:** change format to `"<HHIIQI"` and slice `data[:24]`.

### src/oida/protocols/fhir/proto_args.py:108-113, 455-458, 556-560 — Three phantom CLI flags (`--fhir-version`, `--test-404-vs-403`, `--extract-response`)
Declared but nothing reads `args.fhir_version`, `args.test_404_vs_403`, `args.extract_response`. Silent no-ops with clean exit. Integration tests only assert `returncode in [0, 1]`, masking dead surface. Same class as `--bulk-export` already removed in RELEASE_TODO §1.
**Fix:** wire each handler or remove from `proto_args.py` with CHANGELOG note.

### src/oida/protocols/fhir/mixins/security.py:229-309 — `--credentials FILE` from `add_auth_options` silently ignored
`_load_credentials()` checks `user_file`, `pass_file`, `wordlist`, `username`, `password`, `default_creds` — never reads `args.credentials`. Users get "No credentials to test" without explanation.
**Fix:** add `credentials` block parsing same `user:pass` format as `--wordlist`.

### src/oida/protocols/fhir/mixins/security.py:31-95 — Auth-test sub-clients ignore `--tls-insecure` → false negatives on self-signed servers
`_test_authentication()` constructs fresh `FHIRClient` instances skipping the timeout adapter and `session.verify = False` from `create_conn_obj()`. On self-signed/expired-cert servers (HAPI dev, in-house staging), both probes fail TLS verification before server sees request; SSLError caught and logs "Anonymous access properly denied". False negative — actually anonymous-readable server reported as locked down.
**Fix:** reuse `self.smart_client.server.session` (clearing only Authorization header), or apply `session.verify = not tls_insecure` and timeout adapter to test clients.

### src/oida/protocols/goose/__init__.py:658-667 — Large sqNum gap heuristic false-positives on every legitimate stNum increment
Per IEC 61850-8-1, sqNum resets to 0 when stNum increments. Normal `...sqNum=4321, stNum=5 → sqNum=0, stNum=6` yields `abs(0 - 4321) = 4321 > 100` → 'Large sqNum gap (possible message loss)' on any active GoCB observing state change during capture. Heuristic anti-correlated with condition it claims to detect.
**Fix:** group by `(gocb_ref, st_num)` before checking sqNum monotonicity; or skip check when stNum differs between adjacent samples.

### src/oida/protocols/goose/__init__.py:145-148, 180-185 — R-GOOSE CLI surface wired but mode is stubbed
`__init__` stores `self.rgoose_mode/port/auth/key` from CLI args; `connect()` returns None with 'R-GOOSE mode not yet supported' whenever `rgoose_mode` set; three sub-flags never read elsewhere. User constructing `oida goose --rgoose --rgoose-auth --rgoose-key /path/to/key 10.0.0.1` gets generic 'not yet supported' with no indication auth/key were ignored.
**Fix:** hide the four R-GOOSE flags (and `oida goose --rgoose` example) behind feature flag until mode lands; or have proto_args raise immediately.

### src/oida/protocols/hart/nxc_connection.py:164-178 — Signaling-code wireless detection skipped when `--detect-wireless` is requested
Wireless-detection block: `if --detect-wireless or --wireless-info: call detect_wirelesshart(); else: check physical_signaling_code == WIRELESS_HART`. Cheap fallback only runs when user did NOT pass `--detect-wireless`. If `detect_wirelesshart()` fails to set `is_wireless` (Cmd 20/768/85 error out) but signaling byte already says WirelessHART, dict marks device as non-wireless.
**Fix:** move `if` out of `else`; run signaling-code check unconditionally as baseline.

### src/oida/protocols/hart/mixins/enumeration.py:18-20, 251 + src/oida/protocols/hart/mixins/fuzz.py:179, 208, 224, 236, 250, 265 — Stdlib `logging` instead of `self.logger`
Both files do `import logging; logger = logging.getLogger(__name__)` and call `logger.debug(...)` inside instance methods. Bypasses ICSLogger formatting (no host/port prefix, no -vvv gating). Every other call site in same files already uses `self.logger.debug(...)`.
**Fix:** replace with `self.logger.debug(...)`; drop module-level `import logging` and `logger = ...`.

### src/oida/protocols/hart/mixins/fuzz.py:208, 265 + multiple sites — Copy/paste debug messages describe wrong code
`logger.debug(f"if date:: {e}")` inside `write_tag` exception handler; `logger.debug(f"self.client.perform_self_test(self.po...: {e}")` inside `perform_master_reset`; `mixins/security.py:86,117` `"Failed to get code_padded: {e}"` inside `client.send_command` try-block; multiple `"Failed to get response: {e}"` even though wrapping parsing/status decoding. Output of refactor tool. When user runs `-vvv --debug`, log lies about where failure was.
**Fix:** replace with messages describing actual operation.

### src/oida/protocols/hl7/__init__.py:309-319 — `_get_version` silently ignores explicit `--hl7-version 2.5`
Treats literal `"2.5"` as "not set by user" (`if user_version and user_version != "2.5"`). User explicitly passing `--hl7-version 2.5` against server announcing `2.7` gets auto-detected `2.7`. No way to force 2.5 on 2.7 server (most common downgrade-test case).
**Fix:** track whether value was user-supplied; or expose `--no-detect-version` flag. Do not conflate "user picked default" with "user didn't pick".

### src/oida/protocols/hl7/mixins/continuation.py:1-144 — `ContinuationMixin` is entirely dead code
None of `_send_mllp_message_with_continuation`, `_check_continuation`, `_create_continuation_request`, `_reassemble_fragments` called anywhere. Wired into MRO, 144 lines unmaintained/untested. If ever wired up: `while continuation_pointer` loop has no max-hop bound — misbehaving server echoing same DSC pointer spins forever.
**Fix:** drop file + MRO entry; or wire `_send_mllp_message_with_continuation` into query mixins (and add max-hop bound).

### src/oida/protocols/hl7/mixins/fuzz.py:88-96 — Fuzz inner loop re-encodes payloads through UTF-8, defeating binary fuzzing
`_fuzz_messages` calls `payload.decode("utf-8", errors="replace")` on each fuzzed payload before passing to `_send_mllp_message` which re-encodes with `wrap_mllp` → `.encode("utf-8")`. Any non-UTF-8 byte replaced by U+FFFD on the way in (re-encoded as EF BF BD on the way out). Exactly the bytes most likely to crash a parser (nulls, high-bit, malformed UTF-8) are scrubbed before leaving the scanner.
**Fix:** make `_send_mllp_message` accept raw bytes (skip re-encode round-trip); or call `self.conn.sendall(MLLP_START + payload + MLLP_END)` directly. Also reconnect socket between mutations — current shares one connection and a fuzz-induced disconnect turns remainder into no-ops.

### src/oida/protocols/hl7/mixins/enum.py:58-69, 218-223, 309-314 — Enumeration mixins iterate `self.all_responses` for key never stored
`_enum_providers/_enum_apps/_enum_locations` loop over `self.all_responses` and call `resp_data.get("raw", b"")`. Only writer of `self.all_responses` is `_extract_detailed_response` storing `{message_type, timestamp, segments}` — no `raw` key. Fetched value always empty default. Documented "also extract from any responses we've already collected" path silently does nothing.
**Fix:** store raw bytes on each entry, or drop dead loops.

### src/oida/protocols/iec104/serial.py:190-197 — `_parse_serial_frame` can `IndexError` on short variable-length FT1.2 frames
Reads `length = frame[1]` then unconditionally indexes `checksum = frame[4 + length]`. No length-vs-buffer guard; only `len(frame) < 4` check at line 171. Malformed/truncated frame where `4 + length >= len(frame)` raises `IndexError`. Caller buffers enough from wire, but helper is also used by `_reset_link_101` and `_poll_serial_data`; any test/fuzz harness or flaky serial channel crashes listener.
**Fix:** add `if len(frame) < 4 + length + 2: return None` before line 194.

### src/oida/protocols/iec104/proto_args.py:109-111 — `--asdu-address` default=1 permanently disables CA auto-discovery from CLI
argparse always supplies 1. `scanner.py:91-124`: when present (!= -1), `self.common_address = asdu_address` and `self._ca_explicit = True`. `_best_common_address()` and `_interrogation_ca()` always return user/default; never use `_discovered_stations` even though that path is carefully written and waited on in `discover()`. Every CLI invocation behaves as `--asdu-address 1`; server with CA != 1 sees reads/writes to CA=1, responds UNKNOWN_CA. `constants.py:348-353` lists `default=-1`, confirming intent was 'no default → auto-discover'.
**Fix:** drop `default=1`, let argparse default to None; constructor already handles None.

### src/oida/protocols/knx/mixins/discovery.py:605-626 — `_test_routing` sends raw-bytes payload xknx rejects, then claims routing works
Constructs `Telegram(..., payload=b"\x00")` and sets `routing_test['routing_supported'] = True` after `await knx.telegrams.put(test_telegram)`. (1) Payload expects APCI object not raw bytes — xknx raises on serialisation, except catches, `routing_supported` stays False. (2) Even if accepted, `telegrams.put()` only enqueues for worker; success proves nothing about gateway routing support. `--test-routing` always reports `routing_supported=False`; security analyzer never emits 'KNX routing accessible' finding.
**Fix:** use proper APCI payload (`GroupValueRead()` against benign group address); verify by listening for routed telegram instead of trusting `put()`.

### src/oida/protocols/mms/proto_args.py:57-61 — `--test-write` not gated by `--confirm`
Added to `mms_group` (not `dangerous`); `add_dangerous_options(...)` passed `include_write=False` so flag is outside the dangerous umbrella and never inspects `args.confirm`. In `MMSScanner.discover()` the only guard is `self.test_write and not self.read_only`. `read_only` defaults True (no `--read-only` CLI flag) but framework convention requires `--confirm` for anything transmitting write/control PDUs. User passing `--test-write` on CLI sees no effect.
**Fix:** move into dangerous group (use `include_write=True`); add `args.confirm` guard in `discover()`.

### src/oida/protocols/mms/__init__.py:141-163 — Resource leak when `IedConnection_connect` raises
`IedConnection_create()` returns SWIG-wrapped object that must be released via `IedConnection_destroy()`. Bare `except Exception` at line 161 returns None without destroying. Any pyiec61850-ng exception after create succeeds but before connect returns leaks a native connection handle until Python GC (C library may not collect cleanly across threads).
**Fix:** initialize `connection = None` before try; in generic except call `_Lib.iec61850.IedConnection_destroy(connection)` if not None.

### src/oida/protocols/mms/nxc_connection.py:12-14 — Stdlib logging in NXC layer violates project rule
`import logging` + `logger = logging.getLogger(__name__)` and three `logger.debug(...)` calls inside `_fuzz_data_object` bypass ICSLogger convention.
**Fix:** drop module-level logger; switch debug lines to `self.logger.debug(...)`.

### src/oida/protocols/modbus/nxc_connection.py:197-198, 233, 275-277 — `--diag restart` and several CLI handler branches reference args `proto_args.py` never defines
`_execute_features` reads `full` (196), `quick` (197), `discover` (198), `event_count_only` (233). Namespace produces these via `getattr(..., default=False)` → branches stay dead. `_has_specific_action` list (362-397) enumerates 'full', 'quick', 'discover' as actions; user running `oida modbus host --full` gets argparse error 'unrecognized arguments'.
**Fix:** define flags or strip dead branches and remove from `_has_specific_action`.

### src/oida/protocols/modbus/scanner.py:692-746 — `_test_write_access_destructive` for holding registers can false-positive read-only devices that ACK silently
Writes hardcoded 42 (or 43), treats `not write_result.isError()` as proof of writability. Many servers (Schneider M340, certain Siemens S7-1200 firmware, pymodbus-mock defaults) silently ACK writes to read-only registers; never return ILLEGAL_FUNCTION/ILLEGAL_DATA_ADDRESS.
**Fix:** verify with readback after write-back; only flag writable if actual register value changed.

---

## LOW

### src/oida/cli.py:1027-1059 + src/oida/utils/proto_args_factory.py — `--confirm` gate duplicated across nine protocols (ads, bacnet, dnp3, ethercat, ethernetip, knx, profinet, snmp, tase2)
Every protocol re-implements `--confirm` flag and checks. No shared helper, no central enforcement, no audit log of grants. New author can forget gate entirely; framework will not notice.
**Fix:** lift `--confirm` into global parser (or `add_common_args`); provide `require_confirm(args, action_name)` helper. Emit uniform audit event into JSON log. (See related MEDIUM "No central `require_confirm()` helper".)

### src/oida/cli.py:994, 1052-1054, 665-659 — Protocol aliases leak into export filenames (`oida s7` → `snap7.json`)
Resolves alias before passing `protocol_name` to `export_results`, which uses verbatim as file stem.
**Fix:** thread original `args.protocol` through to `export_results`; or invert alias at file-write time.

### src/oida/targets.py:343, 363, 365, 592, 602 (+ cli.py) — `parse_target_file` logs full filesystem paths at INFO/WARNING; leaks engagement context
`logger.info(f"Loaded {len(targets)} targets from {filepath}")` and warning lines include absolute path. With `--json-log` active, embedded into NDJSON verbatim (e.g. `/home/pentester/clients/acmecorp/scope/internal-targets.txt`) — same leak `format_wordlist_source` was created to prevent.
**Fix:** route every operator-facing target-file path through basename-only formatter (or sibling `format_target_source()`).

### src/oida/utils/ics_logger.py:42, 168-190 — `_logger_cache` grows unbounded across long-running sessions
Process-lifetime dict keyed by `protocol:host:port`, no eviction. CLI runs short; framework also used as library and from long-running test loops. Scanning /16 (~65k hosts) with all 25 protocols leaves ~1.6M `ICSLogger` instances pinned.
**Fix:** LRU cap (e.g. 4096 entries); or `clear_logger_cache()` helper.

### src/oida/utils/lazy_import.py:272-276 — `_build_protocol_dependencies` swallows metadata exception silently
Bare `except Exception:` with no `logger.debug(...)`. Comment correct re: pip install -e but also fires on corrupted RECORD file; framework reports 'pcap dependency missing' for every protocol with no breadcrumb.
**Fix:** add `logger.debug('PROTOCOL_DEPENDENCIES metadata unavailable: %s', exc)` in except.

### src/oida/utils/ics_logger.py:61-78 — JSON log file opened with no atexit cleanup
`set_json_log_path` opens NDJSON in append mode and stores handle. Each write does `.flush()` so normal exit fine, but file only closed if `set_json_log_path(None)` called again — no `atexit.register`. On SIGTERM/`os._exit` from child, fd leaks and any buffered output lost.
**Fix:** register `atexit.register(close_json_log)`; add `close_json_log()` helper grabbing `_json_log_lock`.

### src/oida/protocols/ads/scanner.py:551-560 — `_target_desc` reads xml_length bytes from same offset as length read
Reads 4 bytes at `ig=TC_XML, offset=0x00000001` to get `xml_length`, then reads `xml_length` bytes from same offset. If `xml_length` includes its own 4-byte header (as `_read_file` pattern suggests), first 4 bytes of `xml_str` are size prefix. Downstream `<Name>`/`<Version>` regex still matches elsewhere, masking the bug. XML on disk (when `--output` set, nxc_connection.py:826) may contain 4-byte garbage prefix.
**Fix:** test against live TC3 target; pick correct offset.

### src/oida/protocols/ads/ethercat_ops.py:1278 — Garbled debug log message in EEPROM dump exception handler
`f"headerstation_alias  struct.unpack_fr...: {e}"` — copy-paste truncation from `header["station_alias"] = struct.unpack_from(...)`.
**Fix:** `self.logger.debug(f"SII header partial-parse failed: {e}")`.

### src/oida/protocols/ads/nxc_connection.py:2175 — `_route_name` default differs between scanner ("route") and NXC wrapper ("oida")
`_add_route_nxc` defaults to `"oida"`; `ADSScanner._add_route(...)` defaults to `"route"`. Direct callers get "route", CLI users get "oida". Cosmetic, but inconsistent audit trail.
**Fix:** let wrapper pass `None`; scanner owns default.

### src/oida/protocols/ads/ethercat_ops.py:312-326 — `_delete_file_foe` reports success even when CLOSE silently fails
After opening for write, wraps `ECAT_FOE_CLOSE` in `try/except Exception: pass`; unconditionally sets `result['success'] = True`. Comment notes "Some devices don't return data on close" but swallows real errors. Bandit flags as B110.
**Fix:** narrow except (ignore only short-read RuntimeError); downgrade `success` to `best_effort` when close arm fails.

### src/oida/protocols/astm/records.py:65-79 — Duplicate `_calculate_checksum` implementations drift risk
`ASTMRecordBuilder._calculate_checksum` and `FramingMixin._calculate_checksum` are identical. Builder copy never called from production.
**Fix:** delete builder method; tests call mixin helper; or extract module-level `astm_checksum(data)`.

### src/oida/protocols/astm/mixins/records.py:94-106 — `--cancel-order` silently overrides `--action-code` without warning
`--cancel-order --action-code A` reads then unconditionally overwrites to 'C'. Same in `_send_result_record` for `--correct-result`/`--delete-result` vs `--result-status`.
**Fix:** make mutually exclusive in argparse; or log warning when both set.

### src/oida/protocols/astm/records.py:96-124 — Receiver field index in `build_header` docstring disagrees with ASTM E1394 numbering
Docstring labels receiver-name as 'H-10' but actual placement is index 10 (H-11 per 1-based convention). Sender correctly labelled H-5 at index 4.
**Fix:** correct docstring.

### src/oida/protocols/astm/mixins/records.py:11-59 — `_send_query_record` no `--confirm` gate but performs same PHI-touching wildcard as `--enum-patients`
`--enum-patients` requires `--confirm`. `--send-query` runs `build_query(starting_range='*' if no patient_id, nature_of_request='A')` with no gate. Nature 'A' = ALL info (orders + results + demographics).
**Fix:** pick one policy and document.

### src/oida/protocols/bacnet/proto_args.py:35-49 — `--output` missing from `add_network_options` / no `add_output_options` call
Script check #9 flags. Handlers do `getattr(self.args, 'output', None)`. BACnet relies on inherited parents.
**Fix:** call `add_output_options(p)` explicitly.

### src/oida/protocols/bacnet/mixins/{network,objects,monitoring}.py — Three mixins exceed 1000-line guideline
network.py (1181), objects.py (1092), monitoring.py (1014). Already extracted mixins but loosely cohesive. CHANGELOG entry suggests consolidation in the other direction.
**Fix:** split MS/TP discovery, schedule/calendar/alarm/trendlog into submodules; or consolidate.

### src/oida/protocols/can/mixins/uds.py:176-226 — UDS service enumeration switches diagnostic session via 0x10 and never restores default
Probes service 0x10 with sub 0x01 (defaultSession) — benign because 0x01==default, but loop meant to enumerate further services may only be available in extended sessions. `uds_session_scan` explicitly switches back; if 0x10 ever extended here, ECU left in extended session.
**Fix:** mirror `uds_session_scan` and always send default-session reset after any DiagnosticSessionControl probe.

### src/oida/protocols/can/scanner.py:41 + nxc_connection.py:34 — Two separate `lazy_import('can', ...)` instances; tests must patch right one
Both create LazyModule independently; mixins reach in via `from ..scanner import _python_can` (six call sites). RELEASE_TODO records the fallout. The lazy module caches per-instance — can disagree.
**Fix:** promote single `_python_can` and `_time` to `src/oida/protocols/can/__init__.py`; eliminates dual-cache hazard and 6 of 8 'local import' warnings.

### src/oida/protocols/can/constants.py:13-15 — `import logging` / module-level logger for one debug call
`logger.getLogger(__name__)` consulted by exactly one debug log at line 1293 inside `CANopenSDOResponse.as_string`. Flagged by check #4. Dataclass property has no `self.logger`.
**Fix:** drop debug line (decode with errors='ignore' already swallows); or return None without logging.

### src/oida/protocols/can/nxc_connection.py:909, 1000 — `_handle_send`/`_handle_replay` treat any arb_id > 0x7FF as extended without warning
`is_ext = arb_id > CAN_STD_ID_MAX`. No validation within 29-bit extended range; no log when silently upgraded. `--send 0x800#...` silently sent as 29-bit extended.
**Fix:** warn when ID exceeds CAN_STD_ID_MAX but user typed 3-digit form; reject if exceeds CAN_EXT_ID_MAX.

### src/oida/protocols/coap/helpers.py:222 — `";obs" in attrs_str.lower()` matches `;observable=...` too
Pre-regex shortcut sets `resource["obs"] = True` whenever attr string contains `;obs`. Any attribute beginning with `obs` (`observable`, `observed`, `obsolete`, vendor extensions) flips the flag.
**Fix:** drop lines 222-223; regex loop on 229 handles `;obs` case correctly.

### src/oida/protocols/coap/scanner.py:163 — LwM2M Device Object /3/0 fingerprinted unconditionally even without `-L`
`discover()` always runs `_fingerprint_lwm2m()` against `/3/0/0`-`/3/0/3` regardless of flag. Contradicts CLI help text. Inflates request counts on non-LwM2M targets.
**Fix:** gate on `-L`; or update help.

### src/oida/protocols/coap/scanner.py:471 — `except (asyncio.TimeoutError, Exception)` redundant; swallows `observation.cancel()` errors
`Exception` includes `asyncio.TimeoutError`. `pr.observation.cancel()` is inside same try → any cancel error silently absorbed.
**Fix:** collapse to `except Exception as e:`; wrap `cancel()` in its own try/except.

### src/oida/protocols/dicom/mixins/operations.py:38, 210-228 — `_cget_use_subdirs` flag set only by bulk export, never reset
`_recursive_bulk_export()` sets `self._cget_use_subdirs = True` but never sets back. Single invocation running `--dump-all` then `--get` falls into subdir-creating branch.
**Fix:** initialise in `__init__`; reset before each operation; or pass as parameter.

### src/oida/protocols/dicom/mixins/operations.py:185-186 — Empty for-loop consumes C-GET responses but discards status
`for status, identifier in responses: pass  # Just consume responses`. Silent loss of failures, warnings, sub-op counts from Pending statuses. `_cget_retrieve` (250-257) does inspect statuses; bulk-export should mirror.

### src/oida/protocols/discovery/file_carving.py:158, 175 — Custom `open(filepath, 'wb')` instead of export_table/get_export_path
Flagged by export-utils check. Filenames are network-derived `md5_hash`+extension; `safe_output_path()` already handles traversal — not security issue, just inconsistent.
**Fix:** add justifying comment or thin helper.

### src/oida/protocols/discovery/ssdp.py:16-23 — Single fallback `try/except ImportError` (deliberate; defusedxml is security guard)
Script flags as CRITICAL but intent is opposite: defusedxml is hard security dep; deferred-fail via lazy_import is exactly what guard exists to prevent.
**Fix:** move to project-blessed hardfail variant of lazy_import; or annotate with `# noqa` + rationale.

### src/oida/protocols/discovery/base.py:59 — Stray `assert` in docstring example (false positive in pattern check)
Inside a docstring example, not real code. Mentioning for completeness.

### src/oida/protocols/discovery/lldp.py:660, 685 — Two `# TODO: Add specific parsing for each subtype` markers
Inside LLDP organization-specific TLV parsers (presumably IEEE 802.1/802.3).
**Fix:** decide before 1.0; file as real issue or expand parsers.

### src/oida/protocols/discovery/{ospf_passive,stats}.py — Need ruff/black formatting
Pre-commit hook should catch on next commit.

### src/oida/protocols/dnp3/mixins/polling.py:72, 156, 189, 219, 653 — Redundant 0.5s `time.sleep` after every `_sync_scan`
`_sync_scan` already blocks on `app.wait_for_task(...)`. With `--probe-objects` (123 groups) that's ~60s pure idle. Sleeps are cargo-culted.
**Fix:** drop sleeps; or if known race in bindings, document and replace with `handler.wait_settled(0.5)` flush method.

### src/oida/protocols/dnp3/scanner.py:531-550 — `_run_operation` helper defined but never called
Generic operation runner with consistent error handling — exactly the wrapper that would have prevented the inconsistency flagged for `_perform_class_read`.
**Fix:** retrofit existing mixin methods to use it; or delete as dead code.

### src/oida/protocols/dnp3/scanner.py:65, 92, 140, 183, 232, 263, 457, 832 — 11 local `import opendnp3` calls — should funnel through `self._dnp3`
Scanner already caches on `_dnp3` cached_property; polling/control/file_transfer mixins use `self._dnp3`. Factory helpers and `_command_success` bypass it. Future backend swap has 11 extra spots.
**Fix:** hoist once to module scope via `lazy_import`; or `# noqa: local-import` marker.

### src/oida/protocols/ethercat/eeprom_ops.py:182-184 — `_dump_full_eeprom` reports total_bytes off by 2x
EtherCAT EEPROM words are 16 bits / 2 bytes. pysoem returns 4 bytes per word as wire-encoding artifact. Reported byte count is 2x real EEPROM size; on-disk JSON dump contains 2x bytes.
**Fix:** `total_bytes = len(eeprom_data) * 2`; slice stored hex to `data[:2]`.

### src/oida/protocols/ethercat/eeprom_ops.py:143 — `_read_eeprom_strings` strict UTF-8 decode taints whole EEPROM entry
`slave.name.decode("utf-8")` without `errors="ignore"`. Sister code uses `errors="ignore"`. Non-UTF-8 raises `UnicodeDecodeError`, caught by outer except → entire eeprom-data dict replaced with `{"error": str(e)}`, hiding general/fmmu/sync_manager/pdo results.
**Fix:** `slave.name.decode("utf-8", errors="ignore").rstrip("\x00") if slave.name else ""`.

### src/oida/protocols/ethercat/advanced_ops.py:13-15 + nxc_connection.py:11-13 — `import logging` / module-level logger violates 'use self.logger only'
Two direct stdlib-logging consumers.
**Fix:** capture `self` from enclosing method in `advanced_ops:50`; drop logging in `nxc_connection.py:122`.

### src/oida/protocols/ethercat/proto_args.py:101-105 — `--eeprom-dump` help/code address-range mismatch (0x7E vs 0x7F)
Help says 'addresses 0x00-0x7E'; actual loop is `range(0x00, 0x80)` → 0x00 through 0x7F.
**Fix:** update docstring or range bound.

### src/oida/protocols/ethercat/__init__.py:40-41 — Module-level `pysoem = None` is dead
Annotated 'Module-level exports for test compatibility' but grep finds no references. Lazy_import wrapper `_pysoem` is the actual access path.
**Fix:** delete.

### src/oida/protocols/ethercat/__init__.py:326, 461-465 — processdata thread join timeout (2s) shorter than worst-case blocking call (10s)
`receive_processdata(10000)` (10s) vs `join(timeout=2.0)`. If thread mid-receive when stop set, join returns after 2s with `is_alive() == True`; code nulls `self._pd_thread` and proceeds to `connection.close()` while still-live thread may issue send/recv on closed master → undefined behavior in libsoem (possible segfault, hang).
**Fix:** increase join timeout above worst-case `receive_processdata` (10s+); or shorten per-cycle timeout; or try/finally that nulls master reference.

### src/oida/protocols/ethernetip/mixins/attacks.py:84-103 — Dead `struct.pack` immediately overwritten in `_send_attack_command`
Two `packet = struct.pack(...)` back to back. First (84-93) uses `"<HHIIQIH"` (broken 7-field 26-byte build); second (95-103) labelled `# Fix: proper 24-byte header`. First call is dead.
**Fix:** delete lines 84-93 and `# Fix:` comment marker.

### src/oida/protocols/ethernetip/mixins/attacks.py:169-176 + mixins/class_explorer.py:315-327 — Three exported names never wired through CLI
`_crash_cpu()` + `ATTACK_CRASHCPU_PAYLOAD` re-exported through `attacks.ATTACK_TYPES` and package `__all__`, no CLI flag invokes. Same for `_get_attr_description`/`_get_attr_info`.
**Fix:** delete; or add `--crash-cpu --confirm` flag.

### src/oida/protocols/ethernetip/mixins/advanced_parsers.py:471-486 — Direct file write in `_download_all_files` bypasses export_utils
Uses `safe_output_path()` to defeat traversal; writing binary blobs through `export_table` would be inappropriate.
**Fix:** add single-line comment noting `export_utils` deliberately skipped for binary file dumps.

### src/oida/protocols/fhir/mixins/search.py:103-136 — Wildcard patient enumeration over-fetches by up to 26x
a–z loop sets `_count = max_results` once before loop. Each per-letter request asks for full page (default 100). Accumulates and slices at end. With `--max-results 100` fetches up to 2600 records, throws away 96%. On rate-limited servers can trip throttling.
**Fix:** shrink per-letter `_count` as you go: `prefix_params["_count"] = str(max(1, max_results - len(all_patients)))`; skip queries once full.

### src/oida/protocols/fhir/proto_args.py:591-594 — `--save-response` help text claims "raw FHIR response" but saves parsed scanner results
`_save_response_if_requested` called with `self.results.get("data", {})` — parsed simplified records, not raw FHIR Bundle.
**Fix:** update help to "Save scanner results JSON"; or capture raw bundle via `self.smart_client.server.request_json(...)`.

### src/oida/protocols/goose/__init__.py:30-32, 325, 397 — Module-level `logging.getLogger(__name__)` inside callbacks instead of `self.logger`; debug messages read like pasted code snippets
Lines 325/397 use module logger from instance methods. Debug strings look like bare source pasted in: `logger.debug(f"if sub._subscriber is not None:: {e}")` and `logger.debug(f"self._goose_subscriber.stop(): {e}")`.
**Fix:** `self.logger.debug(f'Failed to read src_mac: {e}')`; drop module-level logger and `import logging`.

### src/oida/protocols/goose/__init__.py:523-526 — `_display_goose_message` reads vlan_id/dst_mac/vlan_prio keys never written
Only `_gocb_info_to_dict` sets those keys (and writes `vlan_priority` not `vlan_prio` — keys mismatched).
**Fix:** extract VLAN/dst-MAC from `_pyiec61850_raw` and align keys; or delete dead branches.

### src/oida/protocols/goose/__init__.py:313-323 — `on_message` closure references `sub` before assigned
`on_message` defined at 313 references `sub` at 320; `sub = ...` at 351. Works because closure resolves lazily and callback can only fire after `sub.start()` at 364. Fragile if library calls listener synchronously from `set_listener` (360) → NameError swallowed by broad except, first packet lost.
**Fix:** refactor to instantiate subscriber first; or pass via class attribute.

### src/oida/protocols/goose/__init__.py:167-169, 215-236 — `check_dependencies` only checks goose submodule, not MMS used by `--mms-enum`
Three pyiec61850 submodules imported separately. If `mms` is broken, runtime surfaces confusing AttributeError instead of friendly 'dependency missing'.
**Fix:** check both `_pyiec61850_goose.is_available` and `_pyiec61850_mms.is_available`.

### src/oida/protocols/hart/nxc_connection.py:575-585 — `--write-descriptor` silently ignored unless `--write-tag` also passed
Cmd 18 writes tag/descriptor/date together. Descriptor only consumed inside `if new_tag is not None:` branch.
**Fix:** require `--write-tag` whenever `--write-descriptor`/`--write-date` given and fail loudly; or accept descriptor-only writes by reading current tag first.

### src/oida/protocols/hart/hartip.py:32-142 — Fallback ImportError block uses try/except instead of lazy_import (deliberate for re-export shim)
Thin re-export shim must expose ~50 names at module-import time. Pattern acceptable; could be cleaned. `HARTIP_AVAILABLE` is dead state (`scanner.py`/`nxc_connection.py` gate via `_hartip.is_available`).
**Fix:** delete `HARTIP_AVAILABLE` or use it.

### src/oida/protocols/hart/scanner.py:33-38 — Import-after-statement (E402)
`from .hartip import (...)` sits below `lazy_import(...)` lines. Re-order to put imports first.

### src/oida/protocols/hart/mixins/security.py:139 — Bruteforce result uses literal `'(already unlocked)'` as fake password
`{"success": True, "password": "(already unlocked)", "tested": 0}`. Bandit flags (B105). Downstream `nxc_connection.py:521-522` surfaces `security_finding("Weak password", f"Device lock code found: '{code}'")` claiming the lock code is `(already unlocked)`.
**Fix:** separate field `{"success": True, "already_unlocked": True, "tested": 0}`; caller branches on it.

### src/oida/protocols/hl7/proto_args.py:908-919 — Two declared CLI options never read (`--save-response`, `--parse-segments`)
Defined in proto_args; no code reads them. Help text promises behaviour scanner does not implement.
**Fix:** implement (save raw bytes; parse and display every segment in latest response); or remove.

### src/oida/protocols/hl7/segments.py:21-28 + utils.py:17-20 — Two fallback `try/except ImportError` blocks for hl7apy
Project standard is `lazy_import()`. Comments justify local check ("defends against transitive paths") but same effect achievable via `lazy_import`.
**Fix:** route through existing lazy_import instance from `__init__.py`.

### src/oida/protocols/hl7/segments.py:11-13 + utils.py:25-27 — Two stdlib `logging` instances bypass ICSLogger
Both files emit `logger.debug(...)` from internal helpers. Used by fuzzer and standalone helpers (no `self`).
**Fix:** pass ICSLogger through at call site; or wrap module-level `_log_debug` delegating to caller-installed logger.

### src/oida/protocols/hl7/segments.py:1016-1022 — `build_mrg` overwrites MRG-3 when both visit and account numbers supplied
Writes prior visit to `mrg.mrg_3` then immediately overwrites with prior account if both supplied. Two values cannot coexist; docstring already notes collision.
**Fix:** map account number to MRG-4 (Prior Patient Account Number); or pick one and document.

### src/oida/protocols/iec104/scanner.py:477-478 — `_extract_value` exception logger prints wrong/garbled message
`logger.debug(f'if tid in (1, 30):   M_SP single-point: {e}')` — copy-paste from first `if` branch; prints misleading text for every type 3..37 that fails parsing. Also one of two stdlib-logging usages flagged.
**Fix:** `self.logger.debug(f'value parse failed (type_id={tid}, offset={ie_off}): {e}')`. Same for `_parse_cp56time2a` (1330).

### src/oida/protocols/iec104/scanner.py:284-295 — `_parse_write_arg` propagates `ValueError` on malformed `IOA[:VALUE]` input
`int(ioa_str)` and `int(raw)` with no try/except. Typo `--write-single foo:on` crashes scanner during `__init__` before logger setup.
**Fix:** try/except ValueError; on failure warn and skip operation.

### src/oida/protocols/iec104/file_transfer.py:87 — Dead expression in directory listing loop
Line 87 is `entry.get('creation_time', 0)` — bare expression. Either developer meant to bind to local for display or it's leftover. Breaks surrounding pattern.

### src/oida/protocols/iec104/scanner.py:1-1634 — Scanner exceeds 1000-line budget (1634 lines)
Largest in module. Split candidates: factor `_create_callbacks` (~280 lines) into `callbacks.py` mixin; `_analyze_security` + `_report_findings` into `reporting.py` mixin.

### src/oida/protocols/iec104/scanner.py:1014-1044 — Station scan can register up to 65k c104 Station objects
`_station_scan` upper-bounds at 65534. For `oida iec104 host -S 1-65534` registers 65,534 stations. c104 may rate-limit or reject after threshold → skews 'no_response' classification.
**Fix:** cap scan width; or post-scan remove stations for inactive CAs; or batch.

### src/oida/protocols/knx/ets.py:410, 534 — `extract_knxproj_hash`/`crack_knxproj` crash with AttributeError when `logger=None` and error path triggers
Both default `logger=None`. Two error paths call `logger.debug(...)` unconditionally. nxc_connection.py call sites pass `self.logger`, so latent in CLI but live for external/test consumers.
**Fix:** wrap with `if logger:`; or default to no-op logger at function entry.

### src/oida/protocols/knx/scanner.py:377, 394 — `listen-time 0` silently coerced to 30 by `or` fallback
`self.args.get('listen-time') or 30` — explicit `--listen-time 0` (natural way to skip listening) gets silently replaced.
**Fix:** `listen_time = self.args.get('listen-time'); if listen_time is None: listen_time = 30`.

### src/oida/protocols/mms/__init__.py:274-297 — `MmsError` handle never destroyed
Allocated per identify call; never freed. Each scan leaks one MmsError object. Contradicts file's own "safe memory handling" doc comment.
**Fix:** add `MmsError_destroy` (or safe_*) in finally.

### src/oida/protocols/mms/__init__.py:727-729 + fingerprint.py:175, 311 — Misleading debug messages copy-pasted from source lines
`self.logger.debug(f"if isinstance(value, bool):: {e}")`; `logger.debug(f"if re.match(rule.domain_pattern, doma...: {e}")`; `logger.debug(f"Failed to get match: {e}")`. Unhelpful when failures occur.
**Fix:** rewrite with actual context.

### src/oida/protocols/mms/fingerprint.py:206-210 — Regex heuristic misidentifies literal anchors
`if expected.startswith("^") or expected.endswith("$"):`. Literal vendor string starting with `^` or ending with `$` routed through `re.match` instead of string comparison. Latent today.
**Fix:** add explicit `"regex": true` flag in fingerprint JSON schema.

### src/oida/protocols/mms/fingerprint.py:290-296 — `_read_attribute` short-circuits to default before reading
Dict containing both `default` and `attribute` returns default immediately; never invokes `read_func`. Rule `{"attribute": "InRef1.purpose", "default": "unknown"}` always reports `unknown`.
**Fix:** try attribute read first; return `default` only if `raw_value is None`.

---

## INFO

### src/oida/protocols/ethercat/ — Test coverage 43% (below 70% project threshold)
Worst offenders: `proto_args.py` 0%, `fuzzing_ops.py` 11%, `eeprom_ops.py` 25%, `nxc_connection.py` 28%, `advanced_ops.py` 45%. 140 unit tests pass. Known/tracked gap, not regression introduced this cycle.

### src/oida/protocols/fhir/ — Test coverage 55% (below 70% threshold)
Script reports CRITICAL. Bulk is `proto_args.py` (0%) and `resources.py` (56%). Easy fix: add `test_proto_args.py` instantiating parser and asserting flag/short/dest. resources.py needs parser tests with mocked fhirclient objects.

### src/oida/protocols/hart/ — Test coverage 25% (script reports CRITICAL <70%)
82 unit tests pass; bulk of nxc_connection.py (7%), mixins (8-45%), scanner.py (57%) uncovered.

### src/oida/protocols/knx/mixins/security.py:49, 120 — BCU brute-force treats auth_level 3 as 'no access' alongside 15 — undocumented heuristic
Only marks key as success when `level != 3 and level != 15`. Level 3 = conventional 'user'/unauthenticated default; reasonable heuristic to suppress false positives. Undocumented; legitimately-configured BCU returning level 3 on real key match silently dropped from `valid_keys`. False-negative risk.
**Fix:** add code comment citing rationale; offer `--report-level-3` opt-in; or report level-3 hits as separate 'plausible default level' bucket.

### src/oida/protocols/mms/ — Test coverage 32% (below 70% threshold)
`__init__.py` 40%, `fingerprint.py` 28%, `nxc_connection.py` 11%. Almost every protocol-interaction path uncovered. Mock-based unit tests around `_extract_error_code`, `_extract_mms_value`, `FingerprintMatcher.verify_rule`, `_handle_fuzz` would lift materially.

### src/oida/protocols/ethernetip/ — Eight E402 + 1 black-unformatted file
Five in `__init__.py` (35/44/54/66/69), two in `mixins/cip_objects.py:24-25`, one in `mixins/cip_security.py:24`. Pattern is codebase-wide `lazy_import + then import dependent constants`; silence with `# noqa: E402`. `mixins/class_explorer.py` fails `black --check`. Bandit raised one Low/Medium false-positive on `"password_auth": None` dict literal — `# nosec B105`.

---

## Areas with zero findings

Based on the raw findings JSON, no reviewer raised explicit findings for these modules during this batch (either fully clean or out of scope for this run): **opcua, profinet, snap7 (s7), snmp, mqtt, ocpp, tase2** (snap7 was referenced as a positive example for `format_wordlist_source` and `_require_confirm` adoption). The `pcap` orchestrator and passive-listener framework were reviewed in aggregate (findings under the framework/pcap bucket above) rather than per-listener — individual listener modules (109 listeners) were not individually surfaced as findings.

**Truncation note:** The raw findings JSON was truncated mid-way through the modbus section (final visible finding cuts off in the middle of `_test_write_access_destructive`). Additional modbus findings beyond `_test_write_access_destructive` may exist in the un-delivered tail of the JSON and should be re-run if a complete modbus picture is required.

---

# Gap follow-up (workflow code-review-gap)

## Summary

- **Areas covered:** `src/oida/shared/` (file_carving_common, igmp_constants), `src/oida/hooks/` (rthook_hl7apy), `src/oida/fuzz/monitors/` (http2, industrial, infrastructure, medical, registry), `src/oida/pcap/passive/` per-listener deep-dive (fins, knx, mssql, mysql), and deep-dive passes on the eight largest protocol dirs (modbus, discovery, ethernetip, hl7, bacnet, knx, snap7, opcua).
- **Raw gap findings:** 153
- **Post-dedup vs. existing report:** 137 surviving findings (16 dropped as duplicates / partial overlaps with existing entries — primarily the `_test_routing` raw-bytes overlap, format_wordlist_source bacnet password_file path, garbled-debug omnibus already covering some sites, `--test-write` confirm-gate variant of the same anti-pattern, and the BCU brute auth_level / KNX project password leak being adjacent to existing ets.py finding).
- **Breakdown by severity:** CRITICAL 2 · HIGH 25 · MEDIUM 50 · LOW 58 · INFO 2.
- **New CRITICAL summary:** (1) NetManageDevice constructs `DiscoveredDevice` with kwargs no field accepts — every Schneider PLC discovery dies with `TypeError` (CHANGELOG markets this as a working feature). (2) HL7 `enum_host_info()` and standalone `utils.probe_server_capabilities()` send ADT^A01 admission writes on every scan with no `--confirm` gate. Both are covered below.
- **New HIGH-impact themes (additive to the original report):**
  - **OPC UA L1 scanner is fundamentally broken** — `set_user` `await` TypeError, missing `connect()`, broken `--fuzz` bool-vs-string dispatch, `--call-method` and `--test-subscription-limits` with no `--confirm`, IPv6 URL parsing, `--policy None` silent downgrade.
  - **Snap7 audit / SZL parser** — `--audit` runs unauthenticated write probes + brute-force without `--confirm`; SZL parser hangs forever on `record_len=0` (attacker-controlled DoS); protection-level false positive on zeroed `S7Protection` struct.
  - **Modbus deep pass** — `load_register_map()` accepts arbitrary paths from `--register-map` (arbitrary file read); `_test_write_access_safe` returns guaranteed-true false positives; SunSpec security override forces `access='rw'`; `_discover_units` mixes int/str dict keys; explicit `-u 1` silently overridden by map `default_unit_id`; `--dry-run` and `--format solarman` advertised but unwired.
  - **BACnet deep pass** — `--assess` and `--test-write/--enumerate-writable` issue real writes via BAC0 path with no `--confirm`; six dispatcher-read CLI flags missing from proto_args (`--cov-lifetime`, `--cov-duration`, `--file-chunk-size`, `--file-access-method`, `--read-range-count` and `--vendor-info` alias); `--assess-network` shortcut sets wrong dest; outOfService Boolean parsing produces false-positive OOS findings; vendor_scan suspicious-pattern check generates noisy false positives on benign vendors.
  - **Discovery deep pass** — VRRP master/backup classification inverted on every observed advertisement; EIGRP/RIP/PIM passive listeners crash silently on cross-listener device merges (AttributeError swallowed); GLBP TLV mis-parses priority; PCAnywhere drops ST replies arriving before NR.
  - **HL7 deep pass** — `segment_builder` pinned to default version at start, never refreshed after server-version auto-detection; `_analyze_security` reports 'Accepts Unknown Sender' on every scan because of the unsolicited ADT probe + sticky `ack_code`; `_send_oru_message` ignores `--obx-value`; enum.py reads PV1 keys (`ConsultingDoctor`, `AdmittingDoctor`) the parser never returns and uses `get_field(fields, 16)` 1-indexed against 0-indexed `fields[16]` guard (returns OBR-15 instead of OBR-16).
  - **Snap7 fuzz monitors / models** — four fuzz/check_dependencies sites use module-level stdlib `logger` instead of `self.logger` and carry refactor-artefact text; `S7FirmwareVersion` overrides `__eq__` on a `@dataclass` without restoring `__hash__`.
  - **Fuzz monitors** — `HTTP2Monitor.post_send` returns None instead of bool (breaks boofuzz crash detection); `IEC104Monitor` mismatched baseline log strings; `HL7Monitor` unbounded `recv` loop (memory exhaustion); `infrastructure.py`/`registry.py` use stdlib logging.
  - **PCAP passive credential leak** — `mssql.py:523` and `fins.py:662` log cleartext credentials (`username:password`, `password=...`) at INFO into both console and `--json-log`, bypassing `format_wordlist_source` and the existing harvest-table gate.

## CRITICAL

### src/oida/protocols/discovery/netmanage.py:442-463 — `NetManageDevice.to_discovered_device()` passes wrong kwargs → TypeError on every NetManage device
Constructs `DiscoveredDevice(ip=..., mac=..., hostname=..., vendor=..., protocol=..., metadata=..., first_seen=datetime, last_seen=datetime, ...)`. None of `ip`, `mac`, `hostname`, `vendor`, `protocol`, or `metadata` are real `DiscoveredDevice` fields (actual fields: `mac_address`, `ip_addresses: List[str]`, `name`, `manufacturer`, etc., per `core.py:1565-1660`). `first_seen`/`last_seen` are typed `str` (ISO strings) but a raw `datetime` is passed. Every successful NetManage discovery raises `TypeError: __init__() got an unexpected keyword argument 'ip'`. In `NetManageScanner.scan()` this triggers at line 676 inside `{ip: dev.to_discovered_device() for ip, dev in ...}` — the dict comprehension fails and the entire scan returns nothing, even when valid responses were parsed. Same kwarg set at line 775 in `NetManagePassiveListener.process_packet`, caught by the broad except at 782 and silently debug-logged. CHANGELOG markets working Schneider PLC discovery; the feature is non-functional.
**Fix:** rewrite as `DiscoveredDevice(mac_address=..., ip_addresses=[self.ip_address], name=self.device_name or self.netbios_name, manufacturer=self.vendor, device_type=self.device_type or 'PLC', discovered_by=['netmanage'], first_seen=self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else str(self.first_seen), ...)` and add a `netmanage_data: Optional[Dict] = None` field to `core.py:1565` alongside `ads_data` for the rich NetManage attributes.

### src/oida/protocols/hl7/__init__.py:507-515 + src/oida/protocols/hl7/utils.py:289-409 — HL7 connection-test and standalone helper send ADT^A01 admission writes with no `--confirm` gate
Two distinct unauthenticated-write paths in HL7:
- `enum_host_info()` always calls `_create_test_message('ADT','A01')` after `create_conn_obj()` and ships a real Admit with populated PID (`PROBE^^^MRN`) and PV1 (location `PROBE^101^A`) on every `oida hl7 <ip>` invocation. Every other ADT path in `mixins/message.py:30-35` enforces `--confirm`; this 'connection test' bypasses it.
- Free-standing `send_probe()` / `probe_server_capabilities()` iterate ADT^A01, ORU^R01, ORM^O01, QRY^A19 — every one except QRY/A19 is a server-side write — and fire them via `wrap_mllp()` over raw sockets with no `args` namespace and no `--confirm` possible. Anyone importing these helpers from fuzzer / external tooling triggers admission / observation / order writes against the target. Also: `sock.send()` at line 317 is not `sendall()`, so larger payloads may silently truncate.
**Fix:** for `enum_host_info()`, probe with QBP^Q40 / a read-only QRY / an empty MSH-only message (never ADT^A01); for `utils.probe_server_capabilities`, either delete (unused by the main `hl7` class) or restrict to read-only types and require explicit `dangerous=False` opt-in.

## HIGH

### src/oida/protocols/opcua/scanner.py:361,394 + scanner.py:392-399 — L1 credential testing is fundamentally broken (every credential silently fails / every credential silently 'valid')
asyncua's `Client.set_user(name)` is a SYNCHRONOUS attribute setter returning None — `await client.set_user(None)` raises `TypeError: object NoneType can't be used in 'await' expression`. The TypeError is swallowed by broad `except Exception` at 364/403. Net result: L1 anonymous test ALWAYS reports DENIED regardless of server state; L1 credential brute reports ZERO valid credentials regardless of server state. Even after fixing the `await`, `set_user` only configures the next connect — `_test_authentication` never calls `await client.connect()` to actually authenticate, so any non-`BadUserAccessDenied` exception (or success-by-default) is counted as `valid_count += 1` and logged `VALID: {username}:{password}`. `_report_findings` at `scanner.py:663` then calls `self.report_credential(username, self.password, ...)` logging `self.password` (the original CLI arg) instead of the iterated `password` — N false-positive 'valid creds' all attributing the same self.password. Also scanner.py:361-365 'tests' anonymous access via `set_user(None)` and reports ALLOWED if no exception — never actually authenticates. The L2 NXC `_brute_force_credentials` (mixins/credentials.py:63-66) does it correctly; copy that pattern.
**Fix:** drop the awaits; perform `await client.connect()` inside the loop after `set_user`/`set_password`; treat connect-success as valid; inspect endpoint `UserIdentityTokens` for `Anonymous` (mirror `discovery.py:303 has_anonymous`).

### src/oida/protocols/opcua/mixins/fuzz.py:26 + proto_args_factory.py:378 — `--fuzz` flag does nothing (bool-vs-string type mismatch silently disables flag-driven fuzzing)
`fuzz.py:26` reads `fuzz_mode = getattr(self.args, "fuzz", "nodes")` and dispatches `if fuzz_mode in ("nodes", "all")` / `("methods", "all")`. But `--fuzz` is declared in `add_dangerous_options(include_fuzz=True)` as `action="store_true"`, so `args.fuzz` is `True` or `False`. `True in ("nodes", "all")` is False. `oida opcua <target> --fuzz --confirm` never fires either branch; dispatcher exits with `total_stats = 0/0/0/0/0`. Only `--fuzz-node X` / `--fuzz-method X` still works because they bypass the broken switch.
**Fix:** change `--fuzz` in OPC UA proto_args to `choices=["nodes","methods","all"]` (with `nargs='?'` and `const="nodes"`), or rewrite dispatcher around the bool flag.

### src/oida/protocols/opcua/mixins/methods.py:101,152 + proto_args.py:191-194 — `--call-method` invokes arbitrary OPC UA methods with NO `--confirm` gate
`_invoke_method` executes the user-specified method NodeId via `await parent.call_method(method_node, *call_args)` with zero safety check. Methods are arbitrary server code (Start/Stop/Restart/Reset/EmergencyShutdown — the module's own `DANGEROUS_KEYWORDS` list at helpers.py:26 enumerates these). Other dangerous OPC UA ops in this module DO gate (writes.py:23, files.py:280, fuzz.py:21). Help text does not even hint at the danger.
**Fix:** gate behind `--confirm`; surface 'dangerous operation' in help text.

### src/oida/protocols/opcua/mixins/subscriptions.py:113 + nxc_connection.py:312-313 — `--test-subscription-limits` performs DoS ramp against live server with NO `--confirm` gate
`_test_subscription_limits` deliberately opens 100 subscriptions in a tight loop against a production-OT endpoint to find a DoS limit. Help text (proto_args.py:274) explicitly says 'Test for subscription-based DoS vulnerabilities'. A defensive-security tool that knowingly attempts a DoS pattern must gate behind `--confirm`.
**Fix:** add `getattr(self.args, 'confirm', False)` check; mirror the snap7 `_require_confirm` reference.

### src/oida/protocols/opcua/mixins/subscriptions.py:18,64 + proto_args_factory.py:573 — `--duration` for `--subscribe`/`--subscribe-events` is silently ignored (arg-name mismatch)
Both sites read `getattr(self.args, "subscribe_duration", 10)`, but `add_monitor_options()` declares `--duration` → `args.duration`. `args.subscribe_duration` never exists, getattr defaults to 10 every time, `--duration 60` has zero effect on data-change / event subscriptions.
**Fix:** rename the lookup to `args.duration` and resolve the missing-default, OR add explicit `--subscribe-duration` in proto_args.py.

### src/oida/protocols/opcua/nxc_connection.py:196-211 + proto_args.py:67 — Default `--policy None` silently downgrades-then-upgrades to Basic256Sha256 when secure channel is requested
`policy_map` has Basic128Rsa15/Basic256/Basic256Sha256/Aes128/Aes256. CLI choices are `["None","Basic128Rsa15","Basic256","Basic256Sha256"]` with default `"None"`. `--mode Sign --policy None` hits `if requested_policy not in policy_map` → warns once → `policy_map.get("None", SecurityPolicyBasic256Sha256)` returns the default fallback. The inline comment explicitly says 'A defensive-security tool must NOT swap the requested policy under the user's feet' — yet that is exactly what happens for the default. Also the two Aes* policies ARE in policy_map but NOT in CLI choices → unreachable from CLI.
**Fix:** drop `None` from `--policy` choices (require a real policy when `--mode != None`), or fail loudly on (mode=Sign/SignAndEncrypt, policy=None) instead of silently substituting.

### src/oida/protocols/opcua/scanner.py:152-158 + helpers.py:142-148 — L1 scanner crashes on `opc.tcp://host:4840/path`; helpers builds invalid URL for bracketed IPv6 with explicit port
`get_target_info` parses `host.replace('opc.tcp://', '').split(':')`; for `opc.tcp://192.168.1.100:4840/path` yields `['192.168.1.100', '4840/path']` then `int('4840/path')` raises ValueError. Reachable from `connect`, `validate_target`, `_report_findings`. L2 helper `_parse_opcua_url` handles `/path` correctly — reuse it. Separately, `_normalize_opcua_url('[::1]:4840')` returns `'opc.tcp://[::1]:4840:4840'` (line 142-148 treats any bracketed input as 'just a host' and appends the default port). `_parse_opcua_url` then `rsplit(':', 1)` produces `host='[::1]:4840', port=4840`, leaving an embedded port that asyncua cannot resolve.
**Fix:** reuse `_parse_opcua_url` in scanner.py; in helpers, detect a closing `]` and re-check whether a port follows the bracket.

### src/oida/fuzz/monitors/http2.py:445-455 — `HTTP2Monitor.post_send` returns None instead of bool, breaking boofuzz crash detection
boofuzz `BaseMonitor.post_send` contract is explicit: 'You MUST return True if the Target is still alive. You MUST return False if the Target crashed.' Every code path returns None implicitly — bare `return` at line 451 (interval skip), fall-through after `if not self._check_alive(...): session.add_fail()` at 453-455. Session sees a falsy value on every test case → monitor either silently never marks crashes or marks every iteration as crashed depending on boofuzz version. Base `ProtocolMonitor.post_send` returns proper bools; this override regressed that. Also `pre_send` at line 457 is `pass` only — skips the `test_case_count` increment, breaking the % gating in post_send.
**Fix:** post_send returns `True` for skip-interval and the `_check_alive` bool otherwise; increment `test_case_count` in pre_send.

### src/oida/protocols/snap7/szl_parser.py:66,141 — SZL parser infinite loop when malformed PLC returns `record_len=0` (attacker-controlled DoS of monitor / audit / slot-scan)
`_parse_0x001c` (66) and `_parse_0x0011` (141): `while offset + record_len <= len(data):` advances `offset += record_len`. When responder returns `record_len = 0`, the loop never advances. Reachable via any path that does `SZLParser.parse(0x001C, ...)` / `parse(0x0011, ...)` on responder-controlled bytes — `_scan_single_slot` (slot_scan.py:127,142), `get_firmware_version` (device_info.py:162), `enumerate_szl` (block_operations.py:413). Multi-target scans against a hostile PLC lose one worker per target, eventually exhausting the pool. The early-exit `if rec_index == 0: break` at line 68/143 does NOT save us because the loop guard fires first when offset+0 == offset <= len(data) for any non-empty buffer.
**Fix:** add `if record_len < 2: result['error'] = 'invalid record_len'; return result` right after parsing the header at lines 55/129.

### src/oida/protocols/snap7/nxc_connection.py:200-219,396-398 — `--audit`/`--audit-quick` NOT in DANGEROUS_ACTIONS — runs unauthenticated write probes (and a brute-force) with no `--confirm` gate
DANGEROUS_ACTIONS lists every individual write/cpu-control/datetime-set flag but excludes `audit` and `audit_quick`. Dispatch calls `self.scanner.audit(self.conn, quick=quick)` with no `_require_confirm()`. Inside `audit()` (block_operations.py:675-724) two write-touching steps run unconditionally: step [4/7] `_test_write_access` performs real `conn.write_area(MK/PA, 0, 0, ...)` (security.py:343-364) — same-byte write, but modbus's `_test_write_access_destructive` is already flagged as a security concern in this same report; step [7/7] (skipped only in audit_quick) calls `bruteforce_password` dispatching the full default-password wordlist. Both are exactly the operations the framework's `--confirm` gate exists to guard. On a real PLC the audit can trip account-lockout and emit unauthenticated writes to process outputs (PA).
**Fix:** add `audit` (and arguably `audit_quick` for the write probe) to DANGEROUS_ACTIONS; lift the brute-force step out of `audit()` so it is opt-in.

### src/oida/protocols/snap7/nxc_connection.py:669,744,788,837 — Three fuzz helpers and `check_dependencies` use module-level stdlib `logger` instead of `self.logger` (refactor-artefact text included)
`_fuzz_db._inner.write_fn` (669), `_fuzz_memory.write_m` (744), `write_q` (788), and static `check_dependencies` (837) all do `logger.debug(f"Failed to get write_data: {e}")` — referring to module-level `logger = logging.getLogger(__name__)` at line 18. Works only because of the shadow, but BYPASSES ICSLogger entirely (no host/port prefix, no `-vvv` gating, no JSON-log integration). Garbled message text (`"Failed to get write_data"` despite surrounding code being `self.conn.db_write(...)`) is the same refactor-tool artefact already flagged for ads/mms/hart/iec104 — but on snap7 it ALSO violates the 'self.logger only' rule via stdlib `logging`.
**Fix:** replace each `logger.debug(...)` with `self.logger.debug(...)` (closures capture self); for `check_dependencies` (staticmethod) drop the debug call or route through the scanner. Fix message text to describe what actually failed.

### src/oida/protocols/snap7/mixins/security.py:43-53,322-326 — `_check_protection_level` treats 'all S7Protection fields == 0' as 'No protection - Full access' (false-positive CRITICAL finding when get_protection() returns zeroed struct)
`has_protection = any(protection_info.values())` is False both when the PLC really has no protection AND when get_protection() returns zeroed fields (some firmwares, communication processors, soft-PLC stack do this on unauthenticated queries instead of raising). Code assigns `level = 1, desc = 'No protection - Full access'`, and `_analyze_security` emits `security_finding('Insecure configuration', detail='protection_level=1')` plus 'No protection - Full read/write access'. Same `None/zero == success` anti-pattern flagged in bacnet (DCC, BBMD, OOS). On any S7-CP / soft-PLC / partially-authenticated S7-1500 target this prints a false 'level 1 - full access' header in every report.
**Fix:** distinguish 'unable to determine' from 'verified open' — return level=None when struct is all zeros AND no successful side-channel write probe has confirmed access; downgrade security_finding to `protection_level_unknown`. Optionally cross-check with a benign read probe.

### src/oida/protocols/modbus/mixins/sunspec.py:738-741 — SunSpec security assessment overrides 'r' access with 'rw' before checking → false-positive 'writable control' findings
`_sunspec_assess_security` reads `access = reg_info.get('access', 'r')`, then immediately does `if access != 'rw' and expected_access == 'rw': access = expected_access  # trust the spec`. Whenever device-specific map declares a register read-only but SUNSPEC_CRITICAL_CONTROLS says it CAN be writable, code overwrites actual access mode to 'rw' and reports it as 'writable control exposed' on the next `if access == 'rw':` branch. Any SunSpec inverter triggering this path emits CRITICAL `security_findings` like 'Inverter connect/disconnect register (Conn) is writable' even on devices where the register is documented read-only. Pollutes every solar engagement report (same way BACnet false-positives do for BACnet).
**Fix:** drop the `access = expected_access` override; only emit when live decoded register reports `access='rw'` OR perform a non-destructive write-back probe before flagging.

### src/oida/protocols/modbus/decoder.py:808-836 — `load_register_map()` accepts arbitrary paths from `--register-map` → arbitrary file read
`load_register_map(map_name)` first runs `if os.path.exists(map_name): open(map_name, 'r')` with no sanitisation. `map_name` flows from CLI `--register-map`. `oida modbus host --register-map /etc/shadow --list-names` opens the arbitrary file. JSON parse fails noisily but the resulting `json.JSONDecodeError` message confirms file readability/contents and the file handle is opened before validation. Downstream recursive glob path (line 833) also accepts a single forward-slash-bearing `map_name` that resolves under any search path.
**Fix:** require map_name to match `[A-Za-z0-9_/-]+` (no leading `/`, no `..` segments); reject absolute paths; only allow paths that resolve inside a bundled search dir via `Path.resolve().is_relative_to()`.

### src/oida/hooks/rthook_hl7apy.py (entire file) — Runtime hook is never wired into any PyInstaller build (orphan file) AND empty marker directories don't actually fix the documented hl7apy bug
The file's only purpose is to be passed via `runtime_hooks=[...]` in a PyInstaller .spec or `--runtime-hook` on CLI. Repo-wide grep (pyproject.toml, scripts/, .github/workflows/, all *.spec, all docs) finds ZERO references to `rthook_hl7apy`, `runtime_hook`, `runtime-hook`, or `runtime_hooks`. No `.spec` file exists. The hook is dead code that does nothing at build or run time, while pretending in its docstring to fix a PyInstaller one-file bundle bug. Additionally, hl7apy.__init__._discover_libraries() builds SUPPORTED_LIBRARIES from `os.listdir(<hl7apy dir>)` filtered by `v2_` prefix — but actual sub-package code (`hl7apy.v2_5_1.tables`, `.segments`, several MB of generated Python) must be collected separately by a PyInstaller hookspec (`collect_submodules('hl7apy')`). If those are on disk under `_MEIPASS/hl7apy/v2_*/`, `os.listdir` already finds them and the hook is unnecessary; if frozen into PYZ (the actual one-file failure mode), importing `hl7apy.v2_5_1` works via bundle import hooks regardless of empty marker dirs. Empty directories alone do not fix the documented problem.
**Fix:** either wire into a PyInstaller `.spec` + add a smoke test that fails the build if the hook stops being applied, or delete the file. Replace with a proper `pyinstaller-hooks-contrib`-style hookspec that uses `collect_submodules`.

### src/oida/pcap/passive/mssql.py:523-525 + src/oida/pcap/passive/fins.py:662 — Cleartext credentials emitted at INFO to console / json-log on every captured Login7 / FINS password
`mssql.py:523-525` logs `self.logger.info(f"MSSQL credential: {username}:{password} db={database} ({src_ip} -> {dst_ip})")` for every Login7 with cleartext SQL auth. `fins.py:662` has equivalent `self.logger.info(f"FINS: password={password} from {src_ip} to {dst_ip}")`. Both fire at INFO — default level of `get_module_logger` (used when listener is instantiated without an nxc_logger, i.e. the pcap pipeline default). Every plaintext MSSQL password and FINS access-password observed on the wire gets written to the operator console AND any `--json-log` file BEFORE the harvest stage runs — without any `--debug` opt-in. Same leak pattern flagged for fhir brute-force loop and `--debug-dumping-CLI-args`. Credential disclosure into structured engagement logs / screenshots / tickets.
**Fix:** drop the password (`f"MSSQL credential captured: {username}@{dst_ip}"`) or move both to `self.logger.debug(...)`; cleartext is already preserved in `self.credentials` and surfaces in harvest tables + the existing `credential_alert` with appropriate scope.

### src/oida/protocols/ethernetip/mixins/attacks.py:135-145 — `AttacksMixin` reports timeout / empty response as attack SUCCESS (false-positive CRITICAL findings in every blocked-attack run)
`_send_attack_command` sets `result['success'] = True` on (a) `response == b''` from `sock.recv` (135-139) and (b) `TimeoutError` (141-145). Both wrapped in `self.logger.warning('… device may have crashed')` but every consumer of the result dict (security_analysis, exports, scan summary) reads `success=True` and reports a successful CPU STOP / CPU CRASH / Ethernet CRASH against any TCP-filtered / idle / firewalled host. Same `None == success` pattern as BACnet flagged elsewhere but here pollutes attack-class findings. Per standard pentest convention, no response from a destructive command is INCONCLUSIVE, not SUCCESS.
**Fix:** introduce `inconclusive=True` field; require an explicit positive response (e.g. CIP `general_status == 0` or a follow-up `_list_identity` confirming reachability change) before marking `success=True`.

### src/oida/protocols/ethernetip/scanner.py:826-830,868-870 — `--fuzz` and `--reset-ethernet` execute destructive writes without `--confirm` gate
`_discover_classes_and_attributes` runs `_fuzz_attributes` (issues `Set_Attribute_Single` writes with random payloads to every non-blacklisted writable attribute) when `self.fuzz` is set, requiring only `not self.read_only` — no `self.confirm` check. FuzzMixin blacklist protects 8 specific class IDs but a writable QoS / vendor / unused attribute is fuzzed without operator opt-in. `--reset-ethernet` (scanner.py:868-870) skips the `--confirm` gate even though `_reset_ethernet` calls a destructive CIP `Reset` service on Identity 0x01. Only `--cpu-stop` and `--crash-ethernet` honor `--confirm`. `_test_write_access` at 821 also runs writes with only `not self.read_only`. Help text for `--write` / `--fuzz` does not mention `--confirm`.
**Fix:** gate all four (`--fuzz`, `--reset-ethernet`, `--write`, the dead `--crash-cpu` re-export) behind `self.confirm` consistently with the existing CPU-stop / crash-ethernet pattern; update help text.

### src/oida/protocols/ethernetip/mixins/write_test.py:144-194 + mixins/class_explorer.py:229-231,281-283 — `_determine_permission` never receives `param_instance_map`; Parameter Object permission path is permanently dead
`_determine_permission(... param_instance_map: Optional[dict] = None)` only consults the Parameter Object descriptor inside `if use_param_obj and param_instance_map:`. Every call site invokes it WITHOUT `param_instance_map`, so the branch is unreachable. The user-facing message `Using Parameter Object descriptors for permission detection` (class_explorer.py:88) is a lie — the function always falls through to write-test (requires `--write`) or returns `?`. Without `--write`, every attribute permission is reported as `?` even on devices that fully implement Parameter Object descriptors.
**Fix:** build `param_instance_map` in class_explorer (mapping `(class_id, instance, attr_id) → param instance`) once before the attribute loop, pass into both calls; or remove the dead parameter and rewrite the docstring/banner.

### src/oida/protocols/ethernetip/mixins/security_analysis.py:128-134 — `SecurityAnalysisMixin.writable_count` counts dict keys, not writable attributes — every finding reports `2 × num_classes`
`writable_count = sum(len(attrs) for attrs in results['write_test_results'].values())`. Each value is the per-class dict `{class_attributes: {...}, instances: {...}}` (built in WriteTestMixin._test_write_access at write_test.py:264). `len(attrs)` returns 2 per class (or 1 if only one key), regardless of how many attributes are actually writable. Downstream finding `Writable access — N CIP attributes are writable` reports `2 × num_classes`. A device with 0 writable attributes still reports `2 attributes writable` if any class made it into `write_test_results`.
**Fix:** descend into nested dicts: `sum(sum(1 for a in cls.get('class_attributes', {}).values() if a.get('writable')) + sum(1 for inst in cls.get('instances', {}).values() for a in inst.values() if a.get('writable')) for cls in results['write_test_results'].values())`.

### src/oida/protocols/ethernetip/mixins/security_analysis.py:51-59 — `SecurityAnalyzer.access_control` reported True purely because `--write` was not used
`access_control: len(results.get('write_test_results', {})) == 0` is True whenever scanner did NOT run write testing (default — `--write` is opt-in). SecurityAnalyzer treats `access_control: True` as a positive control. Every default-mode scan (no `--write`) reports the device as having access control purely because the tool did not look. Inverts the meaning of the flag and produces false-negative findings.
**Fix:** report as Unknown / None when `--write` was not run; always evaluate against an actual write rejection.

### src/oida/protocols/ethernetip/scanner.py:616-619 — ListIdentity always emits spurious `Anonymous access allowed` security finding
`_discover_ucmm_commands` unconditionally logs `security_finding('Anonymous access allowed', detail='Device identity accessible without authentication via ListIdentity')` for every successful ListIdentity. ListIdentity (ENIP 0x0063) is by ODVA Vol 2 spec an UCMM command — supposed to be unauthenticated on every CIP-compliant device; protocol's equivalent of LLDP/CDP/SSDP. Reporting it as 'Anonymous access allowed' pollutes every customer report with a CRITICAL/HIGH false-positive that is by-design protocol behavior.
**Fix:** drop the finding (this is normal protocol behaviour) or downgrade to INFO with detail clarifying it is per-spec.

### src/oida/protocols/bacnet/mixins/security.py:104-136,138-161,70-102 — `--assess` and `--test-write`/`--enumerate-writable` issue real WriteProperty without `--confirm` (BAC0 path)
`_handle_security_assessment()` (invoked by `--assess`, and by `--full` shortcut at nxc_connection.py:194-199) unconditionally calls `_handle_test_write()` and `_handle_enumerate_writable()`. Both helpers issue real `self._write_property(...)` write-back of presentValue (lines 122-124 and 150-152) with no `getattr(self.args, 'confirm', False)` guard. Dispatcher at nxc_connection.py:166-170 also wires `--test-write` and `--enumerate-writable` directly with no gate. Separate from the already-documented `--brute-force`/`--test-dcc` missing-gate (HIGH §266) — this is the BAC0 path. On a permissive target, `oida bacnet host --assess` (no `--confirm`) sends write traffic. BACnet's priority array semantics mean the write registers at default priority 16, bumping any value the controller had there.
**Fix:** add `getattr(self.args, 'confirm', False)` check in `_handle_test_write`/`_handle_enumerate_writable`; mirror the gating used on the bacpypes3 path (`_bacpypes3_test_oos` at line 918).

### src/oida/protocols/bacnet/proto_args.py + mixins/{state,monitoring,files}.py — Six dispatcher-read CLI flags never declared in proto_args
Mixin code reads CLI attributes proto_args never registers: (1) `--cov-lifetime` and `--cov-duration` read by `monitoring.py:530,581` (SubscribeCOV) — operator cannot tune subscription lifetime or listen duration; stuck at hardcoded 300s/30s. (2) `--file-chunk-size` and `--file-access-method` read by `files.py:154-155` for AtomicReadFile reads. (3) `--read-range-count` read by `monitoring.py:632` for trend log pulls. Operator running `oida bacnet host --cov --cov-lifetime 60` gets argparse 'unrecognized arguments' error, despite the code path clearly expecting these flags. (Note: `--control-points`/`--values-only`/`--full-properties`/`--object-types` ARE registered at lines 185-188, contrary to a raw-gap claim.)
**Fix:** declare each flag in proto_args.py (likely as SUPPRESS-hidden advanced options matching existing convention).

### src/oida/protocols/bacnet/nxc_connection.py:219-223,443 + proto_args.py:115,199 — `--assess-network` shortcut sets `enum_networks` but dispatcher reads `networks` → remote-network discovery never triggers
`_apply_shortcuts` sets `self.args.enum_networks=True` when `--assess-network` is passed. proto_args.py registers BOTH `--networks` (line 115, dest='networks') AND `--enum-networks` (line 199, hidden SUPPRESS, dest='enum_networks'). But dispatcher at 443-444 reads `args.networks`. Shortcut sets the wrong attribute; `--assess-network` does discover BBMD/FDT/routers but silently SKIPS the `discover_networks` call. User running `--assess-network` gets less than `--networks` alone.
**Fix:** drop the dead `--enum-networks` flag entirely; have shortcut write `self.args.networks = True` (matching other shortcut writes that target user-facing dest names).

### src/oida/protocols/discovery/vrrp.py:156,169,183-184 — VRRP master/backup classification inverted on every observed advertisement
`is_master = priority == 255` is wrong twice over. (1) Per RFC 5798, priority 255 is reserved for address owner — many deployments never use 255 (100-254 is the norm). (2) **Only the master sends VRRP advertisements** (RFC 5798 §6.2: backup routers do not transmit until takeover). Every captured advertisement is by definition coming from a master, regardless of priority. Current classifier labels almost every real-world VRRP master as 'Router (VRRP Backup)' (line 169) and stamps `state_name='Backup'`, `is_master=False` into `vrrp_data`. Operator concludes there are no active VRRP masters on the segment when there is exactly one per VRID.
**Fix:** treat any observed advertisement as `is_master=True` (sender is the active master at observation time); optionally cross-check against v2 state byte; never derive master/backup state from priority alone.

### src/oida/protocols/discovery/{eigrp_passive,rip_passive,pim_passive}.py — EIGRP/RIP/PIM passive listeners crash silently on cross-listener device merges
All three keys the device dict by `src_mac` (eigrp_passive:292, rip_passive:182, pim_passive:240). Same MAC is also keyed by ARP/IPv6/Ethernet passive listeners using bare MAC — so a `DiscoveredDevice` already exists with protocol-specific `*_data` fields set to None. When the routing-protocol listener fires, the else branch tries `.eigrp_data.get(...)` / `.rip_data[...] = ...` / `.pim_data.get(...)`. Because the field is None, raises `AttributeError`/`TypeError`. Caught by outer broad except → silently debug-logged. End result: when devices are discovered by EIGRP/RIP/PIM *first*, things work; when ARP/IPv6/Ethernet sees them first, all routing-protocol enrichment is silently lost.
**Fix:** in each `_update_device`, if existing record has `*_data is None`, initialise with the new dict (taking the new-route branch).

## MEDIUM

### src/oida/shared/file_carving_common.py:157-169,250-267 vs src/oida/protocols/discovery/file_carving.py:150-185 — Inconsistent path-traversal hardening: pcap listener inherits unsafe base, discovery overrides
`FileCarvingMixin._save_file` (157-169) and `save_files` (250-267) use bare `os.path.join(self.output_dir, filename)` with no path-traversal guard. `discovery/file_carving.py:150-185` overrides both to add `safe_output_path(filename, output_dir)` and explicit `ValueError` branch. `pcap/passive/file_carving.py` does NOT override — silently inherits unsafe versions. Today `filename = {md5_hash}{extension}` (hex-only hash, code-defined extensions) so neither is attacker-controlled, but the asymmetric defense-in-depth is a refactor footgun (any future change letting a network-derived field into the filename only gets caught by the discovery branch).
**Fix:** push `safe_output_path` into the base mixin; drop the discovery override.

### src/oida/shared/file_carving_common.py:168-169,263-264 — Save failures logged at DEBUG, hiding disk-full / permission errors from default `-o` runs
`_save_file` and `save_files` swallow `Exception` into `self.logger.debug(...)`. User invoking with `--output-dir` won't see ENOSPC, EACCES, or read-only-filesystem failures unless they bump to `-v`. The `info(f"Saved {count} files to {output_dir}")` line then misleadingly reports the count of files that *succeeded* with no warning others were silently dropped. Discovery override has the same pattern.
**Fix:** log failed saves at WARNING; surface failure count in the final summary.

### src/oida/shared/igmp_constants.py:35 — `MULTICAST_GROUPS` has a CIDR key (`"239.192.0.0/14"`) that no consumer can match
Line 35 has `"239.192.0.0/14": "Organization-Local Scope",  # Range` as a dict key. All 16 call sites in `protocols/discovery/igmp.py` and `pcap/passive/igmp.py` use exact-match lookups (`MULTICAST_GROUPS.get(group_address, "")`), which will never match `239.192.0.X`. Comment `# Range` shows author was aware but subnet lookup was never implemented. Dead data masquerading as functional.
**Fix:** remove the entry, or implement `ipaddress.ip_network`-based fallback in consumers.

### src/oida/hooks/rthook_hl7apy.py:13-26,27-29 — Hardcoded hl7apy version list silently goes stale; unguarded `os.makedirs` on `_MEIPASS` can crash frozen binary startup
Lines 13-26 list `v2_1` through `v2_8_2` literally. If hl7apy ships `v2_8_3` or `v2_9`, hook keeps running cleanly but the new library is missing from SUPPORTED_LIBRARIES in the frozen binary — silent feature loss. Lines 27-29 call `os.makedirs(d, exist_ok=True)` without try/except. Runtime hooks execute very early — before logging/exception handling. If `_MEIPASS` is on a noexec/read-only mount (hardened CI runners, AppImage-style remounts, corrupted extraction) this raises PermissionError/OSError and the entire frozen `oida` binary fails to start with an opaque traceback for users who never invoke any HL7 command.
**Fix:** derive the list from `pkgutil.iter_modules(hl7apy.__path__)` at build time (a real PyInstaller hookspec) or pin to a specific hl7apy version with a CI check. Wrap the loop in `try/except OSError: pass`.

### src/oida/fuzz/monitors/industrial.py:310-323 — `IEC104Monitor` logs `self.baseline_response.hex()` on mismatch but format string was meant to reference the prior baseline (`baseline_raw`)
After computing `baseline_raw = self.baseline.raw_response or self.baseline_response`, mismatch branch logs `self.baseline_response.hex()` directly (lines 316, 321) instead of `baseline_raw.hex()`. Author introduced `baseline_raw` precisely to handle the dual-source case, then ignored it in format strings. On first check the comparison is False so unreachable today, but any refactor that inverts order (compare-then-establish) dereferences a `None self.baseline_response` and raises AttributeError.
**Fix:** use `baseline_raw.hex()` consistently in both log strings.

### src/oida/fuzz/monitors/infrastructure.py + registry.py — Use stdlib `logging.getLogger` instead of ICSLogger, bypassing host/port prefix and -vvv gating
`infrastructure.py:9-11` and `registry.py:12-14` both do `import logging; logger = logging.getLogger(__name__)` with module-level `logger.debug(...)` at multiple sites (infrastructure:117,124,217,223; registry:145). Every other monitor uses `self.logger` from ICSLogger via ProtocolMonitor base. Same bypass already flagged for hart and goose. For infrastructure.py the calls are inside instance methods where `self.logger` is available. For registry.py the calls are in module-level helpers.
**Fix:** infrastructure.py — replace with `self.logger.debug(...)`. registry.py — use `from ..utils.ics_logger import get_module_logger` or drop the debug logging.

### src/oida/fuzz/monitors/medical.py:78-87 — `HL7Monitor._send_message` has unbounded recv loop, susceptible to memory exhaustion from non-terminating target
`while True: chunk = sock.recv(1024); response += chunk; if MLLP_END in response: break`. A fuzz target that sends a stream without ever emitting the `0x1c 0x0d` MLLP terminator (exactly what a crashing/malformed HL7 daemon can exhibit) accumulates indefinitely until socket timeout (default 5s) trips. On a fast LAN: hundreds of MB resident in monitor process. Monitor's whole purpose is health-checking misbehaving servers; the timeout is the only thing saving us.
**Fix:** cap `len(response)` at e.g. 64 KB (HL7 messages typically <8 KB); break with a warning if exceeded.

### src/oida/fuzz/monitors/http2.py:295-297 — `HTTP2Monitor.protocol_errors` grows unbounded across a long fuzz session (O(n²) per fetch)
`new_errors = [e for e in data if e not in self.protocol_errors]; self.protocol_errors.extend(new_errors)`. No cap. Over a multi-hour session the diagnostic endpoint can return arbitrarily many error records, all kept forever AND linearly-scanned (`in` on list of dicts is O(n) per element → O(n²) per fetch). `get_error_summary()` only returns the last 10, so retaining full history serves no purpose.
**Fix:** bound the list (e.g. `self.protocol_errors = self.protocol_errors[-1000:]` after extend) or use `collections.deque(maxlen=1000)`.

### src/oida/pcap/passive/mssql.py:1240 — MSSQL SSPI/Kerberos detection has duplicate predicate — Kerberos token never matched
`elif buf.startswith("6082") or buf.startswith("6082"):` — both branches of the `or` test the same literal, second arm is dead code. Looks like copy-paste artefact where the second prefix (likely `"6982"` / `"6083"` for SPNEGO continuation tokens, or `"4E45474F"` for `NEGO`) was forgotten. Functional impact: SSPI tokens matching first SPNEGO DER prefix still get labeled `SSPI/Kerberos` so the bug doesn't strictly under-report, but the refactor intent (catch a second variant) is lost.
**Fix:** delete the duplicate clause and the misleading comment, or supply the intended second prefix.

### src/oida/pcap/passive/fins.py:440,454 — Garbled refactor-artefact debug strings in FINS memory-op exception handlers
Two of four exception handlers in `_process_memory_op` print the surrounding `if`-statement text instead of describing what failed: line 440 `self.logger.debug(f"if isinstance(area_raw, str) and area...: {e}")` and line 454 `self.logger.debug(f"if isinstance(addr_raw, str) and addr...: {e}")`. Same auto-rewriter pattern called out for `protocols/discovery/*.py` and explicitly listed for `discovery/fins.py:154`, NOT this pcap file. With `-vvv --debug`, log obscures what was being parsed (FINS memory area code / address) when the int parse blew up. Other two handlers in the same function (line 263, 462) describe correctly — these two were missed.
**Fix:** replace with `self.logger.debug(f"FINS: memory area code parse failed (raw={area_raw!r}): {e}")` and the analogous version for `addr_raw`.

### src/oida/pcap/passive/{knx,mysql}.py — Module-level `logging.getLogger(__name__)` in two pcap/passive listeners bypasses ICSLogger
`knx.py:40-42` and `mysql.py:69-71` each do `import logging` + `logger = logging.getLogger(__name__)` and use module-level `logger.debug(...)` (knx:189,503; mysql:1085) inside instance methods that already have `self.logger`. Same anti-pattern called out for `protocols/hart/*`, `protocols/can/constants.py`, `protocols/ethercat/*`, `protocols/goose/__init__.py` — but the audit batch explicitly noted (CODE_REVIEW.md:735) individual pcap-passive listeners were not surfaced. fins.py and mssql.py do NOT have this issue; only knx.py and mysql.py do.
**Fix:** replace each `logger.debug(...)` with `self.logger.debug(...)`; drop module-level `import logging` and `logger = ...`.

### src/oida/pcap/passive/fins.py:405,656-657 — FINS `_extract_password` mis-attributes plc_ip/client_ip when password field is dissected on a response frame
`_extract_password(omron, src_ip, dst_ip)` is called with raw `src/dst` and the function unconditionally stores `plc_ip=dst_ip, client_ip=src_ip`. For genuine Access-Right-Acquire (0x0801) requests this is correct (src=client). But Wireshark's omron dissector exposes `omron.password` on every frame whose body carries the password field — including server-side echo / response frames or frames whose ICF.DTB resolves to response. In those cases the credential is recorded with PLC and client IPs swapped, leading to wrong attribution in harvest table and confusing `'FINS: password=... from <PLC> to <client>'` log lines. Edge case in practice but cheap to fix.
**Fix:** pass `is_response` through; skip extraction on responses OR swap `plc_ip`/`client_ip` when `is_response` is True. Same change applies to the dedup call at line 652.

### src/oida/protocols/modbus/scanner.py:643-690 — `_test_write_access_safe` verifies readback against the value just written → guaranteed-true false positives
Writes `original_value` back, then reads and compares readback against `original_value` (lines 670, 679). Because the value being written IS the value just read, comparison succeeds for ANY device that returns the same value on two consecutive reads — including read-only devices, devices that silently drop writes, and mock servers that always return the same data. 'Writable' classification therefore depends entirely on `not write_result.isError()` — same fragile signal the existing MEDIUM finding flags for `_test_write_access_destructive`. Docstring claims this 'confirms write capability without modifying any data' — it confirms nothing.
**Fix:** require the readback to differ between an initial read and a post-write read, OR drop the misleading docstring and downgrade label to `write_accepted`.

### src/oida/protocols/modbus/scanner_mixins/discovery.py:124-128 — `_discover_units` mixes int unit_id keys with string `'high_response_count'` / `'high_response_warning'` keys → corrupts iteration
After full scan, when `len(units) > 200`, code injects `units['high_response_count'] = True` and `units['high_response_warning'] = '...string...'` into the same dict that otherwise maps `int unit_id -> {active, last_seen, ...}`. NXC caller (`nxc_connection.py:423`) already filters with `[k for k in units.keys() if isinstance(k, int)]` to avoid the strings, but `self.results['data']['units']` is serialised verbatim into JSON output and other consumers iterate items expecting `(int, dict)` pairs. Mixing keytypes also breaks `sorted(units.keys())` (Python 3 refuses mixed str/int sort).
**Fix:** return `{'units': {int_id: info, ...}, 'high_response_count': bool, 'note': str}` as a structured envelope.

### src/oida/protocols/modbus/mixins/canopen.py:140-146 — `_handle_canopen_write` else-branch dereferences `result.get()` when `result` may be None → AttributeError on failure
`if result and not result.get('error'):` else `self.logger.fail(f"CANopen SDO write failed: {result.get('error', 'Unknown error')}")`. When `result` is None (the missing-helper case already flagged in CRITICAL §57; also any future implementation that returns None on transport error), the else-branch enters and `result.get(...)` raises AttributeError — masking the real failure with a misleading exception.
**Fix:** `err = (result or {}).get('error', 'Unknown error')` before the format, or branch separately on `result is None`.

### src/oida/protocols/modbus/nxc_connection.py:477; src/oida/protocols/modbus/mixins/read_write.py:186 — Map `default_unit_id` silently overrides user-specified `-u 1` (treats explicit default as 'unset')
Both sites use `if unit_id == 1 ... use map's default_unit_id`. Argparse defaults `unit_id` to 1; code cannot distinguish 'user passed `-u 1`' from 'user passed nothing'. User explicitly running `oida modbus host -u 1 --register-map vfd/abb-acs880` against an ABB device whose map declares `default_unit_id: 5` silently scans unit 5, returning empty / wrong-device data with no warning. Same antipattern called out for `--hl7-version 2.5`.
**Fix:** change argparse default to None (or track explicit `--unit-id-user-set` flag); only fall back to map default when namespace attribute is None.

### src/oida/protocols/modbus/validate_maps.py:765-779 — Address-collision check defaults FC=3 for every section, producing both false positives and missed collisions
Inside per-register loop, `fc = reg_def.get('function_code', 3)` is evaluated regardless of which `REGISTER_SECTIONS` section the register lives in. A coil definition under `coils:` without explicit `function_code: 1` defaults to FC=3, so it collides in `addresses_by_fc[3]` with same-address holding registers (false-positive warning) AND legitimate collisions across two `coils:` entries are still flagged but mis-attributed.
**Fix:** when iterating `REGISTER_SECTIONS`, derive natural FC per section (`coils:`→1, `discrete_inputs:`→2, `holding_registers:`/`registers:`→3, `input_registers:`→4) as default before falling back to `function_code`.

### src/oida/protocols/modbus/import_maps.py:467,499-509 — `--dry-run` flag parsed and reported but never honored — files written regardless
`parser.add_argument('--dry-run', action='store_true', help='Show what would be imported')` is registered; `args.dry_run` is read at line 499 to log 'DRY RUN - no files will be written'; then `import_nymea_directory(args.source, output_dir)` / `import_mbmd_directory(...)` are called unconditionally. Neither helper accepts `dry_run`; both unconditionally `json.dump(oida_map, f, indent=2)` to disk. User believes nothing was written and is surprised by `register_maps/imported/...` populated on disk.
**Fix:** thread `dry_run=args.dry_run` through both helpers; gate the `open(out_path, 'w')` block.

### src/oida/protocols/modbus/import_maps.py:462,503-509 — `--format solarman` advertised in argparse choices but dispatch falls through to 'Unknown format'
argparse declares `choices=['nymea', 'mbmd', 'solarman', 'auto']`. Dispatch handles only `nymea` and `mbmd`; `solarman` branch falls through to `logger.error('Unknown format: %s', fmt); sys.exit(1)`. Solarman parsing exists in `parse_solarman_yaml`/`import_solarman_directory` (lines 311, 394) but is wired into the SEPARATE module `convert_maps.py`. User running `python -m oida.protocols.modbus.import_maps /tmp/solarman --format solarman` per the example in the docstring (line 14) hits the dead branch.
**Fix:** delete `solarman` from import_maps choices and example docstring, OR dispatch through `import_solarman_directory`.

### src/oida/protocols/modbus/mixins/monitor.py:56,104; src/oida/protocols/modbus/mixins/raw_function_codes.py:110 — Direct file writes bypass export_utils — operator-supplied paths land outside the export pipeline
`monitor.py:56` does `open(log_file, 'a')` and writes CSV-shaped log with no sanitisation, no `safe_output_path()`, no `get_export_path()`. `raw_function_codes.py:110` does `open(filepath, 'wb')` for `--save-response` likewise. Existing CODE_REVIEW flagged the anti-pattern generically for discovery/ethernetip but did not enumerate modbus instances; both call sites take user-controlled paths.
**Fix:** route through `get_export_path()` / `safe_output_path()` from `utils/export_utils.py` (binary-friendly variant for response dumps); add traversal guard against `..` in user-supplied filenames.

### src/oida/protocols/modbus/{sunspec,custom_fc,validate_maps,fuzz,canopen,identification}.py — Additional garbled refactor-artefact debug strings (modbus deep pass)
Same refactor-tool artefact already flagged for discovery/ads/hart/iec104/mms; modbus copies were missed by the original sweep:
- `mixins/sunspec.py:69` `f"with open(json_file, r) as f:: {e}"`
- `mixins/sunspec.py:99` `f"Optional import math not available: {e}"` (wrong context — wrapping try/except is for a NaN check, not `import math`)
- `mixins/sunspec.py:167` `f"Operation failed: {e}"`
- `scanner_mixins/custom_fc.py:118,160` `'decode failed: %s'` repeated in TypeError-fallback AND outer Exception branches of `send_custom_fc`
- `validate_maps.py:834` `f"with open(json_file) as f:: {e}"`; line 890 `f"with open(r.path) as f:: {e}"`
- `mixins/fuzz.py:136` `f"self.conn.write_register(addr, origin...: {e}"`; lines 289,296,305 three `f"yield self._pack_as_registers(...): {e}"`
- `mixins/canopen.py:160` `f"Failed to get node_id: {e}"` for what is actually subindex/index parsing
**Fix:** rewrite each as a short, human-readable description of the failing operation.

### src/oida/protocols/modbus/scanner_mixins/identification.py:336-441 — `_read_mei_raw` uses `client.socket.send` (not sendall), mutates socket timeout without restoring, holds no socket lock
Three latent issues in the fallback path: (1) line 369 `client.socket.send(mbap + request)` is a short-write opportunity on TCP — `sendall()` is the correct primitive when sending a complete frame. (2) Line 372 `client.socket.settimeout(self.timeout)` permanently changes the client socket timeout for every subsequent pymodbus operation in the session — no `try/finally` restoring previous value. (3) No lock around the socket while writing/reading raw bytes, so concurrent operations through the same client (monitor + identify, fuzz + identify) can interleave bytes between raw MEI and pymodbus framed traffic. The TODO at 345-348 acknowledges the socket access is fragile but doesn't mention these specific footguns.
**Fix:** switch to `sendall`; wrap timeout change in `try/finally`; either skip raw fallback when pymodbus client is shared concurrently or add a lock.

### src/oida/protocols/modbus/scanner_mixins/diagnostics.py:55-57 — `--diag echo --diag-data` crashes scanner with ValueError on non-hex input
`if diag_data: echo_data = int(diag_data, 16)` with no try/except. `oida modbus host --diag echo --diag-data notahex` raises ValueError from inside `_run_diagnostics`; bubbles through `_handle_diagnostics`, caught by outer scanner exception handler, surfaces as generic 'scan failed' with no indication that `--diag-data` was malformed.
**Fix:** try/except ValueError; `self.logger.fail(f'Invalid --diag-data hex value: {diag_data}')` and bail.

### src/oida/protocols/modbus/scanner_mixins/diagnostics.py:104-111,120-122 — Diagnostics echo `match` reports False when pymodbus changes attribute name → false negative on capable devices
`received = getattr(result, 'message', None) or getattr(result, 'data', None)` returns None if pymodbus renames the attribute (happened twice between 3.5/3.8/3.12). Then `'match': test_data == received` → False; reports 'FAIL' for an otherwise-working echo. Same pattern at `_diagnostic_read_register`.
**Fix:** when both attributes are None, return `{'sent': test_data, 'received': None, 'match': None, 'error': 'response attribute missing'}` so the caller can distinguish 'device failed echo' from 'we failed to parse response'.

### src/oida/protocols/modbus/device_db.py:16,27,44 — `device_db.py` uses stdlib logging import and module-level `global _device_db` cache
Two style violations combined: (1) `import logging` at line 16 is a dead import — the module uses `get_module_logger(__name__)` from ICSLogger and never references stdlib logging; (2) line 44 uses `global _device_db` for a module-level cache, which the project's automated review script flags as a CRITICAL pattern. Cache pattern is defensive (avoid re-reading 500-device JSON on every lookup) but should use a sentinel class attribute or `functools.lru_cache`.
**Fix:** drop the dead `import logging`; convert to `functools.lru_cache` on `load_database()` so the variable isn't a module-mutable global.

### src/oida/protocols/discovery/network.py:110,143 — Garbled refactor-artefact debug strings in network.py (missed by original sweep)
Same refactor regression already flagged for enrich/dhcp/infra/ntp/core/fins/stats in HIGH §117-126, but network.py was not listed. Two sites: line 110 `logger.debug(f"Failed to get mreq: {e}")` inside `IP_ADD_MEMBERSHIP` handler (`mreq` is the local variable being constructed); line 143 `logger.debug(f"sock.setsockopt(: {e}")` inside `SO_BINDTODEVICE` fallback (literal opening of the call site). Neither crashes but both obliterate real failure context when operator runs `-vvv` to diagnose a multicast/bind issue.
**Fix:** replace with `logger.debug(f"LLMNR: IP_ADD_MEMBERSHIP failed for {self.LLMNR_MULTICAST_ADDR} on {iface_ip}: {e}")` and `logger.debug(f"LLMNR: SO_BINDTODEVICE({self.interface}) failed: {e}")`.

### src/oida/protocols/discovery/hsrp.py:264,383; src/oida/protocols/discovery/ipv6.py:367 — Bare `data[0]` / `ipv6.dst` reads: dropped version field, stale dst
Three places where a value was meant to be bound but the assignment LHS was dropped: hsrp.py:264 `_parse_hsrp_v1_raw` reads `data[0]` (HSRP version field) but result dict at line 278 sets `"version": 1` constant. hsrp.py:383 `_parse_v2_group_state` reads `data[0]` (HSRP-version-within-TLV byte). ipv6.py:367 `process_packet` reads `ipv6.dst` — needed for downstream debug log but not preserved. Individual impact small but matches the wider refactor regression and indicates more half-finished refactors lurking.
**Fix:** add `_ = ` or remove the statement; for hsrp.py:264 actually read and use `version` instead of hardcoding 1.

### src/oida/protocols/discovery/ics.py:278,654,660,676 — Three bare-expression reads in BACnet NPDU / CODESYS structured parsers (deep refactor artefact)
Line 278 in `_parse_i_am_response` reads `data[offset]` (NPDU version byte) — should be `npdu_version = data[offset]` and `npdu_version != 0x01` should at minimum be debug-logged. Lines 654, 660, 676 are three `struct.unpack_from('<I', data, offset)[0]` calls in CODESYS structured header parsing whose results are discarded. The `offset += 4` after each makes the reads work as skip-N-bytes, but the fields (NSClientHandleData device flags, target flags, and something at offset+22) are documented in CHANGELOG / protocol notes — silently throwing away their values is a maintenance hazard.
**Fix:** replace each with `_ = struct.unpack_from(...)` (or, preferably, capture into a named local and at minimum debug-log it once).

### src/oida/protocols/discovery/pim_passive.py:145,245; src/oida/protocols/discovery/vrrp.py:149 — Dead bare-expression statements (PIM_TYPES.get, dr_priority > 1, vrrp.ipcount)
pim_passive.py:145 `PIM_TYPES.get(msg_type, f"Unknown({msg_type})")` — `msg_type_name` is recomputed at line 242, so the line-145 read is dead. pim_passive.py:245 `dr_priority > 1` — comment above explicitly says 'Higher DR priority is better (wins election)' but boolean is never stored, never logged, never put into `pim_data`; the DR-eligibility check the comment promises does not exist. vrrp.py:149 `vrrp.ipcount if hasattr(vrrp, 'ipcount') else 0` — value read and discarded; user-visible `vrrp_data` dict at 178-189 omits `ipcount` entirely.
**Fix:** pim_passive 145 — delete; pim_passive 245 — expose as `dr_priority_eligible` and stash into `pim_data`; vrrp 149 — bind to `ip_count = ...` and add to `vrrp_data`.

### src/oida/protocols/discovery/{mdns,dhcpv6,ipv6,hsrp,glbp,igmp}.py — Inconsistent device-key conventions across listeners → same device appears multiple times when one listener has MAC and another doesn't
Six listeners use four different schemes: mdns: `src_mac if src_mac else f"mdns:{ip_addr}"`. dhcpv6 passive: `f"mac:{src_mac}" if src_mac else f"ip:{src_ip}"`. dhcpv6 active: `src_mac if src_mac else f"ip:{src_ip}"` (same listener pair disagrees with itself). ipv6: `mac if mac else ipv6_addr`. igmp passive/active: `src_mac if src_mac else f"ip:{src_ip}"`. hsrp: `f"ip:{src_ip}"` (always — never uses MAC). glbp: `f"{device_mac}:{group_id}" if device_mac else f"glbp:{src_ip}:{group_id}"`. arp/ethernet (the canonical pair): bare MAC, no prefix. When scanner.py merges per-listener device dicts, the same physical device shows up under 3-5 different keys.
**Fix:** introduce `device_key_for(mac, ip)` in core.py that always returns `mac.lower()` when valid (per `is_valid_mac`), else `f"ip:{ip}"`. Drop the `mac:`/`mdns:`/`glbp:`/`vrrp:` etc. prefixes; listener provenance is already in `discovered_by`.

### src/oida/protocols/discovery/glbp.py:418 — GLBP Request/Response TLV parser silently ignores priority field promised by code comment
`_parse_request_response_tlv` reads `weight` at offset 4 but the comment above says 'Priority at offset 3 (may override Hello priority)'. Per Wireshark's `packet-glbp.c`, the Request/Response TLV's priority byte SHOULD override the Hello TLV's priority for the forwarder. Current code never reads or applies it, so `vf_state`-derived AVF/SVF determinations on GLBP groups where the forwarder has a different priority than the gateway are computed against the wrong value. Forwarder election analysis in pen-test report will be wrong for any GLBP deployment with per-forwarder priority overrides (common load-balancing tuning).
**Fix:** `result["forwarder_priority"] = data[3]` and either merge into `priority` (last-write-wins matches Wireshark) or expose as separate field in `glbp_data`.

### src/oida/protocols/discovery/infra.py:1287-1295 — `PCAnywhereScanner` silently drops Status response when ST arrives before NR
Both `NQ` (name query) and `ST` (status query) probes are broadcast in `scan()`. Receive loop only processes `ST` packets when `ip in self.discovered_devices`. UDP responses are unordered: if a target's ST reply arrives BEFORE its NR reply (possible because scanner sends NQ first to ALL broadcasts and only then iterates ST), the status byte is dropped silently. Device record ends up with `pcanywhere_data['status']` permanently missing — operator loses Available-vs-Busy classification that the second probe was specifically added for. No second pass to retry STs against newly-discovered devices.
**Fix:** buffer ST responses for IPs not yet in the dict; flush after each NR insertion. Alternatively send NQ first, wait briefly for NR replies, then issue ST probes only to responders.

### src/oida/protocols/ethernetip/mixins/write_test.py:121-134 — `_test_write_with_status` collapses every non-`settable` write error to `0x0E` (silently lies about permission)
When pycomm3 returns a result with `error` truthy but no `service_status`, heuristic string-matches `'attribute not settable'` / `'privilege violation'` / `'not supported'` and falls through to `status = 0x0E` for everything else. A connection drop, TCP RST, unexpected error, or differently-cased pycomm3 error string is misclassified as 'attribute is read-only', producing wrong `R` permission rows in explore-classes table and false `writable=False` entries. Downstream fuzz blacklist relies on these flags.
**Fix:** distinguish transport / parse errors (return -1, propagate as 'unknown') from genuine CIP general status responses; only set `0x0E` when explicit text matches.

### src/oida/protocols/ethernetip/mixins/network_parsers.py:291-298 — Assembly input/output classification by instance-ID parity is fabricated heuristic
`_parse_assembly_instances` labels instances under 100 as 'output' when even, 'input' when odd. CIP Assembly Object spec (Vol 1 §5-5) defines no parity convention; vendor profiles (Rockwell 1756-IB16/OB16, ODVA Generic Device, EtherNet/IP I/O Adapter) routinely use both even and odd numbers for inputs OR outputs (e.g. instances 100/101 are typically BOTH inputs on Rockwell I/O modules; 150/151 are BOTH outputs). Reported `input_assemblies`/`output_assemblies` lists are noise.
**Fix:** drop the parity guess; classify only when a known well-known instance is matched (100-110 = input on Rockwell, 150-160 = output) and otherwise leave `type = 'unknown'`.

### src/oida/protocols/ethernetip/mixins/advanced_parsers.py:313 — `_download_file` transfer-number wraps at 256, every Logix file > ~128 KiB silently truncated or aborted
`transfer_number = (transfer_number + 1) % 256` wraps the per-chunk USINT after byte 255. Per ODVA File Object spec (Vol 1 §5-22), `Upload Transfer` uses the byte to detect duplicate/out-of-order chunks; on wrap the device sees the next transfer as duplicate (or abort, depending on firmware) and either aborts or returns the same chunk again. With default 512-byte chunk, wrap at 128 KiB — well below default `max_file_size = 65536` so unreachable today, but `--max-file-size` lets operator push higher. A 1 MiB firmware/log file quietly truncates or hangs.
**Fix:** enforce `if transfer_number >= 255: break` and emit a warning; or send `Upload Transfer Abort` and re-Initiate with a higher chunk size.

### src/oida/protocols/ethernetip/mixins/cip_security.py:145-180 — `_check_tls_support` leaks underlying socket on TLS handshake failure
`sock = ConnectionHelper.create_tcp_socket(...)` then `ssl_sock = context.wrap_socket(sock, ...)`. If `wrap_socket` raises (cert failure, protocol downgrade, RST during handshake) the bare-except at line 178 swallows the exception and returns False — raw TCP `sock` is never closed (only `ssl_sock.close()` is attempted, inside the success path). Each scan against a non-TLS-capable target leaks one FD per call. Also `ssl_sock.close()` on success doesn't propagate to underlying socket close in every Python version.
**Fix:** wrap entire block in `try: ... finally: try: sock.close() except: pass`.

### src/oida/protocols/ethernetip/mixins/enip_commands.py:43-57 — `_parse_enip_header` data slice mismatched with the header-size assumption (companion to the existing UDINT/UINT options bug)
Companion to the existing finding (§358) about `options` being UINT (2 bytes) vs UDINT (4 bytes): body unpacks `data[:22]` and treats result as a 24-byte header — `data[24 : 24 + length]` (line 56) is rest of header layout assuming 24 bytes total but unpack only consumed 22. Net effect: `options` gets high 2 bytes of what should be the 4-byte options field (so the field is wrong AND any caller comparing `options` against ODVA-defined values fails). The `# data[:22]` line should be `data[:24]` and format `'<HHIIQI'` once the existing UINT→UDINT fix is applied. Both edits must happen together; fixing the format string alone causes `struct.error: unpack requires 24 bytes but 22 are available`.
**Fix:** apply both edits atomically — `'<HHIIQI'` AND slice `data[:24]`.

### src/oida/protocols/ethernetip/scanner.py:314-316,689 — `scanner.route_path` (parsed segments list) built but never consumed; only `route_path_str` truthiness is used
`self.route_path = self._parse_route_path(self.route_path_str)` returns a list of `{port, link}` dicts. Every code path that takes a CIP route either uses `_port_segment_mod.PortSegment(...)` directly (cip_objects.py:220-223,383,505) or checks `self.route_path_str` truthiness (scanner.py:689). The parsed list is never consumed — and the dict shape it produces is incompatible with the `PortSegment` objects `_read_cip_attribute(route_path=...)` actually expects (scanner.py:425,432). Result: `--route-path 1/2,1/0` silently has no effect on actual routing; operator believes the multi-hop route was honored.
**Fix:** either drop `self.route_path` and the parser entirely (and document `--route-path` as a feature flag only, with segments coming from `--discover-routes`), or feed the parsed list through `PortSegment` and pass as `route_path=` on every routed call.

### src/oida/protocols/bacnet/mixins/objects.py:584; security.py:899-905 — `_extract_unsigned` int.from_bytes treats outOfService payload as unsigned int — `bool(uval)` collapses real Boolean tag to truthiness of length-1 hex (false-positive OOS findings)
Deep-enum reads outOfService via `_extract_unsigned` which int.from_bytes the tag data; then casts `bool(uval)`. For a BACnet Boolean True the tag carries 0x01 → True OK. For Boolean False the encoding varies: some stacks send a 0-length application-tagged Boolean (value lives in the tag class/number byte itself, not in tag_data), in which case `_extract_unsigned` returns None and the field falls through to `_extract_string(resp)` — producing a string like `'<Application Tag Boolean ... value=False>'`. `obj_info['outOfService']` ends up a non-empty string, which is truthy. Step-3 then treats the object as 'OUT-OF-SERVICE'. Same flaw mirrored in `security.py:899-905`. Result: false-positive OOS findings on bacpypes3 stacks that elide zero-length payloads.
**Fix:** route Boolean properties through a dedicated extractor that checks for the application-class-tagged Boolean with 0-length tag_data (tagNumber 1 == True, 0 == False per BACnet 20.2.3), or call `pv.cast_out(Boolean)` instead of byte-decoding.

### src/oida/protocols/bacnet/mixins/discovery.py:573-585 — `vendor_scan` suspicious-pattern check matches inside benign property-name labels — false positives on every vanilla vendor
`raw_value` is lower-cased and substring-matched against `sensitive_patterns = ['password', ..., 'config', 'enable', 'unlock', 'service', ...]`. Generic substrings (`enable`, `service`, `config`, `test`) hit on any benign device exposing proprietary property values like 'EnableSchedule', 'ServiceMode', 'TestFlag' (common on Tridium etc.). Tool reports CRITICAL 'potentially sensitive proprietary properties detected' on devices that simply name knobs in English. Combined with the loud warning at line 644-647, every BACnet engagement against a normal vendor produces noisy false-positive 'backdoor / debug interface' findings.
**Fix:** tighten the pattern list to high-specificity tokens (drop 'enable', 'service', 'config', 'test', 'auth' on their own); or require regex word-boundary (`\bpassword\b`).

### src/oida/protocols/bacnet/mixins/{state,monitoring,security,files,discovery,objects,network}.py — Pervasive `except BaseException` swallows KeyboardInterrupt and SystemExit
Pattern repeats throughout bacnet mixins (~91 sites): `except BaseException as e: self.logger.debug(...); continue`. BaseException includes KeyboardInterrupt and SystemExit. Two explicit `except KeyboardInterrupt as e: self.logger.debug(f'... failed: {e}')` blocks (state.py:218, monitoring.py:594) make intent visible, but implicit catches elsewhere mean Ctrl-C during a long scan is reported as 'bacpypes3 vendor scan failed: ' and the loop carries on instead of terminating. Async event-loop shutdown is also blocked.
**Fix:** replace `except BaseException` with `except Exception`, OR chain `except (KeyboardInterrupt, SystemExit): raise` before the broad catch. The explicit `except KeyboardInterrupt as e` blocks should re-raise rather than just log.

### src/oida/protocols/bacnet/mixins/{objects,properties,network}.py — Additional refactor-artefact debug strings in BACnet ('read prop failed', 'extract unsigned failed', 'read bytes failed', 'bacpypes3 read prese failed')
Multiple debug messages templated from surrounding helper name without describing failure. Examples: 'read prop failed: {e}' (objects.py:372 in `_read_prop` helper of `deep_enum` — message is helper name, not operation), 'extract unsigned failed: {e}' inside *Bulk objectList read* try (objects.py:833-837 — wrong helper name), 'read bytes failed: {e}' (network.py:796, 900 — inside Who-Is timeout and probe loops, not the `_read_bytes` helper), 'bacpypes3 read prese failed: {e}' (properties.py:314 — truncated 'read present values'). Like the discovery garbled-debug findings, this destroys debugging value when a real failure occurs.
**Fix:** rewrite each to describe the actual operation being attempted (e.g. `f'objectList[{idx}] read timed out'` or `f'Who-Is to {remote_addr} timed out'`).

### src/oida/protocols/bacnet/mixins/network.py:814-908 — `_bacpypes3_discover_mstp` probes 0..maxMaster serially per segment — minutes of latency
Address-probe loop is `for mac_addr in range(0, max_master + 1):` with `await asyncio.wait_for(... timeout=min(timeout, 1.5))` per iteration. With default `maxMaster=127` and 1.5s probe timeout, a sparse MS/TP segment with no replies costs 127*1.5 = ~190s per port. Multiple MS/TP ports compound. The Who-Is broadcast at line 776 already gives the device list cheaper — per-MAC probe duplicates that work serially.
**Fix:** parallelise the MAC probes with `asyncio.gather` batched at a sensible width (10-20 concurrent), or skip per-MAC probe entirely when Who-Is broadcast returned the expected count of devices.

### src/oida/protocols/bacnet/proto_args.py:191 + nxc_connection.py:436-437 — `--vendor-info` flag declared but never read; `--vendor-scan` is the only working name
proto_args.py:191 registers `--vendor-info` (dest='vendor_info', SUPPRESS). Repo-wide grep finds zero readers. Actual feature (proprietary-property scan in mixins/discovery.py:265) is dispatched by `args.vendor_scan` (nxc_connection.py:436), declared at proto_args.py:212. User following older docs or guessing `--vendor-info` gets a clean accept but no scan.
**Fix:** delete proto_args.py:191 and add a vendor_info → vendor_scan alias if needed for back-compat.

### src/oida/protocols/bacnet/mixins/security.py:113-130 — `_handle_test_write` iterates only the first instance of `analogValue` and `binaryValue` per device — narrow coverage
Loop scope is `for obj_type in ['analogValue', 'binaryValue']` and `instances[0]`. Analog/binary OUTPUT objects (most operationally interesting writable targets — actuators/relays) are excluded entirely, as are multistate types. Sister `_handle_enumerate_writable` at line 145 correctly iterates `CONTROL_POINT_TYPES`. Narrow coverage means a device with writable AO/BO but read-only AV is reported as 'No writable objects found'. Also: early-returns on first success means only one finding per scan.
**Fix:** switch obj_type loop to CONTROL_POINT_TYPES; iterate at least `instances[:5]` to match the sibling.

### src/oida/protocols/bacnet/mixins/connection.py:36-43 — `--bbmd 'IP:PORT'` parser silently discards the port
Parses `bbmd_ip, bbmd_port = bbmd.rsplit(':', 1)` then only writes `kwargs['bbmdAddress'] = bbmd_ip`. `bbmd_port` is dropped on the floor. BAC0.lite() will register foreign-device against the default BACnet port 47808, not the user-specified one. Operator pointing at a non-standard BBMD (e.g. 10.0.0.5:47809) gets a silent miss. TTL is also hardcoded to 30 in both branches; `_bacpypes3_test_bbmd_injection` at network.py:434 uses TTL=60.
**Fix:** pass `bbmd_port` through to kwargs (BAC0 supports it) or fail-loudly if a port was specified but cannot be honored; lift TTL to a single module constant.

### src/oida/protocols/knx/mixins/discovery.py:605-626 — `_test_routing` source-address spoofing + 1.1.255 broadcast destination + no `--confirm` gate (additional to existing HIGH §418)
Two problems BEYOND the existing payload-type / queue-put finding: (1) Source-address spoofing — `1.1.0` is hardcoded as source. On a real customer bus, 1.1.0 is virtually always a Line Coupler / IP Router individual address. Injecting a telegram with the coupler's source can be interpreted by the bus as the coupler itself originating traffic, polluting trace logs and (depending on filter tables) confusing routing tables. (2) Destination 1.1.255 is the line-broadcast individual address — a live device may be at 1.1.255 and react. (3) Flag is not `--confirm`-gated despite injecting on the bus.
**Fix:** use a synthetic, scan-allocated source address (or gateway's own current_address per cemi_handler.py:148); restrict destination to user-supplied `-i`; require `--confirm` to actually transmit; emit security_finding only when L_DATA_IND echo is observed.

### src/oida/protocols/knx/mixins/memory.py:303-315 + scanner.py:319-322 — `--group-write` parses malformed input as `('0/0/0', b'')` and writes empty payload to a real group address without `--confirm`
`_parse_group_write` swallows ANY parse exception and returns silent default `('0/0/0', b'')`. `scanner._async_discover` then unconditionally calls `self._write_group_value(knx, ga='0/0/0', value=b'')`, which constructs Telegram(destination=GroupAddress('0/0/0'), payload=GroupValueWrite(DPTArray(b''))) and puts it on the bus. **0/0/0 is the global-broadcast group address on KNX — every device on the line receives the telegram.** There is no `--confirm` gate on `_write_group_value` (only `--memory-write`, `--restart`, `--key-write`, `--property-write` are gated). A typo in `--group-write` (e.g. `'1/0/1=01'` instead of `'1/0/1:01'`) therefore unintentionally broadcasts a write to every device.
**Fix:** raise on parse error instead of returning silent default; gate `_write_group_value` behind `--confirm`; refuse 0/0/0 as destination unless `--broadcast-confirm` is set.

### src/oida/protocols/knx/mixins/security.py:246-298 — `_test_write_access` writes to memory 0x0116 with no `--confirm` gate (only `read_only` flag, which has no CLI surface)
`_test_write_access` performs an actual write to memory address 0x0116 ('Write the same value back') on every responsive device when `--test-write` is set. The only guard is `if self.read_only:` (line 255). `read_only` has no CLI surface; it is a default attribute. Codebase convention requires `--confirm` for any bus write. Memory 0x0116 is documented MfgData on many BCU types and is writable on real devices — even writing the same value back qualifies as an Authorize-bypassing write on devices with no BCU key set, and operator hasn't consented.
**Fix:** add `if not self.args.get('confirm'): return` at the top of `_test_write_access`; emit a clear log line that `--test-write` requires `--confirm`.

### src/oida/protocols/knx/nxc_connection.py:500-502 — Cracked .knxproj password logged verbatim to security_finding (and structured JSON log)
When `crack_knxproj()` succeeds, the recovered project password is interpolated into a security_finding: `self.logger.security_finding('Weak password', f'KNX project password found: {password}')`. `ICSLogger.security_finding` writes the full message into both stdout and the structured JSON log (--json-log) that operators routinely share back to clients. Recovered password is often a real, in-use credential (customer ETS workstation passwords are commonly reused). Distinct from the existing wordlist-path leak at ets.py:353,359 (which leaks the wordlist's *path*); here the cleartext *credential* is leaked.
**Fix:** redact in log output (`KNX project password recovered (length=N)`); store plaintext only in `self.results['data']['knxproj']['password']` for explicit export; never put cleartext in a security_finding call.

### src/oida/protocols/knx/scanner.py:511-539 — `_parse_device_range` silently falls back to 1.1.1-1.1.255 on any parse error — scans the wrong device range
Wraps entire range-parsing in `except Exception:` and on any failure logs `Invalid device range format: ...` then `for i in range(1, 256): addresses.append(f'1.1.{i}')`. Caller (`_discover_devices` in discovery.py:69) scans those 255 addresses. If user passes `--scan-range 1.1-1.5` (typo, missing area), validator silently rescues by scanning a totally different range. On a live customer bus with multiple lines, could send TConnect probes to the wrong line entirely. Error path uses `self.logger.fail(...)` then continues normally — no exit.
**Fix:** raise the exception (or return empty list and have caller error out). Do not silently scan a different range than the user requested.

### src/oida/protocols/knx/mixins/security.py:107-148 — BCU brute-force holds one mgmt.connection() for entire wordlist — first error kills the run with zero recovery
`_brute_bcu_auth` opens `async with mgmt.connection(addr) as p2p:` OUTSIDE the for loop. All `AuthorizeRequest` calls run on the same connection. On real KNX devices, after several failed AuthorizeRequests many BCU implementations terminate the connection (anti-brute-force); next request raises and propagates to outer `except Exception` at line 149, logs `Connection error: ...`, and the rest of the wordlist is never tested. A successful auth in a later test that triggered transient disconnect drops the entire run including `valid_keys`. No reconnect logic.
**Fix:** open `mgmt.connection()` inside per-key try (like rest of the mixins); or reconnect on disconnect with small backoff (mirror prop_dump retry at properties.py:782-794).

### src/oida/protocols/knx/mixins/memory.py:270-315 + mixins/properties.py:1074-1086 — Memory/property/group-write parsers silently default on bad input — masks user errors
Four parsers swallow parse exceptions and return 'reasonable default' instead of raising: `_parse_memory_range` → `(0x0100, 256)`, `_parse_memory_write` → `(0, b'')`, `_parse_group_write` → `('0/0/0', b'')` (also covered above), `_parse_property_arg` → `(0, 78)`. Each caller proceeds with fabricated defaults: memory_dump reads 256 bytes from 0x0100, memory_write tries to write 0 bytes (caught by SYSTEM_MEMORY_END guard by accident), group_write broadcasts empty payload (see HIGH), property_read fetches Object 0 / PID 78 / HARDWARE_TYPE. User sees `self.logger.fail('Invalid ... format')` but scan continues with values they never specified.
**Fix:** raise ValueError; have callers (`_async_discover`) catch and record `results['<op>'] = {'error': '...'}` without invoking the protocol operation.

### src/oida/protocols/knx/mixins/discovery.py:11-13 + mixins/properties.py:10-12 + nxc_connection.py:34-36 — Three KNX mixin files use `import logging`/`logger = logging.getLogger(__name__)`
Violates project rule 'no logging module usage'. Three concrete sites route real error context through module-level `logger` instead of `self.logger`: `mixins/discovery.py:434` `logger.debug(f'sock.close(): {e}')`; `mixins/properties.py:666` `logger.debug(f'Failed to get name_resp: {e}')`; `nxc_connection.py:532` `logger.debug(f'Failed to get scanner: {e}')`. Users with --debug do not see these (module logger is not wired into ICSLogger's structured JSON emitter). helpers.py and ets.py use approved `get_module_logger(__name__)` wrapper — showing the correct pattern.
**Fix:** delete `import logging` + module logger from discovery.py/properties.py/nxc_connection.py; switch to `get_module_logger(__name__)` or `self.logger.debug`.

### src/oida/protocols/knx/nxc_connection.py:51 — `self.port = getattr(args, 'port', None) or self.default_port` coerces explicit `--port 0` to default
Same bug-shape as the already-flagged `listen-time 0` issue (MEDIUM at scanner.py:377,394), but in a different file. `getattr(args, 'port', None) or self.default_port` treats `--port 0` (a legal argparse value) as falsy and silently substitutes 3671. Operators occasionally use `--port 0` as a sentinel meaning 'let-OS-choose' or as a deliberate probe.
**Fix:** `_port = getattr(args, 'port', None); self.port = _port if _port is not None else self.default_port`.

### src/oida/protocols/knx/nxc_connection.py:387-394 — `create_conn_obj()` returns None instead of bool; violates NXC architecture contract
Per the NXC base class convention, `create_conn_obj()` must return a bool. `knx.create_conn_obj()` returns nothing (implicit None). Today `proto_flow` guards via `if not self.conn:` (line 73) so it happens to work, but: (a) other NXC implementations rely on the bool return for inheritable error-handling; (b) contract enforced by the automated review script's NXC architecture check; (c) future caller using the return value will take the None==False branch even on success.
**Fix:** return `True` after success log at line 392 and `False` after fail log at line 394.

### src/oida/protocols/knx/proto_args.py:33-41 + mixins/discovery.py:362 — `--nat` flag is permanently True (action='store_true' + default=True); flag does nothing useful
argparse with `action='store_true', default=True` makes the flag a no-op: when not passed, value is True; when passed, value is still True. Only way to actually toggle is via separate `--no-nat`. discovery.py:362 reflects this in code: `use_nat = self.args.get('nat', True) and not self.args.get('no-nat', False)` — `--nat` is read but inert. Help text claims `--nat` enables NAT mode; typing it changes nothing. UX trap: operator who reads `--help` and explicitly passes `--nat` (expecting opt-in) gets identical behaviour to omitting it. Intent was clearly `BooleanOptionalAction` (`--nat/--no-nat`).
**Fix:** replace with `parser.add_argument('--nat', action=argparse.BooleanOptionalAction, default=True)` (Python 3.9+); drop `--no-nat`. Or drop `--nat` and keep `--no-nat`-only with help saying 'default behaviour is NAT mode'.

### src/oida/protocols/hl7/mixins/pharmacy.py:251-257,302-309 — Pharmacy `_create_rgv_message` / `_create_rds_message` call `build_rxg` / `build_rxd` with non-existent kwargs → silent fallback to generic test message
Original review caught the RAS variant (HIGH §174); RGV and RDS are the same class of bug. `_create_rgv_message()` calls `build_rxg(give_code=..., give_amount=..., give_units=..., give_dosage_form=...)` but `build_rxg()` has `drug_code, drug_name, give_amount, give_units, give_dosage_form, ...` — no `give_code` kwarg → TypeError → falls through to `_create_test_message('RGV','O15')`. Same in `_create_rds_message()` calling `build_rxd(dispense_code=..., actual_amount=..., actual_units=..., refills_remaining=...)` against `build_rxd(drug_code, drug_name, actual_dispense_amount, actual_dispense_units, prescription_number, ...)` — three unknown kwargs and no `refills_remaining`. `--send-rgv` and `--send-rds --confirm` never carry user-supplied drug/dose, but AA-triggered security finding still claims 'Pharmacy Give/Dispense Accepted', misleading operator.
**Fix:** align kwargs (`give_code → drug_code`, `actual_amount → actual_dispense_amount`); drop or implement extra kwargs as real field overrides.

### src/oida/protocols/hl7/mixins/message.py:85-103 — `_send_oru_message` bypasses `_create_message_with_segments` → ORU is sent without OBR/OBX even when `--obx-value` provided
Unlike `_send_orm_message` (line 135) and `_send_adt_message`, `_send_oru_message` calls `self._create_test_message('ORU', 'R01')` directly. `_create_test_message` (__init__.py:618-660) produces a probe stub with MSH + hard-coded `PID|1||12345^^^MRN||DOE^JOHN||19800115|M` and nothing else — no OBR, no OBX, ignoring `--obx-value`, `--obx-id`, `--obx-type`, `--obx-units`, `--patient-id`, `--patient-name`, etc. Help text and CLI examples (`oida hl7 ... --send-oru -I PT001 --obx-value 95 --confirm`) imply otherwise. ORU should use `_create_message_with_segments('ORU','R01')` (line 269-280).
**Fix:** route ORU through `_create_message_with_segments` like ORM does.

### src/oida/protocols/hl7/__init__.py:333,802-833 — `segment_builder` pinned to default version at proto_flow start, never refreshed after server-version auto-detection
`proto_flow()` initializes `self.segment_builder = HL7SegmentBuilder(version=self._get_version())` BEFORE `enum_host_info()` runs and BEFORE server's MSH-12 is parsed in `_parse_response()` (which sets `self.detected_version`). All subsequent builders use stale `2.5` default — `HL7SegmentBuilder.__init__` stores `self.version`, then every `Segment('PID', version=self.version)` is bound to the old value. `_get_version()` is correct when called directly inside mixin `_create_*` methods, but every PID/PV1/OBR/RXO/etc. built via `self.segment_builder` is bound to 2.5, producing structurally inconsistent messages on 2.7 servers (PID-2 deprecation, OBX-29 additions).
**Fix:** refresh the builder after the first response in `_parse_response`, or always pass `version=self._get_version()` per-segment.

### src/oida/protocols/hl7/mixins/security.py:29-37 — `_analyze_security` flags 'Accepts Unknown Sender' on every scan because of the unsolicited ADT probe + sticky `ack_code`
Combined effect of (a) `enum_host_info()` sending ADT^A01 unconditionally (see CRITICAL above) and (b) `_parse_response` writing the ACK back into `self.results['data']['ack_code']`. By the time `_analyze_security()` runs at end of `proto_flow()`, `ack_code` is always 'AA' on any server that ACKs — so 'Accepts Unknown Sender' / ACCESS finding fires on every customer report. Worse, when later mixins (`_send_oru_message`, `_send_custom_message`, etc.) get a response with no MSA segment, `_parse_response` doesn't reset `ack_code`, so the OLD ACK leaks forward and gates downstream security findings (financial.py:41, message.py:148, master_file.py:52).
**Fix:** scope `ack_code` per-message (return from `_parse_response`), or null it out at the top of each send.

### src/oida/protocols/hl7/mixins/enum.py:158-165 — `_extract_providers_from_response` reads PV1 keys (`ConsultingDoctor`, `AdmittingDoctor`) that `parse_pv1` never returns
Checks `pv1.get('ConsultingDoctor')` and `pv1.get('AdmittingDoctor')` but `HL7SegmentParser.parse_pv1` (segments.py:1252-1268) only emits `AttendingDoctor`, `ReferringDoctor`, `VisitNumber`, `FinancialClass`, `AdmitDate`, `DischargeDate`, `Location`, `PatientClass`, `AdmissionType`. The `consulting` and `admitting` sets are never populated; the dedicated 'Consulting Physicians' / 'Admitting Physicians' display blocks (line 97-110) are dead code; exported `providers.consulting_physicians` / `providers.admitting_physicians` always empty.
**Fix:** add PV1-9 (consulting) and PV1-17 (admitting) to `parse_pv1`, or drop the dead consulting/admitting branches.

### src/oida/protocols/hl7/mixins/enum.py:171-173,185-187 — OBR-16 / RXE-13 extraction is off-by-one — wraps result through 1-indexed `get_field`, returns OBR-15 / RXE-12
Two paths split a segment on `|` (0-indexed list where `fields[0]` is segment name and `fields[N]` is field N), guard with `if len(fields) > 16 and fields[16]:` (correctly checking OBR-16) — then add `HL7SegmentParser.get_field(fields, 16)` to the set. `get_field` (segments.py:1075-1082) is 1-INDEXED HL7-style and returns `fields[index-1]`, so `get_field(fields, 16)` actually returns `fields[15]` (OBR-15 = Collector Identifier). Same bug for RXE: line 186 checks `fields[13]` (RXE-13 = Ordering Provider DEA) but line 187 returns `fields[12]` (RXE-12 = Number of Refills). `--enum-providers` lists wrong field values whenever OBR-16 or RXE-13 are populated. Also: lines 169 and 183 invoke `HL7SegmentParser.parse_obr(segment)` / `parse_rxe(segment)` and discard the result, even though `parse_obr` already returns `OrderingProvider` (segments.py:1287).

### src/oida/protocols/hl7/__init__.py:779-798 — `_identify_vendor` substring match produces false-positive vendor tags for short keys (GE, LAB, DEV, TEST, OPTUM)
After exact-match table lookup, fallback iterates entire `HL7_VENDOR_MAP` and returns on `key in app_upper or app_upper.startswith(key)`. Short keys (`GE`=2, `DEV`=3, `LAB`, `TEST`, `OPTUM`, `MIRTH`, `ATHENA`) match dozens of unrelated app names (`ORANGE` matches `GE`; `LABCORP_API` matches `LAB` before `LABCORP`; `DEVELOPMENT_TOOL` matches `DEV`; `OPTUMSCRIPT` matches `OPTUM`). Dict insertion order means first match wins — rarely the most specific.
**Fix:** sort keys by length descending before substring loop, or require word-boundary / underscore-separated match.

### src/oida/protocols/hl7/mixins/master_file.py:196,213,243 — Additional `master_file` extract reads parser keys `parse_mfi`/`parse_prc` do not emit (companion to existing finding)
Original review (HIGH §178) caught `StaffIDCode` / `ActiveStatus` mismatch for STF; two more sit in the same file. Line 196 filters `if mfi.get('MasterFileID')` while `parse_mfi` returns `MasterFileIdentifier` (segments.py:1342) → MFI rows never make it into `master_files`. Line 213 displays `mf.get('MasterFileID', 'Unknown')` and prints 'Unknown' for every received row. Line 243 column_defs includes `('ActiveInactiveFlag', 'Status')` but `parse_prc` (segments.py:1368-1382) emits no Active-flag key — Status column always blank in `--query-mfn`.
**Fix:** align keys (`MasterFileIdentifier`, add an Active-flag to `parse_prc` or remove the column).

### src/oida/protocols/hl7/mixins/continuation.py:116-144 — `_reassemble_fragments` drops valid MSH from later fragment when first fragment lacks one + bytes-vs-str confusion
Aside from the existing dead-code finding (§398): function unconditionally sets `header_added = True` at end of every fragment iteration, even when the fragment contained NO MSH/MSA/QAK. Result: if fragment 1 is a partial body with no MSH (transport hiccup, or a server that returns leading DSC-only frames), fragment 2's MSH/MSA/QAK is skipped at line 133-135 and reassembled message has no header. Also `split_message()` returns Python `str` from hl7apy via `to_er7()`, then the loop appends those strs into `result_segments` and joins with `'\r'.join(...).encode('utf-8')`. If any fragment is already binary (e.g. EUC-JP MSH-18 charset), it was decoded with `errors='ignore'` upstream and re-fetched raw here — round-tripping through hl7apy mutates whitespace and component padding. Reassembly unsafe for binary-clean transport.

### src/oida/protocols/hl7/mixins/special_query.py:90-117,123-127 — `_create_qbp_message` hard-codes `Message('QBP_Q13')` for every query_tag → MSH-9 `'QBP^Q40^QBP_Q13'` is structurally wrong
Builds `Message('QBP_Q13', version=...)` regardless of `query_tag`, then sets MSH-9 to `f'QBP^{query_tag}^QBP_Q13'`. For Q40 (WhoAmI) canonical structure is QBP_Q15 (or QBP_Q21 depending on version); for Q13 the structure is QBP_Q13 which only works by coincidence. `_create_qbp_immunization_message` sets MSH-9 to `f'QBP^{query_tag}^QBP_Q11'` while still building the hl7apy Message as `QBP_Q13` — MSH-9 ^3 component (message structure) contradicts the actual structure. Strict HL7 parsers (Mirth in validation mode, hl7apy with `validation_level=STRICT`) will reject these.
**Fix:** map `query_tag` to correct structure name and use both for `Message(...)` and MSH-9 ^3.

### src/oida/protocols/snap7/nxc_connection.py:67-76 — `create_conn_obj` auto-bruteforces when `-P` value is a filesystem path, with no `--confirm` gate
When `-P /path/to/wordlist` is passed, `create_conn_obj()` detects the file via `os.path.isfile(password)` and immediately invokes `self.scanner.bruteforce_password(self.conn, wordlist_path=password)` — before the action dispatcher (and DANGEROUS_ACTIONS check) is reached. Same operation triggered explicitly via `--brute --wordlist` also doesn't require `--confirm`. The 'smart' helper goes a step further: fires implicitly during ordinary recon (`oida s7 host -P creds.txt`) and user never typed 'brute'. Help text for `-P` does mention 'if path exists, brute-force', but discovery-style commands that look passive now send a default-password wordlist.
**Fix:** gate the implicit-brute branch behind `--confirm` (matching framework convention); or warn-and-prompt before firing on a value resolving to an existing file.

### src/oida/protocols/snap7/proto_args.py:264-268 — Phantom `--test-write` CLI flag declared but never read anywhere
`write_group.add_argument('--test-write', action='store_true', help='Test write access safely')` is registered but grep finds zero readers. `_has_action()` doesn't list it, `_execute_action`/`_execute_complex_action` never check `args.test_write`, `Snap7Scanner` doesn't consume it. User runs `oida s7 host --test-write` expecting a write probe, gets a clean exit with discovery output. Same class as fhir's `--test-404-vs-403` / `--extract-response` (§362).
**Fix:** wire it (call `self.scanner._test_write_access(self.conn)` from the dispatcher, gated by `_require_confirm`) or remove the flag.

### src/oida/protocols/snap7/mixins/memory.py:53,112-126 — `self.read_only` hardcoded to True; writability tests in `_test_memory_areas` and DB sample-reads in `_enumerate_data_blocks` are unreachable from the CLI
`memory.py:113 if not self.read_only:` gates the actual `connection.write_area(...)` probe and the 'Writable access' security_finding. `read_only` is set in `BaseScanner.__init__` to `parse_bool(args.get('read-only', True))`. snap7's proto_args.py exposes NO `--read-only` (or `--no-read-only`) CLI option, so `args.get('read-only', True)` always returns True. Net effect: write-access enforcement in `_test_memory_areas` never runs from any CLI invocation, the 'WRITABLE: ...' display never fires, the 'Writable access' security_finding (which would be the headline finding of `--test-memory-areas` / `--audit`) is dead. Same gate kills `_enumerate_data_blocks` sample-read at line 53. Audit step [3/7] / [4/7] claim 'Memory area access' / 'Write access test' coverage but only the writable-area emission firing is the one inside `_test_write_access` (security.py:343, which doesn't consult `read_only`).
**Fix:** add `--read-only / --no-read-only` flag to proto_args.py, or stop reading `self.read_only` here and rely solely on `--confirm`.

### src/oida/protocols/snap7/nxc_connection.py:608-617 — `_handle_fuzz` bypasses `_require_confirm()` and reads `args.confirm` directly — inconsistent with every other write flag
Every dangerous handler in `_execute_complex_action` calls `self._require_confirm(action)` so the failure message is uniform and the gate is centrally maintained. `_handle_fuzz` instead inlines `if not getattr(self.args, 'confirm', False): self.logger.fail('--fuzz requires --confirm flag (DANGEROUS operation)')`. Functionally equivalent today, but: (1) `fuzz` not in DANGEROUS_ACTIONS, so future audits miss it; (2) any change to gate behaviour (e.g. JSON-log emission per existing MEDIUM 'central require_confirm helper') silently skips fuzz; (3) duplicates 'must change two strings to update one message' anti-pattern.
**Fix:** add `'fuzz'` to DANGEROUS_ACTIONS and replace inline check with `if not self._require_confirm('fuzz'): return`.

### src/oida/protocols/snap7/nxc_connection.py:518 + mixins/memory.py:367-376 — `db_fill` accepts byte values > 255 without validation — silent overflow into snap7 C library
`_action_db_fill` parses `fill_byte = int(parts[1], 16)` with no range check. Help text says `--db-fill DB:BYTE` and example is `1:00`, but `1:100` parses to `0x100 = 256` and `1:FFFF` parses to 65535. These get passed to `conn.db_fill(db_num, fill_byte)` and forwarded to snap7 ctypes layer where the value is truncated, raises, or fills with garbage depending on binding version.
**Fix:** after parsing, assert `0 <= fill_byte <= 0xFF` and emit `self.logger.fail('--db-fill BYTE must be 0x00-0xFF')` otherwise. Same guard belongs on the high-level `db_fill()` for direct callers.

### src/oida/protocols/opcua/mixins/security.py:362-388,449-451 — Private key dropped in /tmp with PID-only naming — collision & permissions hazard
`_generate_client_cert` writes `oida_client_<pid>.der` and `oida_client_<pid>.pem` (private key) into `tempfile.gettempdir()` and never deletes them — leak across runs. `_test_self_signed_cert_acceptance` uses the same PID-based naming for `oida_test_<pid>.*`. Two issues: (a) When OIDA scans multiple targets in the same process (threaded sweep against IP range), two concurrent OPC UA flows in the same PID will stomp on each other's cert/key files mid-handshake — and `finally` of one test will `os.unlink` the file the other is still using. (b) `setup_self_signed_certificate` uses default umask (commonly 0644) — private key on a shared host becomes world-readable.
**Fix:** use `tempfile.mkstemp(prefix='oida_client_', dir=...)` for unique paths + mode 0600; add cleanup to `_generate_client_cert` parallel to the test path's `finally`.

### src/oida/protocols/opcua/mixins/files.py:200-214 — `_read_file` reads OPC UA FileType node into memory with no upper bound (memory-DoS)
Chunk-read loop appends 4 KiB chunks to `file_content` while `bytes_read == chunk_size`, with no maximum-size cap and no honoring of the Size attribute (read at line 169 only for display). A malicious or buggy server that keeps returning full 4 KiB chunks fills scanner host memory. At line 252-254 a 256-byte hex preview is stored in `self.results['data']['file_read']['content_preview']` — but the full blob remains referenced via `file_content` until the function returns.
**Fix:** add explicit max-bytes cap (e.g. `--file-max-bytes`, default 16 MiB); respect the Size attribute if present; abort with a clear message if it would be exceeded.

### src/oida/protocols/opcua/nxc_connection.py:412,426,433,444,451 — Pre-auth client is replaced without `disconnect()` — connection-state leak
`nxc_connection.py:412` creates a client and calls `connect_and_get_server_endpoints` (line 171, inside `_pre_auth_discovery`). At lines 426/433/444, `self._client = None` is assigned on early-return paths WITHOUT awaiting `disconnect()`. At line 451 success path re-assigns `self._client = Client(...)` without disconnecting prior one. `connect_and_get_server_endpoints` is mostly self-cleaning in current asyncua, but explicit close pattern is absent — any future asyncua change that leaves a TCP socket open silently leaks a connection per scan.
**Fix:** add `await self._client.disconnect()` (best-effort, debug-log on failure) before each reassignment / nulling.

### src/oida/protocols/opcua/nxc_connection.py:98-101 — User-supplied `--port` silently overwritten by the port embedded in `opc.tcp` URL
`nxc_connection.py:98-101` mutates `args.port = port` (parsed from URL) without checking whether the user explicitly set `--port`. `oida opcua opc.tcp://host:4840 -p 9999` silently scans port 4840 with no warning. argparse can't distinguish 'set' vs 'defaulted', but at minimum: only mutate when URL explicitly contained a port (input string had `:port`), or log a warning when overriding a non-default value.

## LOW

### src/oida/shared/file_carving_common.py:53-63 — `FileCarvingMixin` docstring contract references `_get_logger()` that is never called
Mixin docstring says subclasses may provide `self._get_logger()` ('optional, defaults to self.logger'). Grep shows no call site for `_get_logger` anywhere in the mixin — every log path goes through `self.logger.{info,debug}` directly. Stale contract item left from earlier refactor.
**Fix:** drop the line from the docstring.

### src/oida/protocols/discovery/ipv4_resolve.py:98-104 — `IPv4ResolveScanner` silently truncates subnets >/22 to the first /22 with no audit record
When interface subnet is /21 or wider, resolver picks `list(network.subnets(new_prefix=22))[0]` — lowest /22. Devices in any later /22 are silently unreachable. Warning says 'limiting to /22 (1024 hosts)' but does not say *which* /22 was picked. Operator scanning a /20 office network where IPv6-only printers live in the second /22 gets empty `discovered_devices` with no diagnostic.
**Fix:** log the chosen subnet (`logger.warning(f"... limiting to first /22: {subnet}")`); consider sweeping all /22 sub-blocks sequentially when fewer than N candidate MACs are unresolved (or expose `--full-sweep`).

### src/oida/protocols/discovery/{igmp,netmanage}.py — Duplicate docstring line `devices = listener.scan()` in three listener class docstrings
Both docstrings contain the literal line `devices = listener.scan()` twice consecutively (igmp.py:64-65, netmanage.py:37-38). Copy-paste artefact during docstring rewrite. Tiny but obvious in `pydoc`/`help()` output and generated docs.
**Fix:** delete one copy.

### src/oida/protocols/discovery/ics.py:904 — Dead `_tag_names` local in `ADSScanner._parse_tlv_tags` (suppressed with `noqa`)
`_tag_names = {v: k.lower() for k, v in self.ADS_UDP_TAG.items()}  # noqa: F841` — built and never referenced inside the function. The `noqa: F841` admits the staleness instead of fixing it. Either wire into the dispatch (replace chain of `if tag_type == self.ADS_UDP_TAG['HOSTNAME']: ... elif ...` with `result[_tag_names[tag_type]] = ...` lookup) or delete.

### src/oida/protocols/discovery/mdns.py:65-69,251-254 — `MDNSScanner`/`DNSSDScanner` IPv6-only path silently no-ops when zeroconf binds AF_INET only
Both `MDNSScanner.scan()` and `DNSSDScanner.scan()` check `if netifaces.AF_INET not in addrs` and return `{}` — even on IPv6-only interfaces where `AF_INET6` is present and zeroconf can bind to it (zeroconf>=0.39 supports `interfaces=[ipv6_str]`). mDNS over IPv6 is part of documented protocol surface (`ff02::fb` multicast at mdns.py:26) but unreachable from active scanners. Fallout: IPv6-only or dual-stack-with-IPv4-disabled labs get empty mDNS dict and a misleading `No IPv4 address on eth0` warning.
**Fix:** fall back to `netifaces.AF_INET6` when AF_INET is absent; or document IPv6 limitation in `--help`.

### src/oida/protocols/discovery/dhcpv6.py:464-467 (INFO) — DHCPv6 active scanner uses random per-scan link-layer for DUID-LLT, breaking server-side reservation semantics
`_build_solicit` generates a fresh random MAC for the DUID on every invocation. DHCPv6 RFC 8415 §11 explicitly requires DUID to be stable per client. Servers maintaining client-DUID-based reservations or rate-limiting by DUID see each oida scan as a brand new client and may emit Advertise from address pools the operator did not intend to exhaust (memory leak on the DHCPv6 server side over a long pentest engagement). Tiny correctness issue with a real OT-network footprint.
**Fix:** derive DUID-LLT from interface MAC via `get_if_hwaddr(self.interface)` rather than randomising; or switch to DUID-EN with a stable per-host enterprise number.

### src/oida/protocols/ethernetip/mixins/discovery.py:408-423 — Repeated copy-paste exception messages in `DiscoveryMixin` reuse the same wrong context string
Three except branches inside `_broadcast_discovery` all log `f'broadcast discovery failed: {e}'` — once for EXPECTED `TimeoutError` during `recvfrom` (line 408-410, normal exit path), once for legit outer exception (line 414-415), and once for socket-close exceptions in finally (line 421-423). TimeoutError debug message in particular spams every 0.5s for the timeout duration even on a normal scan.
**Fix:** rename to `'recvfrom timeout (normal)'`, `'broadcast send/recv error'`, `'socket close error'`; drop the TimeoutError branch entirely (it's expected and `continue` is correct without logging).

### src/oida/protocols/ethernetip/nxc_connection.py:12-14,177 — `nxc_connection.py` uses stdlib `logging.getLogger` in static `check_dependencies`
`import logging` + module-level `logger = logging.getLogger(__name__)` bypasses ICSLogger. Used only inside `@staticmethod check_dependencies` at line 177 for a debug message never surfaced. Same project-rule violation flagged in mms/nxc_connection.py (§430-432) and hart mixins.
**Fix:** drop the module-level logger; log via a helper that accepts an injected logger, or drop the message entirely (static method has no `self`).

### src/oida/protocols/ethernetip/mixins/network_parsers.py:84-91 — `_parse_tcp_ip_interface` hostname docstring contradicts what the code parses
Comment line 84 reads `# CIP Short String: 2-byte length (UINT) + string data`. CIP `SHORT_STRING` is USINT (1-byte length); `STRING` is UINT (2-byte length). Code at line 86 parses with `<H` (UINT, 2 bytes), which is correct per ODVA Vol 2 §5-3.4.6 for the TCP/IP Interface Object Host Name attribute (STRING, not SHORT_STRING). Comment mislabels the type.
**Fix:** change comment to `CIP STRING: 2-byte UINT length + string data`.

### src/oida/protocols/ethernetip/mixins/cip_security.py:350-356 — `_dump_certificate_management` parses Device Certificate CN as STRING but spec defines SHORT_STRING
Comment says `Device Certificate CN (SHORT_STRING)` but parser uses `struct.unpack('<H', cn_data[:2])` — 2-byte length, which is STRING not SHORT_STRING. Per ODVA Vol 8 §5-2 the Certificate Management Object's Device Certificate attribute is SHORT_STRING (USINT length). If the underlying device emits SHORT_STRING, `cn_len` will be a huge value and subsequent length check usually fails, dropping the CN silently.
**Fix:** `cn_len = cn_data[0]; name = cn_data[1:1+cn_len]` (or check both 1-byte and 2-byte length variants by device vendor).

### src/oida/protocols/ethernetip/scanner.py:52-54,91-93 — Dead `_radamsa_mod` lazy import and `_get_radamsa` helper
`_radamsa_mod = lazy_import('oida.fuzz.core.mutation', ..., install_hint='pip install oida[fuzz]')` and `_get_radamsa()` factory defined but no caller exists in `src/oida/protocols/ethernetip/`. FuzzMixin uses `from ....utils.fuzzer import fuzz` instead (mixins/fuzz.py:278). Carrying lazy import wastes `importlib.util.find_spec` call per startup and tags `oida[fuzz]` as dependency surface no longer used.
**Fix:** delete lines 52-54 and 91-93.

### src/oida/protocols/bacnet/mixins/cip_objects.py:374-378,414-416 — `_discover_chassis_topology` and `_scan_port_addresses` duplicate the pycomm3-logger-level mutation already flagged in nxc_connection
Same pattern as already-flagged `nxc_connection.py:163-169`: `_scan_port_addresses` does `pycomm3_logger.setLevel(logging.CRITICAL)` per call, restores in finally. Restore here works (assignment in `try`), but per-call setup/teardown duplicates what `connect()`/`disconnect()` already maintains in scanner.py:466-468/523-528. Two layers of silencing means even if outer level is restored, inner wins during scan.
**Fix:** rely on outer `connect()` silencing and drop the inner setLevel block; or factor a single `_silence_pycomm3()` context manager.

### src/oida/protocols/bacnet/mixins/properties.py:333-360 — `_read_property`/`_write_property` string-format injection if address/obj_type/prop contains spaces (BAC0 string-protocol API)
Builds `f'{address} {obj_type} {instance} {prop}'` and passes to `self.bacnet.read/write` (BAC0 space-separated string API). `_parse_read_spec`/`_parse_write_spec` accept any string after `:` split, so user passing `-r 'analogInput:1:objectName extraToken'` interpolates a 5-token string and BAC0 parses as `addr obj inst prop extra`. Not a security boundary (user-supplied to user-controlled scanner) but produces confusing failure deep in BAC0.
**Fix:** validate `obj_type`/`prop` against `OBJECT_TYPE_NAMES`/property whitelist before passing; or use BAC0 structured ReadProperty API directly.

### src/oida/protocols/bacnet/mixins/state.py:125-127 — `_handle_diff` resolves and logs absolute baseline path → engagement-context privacy leak in JSON audit log
`baseline_file = Path(self.args.diff).resolve()` then `self.logger.fail(f'Baseline file not found: {baseline_file}')`. Same exposure pattern as the `format_wordlist_source` concern: with `--json-log` enabled, the resolved absolute path (e.g. `/home/pentester/clients/acmecorp/baseline-2026-05-01.json`) lands in structured audit log shared back to client.
**Fix:** log only `baseline_file.name`, or strip path through a baseline-aware formatter similar to `format_wordlist_source`.

### src/oida/protocols/bacnet/mixins/state.py:104-117 — `_handle_dump` only honors `output_format='json'` or `'yaml'`; CSV produces success log but never writes a file
Branches on `output_format == 'json'` or `'yaml'`. With format='csv' (a valid `--format` choice), code reaches `success(f'Dump saved to {dump_file}')` at line 117 with `dump_file` still bound to initial `Path(output_path)` from line 109, suffix unchanged, but no `write_text` was ever called — the success log claims a save that didn't happen.
**Fix:** explicitly reject unsupported formats with `logger.fail`, or fall back to JSON; defer yaml import inside the yaml branch.

### src/oida/protocols/bacnet/mixins/export.py:58-75 — `ExportMixin` only writes JSON or CSV; `--format xml` silently produces no output file
`_export_results` branches `if output_format == 'json'` then `elif output_format == 'csv'`. xml (and the `all` value cli.py advertises) are silently skipped. No log; user thinks export succeeded. Pairs with the missing `add_output_options` call already flagged (§502).
**Fix:** route through `utils.export_utils.export_data` (handles json/csv/xml/all) rather than hand-rolling format dispatch.

### src/oida/protocols/bacnet/mixins/security.py:846-960 — `_bacpypes3_check_oos` and `_bacpypes3_test_oos` do not stash readable/writable findings into `self.results` — export/JSON consumers see no OOS data
`_bacpypes3_test_oos` collects `readable` and `writable` lists locally, logs them, and returns. Neither is appended to `self.results / self.results['data']`. Same for `_bacpypes3_check_priority`, `_bacpypes3_check_schedules` etc. throughout monitoring.py. Operator relying on `-o results --format json` for downstream tooling gets device metadata but not assessment outputs.
**Fix:** standard pattern `self.results.setdefault('security_findings', []).append({...})` per assessment.

### src/oida/protocols/bacnet/mixins/security.py:226-230 — `_handle_check_oos` returns on first OOS-readable hit; never probes additional objects
Inside the for-loop, after logging the first readable OOS, code hits `return` (line 230) — exits the entire function. Reports at most one object even on devices with hundreds. Sister bacpypes3 helper `_bacpypes3_test_oos` at line 879-915 correctly iterates the full test_objects list. Combined with existing HIGH finding that this helper only reads (never tests write), the early return makes the BAC0 path even less useful.
**Fix:** drop the `return`; let the loop complete and aggregate.

### src/oida/protocols/bacnet/constants.py:160-170 + mixins/*.py — Two-phase `_ensure_bacpypes3_globals` + per-mixin `_load_bacpypes3()` do redundant import work
`proto_flow` at nxc_connection.py:102 calls `_ensure_bacpypes3_globals()` which loads bacpypes3 types and injects into constants.py module globals. Every mixin then re-imports the same dict via `types = _load_bacpypes3()` and unpacks ~10 names per call. `_load_bacpypes3()` is cached so it's a dict-lookup, but the pattern is inconsistent: properties.py and discovery.py do per-call import. The injected globals at constants.py:168 are then unused by any mixin (all use local-binding pattern). Dead code: `_ensure_bacpypes3_globals` called once but effect is unused.
**Fix:** drop `_ensure_bacpypes3_globals` entirely; keep the per-mixin `_load_bacpypes3()` pattern.

### src/oida/protocols/knx/{helpers,bcu,ets,nxc_connection}.py + mixins/discovery.py — `from ...utils import ics_logger as module` aliased to literal `module` — refactor artifact
Five files alias the shared ICS logger as `module`: `from ...utils import ics_logger as module` and call `module.warn(...)`, `module.mac_lookup(...)`, `module.fail(...)`. Reads like refactor-in-flight (probably from `from ...utils import ics_logger` → `from ...utils.ics_logger import warn as module_warn, ...` that was abandoned). Concretely problematic because: (1) `module` is built-in concept name (Python uses `module` in many contexts); shadows in linter output / IDE tooltips. (2) Aliased calls hide that these are project-wide ICSLogger free-function helpers, making harder to grep. (3) Inconsistent with helpers.py line 14 which uses `from ...utils.ics_logger import get_module_logger`.
**Fix:** rename the alias to `ics_logger` (or import names directly: `from ...utils.ics_logger import warn, fail, mac_lookup`). Apply uniformly across the 5 files.

### src/oida/protocols/knx/helpers.py:325-336 — `parse_bus_ranges` silently accepts reversed ranges and >2-part splits
Two robustness gaps: (1) No `start <= end` validation. `--scan-range 1.1.255-1.1.1` yields zero addresses (range(255, 2) is empty); scanner reports 0 devices found without telling user the range was malformed. `parse_key_range` in bcu.py:70-71 already has this check. (2) `parts = range_part.strip().split('-')` accepts strings like '1.1.1-1.1.5-9.9.9' silently — splits into 3 parts, code reads parts[0] and parts[1], ignores parts[2:]. User input '1.1.1- -1.1.5' parses without error and silently scans only '1.1.1-' (malformed, falls back to default per related finding).
**Fix:** validate `start <= end` after parsing; raise on `len(parts) > 2`.

### src/oida/protocols/knx/scanner.py:260-426 (~16 sites) — Auth brute-force, fuzz-property, prop-dump default `--individual-address` to `'1.1.1'` — runs against a real address the user didn't specify
Pattern `individual_addr = self.args.get('individual-address', '1.1.1')` repeats 16+ times in `_async_discover`. Many ops are destructive or expensive: `--auth-test/--key-file/--key-range` brute-forces BCU auth, `--fuzz-property`, `--memory-write`, `--property-write`. If pentester runs `oida knx 10.0.0.50 --auth-test --key-file keys.txt` and forgot `-i`, they brute-force device 1.1.1 — the standard line-coupler address on virtually every KNX line and the LAST device you want to lock out.
**Fix:** require `-i` for any operation that targets an individual address; emit `self.logger.fail('--auth-test requires -i')` and skip the action instead of defaulting. Mirror the `--restart requires -i` guard at scanner.py:327-328.

### src/oida/protocols/knx/mixins/device_info.py:23-42 — `_read_descriptor` return type contract violation: docstring says 2-tuple, returns 3-tuple
Docstring says 'returns (desc_hex, mask_version) or (None, None)'. Actually: success path (line 39) `return desc_hex, mask_version, desc_bytes` (3-tuple); exception path (line 42) `return None, None, None` (3-tuple). Docstring is wrong; real contract is 3-tuple, which all 3 callers (device_info.py:78,183,430) already unpack correctly. But docstring lie is a maintainability hazard: new caller reading docstring will write `desc_hex, mask_ver = await self._read_descriptor(...)`, which raises ValueError at runtime ('too many values to unpack').
**Fix:** update docstring to '(desc_hex, mask_version, desc_bytes) or (None, None, None)'.

### src/oida/protocols/knx/mixins/properties.py:818-948 — `_dump_all_properties` resume-position drift: `prop_start` only advances on success
Inside per-object scan, `prop_start = prop_id + 1` is set only at line 918, inside success branch. The `continue` paths at line 844 (max_count==0) and line 945 (exception) do NOT update prop_start. If a stretch of properties returns max_count=0 (documented 'end-of-properties' signal) and is then followed by a connection-lost exception, reconnect re-enters `range(prop_start, 256)` from stale prop_start pointing at an already-processed property — those properties are re-scanned, wasting time and potentially re-triggering rate-limit / lockout. Retry budget (`max_retries=3`) means up to 3 full re-scans of skipped range.
**Fix:** update `prop_start = prop_id + 1` at the top of every iteration (before the try block) rather than only on success.

### src/oida/protocols/knx/ets.py:495-534 — `extract_knxproj_hash` temp file written with `NamedTemporaryFile(delete=False)`; cleanup relies on later unlink
`tempfile.NamedTemporaryFile(suffix='.zip', delete=False)` writes the encrypted inner ZIP (the actual customer project archive) to /tmp/tmpXXXXXX.zip. Unlinked at line 532, but on KeyboardInterrupt (Ctrl-C during zip2john run), the unlink is never reached, and the customer's encrypted project file sits in /tmp until reboot or temp cleanup. On shared workstations, leftover .zip files in /tmp may be readable by other accounts depending on umask history. Operator doesn't know a copy was written.
**Fix:** wrap entire post-tempfile block in `try / finally: os.unlink(temp_path)`; or use `tempfile.SpooledTemporaryFile` (zip2john can read from stdin via `-`).

### src/oida/protocols/knx/ets.py:113,322 — Generic 'Operation failed' debug messages with no context
Both `_test_knxproj_password_fast_mp` and `test_knxproj_password_fast` catch `Exception as e` and log `logger.debug(f'Operation failed: {e}')`. In a crack run with 50k passwords, every wrong-password attempt hits this except (because `inner.read` raises BadZipFile / InvalidPassword), spamming `Operation failed: ...` at debug. Operator running with --debug sees an uninterpretable wall of identical messages.
**Fix:** narrow except (catch `InvalidPassword`/`BadZipFile` explicitly and silently `return None`); log only unexpected types with a real message.

### src/oida/protocols/hl7/mixins/device.py:99-111 — `DeviceMixin` always overrides user `--sending-app` for PCD-01; override silent and undocumented
PCD-01 hard-codes `sending_app = f'{device_apps.get(device_type,"DEVICE")}_{device_id}'` and passes positionally to `populate_msh`. `populate_msh`'s `sending_app` kwarg overrides args.sending_app default, so `--sending-app=MY_TEST` is silently ignored for PCD-01/03/alarm. May be intentional (impersonate a real device) but CLI help (`--sending-app: Sending application name (default: OIDA)`) doesn't mention it; operators using a config file to set constant audit identity get inconsistent MSH-3 across protocols.
**Fix:** document or honour the override.

### src/oida/protocols/hl7/segments.py:1075-1082 — `get_field`'s exception handler logs an unintelligible garbled message
Refactor artefact: `logger.debug(f"if 0  index  len(fields):: {e}")` (line 1081) — garbled rewrite of `0 < index <= len(fields)`. Also `_get_field_value` returns `default` on any exception including AttributeError from missing fields, but logs at debug — under `-vvv --debug` every missing optional field spams the log.
**Fix:** rewrite to describe the actual operation; narrow the except.

### src/oida/protocols/hl7/segments.py:900-904 — `build_dg1` unconditionally overwrites DG1-5 with `now()` when caller passes empty string
`build_dg1` is called from `_create_message_with_segments` whenever `dx_code OR dx_description` is set (message.py:301-312). Inside, `if diagnosis_datetime: dg1_5 = ... else: dg1_5 = now()`. Every DG1 emitted by OIDA carries a 'diagnosis datetime' = scan timestamp, even when operator only wanted to inject a code. Receivers that audit DG1-5 (revenue cycle systems flagging same-day-of-service rules) see anomalous data.
**Fix:** leave DG1-5 empty when not provided, or expose `--dx-datetime` (currently absent from proto_args).

### src/oida/protocols/hl7/mixins/probe.py:38-49 — Probe results 'timeout' bucket conflates real timeouts with unknown ACK codes; ack_code state coupling with `_analyze_security` is fragile
`_extract_ack_code(response)` returns `None` both when there is no response AND when the response has no MSA. The else branch (line 48-49) categorizes any non-AA/AR/AE/CA/CR/CE response as 'timeout', including valid HL7 responses whose ACK code is e.g. 'CR' uppercase with whitespace, vendor-extension codes ('XX'), or 'NAK' textual ack. Probe summary under-reports 'supported' types on Mirth Connect / Cerner permissive endpoints. Also: probe doesn't call `_parse_response`, so `self.results['data']['ack_code']` from prior `enum_host_info` ADT^A01 is what `_analyze_security` reads after probe finishes (probe early-returns at __init__.py:351-356) — probe loop result and security analysis disagree on which message defined the 'accepted' state.
**Fix:** distinguish `None` (no response) from `'?'` (response without canonical ACK); scope ack_code per message.

### src/oida/protocols/snap7/models.py:13-15,55 — `models.py` uses stdlib logging instead of ICSLogger; debug message is refactor-artefact 'Failed to get clean'
Two violations: (1) `import logging; logger = logging.getLogger(__name__)` at module top, then `S7FirmwareVersion.from_string` line 55 emits `logger.debug(f'Failed to get clean: {e}')`. `clean` is the local variable holding the stripped version string — copy-paste artefact identical to 'Failed to get <localvar>' pattern flagged for discovery/enrich. Module is stateless helper without `self`; project rule still routes debug through ICSLogger.
**Fix:** drop `import logging`; pass caller's logger in or accept it as optional kwarg (same pattern as `knx/ets.py`). Rewrite message to describe operation: 'firmware version parse failed for %r: %s'.

### src/oida/protocols/snap7/models.py:29-73 — `S7FirmwareVersion` defines custom `__eq__` on a @dataclass without restoring `__hash__`, making instances unhashable
@dataclass auto-generates `__eq__` and (with eq=True, frozen=False default) sets `__hash__ = None` making the instance unhashable. The manual `__eq__` override at line 70 silences auto-generation but leaves `__hash__ = None`. Any caller doing `set(versions)` or `{ver: meta}` raises `TypeError: unhashable type: 'S7FirmwareVersion'`. Not exercised today, latent if firmware-version dedup is ever added.
**Fix:** pass `eq=True, frozen=True` to @dataclass (drops need for manual ordering/equality methods); or add `def __hash__(self): return hash((self.major, self.minor, self.patch))`.

### src/oida/protocols/snap7/mixins/block_operations.py:113-118 + mixins/memory.py:280-287 — `upload_db`/`dump_db` silently truncate to 256 bytes when `get_block_info()` fails
Both helpers fall back to `size = 256` when `get_block_info(Block.DB, db_num)` raises or returns missing/0 MC7Size / LoadSize. Fallback becomes the size of the read, and result dict reports `size: 256` and a 256-byte hex payload. For DBs larger than 256 bytes (DBs often exceed 1 KiB), `--upload-db <num>` / `--dump-db <num>` returns silent partial dump. User saving to disk via `--output-file` gets a 256-byte file with no warning.
**Fix:** when falling back, log `self.logger.warning('DB size unknown — defaulting to 256 bytes (data may be truncated)')`; ideally walk DB with successive `db_read` calls until error indicates end-of-data.

### src/oida/protocols/snap7/mixins/device_info.py:240-280 — `_identify_series_from_order_code`: dead branches and redundant guards
(1) `elif num_part.startswith('22'):` is reachable only if earlier `startswith('21')` did not match — fine, but order code 22x is not actually used by Siemens for S7-1200; comment 'S7-1200 compact (22x)' has no datasheet basis and will misclassify a future 22x order code. (2) Final `elif` reads `num_part.startswith('2') and not num_part.startswith('21') and not num_part.startswith('22')` — by control flow, both earlier branches already returned, so the two `not startswith` guards are guaranteed-true dead checks. (3) `_identify_series_from_order_code` is a `DeviceInfoMixin` method but referenced (with `self.`) from `SlotScanMixin._scan_single_slot` (slot_scan.py:155,186) — works only because SlotScanMixin is composed alongside DeviceInfoMixin in `Snap7Scanner`. If future refactor uses SlotScanMixin standalone, AttributeError.
**Fix:** drop the redundant guards; validate the 22x claim against a Siemens datasheet (likely remove it); move helper to a shared utility module or declare the dependency explicitly in SlotScanMixin's docstring.

### src/oida/protocols/snap7/mixins/security.py:124-126,235-236,278-280,316 — `host, port = self.get_target_info()` result discarded in several sites
Several blocks compute `host, port = self.get_target_info()` and immediately use only one (or neither). Examples: line 125 then `self.logger.security_finding(...)` (neither used in finding text); line 316. Style noise that suggests 'this finding is host-scoped' when host context is being lost.
**Fix:** drop the unused unpack, or wire values into security_finding payload (e.g., `detail=f'protection_level={protection_level} on {host}:{port}'`).

### src/oida/protocols/snap7/mixins/block_operations.py:904-907 — `monitor()` treats KeyboardInterrupt as a 'failed' debug log message
`except KeyboardInterrupt as e: self.logger.debug('monitor failed: %s', e)` then immediately displays 'Monitor stopped by user'. KeyboardInterrupt is the expected exit path for an infinite-duration monitor (line 809 says '... Ctrl+C to stop'); calling it 'failed' misleads anyone parsing the JSON audit log. KeyboardInterrupt carries no meaningful payload — `str(e)` is empty, so the message is literally `monitor failed: `.
**Fix:** drop the debug line; or replace with `self.logger.debug('monitor stopped by Ctrl+C after %d iteration(s)', iteration)`.

### src/oida/protocols/opcua/scanner.py:361-365 — `_test_authentication` calls `set_user(None)` and unconditionally reports 'Anonymous access: ALLOWED'
'Tests' anonymous access by calling `set_user(None)` and reporting ALLOWED if no exception raised. `set_user` is a synchronous setter that never raises — and never authenticates. Proper anonymous test inspects `UserIdentityTokens` on the endpoint list for `Anonymous` (L2 NXC discovery already does this — `has_anonymous` in discovery.py:303). Conceptual root cause of the CRITICAL/MEDIUM scanner.py findings above; even after the `await` TypeError is fixed, test is still wrong because no auth is performed.

### src/oida/protocols/opcua/mixins/credentials.py:62,184 — Hardcoded 5s timeout in brute-force ignores `--timeout`
`credentials.py:62` sets `test_client.timeout = 5` regardless of `getattr(self.args, 'timeout', 5)`. RBAC test does the same at line 184. Other OPC UA flows honor `--timeout` (nxc_connection.py:413,452). Inconsistent and surprising when scanning slow/WAN-reachable endpoints.

### src/oida/protocols/opcua/mixins/fuzz.py:468-473 — `--fuzz-method` iteration arithmetic mis-targets 'too few args' / 'too many args' edge cases at small iteration counts
Mutates `fuzz_args` for `i == iterations-2` (too-many) and `i == iterations-1` (too-few). With `--fuzz-iterations 1` only the too-few branch fires and no actual fuzz value is sent. With `iterations=2` only one fuzz value plus two edge cases run — two of three iterations exercise non-fuzz code paths.
**Fix:** reserve a fixed quota of edge-case iterations on top of `iterations`, or skip edge-case mutation when `iterations < 3`.

### src/oida/protocols/opcua/mixins/{browse,methods,security}.py — Three mixins use forbidden `import logging` + `logging.getLogger(__name__)`
`browse.py:9-11`, `methods.py:11-13`, `security.py:13-15` all do `import logging; logger = logging.getLogger(__name__)` then `logger.debug(...)` (browse:123,199,393,446,454; methods:54; security:181,190,200,336). Per project convention only `self.logger` is allowed — discovery.py was already migrated to `get_module_logger(__name__)` and other mixins call `self.logger.debug(...)` throughout. Mixed style is inconsistent and bypasses centralized formatting/verbosity controls.
**Fix:** convert all three to `self.logger.debug` (or `get_module_logger` if module-scope logging is genuinely needed).

### src/oida/protocols/opcua/mixins/files.py + nxc_connection.py + fuzz.py — Generic copy-paste debug strings obscure which operation actually failed
files.py has ~10 `self.logger.debug('search failed: %s', e)` calls inside differently-named functions (`is_file_like`, `search`, `_read_file`, `_write_file`). Same pattern in nxc_connection.py:509/514/519/525/535/541 where every except logs `'async proto flow failed: %s'` — disconnect-in-finally exception is misreported as 'async proto flow failed'. fuzz.py has many `'write value failed'` lines inside `_find_writable_nodes`, `_find_callable_methods`, etc. Pick a per-call-site message so the next failure is debuggable from the log alone.

### src/oida/protocols/modbus/scanner_mixins/custom_fc.py:69-106 — `send_custom_fc` registers a fresh CustomFCResponse PDU class per call; long fuzz sessions accumulate registrations
Each invocation defines new local classes `CustomFCRequest`/`CustomFCResponse` (closing over `fc` and `payload`) and calls `client.register(CustomFCResponse)`. Pymodbus's internal PDU registry indexes by function code; subsequent calls with the same FC overwrite the previous entry, but a fuzz pass exercising 63 vendor FCs leaves 63 distinct class objects alive on the client until destroyed. Small memory growth but unbounded per long-running monitor+fuzz session and invisible to GC.
**Fix:** define classes once per FC at module/scanner scope (memoised by fc); or `client.unregister(fc)` before returning.

### src/oida/protocols/modbus/mixins/sunspec.py:319-323 — SunSpec model walk treats `model_length==0` as 'suspicious' but length=0 is legal for the end-block
`if model_length == 0 or model_length > 2000: break  # suspicious`. SunSpec `model_id 0xFFFF` (END_MODEL_ID) has defined length of 0; line 314 already handles that sentinel before this check, so length=0 branch fires only on a malformed model header. But debug message labels length=0 as suspicious which contradicts the upstream comment about end-sentinel handling.
**Fix:** drop the `model_length == 0` clause (caught by prior end-sentinel branch when device is well-behaved), or change message to 'length=0 for non-end model id, stopping'.

### src/oida/protocols/modbus/import_maps.py:345 + convert_maps.py:145 — Dead expression `group.get('group', '')` in import/convert helpers
Both functions iterate `for group in data.get('parameters', []):` then immediately do `group.get('group', '')` as a bare expression whose return value is discarded. Pattern strongly suggests a refactor that lost `group_name = group.get('group', '')`. Either group_name was meant to be used (as a register prefix or in description) and wiring is missing, or the line is dead.
**Fix:** wire it up (e.g. include as register prefix), or delete.

### src/oida/protocols/modbus/import_maps.py:72 — `except (json.JSONDecodeError, Exception)` is redundant — JSONDecodeError is a subclass of Exception
Equivalent to `except Exception as e:`. Either keep only `Exception` or split into two arms with different log messages. Probably a refactor artefact from a version that had a specific JSONDecodeError handler.

### src/oida/protocols/discovery/file_carving.py (already covered — kept for cross-ref) — see existing LOW §545
Existing finding covers the file-carving `open(filepath, 'wb')` site; the cross-listener inconsistency at the *base mixin* level is captured in the new MEDIUM `shared/file_carving_common.py` finding above.

## INFO

### Areas with zero NEW findings
After dedup against the existing report, no NEW gap findings were generated for: framework layer (cli/loader/connection/targets/lazy_import/login_scanner/ics_logger), pcap orchestrator, the `discovery/scanner.py` and `discovery/core.py` core modules, `coap`, `dnp3`, `ethercat`, `fhir`, `goose`, `iec104`, `mms`, `dicom`, `ads`, `can`, `astm`, `hart`, `mqtt`, `ocpp`, `snmp`, `tase2`, `profinet`. The existing review's coverage of those modules already enumerates the high-value findings.

### Note on rthook_hl7apy
Three of four rthook findings (orphan, hardcoded version list, makedirs crash) collapse into a single 'this file is build-dead' decision: either the hook is wired into a proper PyInstaller spec (with the proper `collect_submodules`-style hookspec replacing the empty-marker-dir trick) and gets a CI smoke test, OR the file is deleted entirely. The MEDIUM 'empty dirs don't actually fix the hl7apy bug' finding is the load-bearing one — if the bug is real, the current implementation does not fix it; if the bug is fictional, the file is pure dead code.
