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
