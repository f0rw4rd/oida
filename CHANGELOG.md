# Changelog

All notable changes to OIDA are documented here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## 1.0.0 — unreleased

First stable release.

### Added

- **Test suite expanded by 175 tests** (13,250 → 13,425 passing) in the
  release-prep push: 28 new pcap-listener test files (one per audit-flagged
  listener), false-positive coverage extended from 6 to 16 protocols,
  `tests/unit/<proto>/test_proto_args.py` added for the 6 thinnest-tested
  protocols (mms, snmp, hart, dicom, tase2, mqtt), and 23 regression tests
  pinning ADS `--confirm` enforcement.
- **§4.1 fuzzer optimizations (26 items across 11 protocols)** landed via a
  parallel-agent workflow: DNP3 gained `DNP3_Object_Sweep` /
  `DNP3_IIN_Master` / `DNP3_DL_Bad_CRC`; ADS gained `ADS_Port_Enumeration`,
  `ADS_SumReadWrite`, and `ADSMonitor` wiring; EtherNet/IP gained
  `CIP_Class_Enumeration` plus fuzzable-flag flips on CIP_Path_* and
  Forward_Open RPI; IEC 104 extended `ASDU.TypeId` to reserved/vendor
  ranges + `CommonAddress` sweep; MMS gained `BER_Tag_Confusion`; SNMPv3
  gained Set/Trap/Inform/GetBulk PDU types and USM auth-param fuzzing;
  OPC UA extended `ExtensionObject TypeId`; HL7 gained MSH-12 version
  sweep + Z-segment injection; MQTT gained Sparkplug B + reason code
  sweep; modbus added `max_len=4096` cap on ADU overflow primitives.
- **Centralised wordlist privacy helper** —
  `utils.login_scanner.format_wordlist_source(path)` returns the basename
  (not the full path) for user-facing log lines so engagement-sensitive
  paths like `/home/pentester/clients/acmecorp/internal-creds.txt` no
  longer leak into screen output or JSON logs. Adopted by snap7, dicom,
  hart, and the snap7 brute-force mixin.
- **ADS state-change `--confirm` enforcement** — `validate_args()` now
  refuses `--scan-coe`, `--write-coe`, `--add-route`, `--foe-write`,
  `--foe-delete`, `--write-symbol`, `--memory-write`, `--set-state`,
  `--fuzz`, `--fuzz-coe` without `--confirm`. Help text already said
  "Requires --confirm"; this turns the promise into a hard gate. Mirrors
  the dnp3 / ethercat pattern.
- **ADS listener `state_flags` extraction** — per-bit decoding of
  `ams.state_adscmd / state_syscmd / state_highprio / state_initcmd /
  state_timestampadded / state_udp / state_broadcast / state_noreturn`
  populated into `interaction.details["state_flags"]` (list of active
  bit names).
- **LDAP SASL/GSSAPI-encrypted message recording** — Kerberos-bound LDAP
  sessions previously fell through the operation-classifier with no
  interaction recorded. Now emit `SASL-Encrypted` interactions carrying
  `sasl_buffer_length` + `encryption` metadata so operators can see the
  session exists even though the LDAP payload is opaque.
- **`docs/ARCHITECTURE.md`** — documents the canonical Layer-1 / Layer-2
  facade pattern, lists protocols that deviate, and codifies the
  `proto_logger()` contract.
- **`RELEASE_READINESS.md`** — snapshot of the audit work feeding 1.0,
  including six per-subsystem review reports.
- **DECODE_AS scanner integration** — pcap listeners can declare per-listener
  `DECODE_AS` hints (`tcp.port==X: dissector`) which are now actually applied
  by the scanner. `ajp`, `rmi`, and `rsync` listeners produced zero matches
  before this fix.
- **`get_local_ip()` helper** in `utils.socket_helpers` — replaces three
  copies of the UDP-connect trick (`ads/scanner.py`, `bacnet/nxc_connection.py`,
  `discovery/ics.py`). BACnet no longer connects to `8.8.8.8` to detect the
  local IP.
- **`Crash.crash_hash`** column + BLAKE2b signature computation — fuzzer
  crash dedup at triage time. Duplicate crashes can be grouped via
  `GROUP BY crash_hash`.
- **CI matrix** — tests now run against Python 3.10, 3.11, and 3.12
  (was 3.12 only).
- **Brotli, docker, defusedxml** added to the `[dev]` extra so the test
  matrix doesn't silently skip.
- **`oida snap7`** now works as the canonical CLI subcommand for Siemens S7;
  `oida s7` is an alias.
- **`SECURITY.md`**, **`CODE_OF_CONDUCT.md`**, and `.github/ISSUE_TEMPLATE/`
  + `.github/pull_request_template.md` ship for the 1.0 community-files
  baseline. Private vulnerability disclosure goes through https://getoida.dev/contact.
- **`tests/coverage/fuzz/test_cve_replication.py`** + **`tests/coverage/
  fidelity/test_conpot_diff.py`** — scaffolds for the axis-2 and axis-3
  real-coverage suites (see `docs/REAL_COVERAGE_PROPOSAL.md`). Per-CVE
  driver and Conpot diff classification land post-1.0.
- **`.github/workflows/coverage-nightly.yml`** — nightly cron job that
  runs all three real-coverage axes against the full mock stack,
  publishes JUnit + JSON artifacts, and pushes a dashboard.md to the
  `coverage-dashboard` orphan branch.

### Changed

- **`services.py` mock management is now fully data-driven from compose
  labels.** The hardcoded `PROTO_SPECS` table (14 `up-<proto>` subcommands
  with duplicated service lists/ports/profiles) was removed; service
  metadata is read live from the `oida.*` labels in `compose.yml` /
  `compose.cve.yml`. `up <group>` now resolves every member of an
  `oida.group` across **both** compose files (core + CVE) and auto-selects
  the `vuln-*`/profile each member declares — previously it only saw core
  services and missed CVE members (and CVE-only groups like `dns`/`smtp`
  were unreachable). New `groups` command lists the valid group names.
  `python services.py up` now shows normal docker pull progress by default;
  pass `--quiet-pull` to suppress it. The 14 `up-<proto>` commands
  (`up-goose`, `up-mqtt`, …) are removed — use `up <group>` or
  `up-cve <proto>` instead.
- **`NetworkConnection.__init__`** auto-calls `proto_logger()` before
  `proto_flow()`. Subclasses no longer need to call it as their first line
  (the 26 redundant calls were stripped). See `docs/ARCHITECTURE.md` for
  the new contract.
- **ASTM default port: `1394` → `12000`.** The previous default was a
  misread of the ASTM "E1394" standard name (IEEE-1394 is FireWire). Most
  ASTM/LIS instruments listen on 12000; other vendors use 5000/6000/9100
  — override with `--port`.
- **`oida` no-args banner** now lists all 26 registered protocols (was 19,
  missing CAN, CoAP, FHIR, GOOSE, OCPP, PCAP, SNMP).
- **Help-banner deduplication** — `ethernetip`, `mqtt`, `mms`, `can` no
  longer emit "success" twice per connection. EtherNet/IP scanner's
  pycomm3-driver "Connected via …" lines downgraded to `.debug`; MQTT now
  emits the green success banner only on actual successful connection
  (was previously emitted in the auth-failure path); MMS drops the
  redundant "MMS/IEC 61850: host:port" display; CAN drops "CAN Bus:
  channel" / "Bitrate" repeats.
- **iec104 CLI** no longer shadows the main parser's `--verbose`/`--debug`/
  `--output`/`--format`. Removed redundant declarations; kept only
  iec104-specific `--full-width` (no `-W` short alias) and `--json-log`.
- **`oida fuzz`** no longer redefines `-v/--verbose` as `store_true`
  (conflicted with the main parser's `count` action).
- **`MANIFEST.in`** rewritten — was referencing the pre-rename `msf_ics/`
  paths so sdists shipped without any data files.
- **`pyproject.toml [tool.setuptools.package-data]`** now includes
  `protocols/hart/data/*.json` and `protocols/opcua/data/*.txt`. These
  data files would not have shipped in wheels.

### Fixed

- **DNP3 control operations now actually require `--confirm`.** Every
  `--bo-direct`, `--cold-restart`, `--write-file`, `--stop-app`,
  `--freeze-immediate`, `--assign-class`, etc. has had "requires --confirm"
  in its help text for some time; the runtime never enforced it. Now it does.
  3 regression tests added.
- **EtherCAT `--op-state` and `--boot-state` now require `--confirm`.**
  These transition slaves into OPERATIONAL (energising outputs) or BOOTSTRAP
  (firmware-flash). The rest of EtherCAT's write ops were gated; these two
  were the inconsistency.
- **SSDP/UPnP `defusedxml` is now a hard dependency.** The fallback to
  stdlib `xml.etree` opened an XXE / XML-bomb attack surface on attacker-
  controlled UPnP device descriptions.
- **SNMPv3 short passphrases refused with a clear error** instead of being
  silently NUL-padded. The previous `_pad_snmp_key` helper produced a
  localized key that could never match the device, manifesting as "no
  response" — RFC 3414 §11.2 mandates ≥8 octets.
- **HL7 MLLP and `send_hl7_message_simple` recv loops bounded at 16 MiB.**
  A hostile peer that never sends `MLLP_END` could previously OOM the scanner.
- **EtherNet/IP no longer permanently silences the host `pycomm3` logger.**
  `connect()` used to set `logging.getLogger("pycomm3").setLevel(CRITICAL)`
  without restoring it; the rest of the Python process inherited the
  silence.
- **`NetworkConnection.__init__` no longer mutates the caller's argparse
  Namespace** when applying `default_port`. Cross-protocol dispatcher
  invocations no longer leak port settings between protocols.
- **`BaseScanner.export_results()`** is no longer silently broken for
  Layer-1 scanners. Was calling `export_data(dict, format_str, filename)`
  where the function expected `(rows, headers, format, dir, prefix)`. Now
  serialises the result dict as JSON (csv/xml are not meaningful for
  heterogeneous Layer-1 results — a warning is emitted).
- **`load_config_file` no longer crashes with `NameError` when PyYAML is
  missing.** The `except (json.JSONDecodeError, yaml.YAMLError)` clause
  referenced `yaml` unconditionally.
- **iec104 listener direction logic** no longer hardcodes destination
  port 2404. On non-standard ports (the repo's own mocks use 2405/2409),
  controlling/controlled labels were silently flipped — write-operation
  alerts pointed at the wrong side.
- **modbus listener direction logic** gains a "lower port wins" fallback
  when neither side is on TCP 502 (gateways and security devices commonly
  relay over non-standard ports). Same fix on the MBAP-only keepalive
  path so client/server roles stay consistent.
- **mms listener direction logic** gains the same lower-port fallback
  for substations running on TCP 10102/10106/10108/etc. instead of 102.
- **BFD and RIP listeners** now pass `src_port`/`dst_port` to
  `_record_interaction()` (commit `cf7c272a` fixed 10 listeners but missed
  these two).
- **OPC UA NXC `__init__`** no longer attempts `self.logger.debug` before
  `super().__init__` creates the logger.
- **ADS local AMS Net ID fallback** no longer uses `192.168.1.100` (a
  common lab IP that collided with real devices). Now `127.0.0.1` with a
  warning telling the user to pass `--local-netid` explicitly.
- **86 truncated debug log strings** rewritten with meaningful operation
  context (was `f"Failed to get s: {e}"` — `s` was the local variable
  name; now `f"Failed to parse frame_type as int: {e}"` etc.).
- **HART `hartip-py` import is honest** — the `try: from hartip import …
  except ImportError: …` wrapper actually allows the module to load
  without the optional dep, matching the HL7 fix.
- **HL7 `hl7apy` import is honest** — same fix as HART. `utils.py`'s
  `from hl7apy.core import Message` was unguarded; fuzzer code paths
  importing utils directly bypassed the availability gate and hit a raw
  ImportError instead of the friendly install hint.
- **PIM listener handles Register messages** — encapsulated IPv6 headers
  made pyshark's `EkLayer.__getattr__` raise on nested-dict iteration;
  `get_ip_info` falls back to the raw `_fields_dict` and extracts the
  outer header src/dst. Was 17/20 silent drops; now 20/20.
- **BACnet over ARCNET datalink supported** — `get_mac_info` gained an
  ARCNET fallback synthesising `AR:NN` identifiers from the 8-bit node
  IDs when no eth layer is present. Was 0/564 interactions on
  `wireshark_bacnet_arcnet.cap`; now 564/564.
- **Modbus listener accepts `mbtcp.prot_id` misread frames** — pyshark's
  EK output mis-reads the Protocol Identifier byte on frames where tshark
  emits a "Cannot classify packet type" warning. The hard `prot_id != 0`
  reject is now a soft signal; presence of an mbtcp layer + modbus
  payload is sufficient evidence. Was 12/17 dropped on
  `zeek_modbus_mixed_p502.pcap`; now 17/17.
- **Test-isolation pollution** — `tests/unit/knx/test_helpers.py`
  replaced `sys.modules['oida.utils.ics_logger']` with a `MagicMock` and
  never restored it; every subsequent `isinstance(x, ICSLogger)` then
  raised `TypeError` because `ICSLogger` was a Mock instance. Added an
  autouse module-scoped fixture that snapshots and restores
  `sys.modules` entries the test mutates.
- **Fuzz DB performance refactor** — bulk insert APIs
  (`store_test_cases_bulk`, `store_metadata_bulk`) collapse N fsyncs to
  1; WAL + `synchronous=NORMAL` + 64 MB cache PRAGMA listener; single
  aggregate query in `get_statistics()` (was 8 round-trips); covering
  index on `(protocol, result, timestamp)`; `BigInteger` for unsigned
  CRC32 columns; `crash_hash` now actually surfaced in `get_crash()`;
  default `limit=10_000` on `get_test_cases` to prevent OOM on
  million-case sessions (callers that want everything pass `limit=None`).

### Removed

- **`SQLiteDatabase`** (raw SQL backend). `SQLAlchemyDatabase` is now the
  single canonical backend; `MockDatabase` (moved to a dedicated file)
  remains for tests. The two backends had drifting schemas; this resolves
  it. `fuzz_cli.py` replay now uses `SQLAlchemyDatabase` like the rest of
  the runtime.
- **FHIR `--bulk-export`, `--bulk-export-type`** — handler was a stub
  that printed "not implemented" then exited. Use the FHIR `$export`
  operation directly via your HTTP client until a real implementation
  lands.
- **OPC UA fuzzer phantom `OPCUA_Query` request** — advertised by
  `--list-requests` but no corresponding `Request("OPCUA_Query")` object
  existed. Removed from the request inventory.
- **Repository slop** — ~76,000 lines / 275 files of AI scratch reports,
  leftover databases, dead modules, duplicate vendor maps, stale build
  scripts, and a misformed root-level `.env`. See commit `453a8f28` for
  the full list.
- **Dead modules**: `port_aliases.py` (no callers), `modbus_device_db.py`
  (compat shim with no callers), `ICSPermissionError` exception (never
  raised). The dead 615-line `knx_vendors` block in `utils/vendor_maps.py`
  (a stale HTML-encoded duplicate of `protocols/knx/data.py:VENDORS`).
- **`requirements.in` / `requirements.txt`** — stale pip-compile outputs
  diverging from `pyproject.toml`. CI uses `pip install -e .[dev,all]`;
  the requirements files were dead weight.
- **`setup.py`** — duplicate of `pyproject.toml` with stale dep pins.
- **`justfile`** — superseded by `services.py` (commit `810367d4` already
  added the replacement but left the old file).

### Architecture (post-1.0 work documented but not landed)

These are flagged in `docs/ARCHITECTURE.md` as known refactor targets:

- **opcua and knx** have parallel Layer-1/Layer-2 implementations
  (~2,400 LoC total). Should adopt the modbus facade pattern.
- **astm, bacnet, dicom, fhir, hl7, profinet** ship only a Layer-2 NXC
  class. Library users have no L1 entry point; the existing fat NXC
  should be split into `XxxScanner` + adapter.
- **hl7, ethernetip, bacnet, opcua** carry 10+ mixins each with
  18-level MROs. Worth merging the over-decomposed splits.

### Known limitations

- **`--format xml`** is accepted by the argument parser but the per-protocol
  XML export is not yet implemented — the CLI emits a warning and falls
  back to JSON. Use `--format json` for structured output.
- **mypy** reports thousands of errors; not a CI gate yet. The KNX scanner
  cluster has the most concentrated drift.
- **109 pcap listeners** total; 28 lack a dedicated test file. The
  `test_false_positives.py` regression suite covers 6 of them.
