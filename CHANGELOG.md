# Changelog

All notable changes to OIDA are documented here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## 1.0.0 — unreleased

First stable release.

### Added

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

### Changed

- **`NetworkConnection.__init__`** auto-calls `proto_logger()` before
  `proto_flow()`. Subclasses no longer need to call it as their first line
  (the 26 redundant calls were stripped). See `docs/ARCHITECTURE.md` for
  the new contract.
- **ASTM default port: `1394` → `12000`.** The previous default was a
  misread of the ASTM "E1394" standard name (IEEE-1394 is FireWire). Most
  ASTM/LIS instruments listen on 12000; other vendors use 5000/6000/9100
  — override with `--port`.
- **`oida` no-args banner** now lists all 25 registered protocols (was 19,
  missing CAN, CoAP, FHIR, GOOSE, OCPP, PCAP, SNMP).
- **Help-banner deduplication** — `ethernetip`, `mqtt`, `mms`, `can` no
  longer emit "success" twice per connection.
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
- **HL7 `hl7apy` import is honest** — same fix as HART.

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
