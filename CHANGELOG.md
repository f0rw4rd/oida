# Changelog

All notable changes to OIDA are documented here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## 1.0.0 — unreleased

First stable release.

### Added

- **`<host>:<port>` target shorthand, for every host-based protocol** — any
  target form may now carry a port (`10.0.0.5:5020`, `10.0.0.0/24:5020`,
  `192.168.1.1-254:5020`, `[2001:db8::1]:5020`, or per line in a target file),
  so `-p/--port` no longer has to be repeated, and hosts on different ports can
  be scanned in one run. The port in the target wins over `-p` (warned once per
  run when they disagree). URL targets (`opc.tcp://`, `ws://`, `https://`),
  pcap file paths, serial devices and interface targets (`can`, `goose`,
  `ethercat`, `discovery`, `profinet`) are left untouched. The splitter used by
  `oida fuzz` is now shared: `oida.targets.split_host_port()`.
- **Fuzzer depth controls `--max-depth` / `--only-depth`** — cap a boofuzz run
  at depths 1..N, or fuzz only depth N so those cases go out from the first
  packet. Mutually exclusive. Replaces seek-by-test-case-index, which boofuzz
  cannot do without regenerating the whole lower-depth prefix.
- **Six new passive PCAP listeners** — `selfm` (SEL Fast Message, flags Fast
  Operate breaker control), `egd` (GE EGD), `tte` (TTEthernet/AS6802), `rtps`
  (DDS participant discovery), `ieee1722` (AVTP/AVB) and `mqttsn`. Each ships a
  dissector-verified fixture under `tests/fixtures/pcap/<proto>/` plus a
  dedicated test file and PcapScanner end-to-end coverage.
- **Modbus passive listener covers UDP and RTU** — `mbudp` and `mbrtu` join
  `mbtcp` on the same per-PDU path (each transport normalised to a synthetic
  header layer). `modbus_passive_data.protocol` reports `Modbus/TCP` | `/UDP` |
  `/RTU`.
- **175 new tests** (13,250 → 13,425 passing): 28 pcap-listener test files,
  false-positive coverage 6 → 16 protocols, `test_proto_args.py` for the six
  thinnest-tested protocols, and 23 ADS `--confirm` regression tests.
- **§4.1 fuzzer optimizations — 26 items across 11 protocols**: DNP3 object
  sweep / IIN master / bad-CRC; ADS port enumeration, SumReadWrite, `ADSMonitor`;
  EtherNet/IP CIP class enumeration and Forward_Open RPI; IEC 104 reserved
  `TypeId` + `CommonAddress` sweep; MMS BER tag confusion; SNMPv3 Set/Trap/
  Inform/GetBulk + USM auth-param fuzzing; OPC UA `ExtensionObject TypeId`;
  HL7 MSH-12 sweep + Z-segment injection; MQTT Sparkplug B + reason codes;
  modbus ADU overflow capped at 4096.
- **Wordlist path privacy** — `format_wordlist_source()` logs the basename only,
  so engagement-sensitive paths stay out of screen output and JSON logs. Adopted
  by snap7, dicom, hart, and the snap7 brute-force mixin.
- **ADS `--confirm` enforcement** — `validate_args()` refuses `--scan-coe`,
  `--write-coe`, `--add-route`, `--foe-write`, `--foe-delete`, `--write-symbol`,
  `--memory-write`, `--set-state`, `--fuzz`, `--fuzz-coe` without it. The help
  text already promised this; now it's a hard gate, matching dnp3 / ethercat.
- **ADS listener `state_flags`** — per-bit decoding of the eight `ams.state_*`
  bits into `interaction.details["state_flags"]`.
- **LDAP SASL/GSSAPI message recording** — Kerberos-bound sessions now emit
  `SASL-Encrypted` interactions with `sasl_buffer_length` + `encryption`, instead
  of recording nothing.
- **DECODE_AS scanner integration** — per-listener `tcp.port==X: dissector`
  hints are now actually applied. `ajp`, `rmi` and `rsync` matched nothing
  before this.
- **`get_local_ip()`** in `utils.socket_helpers` — replaces three copies of the
  UDP-connect trick. BACnet no longer connects to `8.8.8.8` to find the local IP.
- **`Crash.crash_hash`** + BLAKE2b signatures — fuzzer crash dedup at triage
  time via `GROUP BY crash_hash`.
- **CI matrix** — Python 3.10, 3.11 and 3.12 (was 3.12 only).
- **Brotli, docker, defusedxml** added to `[dev]` so the matrix stops silently
  skipping.
- **`oida snap7`** is the canonical Siemens S7 subcommand; `oida s7` is an alias.
- **Community files for 1.0** — `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  `.github/ISSUE_TEMPLATE/` and `.github/PULL_REQUEST_TEMPLATE.md`. Private
  disclosure goes through https://getoida.dev/contact.
- **Real-coverage scaffolds** — `tests/coverage/fuzz/test_cve_replication.py`
  and `tests/coverage/fidelity/test_conpot_diff.py` (axes 2 and 3, see
  `docs/REAL_COVERAGE_PROPOSAL.md`). Per-CVE driver and Conpot diff
  classification land post-1.0.
- **`.github/workflows/coverage-nightly.yml`** — nightly run of all three
  coverage axes against the full mock stack; publishes JUnit + JSON artifacts
  and a dashboard to the `coverage-dashboard` orphan branch.

### Changed

- **`oida fuzz` port precedence now matches the scanner.** A port embedded in
  the target (`oida fuzz modbus 10.0.0.5:5020`) previously lost to `--port`; it
  now wins, and the run banner says when `--port` is being ignored.
- **Usage text advertises the `<host>:<port>` shorthand everywhere.** The
  module `--help` examples and the `oida` no-args banner now show a `host:port`
  target, and the six protocols that override `--port` help (ads, coap, dicom,
  mms, mqtt, ocpp) append "a port in the target wins" like the default help —
  previously only the shared target/port help mentioned the shorthand.
- **OCPP wss:// default-port resolution uses the explicit-port signal.** A
  `wss://host/CP` target with no port now bumps to 443 based on whether `-p`
  (or a `host:port` target) was actually supplied (`args._port_explicit`),
  replacing a `port == 9000` magic-number heuristic that mistook a user who
  deliberately passed `-p 9000` for one who passed nothing.
- **`knx` gained the `-p` short flag** to match every other host-based
  protocol; `oida knx host:3671` also works via the shorthand.
- **The scan progress banner shows the target port when unambiguous.** When
  every target in a run carries the same embedded `<host>:<port>` port, the
  `PROTOCOL *:<port>` banner now shows that port instead of the flag/default;
  mixed or portless runs still show the run-global default (each scan always
  uses its own per-target port regardless).
- **Argument dicts stop storing every key twice.** `_convert_args_to_dict` used
  to dual-write each flag under both its underscore (`unit_id`) and hyphen
  (`unit-id`) spelling so legacy scanners reading the CLI spelling would hit —
  doubling the dict and letting a single-spelling write desync the two. It now
  returns a normalizing `ArgsDict` (`oida.utils.args_dict`) that canonicalizes
  `-`↔`_` to one slot on every read/write; both spellings still resolve, so no
  reader site changed. `_normalize_args` wraps plain Layer-1 dicts in the same
  type, closing the gap where the dict path (unlike the Namespace bridge) never
  normalized at all.
- **`services.py` is fully data-driven from compose labels.** The hardcoded
  `PROTO_SPECS` table and the 14 `up-<proto>` subcommands are gone; metadata is
  read live from `oida.*` labels. `up <group>` now resolves members across
  *both* compose files and auto-selects each member's `vuln-*`/profile —
  previously CVE members were invisible and CVE-only groups unreachable. New
  `groups` command; docker pull progress shows by default (`--quiet-pull` to
  suppress). Use `up <group>` or `up-cve <proto>`.
- **`NetworkConnection.__init__`** auto-calls `proto_logger()` before
  `proto_flow()`; the 26 redundant subclass calls were stripped.
- **ASTM default port `1394` → `12000`.** The old default misread the ASTM
  "E1394" standard name (IEEE-1394 is FireWire). Vendors also use 5000/6000/9100
  — override with `--port`.
- **`oida` no-args banner** lists all 26 protocols (was 19 — missing CAN, CoAP,
  FHIR, GOOSE, OCPP, PCAP, SNMP).
- **No more doubled success banners** in `ethernetip`, `mqtt`, `mms`, `can`:
  pycomm3 "Connected via …" downgraded to debug; MQTT only banners on real
  success (was also firing on auth failure); MMS and CAN drop repeated
  host/channel lines.
- **iec104 CLI** no longer shadows the main parser's `--verbose`/`--debug`/
  `--output`/`--format`; keeps only `--full-width` and `--json-log`.
- **`oida fuzz`** no longer redefines `-v/--verbose` as `store_true` against the
  main parser's `count`.
- **`MANIFEST.in`** rewritten — referenced pre-rename `msf_ics/` paths, so
  sdists shipped with no data files.
- **`package-data`** now includes `protocols/hart/data/*.json` and
  `protocols/opcua/data/*.txt`, which would not have shipped in wheels.

### Fixed

- **Twelve correctness bugs from the repo-wide bug-hunt** (each with a
  fail-before/pass-after regression test):
  - SMTP: CRAM-MD5 credentials were never harvested (client base64 line
    carried no tshark tags, so the regex never saw it — now recovered from
    the raw payload).
  - X11: MIT-MAGIC-COOKIE-1 stored as U+FFFD mojibake (pyshark decodes
    binary with `errors=replace`) — true bytes now carved from the payload.
  - Telnet: failed-login credential dropped when the failure banner and
    next prompt coalesce into one TCP segment (common for real telnetd).
  - C12.22: passwords travel on SECURITY (0x51) but capture was gated to
    LOGON (0x50), so they were never recorded.
  - Redis: AUTH passwords containing commas were corrupted by `split(",")`
    over the bytes-list repr.
  - MySQL: `mysql_clear_password` values are plaintext but were labeled
    `hash` and never decoded.
  - MSRPC: NTLMv1 hashcat format was never built (condition required
    `ntproofstr`, which NTLMv1 never has).
  - MQTT: anonymous client_id-only CONNECTs fabricated `username_only`
    credential rows.
  - Fuzz ASN.1: OID builder crashed on `-O oid_prefix=2.999.1` (first
    combined arc > 255), aborting the whole campaign.
  - Export: any XML-1.0-illegal char (sysDescr/banners) silently dropped
    the entire XML deliverable; ragged rows rejected the whole table.
  - DICOM: one non-UTF-8 byte in an AET wordlist aborted the brute (same
    class as the two earlier wordlist fixes).
  - KNX: a truncated DIB raised into the catch-all and silently dropped a
    real device; bounds-checked now.
- **`check-secrets` hook: password pattern bridged newlines** — a comment
  mentioning `("password:")` matched an unrelated quoted string lines later,
  false-positiving on committed code. Match stays on one line now; the
  `SCREAMING_CASE = "snake_case"` enum idiom is exempt.
- **Runtime metadata lookups use the real distribution name.** The import
  package and the `oida` command are unchanged, but the published distribution
  is `oida-ics`, so `importlib.metadata` calls asking for `oida` silently
  returned nothing: `PROTOCOL_DEPENDENCIES` came out empty (losing every
  protocol dependency hint, and every protocol in a frozen build) and
  `oida --bug` crashed with `PackageNotFoundError`. All lookups now go through
  `oida.utils.lazy_import.dist_name()`, which resolves the distribution from
  the import package, and `pip install ...` hints are built from it.
- **Bracketed IPv6 targets are no longer mangled.** `parse_targets` stripped
  only the leading bracket off `[2001:db8::1]:502`, yielding the unresolvable
  `2001:db8::1]:502`. Brackets are now parsed properly, and IPv6 targets keep
  their bracketed form when a port is attached during CIDR/range expansion.
- **`--timeout` is per-protocol, and config-file `timeout:` is honored.** It was
  declared both globally and per-subparser against the same dest, so the
  subparser default silently clobbered `oida --timeout 30 modbus HOST` and made
  config-file `timeout:` a no-op. The global flag is gone; per-protocol defaults
  (modbus 2s, dicom 10s) are preserved, `ads`/`tase2` gained their own (5s), and
  placing it before the subcommand is now a clean error rather than a wrong
  value. `merge_config_with_args` baselines against the active protocol's own
  defaults. Regression tests added.
- **Global `-v` no longer dropped before `serial`.** `serial list`/`detect`
  re-declared `-v` with a concrete default, clobbering `oida -v serial list`;
  they now use `argparse.SUPPRESS` like `fuzz`.
- **DNP3 control ops actually require `--confirm`** — `--bo-direct`,
  `--cold-restart`, `--write-file`, `--stop-app`, `--freeze-immediate`,
  `--assign-class` and friends promised it in help text but never enforced it.
  3 regression tests.
- **EtherCAT `--op-state` / `--boot-state` require `--confirm`** — they drive
  slaves into OPERATIONAL (energising outputs) or BOOTSTRAP (firmware flash).
  The rest of EtherCAT's writes were already gated.
- **SSDP/UPnP `defusedxml` is a hard dependency** — the stdlib `xml.etree`
  fallback was an XXE / XML-bomb surface on attacker-controlled device
  descriptions.
- **SNMPv3 short passphrases are refused** with a clear error instead of being
  NUL-padded into a key that could never match the device (RFC 3414 §11.2
  mandates ≥8 octets); it surfaced as "no response".
- **HL7 MLLP recv loops bounded at 16 MiB** — a peer that never sends
  `MLLP_END` could OOM the scanner.
- **EtherNet/IP restores the `pycomm3` logger level** — `connect()` set it to
  CRITICAL permanently and the rest of the process inherited the silence.
- **`NetworkConnection.__init__` no longer mutates the caller's Namespace** when
  applying `default_port`, so ports stop leaking between protocols in
  cross-protocol dispatch.
- **`BaseScanner.export_results()`** was calling `export_data()` with the wrong
  signature entirely; it now serialises the result dict as JSON (csv/xml aren't
  meaningful for heterogeneous Layer-1 results — a warning is emitted).
- **`load_config_file`** no longer raises `NameError` when PyYAML is missing —
  the `except` clause referenced `yaml` unconditionally.
- **iec104 listener direction** no longer hardcodes port 2404; on non-standard
  ports (the repo's own mocks use 2405/2409) controlling/controlled were
  flipped, pointing write alerts at the wrong side.
- **modbus and mms listener direction** gain a "lower port wins" fallback when
  neither side is on 502 / 102 — common for gateways, security devices and
  substations on 10102/10106/10108. Applied to the MBAP-only keepalive path too.
- **BFD and RIP listeners** now pass `src_port`/`dst_port` to
  `_record_interaction()` (missed by commit `cf7c272a`).
- **OPC UA NXC `__init__`** no longer calls `self.logger.debug` before
  `super().__init__` creates the logger.
- **ADS local AMS Net ID fallback** is `127.0.0.1` with a warning to pass
  `--local-netid`, not `192.168.1.100` (a lab IP that collided with real
  devices).
- **86 truncated debug strings** rewritten with real context (`f"Failed to get
  s: {e}"` — `s` was the variable name — became `f"Failed to parse frame_type
  as int: {e}"` and so on).
- **HART and HL7 optional imports are honest** — both modules now really load
  without their optional dep. HL7's `utils.py` had an unguarded
  `from hl7apy.core import Message`, so fuzzer paths importing utils hit a raw
  ImportError instead of the install hint.
- **PIM listener handles Register messages** — encapsulated IPv6 headers made
  pyshark raise on nested-dict iteration; `get_ip_info` falls back to
  `_fields_dict`. Was 17/20 silent drops, now 20/20.
- **BACnet over ARCNET** — `get_mac_info` synthesises `AR:NN` identifiers from
  8-bit node IDs when there's no eth layer. Was 0/564 interactions on
  `wireshark_bacnet_arcnet.cap`, now 564/564.
- **Modbus listener tolerates misread `mbtcp.prot_id`** — pyshark's EK output
  mis-reads that byte on frames tshark can't classify, so the hard `!= 0` reject
  is now a soft signal. Was 12/17 dropped on `zeek_modbus_mixed_p502.pcap`, now
  17/17.
- **Test-isolation pollution** — `tests/unit/knx/test_helpers.py` swapped
  `sys.modules['oida.utils.ics_logger']` for a `MagicMock` and never restored
  it, so every later `isinstance(x, ICSLogger)` raised `TypeError`. An autouse
  fixture now snapshots and restores the mutated entries.
- **Fuzz DB performance** — bulk insert APIs collapse N fsyncs to 1; WAL +
  `synchronous=NORMAL` + 64 MB cache; `get_statistics()` down from 8 round-trips
  to one aggregate query; covering index on `(protocol, result, timestamp)`;
  `BigInteger` for unsigned CRC32; `crash_hash` surfaced in `get_crash()`;
  `get_test_cases` defaults to `limit=10_000` to avoid OOM on million-case
  sessions (`limit=None` for everything).

### Removed

- **Dead `SERIAL_PROTOCOLS` set** in `cli.py` — an empty set that gated a
  serial-target branch, a `--list-ports` branch and an error message, all
  provably unreachable (serial devices go through the `oida serial`
  subcommand). Removed the set and its dead branches; `_resolve_targets` lost
  its unused `is_serial_protocol` parameter.
- **`SQLiteDatabase`** (raw SQL backend) — `SQLAlchemyDatabase` is the single
  canonical backend and `fuzz_cli.py` replay now uses it too; `MockDatabase`
  (moved to its own file) remains for tests. The two backends had drifting
  schemas.
- **FHIR `--bulk-export`, `--bulk-export-type`** — the handler printed "not
  implemented" and exited. Use the FHIR `$export` operation directly until a
  real implementation lands.
- **OPC UA fuzzer phantom `OPCUA_Query`** — advertised by `--list-requests`
  with no backing `Request` object.
- **Repository slop** — ~76,000 lines / 275 files of AI scratch reports, stray
  databases, dead modules, duplicate vendor maps, stale build scripts and a
  misformed root `.env`. Full list in commit `453a8f28`.
- **Dead modules** — `port_aliases.py`, `modbus_device_db.py` (compat shim, no
  callers), the never-raised `ICSPermissionError`, and the 615-line
  `knx_vendors` block in `utils/vendor_maps.py` (a stale HTML-encoded duplicate
  of `protocols/knx/data.py:VENDORS`).
- **`requirements.in` / `requirements.txt`** — stale pip-compile outputs
  diverging from `pyproject.toml`.
- **`setup.py`** — duplicate of `pyproject.toml` with stale pins.
- **`justfile`** — superseded by `services.py` (commit `810367d4` added the
  replacement but left the old file).

### Architecture (post-1.0 work documented but not landed)

Known refactor targets, documented on the docs site:

- **opcua and knx** carry parallel Layer-1/Layer-2 implementations (~2,400 LoC).
  Should adopt the modbus facade pattern.
- **astm, bacnet, dicom, fhir, hl7, profinet** ship only a Layer-2 NXC class;
  library users have no L1 entry point. The fat NXC should split into
  `XxxScanner` + adapter.
- **hl7, ethernetip, bacnet, opcua** carry 10+ mixins each with 18-level MROs,
  worth merging.

### Known limitations

- **`--format xml`** parses but isn't implemented per-protocol — the CLI warns
  and falls back to JSON.
- **mypy** reports thousands of errors and is not a CI gate; the KNX scanner
  cluster has the most concentrated drift.
- **109 pcap listeners**, 28 without a dedicated test file.
  `test_false_positives.py` covers 6 of them.
