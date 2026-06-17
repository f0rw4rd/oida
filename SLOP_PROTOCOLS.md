# Slop-check sweep — scanner protocol modules (`src/oida/protocols/`)

Hunt for AI-slop (dead scaffolding, hallucinated APIs, cargo-cult patterns, dead
writes) across all 26 scanner protocol packages (~327 .py files). Run
per-protocol-directory (slop-check caps at 25 files/run); modbus (34) and
discovery (32) are split into two batches each.

Status legend: ⏳ running · ✅ report in · — not started

> **SWEEP COMPLETE — all 26 scanner protocol packages reviewed (28 batches).**
> Totals: **108 HIGH, 388 MEDIUM, 309 LOW** (~805 findings). Run one-at-a-time
> (parallel triggers server rate-limiting); two transient usage-limit stalls
> were retried. Diagnostic only — nothing was changed. Full per-file detail in
> each protocol's task-output file (IDs cited per section).

| Protocol | Files | Status | HIGH | MED | LOW |
|---|---|---|---|---|---|
| opcua | 17 | ✅ | 4 | 9 | 16 |
| ethernetip | 21 | ✅ | 3 | 18 | 25 |
| snap7 | 14 | ✅ | 1 | 20 | 14 |
| ethercat | 14 | ✅ | 3 | 21 | 10 |
| hl7 | 19 | ✅ | 1 | 15 | 10 |
| knx | 16 | ✅ | 11 | 30 | 18 |
| bacnet | 15 | ✅ | 5 | 21 | 18 |
| snmp | 12 | ✅ | 0 | 10 | 7 |
| tase2 | 11 | ✅ | 11 | 10 | 9 |
| can | 11 | ✅ | 1 | 9 | 12 |
| profinet | 10 | ✅ | 7 | 16 | 10 |
| mqtt | 10 | ✅ | 2 | 8 | 9 |
| iec104 | 10 | ✅ | 10 | 9 | 7 |
| hart | 10 | ✅ | 5 | 12 | 4 |
| dicom | 10 | ✅ | 1 | 11 | 8 |
| ocpp | 9 | ✅ | 4 | 9 | 5 |
| fhir | 9 | ✅ | 0 | 9 | 6 |
| dnp3 | 9 | ✅ | 3 | 8 | 5 |
| astm | 9 | ✅ | 2 | 8 | 5 |
| ads | 7 | ✅ | 0 | 11 | 10 |
| coap | 6 | ✅ | 0 | 17 | 11 |
| pcap | 4 | ✅ | 0 | 1 | 1 |
| mms | 4 | ✅ | 2 | 8 | 6 |
| goose | 3 | ✅ | 0 | 3 | 3 |
| modbus mixins/ | 13 | ✅ | 1 | 3 | 7 |
| modbus scanner_mixins/ | 9 | ✅ | 0 | 5 | 10 |
| modbus core | 12 | ✅ | 2 | 14 | 15 |
| discovery 1/2 | 16 | ✅ | 14 | 33 | 21 |
| discovery 2/2 | 16 | ✅ | 15 | 40 | 27 |
| **TOTAL** | **~327** | **✅ 26/26** | **108** | **388** | **309** |

---

## Findings by protocol

### opcua (4 HIGH, 9 MEDIUM, 16 LOW) — vulture 22@60 (mostly dynamic-dispatch FPs), ruff clean

**HIGH**
- `helpers.py:50-64,81-105` — `_SecurityPoliciesCache` + `_get_security_policies(_cached)` zero production callers (prod uses `lazy_import("asyncua.crypto.security_policies")` directly). Delete + drop `__init__` exports + dead tests.
- `nxc_connection.py:112-137,390-392` — `_has_any_operation_flag()` zero callers; it's the only reader of the 26-entry `_OPERATION_FLAGS`. Both dead (live dispatch uses getattr per flag). Delete both.
- `mixins/browse.py:328-533` — `_dump_permissions` (~205 lines) zero callers: no dispatch entry, no CLI flag, no test. Delete (or wire into dispatch + CLI + test). Drop `DANGEROUS_KEYWORDS` import if only it uses it.
- `mixins/methods.py:15-95` — `_discover_methods()` (+nested closure) never called; live discovery walks address space in browse/fuzz. Delete.
- `mixins/discovery.py:49` — **API hallucination**: `gds_client.timeout = ...` — asyncua `Client` has no settable `timeout` attr (constructor arg only). Operator GDS timeout silently never applies. Fix: `Client(gds_url, timeout=getattr(self.args,"timeout",5))`.

**MEDIUM**
- `scanner.py:357` — `authentication_test["certificate_auth"]` set False, never reassigned/read (cert-auth probe never implemented).
- `helpers.py:29-47,73-78` — `_AsyncuaCache` is a cache-around-a-cache (`_asyncua` LazyModule already lock-guards/caches). Delete.
- `__init__.py:17-79` — re-export barrel exposes 22 names; only 4 used via package root. Trim.
- `proto_args.py:246-250` — `--history-raw` parsed but never read (history.py:62 always calls `read_raw_history()`); help text false. Wire or remove.
- `mixins/browse.py:368,385` — dead-writes `entry["access_level"]`/`entry["restrictions"]` never read (consumers use derived flags).
- `mixins/subscriptions.py:23-24,76-77` — guard for non-existent `subscribe_duration` argparse dest; duplicated 6-line comment. Simplify.
- `mixins/methods.py:379-383` — `_get_method_arguments` builds `data_type`/`value_rank` keys no consumer reads.
- `mixins/files.py` — broad-except density 5.9% (mostly NXC log+continue; spot-check the swallows log context).

**LOW (16)** — selected: `scanner.py:537` dead `access_level` write; `helpers.py:11-17` empty `if TYPE_CHECKING: pass`; `helpers.py:70` `asyncua=None` mock-anchor; `__init__.py:53-68` 8 private `_`-names in public `__all__`; `mixins/security.py:13,108,117,127,263` module logger used in 4 excepts instead of `self.logger`; `mixins/history.py` + `mixins/discovery.py:271` dead trailing `pass` after debug logs; `mixins/discovery.py:310-319` dead `has_sign_only or` sub-expr; `mixins/methods.py:267-293,401-426` two near-identical builtin-type dicts; `mixins/writes.py:78-81` identical signed/unsigned int branches; plus pointless intermediate vars + fluff comments. (Full report: task output `w5p3k730m`.)

### ethernetip (3 HIGH, 18 MEDIUM, 25 LOW) — vulture 45@60, ruff clean (one sub-check usage-policy blocked, report synthesized)

**HIGH**
- `scanner.py:340-374` — `_parse_route_path()` zero production callers (inline TODO admits route reads "not yet wired into" enum); kept green only by tests. Delete + tests.
- `controller_info.py:615-646` — `_get_device_identity` zero callers; near-dup of live `_get_device_info`, hardcodes vendor 'Rockwell Automation'. Delete + its test.
- `write_test.py:208-245` — `_test_attribute_write` zero callers; superseded by `_test_write_with_status`. Delete + tests.

**MEDIUM (18)** — highlights:
- `scanner.py:470` — **API hallucination**: `LogixDriver(host, slot=slot)` — pycomm3 1.2.16 has no `slot=` kwarg (swallowed by `**kwargs`); `--slot N` is a silent no-op (always slot 0). Fix: encode in path `f"{host}/{slot}"`.
- `scanner.py:288` — `self.list_identity` written from CLI, never read (`_discover_ucmm_commands` runs ListIdentity unconditionally); `--list-identity` inert.
- `cip_definitions.py:537,539` — `AttrDef.encode`/`perm` fields populated, never read.
- `cip_objects.py:579,594-596` — `force_probe` never set True; dead guard operand.
- `cip_security.py:35-85,145-181` — `_detect_cip_security()`+`_check_tls_support()` never wired into scan flow (~50-line dead subtree); stale comment in security_analysis.py:216.
- `class_explorer.py:315-393` — `_print_attr_table` `show_perm=False` branch dead (caller always True); `len(row)>=7` guard + 6-tuple fallback unreachable.
- `network_parsers.py:114-148,227-243` — `_parse_interface_config`/`_parse_mac_address` list/tuple/dict/str/int branches dead (only bytes|None reaches them); `value: Any` hides real type.
- `enip_commands.py:131-145` — `_send_enip_command` `use_udp` branch dead (never set True); `additional_status` parsed but never read.
- dead-writes: `controller_info.py:111` ptp_enabled=None, `discovery.py:180-181` status_owned/status_configured, `fuzz.py:264` "type" key, `write_test.py:287,309` "perm" keys.

**LOW (25)** — one-line `.get()` wrappers (`cip_definitions.py:1051`), more dead result keys, redundant branches, fluff. (Full report: task output `wzvipebvn`.)

### snap7 (1 HIGH, 20 MEDIUM, 14 LOW) — vulture 22@60, ruff clean

**HIGH**
- `mixins/block_operations.py:256-265` — **real bug**: `conn.full_upload(...)` returns `(bytearray, int)` in python-snap7 3.0.0, but code feeds it to `Path.write_bytes(data)`/`len(data)`/`data[:128]` → TypeError swallowed by `except Exception` → block upload silently 100% broken. Fix: `data, size = conn.full_upload(...)`.

**MEDIUM (20)** — highlights (several real API misuse):
- `mixins/slot_scan.py:73-75` — `set_param()` called with stale raw ints that mismap enums: `set_param(2,…)`=RemotePort (not PingTimeout), `set_param(3,…)`=PingTimeout (not RecvTimeout); intended RecvTimeout never set. Use `snap7.type.Parameter` members.
- `mixins/block_operations.py:607` — `getattr(order_code,"Code",…)` — wrong field (S7OrderCode has `OrderCode`); always misses. cf. correct usage at :497.
- `proto_args.py:75-82,83-90` — `-C/--connection-type` and `-N/--pdu-size` parsed but never read/applied → inert flags.
- dead public methods: `block_operations.py:438-455` `get_cp_info()`, `:457-474` `get_pdu_length()` (read inline elsewhere); `security.py:163-177` `authenticate()` (only its test; dup of bruteforce probe).
- `nxc_connection.py:88-97,104` — `enum_host_info()`/`print_host_info()` pair never called by the overridden `proto_flow()` → compute-and-discard.
- `nxc_connection.py:844-851` — `check_dependencies()` `__new__` dance + try/except around a pure bool read; simplify.
- dead-writes: `security.py:108,110,131` result keys `method`/`security_risk`; `slot_scan.py:153,154,264` `bootloader`/`status`/`is_main_cpu`; `models.py:24,26` `as_name`/`copyright` (S7CPUInfo never instantiated).
- `models.py:58-68` — `__lt__/__le__/__gt__/__ge__` on S7FirmwareVersion never used (no version-gated check) — speculative.

**LOW (14)** — no-op `pass` after debug logs (`block_operations.py:510,518,528,543`), redundant `method_name` param (`nxc_connection.py:483-522`), redundant boolean disjunct (`:193`), empty `if TYPE_CHECKING: pass` (`scanner.py:32-34`), duplicated fuzz blocks. (Full report: task output `wttexxr7a`.)

### ethercat (3 HIGH, 21 MEDIUM, 10 LOW) — vulture 16@60, ruff clean

**HIGH**
- `advanced_ops.py:39-215` — `_dump_esc_registers()` builds/returns a large nested dict (stored as `esc_debug`) with no reader (`_export_dump_data` has no branch, nothing references it); only side-effect is display. Sub-keys `base_state`/`error_flag`/`al_control`/`watchdog_pdo_timeout` dead even in-method.
- `eeprom.py:66-69` — `parse_sii_header()` writes 4 PDI-config keys (pdi_control/pdi_config/sync_impulse_len/extended_pdi_config) with zero readers.
- `eeprom.py:175-179` — `parse_general_category()` writes 5 detail keys (foe_details/eoe_details/soe_channels/ds402_channels/sysman_class) never read.

**MEDIUM (21)** — highlights:
- `eeprom_ops.py:76-150` — **8 hallucinated `getattr(slave, …)` reads** vs pysoem 1.1.13 `CdefSlave` (serial/delay/port_des/FMMUfunc/SMfunc/group/image/dtype don't exist) → fields always empty/0, AND `FMMUfunc`/`SMfunc` drive `range(...)` loops that never iterate → `_read_eeprom_fmmu`/`_read_eeprom_sync_manager` silently return empty. Source from parsed SII categories instead.
- `eeprom_ops.py:196-226` — 8 pure pass-through delegation wrappers (`return <imported_func>(...)`, "Delegates to eeprom module") — delete, call free funcs directly.
- `coe_ops.py:325-330,400-408` — dead try/except around non-raising `decode("utf-8", errors="ignore")` (unreachable "decode failed" debug).
- dead-writes: `coe_ops.py:403` `result["text"]`; `eeprom.py:260-267` SM keys, `:331-344` PDO int keys, `:383-389` DC keys; `fuzzing_ops.py:26` `crashes_detected=0` never incremented (gates unreachable reporting.py:55-58 branch), `:27` top-level `anomalies=[]` never used (real ones nested).
- `constants.py:15,17,18` — dead `# noqa: F401` backward-compat re-exports (SLAVE_STATES, COE_STANDARD_OBJECTS, get_coe_object_name) with zero consumers.
- `__init__.py:37-38` — `pysoem = None` dead write + misleading comment (all paths use `_get_pysoem()`).

**LOW (10)** — (Full report: task output `wggqeq4no`.)

### hl7 (1 HIGH, 15 MEDIUM, 10 LOW) — vulture 267@60 (mostly HL7 field-map/segment-builder FPs), ruff clean

**HIGH**
- `segments.py:1775-1796` — `parse_rxe()` dead public method, near-verbatim dup of live `_parse_rxe_segment()`; zero callers (a comment at enum.py:181 describes NOT calling it). Delete.

**MEDIUM (15)** — highlights:
- `segments.py:21-28` — duplicate `try/except ImportError`/`HL7APY_AVAILABLE` shadows the sanctioned `lazy_import()` gate; no production reader; false comment.
- inert CLI flags: `proto_args.py:908-913` `--save-response`, `:915-919` `--parse-segments`, `:549-554` `--ssn` (build_pid accepts ssn= but all 12 call sites omit it → user SSN dropped) — all masked by tests.
- `continuation.py:28` — `_send_mllp_message_with_continuation` (the only orchestrator wiring the DSC/MSH-14 helpers) has ZERO callers; ~120 lines integration-dead (docstring TODO admits not wired); `:41,59` `continuation_style` unpacked but never read.
- dead structured-result writes never read by `_export_results`: `enum.py:126-133,245-251,350-355` (providers/interface_topology/locations), `master_file.py:258-262`, `special_query.py:179,215`, `utils.py:249-251,278-281` (ack_code/ack_text).
- `__init__.py:843-851` — `_extract_ack_code()` single-call wrapper dup of `utils.extract_ack_code()`.

**LOW (10)** — field-map dicts read only by existence-tests (`segments.py:1369,1411,1437`), dead `pass` after debug logs, unreachable `else None` ternary arms, duplicated `_send_rx_message`. (Full report: task output `wc69un9qh`.)

### knx (11 HIGH, 30 MEDIUM, 18 LOW) — vulture 27@60, ruff clean — highest HIGH count so far

**HIGH**
- `mixins/security.py:234` & `:290` — **API bug**: `resp.data` on xknx `Telegram` (data is at `resp.payload.data`) → always AttributeError, swallowed → read-access & write-access tests silently never work.
- `mixins/discovery.py:606-614` — **API bug**: `Telegram(payload=b"\x00")` (xknx needs an APCI instance) → ConversionError raised later in xknx queue, so `routing_supported=True` set unconditionally → false positive. Use `GroupValueWrite(DPTBinary(0))` and confirm send.
- dead methods (superseded, zero callers): `security.py:20-68` `_test_bcu_auth` (→`_brute_bcu_auth`), `device_info.py:57-114` `_read_device_info` (→`_identify_device`), `discovery.py:93-162` `_discover_group_addresses` (~70 lines), `ets.py:270-323` `test_knxproj_password_fast()` (dup of `_mp`, exists only for a sync test).
- `scanner.py:76-79` — 4 address-scan attrs (auto_addr/addr_min/addr_max/device_range) from CLI, zero readers (real path uses `scan-range`) → inert flags.
- `constants.py:94,100,130,133` — 4 `_xknx_cls` slots populated never read (tpci/P2PConnection/GroupValueRead/Restart) + paired dead `=None` decls.

**MEDIUM (30)** — highlights:
- `ets.py:86-101,295-310,423-449` — ETS6 PBKDF2 derivation (magic salt/iter) copy-pasted 3× despite existing `derive_ets6_zip_password()`.
- `helpers.py:99` `_get_p2p_connection()` getattr for non-existent xknx `P2PConnection` → always None; `:151-152` apci dict keys never read.
- `mixins/discovery.py:30-42` `_get_gateway_info` reads keys it never sets → always logs `Unknown:0`.
- dead `__init__`/result attrs never read: `scanner.py:70,80,91,92` (interface/wordlist_path/discovered_devices/device_info); `data.py:1202-1210` `MEMORY_MAP`, `:1237-1239` `get_prop_type_name()`.
- `device_info.py:160-193` `expected_len` unpacked from DEVICE_PROPS but never used (decorative byte-count implying validation that doesn't happen).

**LOW (18)** — (Full report: task output `wdhoaxt5q`.)

### bacnet (5 HIGH, 21 MEDIUM, 18 LOW) — vulture clean, ruff clean

**HIGH**
- `mixins/network.py:152,634` — **API bug**: `PropertyIdentifier("numberOfNetworkPorts")` doesn't exist in bacpypes3 0.0.106 → ValueError swallowed by `except BaseException` → "Router has N ports" branch unreachable, mstp num_ports always None.
- `mixins/network.py:694` — **API bug**: `PropertyIdentifier("slavePollTimeout")` doesn't exist → slave_poll_timeout always None, display unreachable.
- `mixins/connection.py:33-34,47` — **API bug**: `BAC0.lite(localIPAddr=...)` — real param is `ip`; collides with Lite's internal `localIPAddr` → `TypeError: multiple values for 'localIPAddr'` on `--interface`, masked as generic "Failed to connect". Fix: `kwargs["ip"]=interface`.
- `mixins/security.py:86-94` `_is_no_reply()` dead wrapper (zero callers; inline `if response is None` used instead); `constants.py:162-165` `bp()` accessor zero callers.

**MEDIUM (21)** — highlights:
- Widespread **legacy-API misuse**: `hasattr(response.propertyValue, "tagList")`/`tag.tag_data` always False in bacpypes3 (propertyValue is `Any`; correct path is `cast_out(<type>)`) — across `security.py:677-982`, `discovery.py:313-537` (→ proprietary-object & backdoor-pattern detection can NEVER fire), `properties.py:238-324`, `files.py:75-136` (file_size always 0). Sibling code already uses `cast_out` correctly.
- `monitoring.py:587-600` — COV listen loop is a no-op busy-wait (sleeps, reads no queue; comment admits needs app subclassing) → never observes a notification.
- inert flags / dead writes: `proto_args.py:213,215` `--subnet-mask`/`--network-number` zero readers; `nxc_connection.py:233` `args.enum_networks=True` dead (real is `:232 networks`), `:63` `host_info={}` never read; `network.py:680,701,898-899` write-only port_info keys.
- `state.py:9,118-127` — unreachable `elif output_format=="yaml"` (argparse `--format` excludes yaml); `import yaml`/PyYAML dep exist only for it.

**LOW (18)** — split timeout-vs-BaseException excepts with identical bodies, redundant local re-imports, etc. (Full report: task output `wtrwa3ajo`.)

### snmp (0 HIGH, 10 MEDIUM, 7 LOW) — vulture 11, ruff clean — relatively clean

**MEDIUM (10)** — highlights:
- `scanner.py:243,261,265,611` — `self._last_error` written 4× (connect/_get_auth_data), never read (failure signalled via return-None; diagnostics already logged).
- `scanner.py:740-777` — `scan_targets()` exported in `__all__` but zero callers; no loader convention uses it; dup of run_scan path → speculative.
- `constants.py:32-64` — `SNMP_TABLES` (25 OIDs) exported + test-pinned but never functionally read (enumeration uses NETWORK_ENUM_OIDS + hardcoded literals); alias keys `arpTable`/`dot1dTpFdbTable` doubly dead.
- unused OID dict keys never read: `constants.py:605-606` (ipAddressType/ipAddressPrefix), `:613,615` (nsExtendInput/nsExtendRunType), `:487` (vacmAccessNotifyViewName).
- `raw_queries.py:168-192` — dead importlib/getattr/None fallback around `bulk_walk_cmd` (stable public pysnmp symbol; sibling hard-imports `walk_cmd` unguarded).
- dead-writes `version_detection.py:55,189` engine_time, `:235-255` format_name (all 6 branches), `:190` engine_id.

**LOW (7)** — deprecated pysnmp camelCase APIs (`addAsn1MibSource`/`resolveWithMib`), unused unpack vars (`error_index`/`var_binds`/`idx`), unconfigurable `max_entries=2000` param. (Full report: task output `we51ara0z`.)

### tase2 (11 HIGH, 10 MEDIUM, 9 LOW) — vulture 77, ruff clean — many real API bugs + dead spec-transcription

**HIGH**
- **API bugs (uncaught → crash)**: `nxc_connection.py:409-411` `ServerInfo.domains/bilateral_tables/supported_blocks` don't exist (real: vendor/model/revision/bilateral_table_count/…) → `--get-server-info` AttributeError crash; `:213-216` `get_domain_variables()` returns `List[str]` but code does `v.name` → `--list-variables` crash.
- **API bugs (swallowed → feature dead)**: `enumeration.py:119` `read_points(domain, names)` wrong arity (real: single `List[tuple]`) → get_data_values always []; `:204` `create_data_set()` passed List[Dict] not List[str] → data sets never created.
- dead islands: `scanner.py:246-287` `parse_tase2_error()` + 2 supporting classes (zero callers); `scanner.py:75-219` **7 unused TASE.2 enum/constant classes** (~130 lines spec transcription; control.py uses raw "ARMED"/"IDLE" literals instead).
- `security.py:44,236-253` `client_security={}` hardcoded → entire merge block unreachable (~20 lines); docstring claims uncalled API.
- `control.py:177-280` `select/operate_device_with_checkback` zero callers (CLI bypasses the CheckBackID/ARMED-IDLE machinery, ~104 lines); `:52-53,61` dead control_info flags.
- `transfer_sets.py:60,84,132,154` — 4 public transfer-set methods zero call sites/no dispatch (~115 lines).
- `info_messages.py:128-137` — producer/consumer key sets disjoint → produced fields surface nowhere.

**MEDIUM (10)** — `getattr(buf,"storage_status",...)` masks non-existent attr → IM injection heuristic (`:407-413`) never fires; docstrings describe unimplemented fallback tiers; `create_information_message_store` speculative stub (always "not supported"); inert `--discover-icc`; dead `bilateral_table_id`; discarded `_sbo_devices` comprehension; duplicate get_server_blocks round-trip.

**LOW (9)** — (Full report: task output `wg0l5nf5u`.)

### can (1 HIGH, 9 MEDIUM, 12 LOW) — vulture 168 (≈155 FPs: protocol constant tables + framework hooks), ruff clean

**HIGH**
- `constants.py:601-602` (written `traffic.py:85,87`) — `CANTrafficStats.id_first_seen`/`id_last_seen` written every message, no reader anywhere → unbounded dead state. Drop or wire into export.

**MEDIUM (9)** — dead dataclass fields written-never-read or never-written: `constants.py:606` bus_load_estimate, `:622` security_access_levels, `xcp.py:143,206` comm_mode_basic, `:527,539` CCP device_id/session_status (only set by uncalled `ccp_get_info()`); `uds.py:243-594` `resp_id` param unused in 5 methods (recomputed internally); `uds.py:223` negative_responses populated but omitted from both serialization paths (likely a real omission — "service exists but blocked"); dead SDO command-byte chain `constants.py:842-855`.

**LOW (12)** — `import time # noqa` test-patch anchor + indirection; dead try/except around non-raising decode (`constants.py:1290`); many unused spec-table constants (J1939 masks, XCP/CCP TX bytes, CANOPEN_OD_* scalars duplicating the dict, CiA-309 gateway bases) referenced only by echo-assertion tests; `OBD2_VEHICLE_INFO_PIDS` in `__all__` no reader; `canopen_nmt_state_read()` zero callers. (Full report: task output `wlqyj0jnp`.)

### profinet (7 HIGH, 16 MEDIUM, 10 LOW) — vulture 53 (mostly dataclass FPs), ruff clean

**HIGH**
- dead methods/functions zero callers: `gsdml_parser.py:378-380` `match_device()`, `:141-154` `get_slot_structure()`; `rpc.py:605-613` `_read_ar_data()` + `:615-623` `_read_api_data()` (advertised in docstring, never wired).
- dead fields written-never-read: `gsdml_parser.py:241-264` 5 GSDML metadata fields; `__init__.py:156-158` MockDCPDesc.device_type/roles/vendor_name; `cyclic.py:241-246` received_count + on_input callback (real count from `stats.frames_received`).

**MEDIUM (16)** — highlights (profinet 0.6.0 **API misuse → silent dead features**):
- `rpc.py:311-325` — ModuleDiffBlock `all_ok`/`get_mismatches()`/`entries` don't exist (only `modules`) → all hasattr-guarded → only generic fallback runs.
- `rpc.py:266-267` — `InterfaceInfo.netmask_str` doesn't exist (real: `subnet_str`) → netmask line never printed.
- `rpc.py:292-293` — `PeerInfo.mgmt_addr` doesn't exist → LLDP mgmt-address line never reached.
- inert flag `proto_args.py:99-107` `--port/--rpc-port` discarded (RPCCon built without port); unused params `fuzz.py:28` device, `cyclic.py:36` profinet_mod; dead-writes `enumeration.py:488` `.indices`, `models.py:23` supported_options, various gsdml RecordData/Module fields.

**LOW (10)** — `gsdml_parser.py:10-13` **defusedxml try/except → stdlib fallback silently disables XXE protection** on attacker-supplied GSDML (use `lazy_import` hardfail); dead `first_seen`/`last_seen`; single-call wrappers. (Full report: task output `wiv8rv8h9`.)

### mqtt (2 HIGH, 8 MEDIUM, 9 LOW) — vulture 34 (mostly paho callback FPs), ruff clean

**HIGH**
- `scanner.py:575-578` — 4 `self.tls_*` attrs written, never read (live TLS uses `build_tls_context(self.args)` off the raw args dict); only pin-tests reference them. `use_tls` is live — keep.
- `nxc_connection.py:52-63` — `_get_subscribe_topics()` orphan (logic inlined into `_handle_publish_and_listen`).

**MEDIUM (8)** — dead writes/state never read: `scanner.py:358-377` `MQTTMessage.to_dict()` (test-only), `:624` broker_info, `:630,657` `_connected`; `nxc_connection.py:25,196` `_scan_results` (real path `results["data"]["scan_results"]`); `auth.py:121` valid_credentials, `topic_discovery.py:88,270` `self.messages` appends; `security.py:72-75` dead list/tuple cred branch (producer only appends dicts).

**LOW (9)** — unpopulated MQTT5 property fields; copy-paste garbage debug strings (`nxc_connection.py:225,228`, `messaging.py:87-88` `f"if self.timeout  0:: {e}"`); kebab-case dict-key fallbacks that never match (argparse normalizes to snake_case); redundant `min()` before slice; `__import__("argparse")` in lambda. (Full report: task output `wvnum72mz`.)

### iec104 (10 HIGH, 9 MEDIUM, 7 LOW) — vulture 24@60, ruff clean — entire file-transfer feature is fabricated API

**HIGH**
- **`file_transfer.py:71,146,216,298,347`** — **5 fabricated c104 APIs** that don't exist in c104 2.2.1: `conn.browse_directory()`/`download_file()`/`upload_file()`/`query_log()`/`delete_file()` → AttributeError swallowed → `--list-files`/`--probe-files`/download/upload/log/delete **all silently never work** (c104 has no high-level file-transfer API; needs manual F_* ASDUs).
- `commands.py:168,367,534` — **API bug**: `station.remove_point(point_obj)` but signature needs `int io_address` → TypeError swallowed → delete-then-recreate recovery silently fails whenever IOA already exists as a monitoring point.
- `commands.py:648-650` — no-op `elif hasattr(conn,"command"): pass` + dead `send_raw` arm → fuzz loop increments `tested` counters while sending nothing (re-introduces the counter-lies bug a comment claims to fix).
- inert flags / dead validation: `scanner.py:174-175` `--max-commands` zero readers; `:99-115` IOA-range parse+clamp feeds attrs nothing reads.
- `file_transfer.py:87` — discarded bare expression `entry.get("creation_time", 0)`.

**MEDIUM (9)** — `commands.py:33-50` `_test_commands` do-nothing stub returns hardcoded empty dict into results; `_deps.py:21-54` `_C104Cache` cache-around-lazy_import + dead `c104=None`/sys.modules write-back; `scanner.py:60-62,479` module `logging.getLogger` + copy-paste debug `f"if tid in (1,30): … {e}"`; `:261` output_format never read.

**LOW (7)** — `constants.py:44` APCI_HEADER_SIZE unused, etc. (Full report: task output `w8rf40ya0`.)

### hart (5 HIGH, 12 MEDIUM, 4 LOW) — vulture 22@60, ruff clean

**HIGH**
- `proto_args.py:159-181,308-314` — cluster of CLI flags with dests no code reads: `--enumerate-device-specific`, `--probe-calibration`, `--probe-write`, `--scan-mode` → silent no-ops.
- dead code: `nxc_connection.py:23` `_scan_results` cargo-cult (HART uses `results["data"]`); `scanner.py:31` unused `_fuzzer` lazy_import (real one in fuzz.py); `enumeration.py:327-330` `enumerate_device_specific_commands()` zero callers; `fuzz.py:54-55,121-164` `_basic_fuzz` fallback unreachable (gate checks an in-tree module that always imports).

**MEDIUM (12)** — `scanner.py:435-457` `metadata()`/`run()` compat shims zero callers; `:322-431` `discover()`+`_result_to_dict()` dead parallel orchestration duplicating nxc path; `:239` `self.debug` re-write after base already set it (discards verbose semantics); `security.py:26-89` unused `client=None` DI param on 3 methods; `enumeration.py:18-251` module `getLogger`; `device_info.py:58` dead `info.flags` write; `hartip.py:116-142` 5 never-called typed stub factories; granular `--read-*` flags never gated.

**LOW (4)** — 10 impossible `if not self.scanner: return` guards, test-only lock-state helpers, `HARTIP_AVAILABLE` read nowhere. (Full report: task output `w1tjzcb0v`.)

### dicom (1 HIGH, 11 MEDIUM, 8 LOW) — vulture 30@60 (mostly pydicom Dataset/pynetdicom config FPs), ruff clean

**HIGH**
- `nxc_connection.py:40-47` — `_get_pynetdicom()`/`_get_pydicom()` zero callers (consumers use module-level lazy objects). Delete.

**MEDIUM (11)** — mostly dead `self.results["data"][...]` writes never read by `_export_results` (cherry-picks keys): `nxc_connection.py:702` reject_reason, `enumeration.py:274-281` personnel, `:418-425` devices, `:549-558` time_analysis, `reporting.py:259` supported_operations, `cfind.py:143` StudyUID/SeriesUID (several are real findings worth wiring into `_analyze_security` — personnel exposure, >10y retention). `__init__.py:43,47` dead `evt` binding; `cfind.py:62-71` STUDY-branch assignments unconditionally overwritten.

**LOW (8)** — `__init__.py:42-48` patchability block omits `Verification` → **live test AttributeError** (`test_scanner.py:740` patches it); `nxc_connection.py:443` pydicom `write_like_original=` deprecated (removed in v4 → future TypeError); single-call wrappers; redundant `pass`/`list()`/unused loop var. (Full report: task output `w5898670n`.)

### ocpp (4 HIGH, 9 MEDIUM, 5 LOW) — vulture 100@60 (mostly spec value-tables + facade FPs), ruff clean

**HIGH**
- `scanner.py:565-652` — `_listen_for_commands` (88 lines) zero callers (superseded by `listen_mode()` + inline server-CALL handling).
- `messages.py:52-78` — `_build_call_error` no production caller (OIDA is read-only OCPP client; never emits CALLERROR); only tests.
- `__init__.py:161-163` — `_has_any_operation_flag()` dead (proto_flow open-codes the checks) — same copy as the dead opcua one.
- `constants.py:318-483` — **10 enum classes never read** (ResetType/UnlockStatus/ChargingProfilePurpose/…); builders hardcode the identical string values → duplicate source of truth that can drift.

**MEDIUM (9)** — inert CLI flags read nowhere: `proto_args.py:145-159` `--vendor`/`--model` (boot notification hardcodes them), `:226-230` `--firmware-info` (no dispatcher), `:108-113` `--ws-path` override; dead `scanner.py:498-500` `_server_commands` (test-only); `constants.py:355-374` `METER_VALUE_MEASURANDS` zero readers.

**LOW (5)** — in-function stdlib imports (`security.py:1191-1270`), copy-paste wrong-condition debug strings (`discovery.py:492,1090`), parallel `_*_FLAGS` source-of-truth, single-call wrapper. (Full report: task output `w7c5c1pm2`.)

### fhir (0 HIGH, 9 MEDIUM, 6 LOW) — vulture 14@60, ruff clean

**MEDIUM (9)** — inert CLI flags read nowhere: `proto_args.py:155-160` `--auth-url` (sibling `--token-url` IS consumed → real omission), `:454-458` `--test-404-vs-403`, `:555-560` `-X/--extract-response` (FHIR side never reads it; only HL7 does). dead builders `resources.py:222,304,403` (build_medication_request/condition/encounter — ~250 LOC test-only); `:17-18` static-class `__init__`/`self.version` dead write; `search.py:699-729` 5 unreachable resource-type model-map entries; `security.py:27` `token_required` write-never-read; `helpers.py:94-131` 16 redundant `_xxx`→`xxx` lazy alias pairs.

**LOW (6)** — unused `is_file` unpack, misleading debug message, never-overridden `date_only` param, `FHIR_SECURITY_MODES` re-exported but unread. (Full report: task output `wrp3702xh`.)

### dnp3 (3 HIGH, 8 MEDIUM, 5 LOW) — vulture 59 (mostly opendnp3 C++ callback FPs), ruff clean

**HIGH**
- dead public methods zero callers: `scanner.py:531-550` `_run_operation()` (test-only), `:1137-1151` `time_sync_cmd()` (→`_perform_time_sync`), `:1190-1214` `write_analog_output()` (dup of `_perform_analog_control`).

**MEDIUM (8)** — **API bugs via getattr masking**: `control.py:559` `getattr(FunctionCode,"ACTIVATE_CONFIGURATION",None)` — typo, real member is `ACTIVATE_CONFIG` → always "not available", never sends; `:519` `SAVE_CONFIGURATION` nonexistent → `_save_configuration` dead; `file_transfer.py:533-540` `getattr(val_obj,"value",b"")` on opendnp3 OctetString → always empty (real accessor `ToBytes()`) → Group 110/111 reads report success but hex_value="". inert `--no-ack` flag (`scanner.py:410`); dead `_scan_data` dict; ~40 identity no-op arg-mapping entries (`nxc_connection.py:63-125`).

**LOW (5)** — dead `except KeyError`, blind `time.sleep()` guarding no race, collapsible `ao_type` dispatch, redundant underscore-form key checks. (Full report: task output `wh9kw2nbe`.)

### astm (2 HIGH, 8 MEDIUM, 5 LOW) — vulture 13@60, ruff clean

**HIGH**
- `records.py:514-577` `build_scientific()` (64 lines) zero callers; `:592-600` 9 `RECORD_*` constants no production readers (code matches record types with bare literals; only echo-back tests reference them).

**MEDIUM (8)** — `build_manufacturer()` test-only; duplicate `_calculate_checksum()` in builder vs framing (can diverge); 3 dead delimiter attrs (`_escape_field` hardcodes inline); `__init__.py:23-37` record-constant re-export block no namespace readers (all `# noqa: F401`); dead HL7-copy scaffolding `nxc_connection.py:38,40` all_responses/detected_version.

**LOW (5)** — unused builder params (reserved/version), never-exercised `intermediate=True` ETB branch, mislabeled `_unicode` fuzz case carrying ASCII payload. (Full report: task output `wnibol22n`.)

### ads (0 HIGH, 11 MEDIUM, 10 LOW) — vulture 22@60, ruff clean

**MEDIUM (11)** — `ethercat_ops.py:78,188,446,544,666` dead `connection` param threaded through 5 methods, structurally unusable (each opens its own pyads conn; `self.conn` bound to wrong AMS port); `helpers.py:190-195` `_test_coe_write_access` pure rename of `_write_coe_sdo`; single-call factory wrappers; dead result keys never read (`scanner.py:667` licenses always [], `:873` UDP port, `ethercat_ops.py:399,1280,1441` raw_size/dc_system_time_ns); `nxc_connection.py:66` `_scan_results` cargo-cult.

**LOW (10)** — partial struct-unpack dead fields, decorative branches, redundant `pass` after debug, copy-pasted dtype-decode ladder, `_connection` redundant shadow of `self.conn`. (Full report: task output `wo16j35f5`.)

### coap (0 HIGH, 17 MEDIUM, 11 LOW) — vulture 24@60, ruff clean

**MEDIUM (17)** — highlights:
- **API hallucination**: `helpers.py:512-519` `try_dtls_cert` calls `aiocoap_creds.DTLS(client_cert=,private_key=,ca_certs=)` but pinned aiocoap 0.4.17 DTLS is `(psk, client_identity)` only → always TypeError masked by `except TypeError` returning canned "not supported" → cert DTLS **can never succeed** (cert/key/ca reads wasted); `:602` `try_dtls_rpk` `raw_public_key=` kwarg doesn't exist → RPK path permanently unreachable.
- dead decode tables `constants.py:10-52` (MSG_TYPES/METHODS/RESPONSE_CODES — code uses inline literals / aiocoap objects); `scanner.py:63-129` `self._ctx` written 4× test-only; `_EventLoopHolder` lock/singleton guards an impossible race (single-threaded); `coap_put_blockwise` no caller; inert `-r/--resources` flag; dead `__init__.py:45-49` dependency flags / duplicate lazy_imports.

**LOW (11)** — `return _aiocoap()` wrapper, `default_port` re-assign no-op, `except (asyncio.TimeoutError, Exception)` redundancy, function-local imports. (Full report: task output `wxri4tl0w`.)

### pcap (0 HIGH, 1 MEDIUM, 1 LOW) — vulture 12@60, ruff clean — cleanest (only scanner/registry/args; 109 listeners not in this dir)

**MEDIUM (1)** — `__init__.py:20-42` hand-rolled PEP 562 lazy-import shim addresses no real failure (deps already lazy in scanner, no import cycle); collapse to plain `from .scanner import ...` (same for discovery). Candidates `scanner.py:800` `_x509` / `:1115` `_resolve_host` flagged for review.

**LOW (1)** — `scanner.py:477-501` byte-identical subprocess-kill block duplicated across two crash branches; hoist once. (Full report: task output `wrxgkby1r`.)

### mms (2 HIGH, 8 MEDIUM, 6 LOW) — vulture 12@60, ruff clean

**HIGH**
- `fingerprint.py:154-157` `add_rule()` zero callers (rules loaded only via JSON); `:344-348` `load_mms_fingerprints()` convenience fn unused (real caller inlines).

**MEDIUM (8)** — inert CLI flags `proto_args.py:34-51` `-i/--identify`/`-l/--get-name-list`/`-r/--variable` never consumed; `__init__.py:88-119` `wordlist-path` dead scaffolding for unbuilt fuzzing; dead writes `fingerprint.py:42,245` raw_attributes, `:115,147` loaded_files, `__init__.py:311` hardcoded `supports_get_server_directory`.

**LOW (6)** — copy-paste source-line debug (`__init__.py:726` `f"if isinstance(value, bool):: {e}"`), constant `match_confidence=1.0` never computed, unused tuple-unpack `error_code`/`ok`, redundant fuzz guard. (Full report: task output `wn5egnrbe`.)

### goose (0 HIGH, 3 MEDIUM, 3 LOW) — vulture 15@60, ruff clean

**MEDIUM (3)** — `__init__.py:434-437` `getattr` masks nonexistent `GooseMessage.is_test`/`.test` → TEST/SIMULATION flag permanently False → dead-codes the security warning at 603-607; `:530-533` dead VLAN/dst_mac display branches (keys never set; `vlan_prio` vs `vlan_priority` mismatch); `:154` `gocb_info` attr never populated/read (real path uses local list).

**LOW (3)** — speculative `_format_mac` type-dispatch (caller always passes bytes), unexplained `time.sleep(0.1)` in cleanup, single-call wrapper. (Full report: task output `wfjimd6sx`.)

### modbus mixins/ (1 HIGH, 3 MEDIUM, 7 LOW) — vulture 31, ruff clean

**HIGH**
- `read_write.py:40` — **hallucinated import** `from ..decoder import MapNameResolver` (no such class) → `_get_resolver()` only catches ValueError so the ImportError **crashes every `--read-name`/`--write-name`/`--list-names`/`--search-name`** (wired in nxc_connection.py); entire resolver API unimplemented; masked by --help-only tests. Implement or repoint to `load_register_map()`/`decode_with_map()`.

**MEDIUM (3)** — `sunspec.py:113-168` `_raw_regs_to_value` reimplements ModbusDecoder (fictional "avoid pymodbus" justification); `fuzz.py:142` dead `iterations` param (FC half ignores the budget); `:287-307` dead try/except around `struct.pack` on in-range values.

**LOW (7)** — malformed copy-paste debug (`sunspec.py:70` `"with open(json_file, r) as f:: {e}"`), dead `access` element in SUNSPEC_CRITICAL_CONTROLS tuples, redundant `total_stats`, single-call wrapper, unused `path`/`subfunc`/`modbus` import. (Full report: task output `wrzypscjw`.)

### modbus scanner_mixins/ (0 HIGH, 5 MEDIUM, 10 LOW) — vulture 21@60, ruff clean

**MEDIUM (5)** — recurring **pymodbus version-skew dead branches** contradicting the 3.13.0 pin: `identification.py:216-229` dead `.objects` branch (response only has `.information`), `diagnostics.py:121-130` `getattr(client,"diag_restart_communication")` guard for an always-present method, `custom_fc.py:134-150` unreachable response-extraction fallback (registered decoder always sets raw_data); plus `reporting.py:23-60` `_decode_register_values` test-only dead method.

**LOW (10)** — docstrings advertising nonexistent "monitoring/polling", redundant `pass` after debug, try/except around non-raising `decode(errors=...)`, unused request-class unpacks, redundant guards, dict-only `_args_get` polymorphism. (Full report: task output `whn22qpx0`.)

### modbus core (2 HIGH, 14 MEDIUM, 15 LOW) — vulture 113@60 (mostly enum/framework FPs), ruff clean

**HIGH**
- `device_db.py:1-851` — **entire 851-line lookup library unwired**: only src import is `scanner.py:151` (`get_exception_info`), which is itself never called. ~13 zero-reference functions (identify_device/search_vendors/get_function_code_info/analyze_exception_response/…) + 4 test-only. Wire the MEI/exception-fingerprint functions into the scan path or delete.
- `scanner.py:148-153` — dead conditional import + None fallback for `get_exception_info` (never referenced).

**MEDIUM (14)** — `_PymodbusCache` singleton+RLock cache-around-lazy_import; `nxc_connection.py:345-349` test_write/test_write_thorough both call identical zero-arg handler; dead unwired `decoder.py:683-793` `decode_with_map()` (+ scale-factor/enum machinery) & `:416-441` `decode_auto()`; `constants.py:104-129` `CANOPEN_DATA_TYPES` zero readers; `validate_maps.py:276-291` `is_valid_enum_key()` defined+tested never called; bare discarded `group.get("group","")` expr (`convert_maps.py:145`, `import_maps.py:345`); `except (json.JSONDecodeError, Exception)` redundancy; triplicated identify_vendor return dict.

**LOW (15)** — redundant check_dependency-before-except guards, backwards-compat test-only wrappers, enum/dict duplication, large speculative encode_*/decode_* public surface ahead of demand. (Full report: task output `wsgimd37q`.)

### discovery 1/2 (14 HIGH, 33 MEDIUM, 21 LOW) — vulture clean, ruff clean — dominant defect: dead-write payloads dropped by export allowlist

**Systemic issue**: many listeners parse a structured `*_data` dict, store it on the device, and merge it — but `_device_to_dict` (scanner.py:2197) has an allowlist that omits them, so the data is **computed then dropped before export**; only tests read it.

**HIGH (14)** — dead methods zero callers: `base.py:223-269` `_add_device`/`_get_timestamp`; `core.py:280-289,346-362,674-726,1190-1324` `is_broadcast_mac`/`wait_for_interface`/`get_interface_info`/`create_discovered_device` (135-line factory, test-only, dup field_map); `file_carving.py:166-185` `save_files` override; `infra.py:1317-1326` `PCAnywhereScanner._parse_response`. dead-write payloads never serialized: `enrich.py:81-191` ping_data/dns_names, `eigrp_passive.py` autonomous_systems, `glbp.py:229-252` glbp_data (~24 keys), **`infra.py` all 9 IT-infra payload dicts** (hid/mssql/bjnp/sonicwall/db2/sybase/xdmcp/jenkins/pcanywhere), `hsrp.py:492-495` MD5 digest parsed then discarded.

**MEDIUM (33)** — `arp.py:35-158` `ResilientSniffer` (~125 lines) for undemonstrated flapping; `arp.py:237-532` two listeners re-implement `PassiveListenerBase` instead of subclassing (lose debug hexdump); more dropped `*_data` (ads_data, netmanage_data); dhcp per-server stat dicts never read; docstring claiming nonexistent alias.

**LOW (21)** — (Full report: task output `wlbr98nko`.) Note: discovery has a likely-duplicate listener layer vs `pcap/passive/` (eigrp/glbp dead copies).

### discovery 2/2 (15 HIGH, 40 MEDIUM, 27 LOW) — vulture 121@60, ruff clean — same export-allowlist dead-write pattern, plus a hallucinated scapy import

**HIGH (15)** — dead production classes/methods: `ipv4_resolve.py:146-198` IPv4ResolvePassiveScanner (test-only, not wired/exported), `ipv6.py:289-315` `_add_device` dup, `stats.py:333-365` `process_packet()` + **~500-line dead scapy subtree** (only pyshark path used), `stats.py:1631-1657` `add_certificate()` zero callers. **API hallucination**: `pim_passive.py:68` `from scapy.contrib.pim import PIM` — no `PIM` in scapy 2.7.0 (it's `PIMv2Hdr`); ImportError swallowed per-packet → entire scapy parse branch permanently dead. dead-write payloads dropped by `_device_to_dict`/`merge_from` allowlists: `mdns.py` mdns_data, `ntp.py:244-254` ntp_data, `rip_passive.py:197-233` rip_data (+ vrrp/ospf/eigrp/pim_data). `proto_args.py:127-171` **34 `--no-<proto>` toggles** that no scanner code reads → silent no-ops. bare discarded expressions (`network.py:867`, `pim_passive.py:145,245`).

**MEDIUM (40)** — `scanner.py:1872` `device.vendor = ...` writes a **non-existent dataclass field** (real field `manufacturer`) → vendor silently lost (latent bug); `lldp.py:994-1177` error handlers call `self.logger` never set → AttributeError instead of logging; duplicate `lookup_mac_vendor` copy; many unused class constants (ICMPV6_*, NETBIOS ports, CDP_ETHERTYPE); more write-only accumulators (workgroups, ntp_servers, protocol_version).

**LOW (27)** — dead locals, unused signal-handler args, etc. (Full report: task output `ww6gal46u`.)

---

## Cross-cutting themes (whole sweep)

1. **Dead-write payloads dropped at the serializer boundary** (the single biggest class, esp. discovery): listeners parse a rich `*_data` dict, store + merge it, but `_device_to_dict`'s allowlist (discovery/scanner.py:2197) and several `_export_results`/`_report_findings` paths omit it → parsed intelligence is computed then silently discarded. Fixing the allowlists likely "turns on" a lot of already-written extraction.
2. **Hallucinated / wrong third-party APIs that no test catches** (highest-severity, real behavioral bugs): iec104 (5 nonexistent c104 file-transfer methods), bacnet (`PropertyIdentifier` names + `BAC0.lite(localIPAddr=)`), knx (`Telegram.data`, `Telegram(payload=bytes)`), profinet (ModuleDiffBlock/InterfaceInfo/PeerInfo attrs), snap7 (`full_upload` tuple), dnp3 (`getattr` enum typos, `OctetString.value`), coap (DTLS cert/RPK kwargs), modbus (`MapNameResolver`), pim (`scapy…PIM`), goose (`GooseMessage.is_test`). Pattern: the bad call sits inside `except Exception`/`getattr(...,None)`, so the feature silently no-ops and only `--help`/round-trip tests "cover" it.
3. **Inert CLI flags** across almost every protocol: registered with a `dest` nothing reads (snap7 `-C/-N`, hl7 `--save-response/--parse-segments/--ssn`, bacnet `--subnet-mask/--network-number`, hart cluster, ocpp `--vendor/--model/--ws-path`, fhir `--auth-url/...`, iec104 `--max-commands`, discovery's 34 `--no-*`). They appear in `--help` and silently do nothing.
4. **Dead methods/classes kept green only by their own tests** (false coverage) — pervasive; many are superseded duplicates of the live path.
5. **Cargo-cult ceremony**: cache-around-lazy_import singletons+locks (opcua/iec104/can/coap/modbus), pure pass-through wrappers, try/except around non-raising `decode(errors=...)`/`struct.pack` on in-range data, `except (Specific, Exception)` redundancy, copy-paste debug strings echoing source lines.

**Note on false positives** (already weighted down per-protocol): vulture flags framework-contract hooks (`proto_flow`/`get_protocol_name`/`proto_args`/`_handle_*` dispatch), library callback signatures (paho/opendnp3/asyncua/scapy), and quoted-annotation TYPE_CHECKING imports — these are NOT slop. The NXC "log + continue" `except Exception` pattern is intentional (no bare excepts anywhere).
