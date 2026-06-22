# /slop-check report - full src sweep (582 files, no skips)

582 files reviewed across 58 clusters (0 failed). Findings: HIGH=10, MEDIUM=76, LOW=95.

## HIGH - likely real defects

- **`src/oida/protocols/snap7/nxc_connection.py:79-121`** - enum_host_info()/print_host_info() never called in snap7. proto_flow() override only calls create_conn_obj() then _execute_action()/_execute_scan(); unlike every other protocol it never invokes either method. Both (~43 lines) are dead; CPU-info display is emitted via scanner._get_cpu_info()/discover(). *Fix:* delete both methods, or call them from proto_flow() if the host-info banner is intended.
- **`src/oida/protocols/snap7/mixins/device_info.py:164-166`** - firmware extraction method 2 keys off `fw_version`, a key SZLParser never emits (it sets `version_info`). The SZL-fallback firmware-version branch is unreachable; only order_code (line 167) is salvageable. *Fix:* change the key to `version_info`, or drop lines 164-166.
- **`src/oida/protocols/tase2/mixins/info_messages.py:26`** - _discover_information_messages(connection, results) has zero callers anywhere in src/ or tests/; scanner.discover() never invokes it and nxc_connection uses its own inline loops. Fully dead. *Fix:* delete it, or wire it into TASE2Scanner.discover().
- **`src/oida/pcap/cotp.py:108-130,396-446`** - COTPConnection lifecycle fields written but never read: state/calling_tsap/called_tsap/cotp_class/tpdu_size/dc_seen/dt_count/total_bytes/last_seen are assignment-only; only cc_seen/cr_seen/dr_seen + ip/ref are read in harvest() for one alert. Device table is built from the separate COTPEndpoint. *Fix:* drop the unread fields and the _handle_cc/_handle_dc/_handle_dt write-only bodies, or surface the state machine in harvest/_build_device_data.
- **`src/oida/pcap/mongodb.py:216-283`** - op_detail string built across an 18-line opcode/auth/admin/query-failure ladder but never passed to details, summary, _record_interaction, or logging. The detail column is rebuilt independently in _format_protocol_columns (line 346). Pure wasted work and a maintenance trap. *Fix:* delete op_detail and all 13 assignments, or wire it into details.
- **`src/oida/fuzz/core/connections/raw_socket.py:160-208`** - EthernetFrame class (build/parse_mac/format_mac) has zero callers; only its def file + lazy-import shim reference it. RawSocketConnection in the same file IS used; EthernetFrame is not. *Fix:* delete the class and remove it from connections/__init__.py (_raw_attrs, lazy import, __all__).
- **`src/oida/fuzz/primitives/reduced_string.py:165-168`** - ReducedString._fuzz_library_to_use property never read anywhere; it is the sole consumer of _instance_fuzz_library. Pure dead code. *Fix:* delete the property (and reconsider _instance_fuzz_library - see MEDIUM).
- **`src/oida/utils/cli.py:427-429`** - cli.main() is `def main():` (0 params) calling `run({}, lambda args: None)`, but every caller invokes `main(sys.argv, run, metadata)` (3 args) from dead `__main__` blocks (opcua/scanner.py:757, mms/__init__.py:834, goose/__init__.py:709); two import `from utils.cli import main`, an unresolvable top-level path. Broken cargo-cult; never reached. *Fix:* delete main() and the three dead __main__ blocks, or fix them to call run(metadata, callback, soft_check).
- **`src/oida/utils/ics_logger.py:598,633,652,662`** - log_connection, log_security, log_scan_result, log_enumeration emit structured JSON events but have zero call sites; production uses display/success/fail/vuln/security_finding instead. *Fix:* delete the four unless a JSON-log consumer is planned.
- **`src/oida/utils/login_scanner.py:167-233`** - make_scanner (user:pass factory) is exported/documented but never imported; only make_password_scanner is used (hart/mixins/security.py). ~67 dead lines. *Fix:* delete make_scanner and drop it from the module docstring.

## MEDIUM - review and confirm

- **`src/oida/protocols/coap/helpers.py:151`** - `--ipatch` dead at runtime: `hasattr(aiocoap,"IPATCH")` is never true (real symbol is `aiocoap.iPATCH`, lowercase-i). IPATCH never enters the method map; any --ipatch returns unsupported, while proto_args/nxc_connection/tests assume it works. *Fix:* reference `getattr(aiocoap,"iPATCH",None) or getattr(aiocoap.numbers.codes.Code,"iPATCH",None)`, or drop --ipatch.
- **`src/oida/protocols/opcua/mixins/discovery.py:265`** - display_cert_info(self.logger, server_cert, self.results.get("data")) binds the data dict to the `protocol` param; intended `results` stays None so cert info is never recorded. Masked by surrounding try/except. *Fix:* call with keywords (protocol="opcua", results=...).
- **`src/oida/fuzz/primitives/transformers/authentication.py:462-463`** - DigestAuthTransformer uses nonexistent `hashlib.sha512_256`; constructing with algorithm="SHA-512-256" raises AttributeError despite being advertised. *Fix:* use `hashlib.new("sha512_256")` or drop SHA-512-256.
- **`src/oida/protocols/astm/mixins/framing.py:101-174`** - _receive_frame has no production caller; nxc_connection._receive_server_response (291-338) reimplements its own inline frame-read/checksum loop. Two copies that can drift. *Fix:* route _receive_server_response through _receive_frame, or delete the unused method + its tests.
- **`src/oida/protocols/discovery/eigrp_passive.py:100-101,139-140,171-172,248-249,259-275`** - seq_num/ack_num parsed in both paths, threaded through _update_device's 14-arg signature, but never stored or read. *Fix:* persist into device.eigrp_data, or drop from both parse paths and the signature.
- **`src/oida/protocols/discovery/core.py:732,755,764,782`** - four InterfaceCapabilities methods (is_local_ip/get_available_scanners/log_warnings/print_status) have zero callers; get_excluded_ips/get_disabled_scanners become dead with print_status. *Fix:* remove, or mark as intentional public API with a smoke test.
- **`src/oida/protocols/discovery/scanner.py:431,440,448`** - self.interface_network (singular) assigned in all three branches with "# For display" but never read; the promised display use does not exist. *Fix:* delete the three assignments (keep interface_networks).
- **`src/oida/protocols/discovery/lldp.py:30`** - module global dependencies_missing defined but never read; check_dependencies returns _scapy.is_available directly. Vestigial copy from mqtt/ocpp/ethernetip. *Fix:* delete line 30.
- **`src/oida/protocols/discovery/stats.py:219,263,966,1040,1301`** - dead certificate feature: self.certificates is init'd/read but nothing ever writes to it; Certificate dataclass + parse_certificate + _print_certificates are dead scaffolding. *Fix:* remove the cert feature, or wire a producer into _process_pyshark_layers.
- **`src/oida/protocols/discovery/stats.py:170,910`** - duplicate _is_server_port implementations (module fn + instance method) with a redundant ephemeral early-out divergence; maintenance hazard. *Fix:* keep one, route all callers to it.
- **`src/oida/protocols/hl7/mixins/continuation.py:19-111`** - ContinuationMixin (_check_continuation/_create_continuation_request/_reassemble_fragments) never called by proto_flow or any scan path; its own docstring admits "not yet chained into the query/scan path". *Fix:* wire into _send_mllp_message/query path, or remove the mixin and its tests.
- **`src/oida/protocols/knx/mixins/discovery.py:360-398`** - _scan_bus_devices COMMON_RANGES else-branch is dead: every caller passes a non-None scan_range, so use_custom_range is always True. *Fix:* drop the COMMON_RANGES split, make scan_range required.
- **`src/oida/protocols/knx/nxc_connection.py:408-418`** - print_host_info override never invoked; knx overrides proto_flow() which never calls self.print_host_info(). *Fix:* delete the override, or call it from proto_flow() after enum_host_info().
- **`src/oida/protocols/modbus/import_maps.py` / `convert_maps.py`** - near-duplicate standalone import tools parsing the same nymea/Solarman formats; neither imported anywhere; duplicated type-mapping tables. *Fix:* consolidate into convert_maps.py (fold in mbmd parser), delete import_maps.py.
- **`src/oida/protocols/modbus/scanner_mixins/reporting.py:22`** - _decode_register_values has no production caller; real decoding goes through _build_decode_*_rows. Underscore-private so the unit test only covers dead code. *Fix:* delete it and its test, or wire it into the reporting path.
- **`src/oida/protocols/mqtt/scanner.py:601`** - self.sparkplug_nodes assigned in __init__, zero readers; Sparkplug data is returned via results["sparkplug"]. *Fix:* delete the line.
- **`src/oida/protocols/profinet/gsdml_parser.py:182-192`** - nested find/findall namespace-aware helpers never called; parser uses root.iter()+substring matching. NS dict at line 28 is only used by these. *Fix:* delete the helpers (and NS dict), or actually use them.
- **`src/oida/protocols/tase2/mixins/info_messages.py:361,212`** - _analyze_im_security (test-only, duplicates security.py block-4 logic) and get_im_transfer_attributes (no CLI flag, no dispatch) are unreachable in production. *Fix:* wire in or delete.
- **`src/oida/protocols/tase2/mixins/security.py:47-49,89,110,135,180,187`** - _analyze_security reads keys the scanner never sets (tls_enabled, certificate_info, access_violation_event, check_back_ids, block11/12, ts.critical), making whole branches permanently unreachable. *Fix:* drop the dead branches or collect the underlying data.
- **`src/oida/pcap/dns.py:404-425,514-546`** - all_fields plumbed into 7 _parse_*_records methods; only _parse_a_records touches it, in a dead loop (543-546) whose body is just `continue`. *Fix:* delete the loop, drop the param from all 7 signatures, remove the get_all_fields(dns) call.
- **`src/oida/pcap/dicom.py:207,432,515`** - DICOMAssociation.impl_class_uid written but never read; get_sessions_summary omits it. *Fix:* add to the summary, or remove the field and writes.
- **`src/oida/pcap/dns.py:21-28,74`** - DNS_TYPE_A..DNS_TYPE_SOA constants + DNS_TYPE_FROM_NAME reverse map unused (code uses DNS_TYPE_NAMES). *Fix:* delete.
- **`src/oida/pcap/ethercat.py:130,245,264`** - WRITE_COMMANDS, MAILBOX_TYPE_NAMES, COE_TYPE_NAMES dicts never read (component int constants are used). *Fix:* delete the three.
- **`src/oida/pcap/epl.py:532`** - get_nodes_summary has zero callers and is not in the hasattr-dispatch set. *Fix:* remove, or wire into EPL harvest/test path.
- **`src/oida/pcap/interactions.py`** - whole module is a dead backward-compat re-export shim; zero importers after the pcap/passive flatten. *Fix:* delete; import ProtocolInteraction from .pyshark_base directly.
- **`src/oida/pcap/hl7.py:126`** - HL7_SEGMENTS 24-entry dict never read (PHI_SEGMENTS is used). *Fix:* remove, or wire into segment naming.
- **`src/oida/pcap/hsr.py:70,81`** - HSR_TLV_TYPES and HSR_NODE_TYPES never read; node typing uses literal strings. *Fix:* delete or use.
- **`src/oida/pcap/hartip.py:215`** - MSG_TYPE_NAMES dict never read (MSG_ID_NAMES/DEVICE_STATUS_FLAGS are used). *Fix:* remove or use.
- **`src/oida/pcap/ipsec.py:141`** - self.crypto_proposals init'd, never written or read. *Fix:* delete.
- **`src/oida/pcap/kerberos.py:163,261`** - self._seen_errors (dedup done via error_counts) and _parse_etype (live code uses _has_crackable_etype) both unused. *Fix:* delete both.
- **`src/oida/pcap/ldap.py:226,114`** - self._client_stats has no accessor/readers (asymmetric to _server_stats); _T1_FIELDS coverage manifest tuple references a nonexistent audit tool. *Fix:* delete both.
- **`src/oida/pcap/lldp.py:112,118,128`** - _MGN_ADDR_FIELDS, _IEEE_802_3_FIELDS, _IEEE_802_1_FIELDS tshark-field manifest tuples never iterated; extraction uses hardcoded names. (_ENABLED_CAP_FIELDS etc. are live.) *Fix:* delete the three.
- **`src/oida/pcap/mssql.py:1268`** - `elif buf.startswith("6082") or buf.startswith("6082")` tests the same prefix twice; the second operand (likely 6182/6e82 SPNEGO/Kerberos) was never changed, so some Kerberos SSPI buffers are misclassified. *Fix:* use the intended second prefix, or drop the redundant OR.
- **`src/oida/pcap/opcda.py:722-726`** - inner loop over self.interactions computes nothing and only breaks ("Already covered by normal flow"); also O(sessions*interactions). *Fix:* delete the loop.
- **`src/oida/pcap/profinet.py:251-253,1486,1491,1492`** - IMRecord.profile_specific_type/im_version_major/im_version_minor assigned but never read; _im_record_to_dict omits them. *Fix:* add to serializer, or delete fields + parsing.
- **`src/oida/pcap/sip.py:687,695`** - get_active_calls/get_completed_calls have zero callers and are not hasattr-dispatched. *Fix:* delete, or wire into get_calls_summary.
- **`src/oida/pcap/rmi.py:104`** - self.protocol_versions init'd once, never populated or read (and is a listener attr, not serialized). *Fix:* delete the line.
- **`src/oida/pcap/smb.py:797`** - _parse_ntlmssp_field superseded by _parse_ntlmssp_layer (called at :745); zero callers. *Fix:* delete.
- **`src/oida/pcap/synchrophasor.py:116,136,148,230`** - _TIME_QUALITY, _PMU_TIME_QUALITY, _UNLOCK_TIME, _DEFAULT_PORTS never read. *Fix:* delete, or wire the time-quality maps into _process_data_frame.
- **`src/oida/pcap/synchrophasor.py:875`** - get_pmu_summary has zero callers and is not reflectively dispatched. *Fix:* remove or add a caller/test.
- **`src/oida/fuzz/core/connections/raw_socket.py:127-138` / `scapy.py:146-155`** - set_timeout/get_max_send/get_max_recv mimic a non-existent boofuzz ITargetConnection contract (verified: only open/close/send/recv/info exist); zero callers. *Fix:* remove from both classes.
- **`src/oida/fuzz/core/base_fuzzer.py:1396-1438`** - enable/disable_invalid_state_testing + force_invalid_state_transition trio has no callers (only docstring mentions). *Fix:* wire into a CLI flag/test, or drop the trio.
- **`src/oida/fuzz/core/codecs/asn1.py:397-417`** - build_context_specific `explicit` param is inert: the if/else branches are byte-for-byte identical and `constructed or explicit` (explicit always True for all callers) silently ignores the caller's `constructed`. *Fix:* drop the param + duplicated branch; build the tag from `constructed` alone.
- **`src/oida/fuzz/core/database/mock.py:106-136`** - MockDatabase add_test_case/get_test_case_steps/get_test_case_info not in DatabaseInterface and never called. *Fix:* delete the three.
- **`src/oida/fuzz/core/database/orm.py:574,634,747`** - SQLAlchemyDatabase search_test_cases/cleanup_old_data/get_crash_events are public but not in the abstract interface and have zero callers. *Fix:* remove, or add a test/caller.
- **`src/oida/fuzz/core/session/test_case.py`** - entire test-case-registry module (ProtocolFeature/HTTPFeature/TCPFeature/TestCaseDefinition/TestCaseRegistry) is imported only as a re-export; zero functional consumers; no test. *Fix:* delete the file + the session/__init__.py imports, or add a consumer.
- **`src/oida/fuzz/primitives/reduced_string.py:145-233`** - per-protocol payload registry writes _instance_fuzz_library, but boofuzz reads the class attr _fuzz_library, so registered payloads never affect mutations; protocol_name param + register/list/clear subsystem is wired to nothing. *Fix:* override mutations() to use it, or remove the registry.
- **`src/oida/fuzz/primitives/transformers/authentication.py:328-374`** - JWTTransformer.verify() (~45 lines) has no callers and no tests. *Fix:* remove unless a round-trip-validation consumer is added.
- **`src/oida/fuzz/primitives/asn1_blocks.py:207,345,455,508,626`** - five self.X attrs (_mutation_index, _context_tag, _bytes_value, _unused_bits, _string_value) written but never read. *Fix:* delete the five assignments.
- **`src/oida/fuzz/primitives/delimited.py:1-2553`** - whole 2553-line delimited/HL7 builder module is unused by any production fuzzer (the HL7 fuzzer uses a separate builder); only re-export + one test reach it. *Fix:* route the HL7 fuzzer through it, or remove the duplicate subsystem.
- **`src/oida/fuzz/protocols/bacnet.py:222,238,248`** - _create_bvlc_header/_create_npdu_unicast/_create_npdu_broadcast never called; Request defs build BVLC/NPDU inline. *Fix:* delete, or refactor inline blocks to call them.
- **`src/oida/fuzz/protocols/dns.py:2835`** - get_fuzzing_targets is dead doc-only; get_request_definitions() already serves --list-requests. *Fix:* delete get_fuzzing_targets.
- **`src/oida/fuzz/protocols/coap.py:109`** - self.protocol_name set but never read (framework keys off class-level PROTOCOL_NAME). *Fix:* remove the assignment.
- **`src/oida/fuzz/protocols/modbus/pdu.py:614`** - create_invalid_fc_pdu never imported/called; duplicates inline INVALID_FUNCTION_CODES usage. *Fix:* delete lines 614-622.
- **`src/oida/fuzz/protocols/mms.py:314,1658`** - self.request_sequence written twice, never read. *Fix:* remove both assignments.
- **`src/oida/fuzz/protocols/mqtt.py:1165`** - _encode_remaining_length hand-rolled encoder with zero callers (packets use boofuzz Size/Static). *Fix:* delete.
- **`src/oida/fuzz/protocols/mqtt.py:232,248`** - store_publish_response/get_mqtt_state_info ("State Machine V2") never wired up; contrast store_connack_response which IS called. *Fix:* delete, or wire store_publish_response into QoS1/QoS2 handling.
- **`src/oida/utils/fuzzer.py:176,20`** - bare expression `len(original) if original else 4` is a no-op statement (dropped assignment); HAS_RADAMSA flag never read. *Fix:* remove the bare line (or assign orig_len); delete HAS_RADAMSA.
- **`src/oida/utils/cli.py:108,139`** - MockCLI.eprint (zero callers) and MockCLI.report (empty body, unused params) are vestigial msf-style stubs. *Fix:* delete both.
- **`src/oida/utils/protocol_registry.py:15,88-93`** - _protocol_registry global populated for ~26 protocols but never read; the live path is scanner_class._protocol_metadata (line 84). *Fix:* delete the global and the population block.
- **`src/oida/utils/vendor_maps.py:7404,7955`** - OUI_DICT vendor map and lookup_s7_module() have zero consumers (lookup_s7_series IS used). *Fix:* remove, or wire into a MAC-vendor / MLFB lookup.
- **`src/oida/utils/protocol_helpers.py:310,333,350`** - SecurityAnalyzer analyze_authentication/analyze_encryption/check_default_credentials never called (only assess_protocol_security is). *Fix:* delete the three.
- **`src/oida/shared/glbp_constants.py:7-20,3`** - 7 GLBP constants never imported (only VG_STATES/VF_STATES/AUTH_TYPES are); module docstring claims a non-existent second consumer protocols/discovery/glbp.py. *Fix:* delete the 7 constants; correct the docstring.
- **`src/oida/shared/ospf_constants.py:28-34`** - OSPF_NETWORK_TYPES has zero references (other OSPF constants are live). *Fix:* delete.
- **`src/oida/cli.py:488`** - parser._subparsers_map = {} set, never read; the real handle is parser._subparsers_action. *Fix:* delete the line + its comment.
- **`src/oida/connection.py:60,307`** - self.hostname assigned, never read (logger hostname populated independently); login() default no-op never called or overridden by any subclass. *Fix:* remove self.hostname; remove login() and its docstring line.

## LOW - calibration / cleanup

### dead-code / dead-write (unused constants, fields, helpers)
Representative, not exhaustive:
- **`src/oida/protocols/can/uds.py:666`** uds_tester_present_keepalive - no production caller.
- **`src/oida/protocols/can/constants.py:18-85,408,786`** unused CANopen/CAN reference constants incl. self-documented duplicate block at 694-708.
- **`src/oida/protocols/coap/helpers.py:340-405`** coap_put_blockwise - zero callers; **`coap/constants.py:116`** WRITE_METHODS never read.
- **`src/oida/protocols/dicom/mixins/cfind.py:320,324`** total_count counted but never read.
- **`src/oida/protocols/ethernetip/cip_definitions.py:378-389`** five unused CIP_STATUS_* (incl. duplicate STATE_CONFLICT); **`proto_args.py:40-45`** --list-identity flag is a no-op.
- **`src/oida/protocols/ethercat/__init__.py:758`** unused read_size unpack; **`coe_ops.py:163`** discarded val_str.
- **`src/oida/protocols/hart/scanner.py:110-113`** unused PhysicalSignaling constants; **`iec104/constants.py:45,66,238`** ASDU_VSQ_OFFSET/VSQ_COUNT_MASK/IOA_MAX.
- **`src/oida/protocols/knx/helpers.py:94-103,131,134,156,159` / `ets.py:578,582`** dead dict entries, over-broad tuple return, unused loop keys.
- **`src/oida/protocols/modbus/decoder.py:1027-1077`** unused decode_*/encode_* convenience wrappers; **`scanner_mixins/discovery.py:142`** always-false getattr clause in verbose_fc.
- **`src/oida/protocols/mqtt/mixins/messaging.py:41`** retained_count never surfaced; **`profinet/models.py:31`** epm_annotation never produced; **`tase2/scanner.py:234`** device_tags never populated.
- **`src/oida/pcap/`** wide family of defined-never-read module constants: cdp.py:47, coap.py:191, cotp.py:102, c1222.py:86, can.py:76+88, ajp.py:50-51, epl.py:131, ff_hse.py:71, dtp.py:48, ipmi.py:66, j1939.py:145, knx.py:131+149, ldap.py:101 (STARTTLS_OID also holds the *wrong* OID), lontalk.py:184, mdns.py:42-43, mssql.py:66-77+114, opcua.py:201-206, ntp.py:55-59, ntlm.py:31, pjl.py:57+72, ptp.py:97+100, redis.py:43-44+79, rtsp.py:63, smartinstall.py:57, smb.py:25, rip.py:79-80, vnc.py:30-37, vrrp.py:90-110, vtp.py:70+91, wsdiscovery.py:56, x11.py:129, eigrp.py:135-158/fins.py:224-237/ftp.py:43-46 (dead credential @property aliases).
- **`src/oida/pcap/`** write-only state/counters: pgsql.py:134+728+1266, ptp.py:203+337, stp.py:125+235, sv.py:133+139-141, mongodb.py:213, mssql.py:274, ff_hse.py:231, irc.py:51+183.
- **`src/oida/pcap/`** orphaned summary accessors: lontalk.py:594+609, ptp.py:717, tftp.py:453, devicenet.py:503/ethercat.py:1445/ff_hse.py:600 (untested get_sessions_summary copies).
- **`src/oida/fuzz/`** core/database/models.py:423-425 type aliases; connections/tcp.py:489-492 reconnect_count; mutation/__init__.py:31-42 get_mutator + prefer_native; mutation/radamsa.py:18-134 production-dead RadamsaMutator; session/test_case.py:14 _log; protocols/ads.py:53+, ethernet.py:58-61, hl7.py:61, modbus/constants.py:47-48 unused constants; primitives/transformers/__init__.py + radamsa_primitives.py + smart_string.py:596 test-only exports.
- **`src/oida/`** core: connection.py:174+398+458, loader.py:369+378+409+451, targets.py:23+43+461, protocols/__init__.py:55 unused convenience methods; platform_compat.py:49 IS_POSIX; protocol_helpers.py:136+254 test-only/orphaned helpers.

### defensive-slop / cargo-cult
- **`src/oida/protocols/astm/mixins/framing.py:51-61`** unreachable _calculate_checksum local fallback (test-only).
- **`src/oida/protocols/fhir/helpers.py:126-132`** _get_fhir_validation_error type() fallback guards a corrupt-install edge only.
- **`src/oida/protocols/snap7/device_lookup.py:563-565`** lookup_device_name space/dash variant loop can never match any key.
- **`src/oida/utils/exceptions.py:48-101`** seven exception subclasses re-declare an identical forwarding __init__.

### fluff (cosmetic)
- Duplicated `devices = listener.scan()` docstring lines: discovery/igmp.py:64-65, pcap/dns.py:95-96, ftp.py:74-75, glbp.py:73-74, igmp.py:69-70, telnet.py:154-155.
- Garbled debug messages that echo the guarded source line: hl7/segments.py:1400, pcap/ads.py:528 (pattern recurs across pcap/fins/enip/ntlm/modbus/s7comm), fuzz raw_socket.py:122.
- Stale docstrings: mms/fingerprint.py:99-107 (2-arg API drift), discovery/stats.py:47-48 (tuple value that does not exist).
- Commented-out dead extraction: pcap/amqp.py:274-275. Redundant comment: fuzz/utils/__init__.py:7. Misplaced shebang below code: protocols/__init__.py:1-6.

## Coverage & skips
- 582 files reviewed across 58 clusters; failed clusters (re-run needed): none.

## Calibration notes
Several patterns that look dead are live via indirection and were weighted down: pcap listener summary methods (get_credentials_summary/get_write_operations/get_control_operations) are reflectively hasattr-dispatched by pyshark_base/scanner, and credential @property aliases on some listeners (irc/radius/vrrp) are read via getattr in the scanner credential loop - so only the copies with *no* such consumer are flagged. Fuzzer protocol methods (get_request_definitions, _length_to_bytes Size override, store_connack_response) are framework-dispatched and legitimate; only their unwired siblings are flagged. NXC "log and continue" error handling and field-adding exception subclasses are intentional and not counted. Many flagged constants live in protocol reference tables, which calibration treats leniently - hence the LOW grading despite zero readers.
