# Fuzzer test audit

Systematic review of every fuzzer test (98 files, ~2390 test functions) for
bugs that make a test "not work" -- i.e. pass or skip without actually
exercising the fuzzer: vacuous asserts, silent skips, over-mocking, dropped
assertions, and module-identity crossings.

Baseline (this environment, all extras installed, no tshark/docker/MMS-mock):
the fuzz unit suite is green; the only skips are environmental
(tshark: 86, MMS mock server: 7).

## Findings and fixes

### F1 (systemic) -- `from src.oida...` double-imports the package
37 fuzz test files imported the code under test as `src.oida.*` instead of
`oida.*`. Python treats `src.oida.fuzz.X` and `oida.fuzz.X` as *distinct
module objects with distinct class identities* even though they load the same
source file. Consequences: `isinstance()` / registry / enum-identity checks
silently mismatch, and -- most dangerously -- any `patch("oida...")` /
`monkeypatch.setattr(oida.X, ...)` becomes a no-op against code imported via
`src.oida`, so the test passes without the patch taking effect. Each file was
internally consistent today (so not yet visibly broken), but it is a
vacuous-pass footgun the moment a bare-`oida.` patch target is added.
Fixed: rewrote `from src.oida` / `import src.oida` / `patch("src.oida...")`
to `oida.*` across all fuzz tests so they exercise the same module tree as
production. `test_smtp_starttls_deferred.py` is now actually correct: it
patched `src.oida...BaseFuzzer.fuzz_all` while building the fuzzer from
`src.oida` -- consistent by luck; now both are `oida`.

### F2 -- MMS graceful-degradation tests asserted nothing
`test_mms_fuzzer_integration.py` (unit + integration copies)
`test_fuzzer_handles_server_disconnect` / `test_fuzzer_handles_timeout` mocked
a failing connect, called `_define_state_machine()`, and had only a comment
where the assertion should be. They passed as long as nothing raised.
Fixed: assert the documented contract -- on handshake failure the connection
flags stay `False` and the state machine is still built so fuzzing can run.

### F3 -- `test_ber_encoding_imports` imported nothing
`test_mms_fuzzer.py::test_ber_encoding_imports` had a body of a single comment
("Should not raise ImportError") with no import statement -- it validated
nothing. Fixed: import the four BER helpers the MMS fuzzer depends on and
assert their concrete DER byte shapes (length short/long form, INTEGER,
VisibleString, context tag primitive vs constructed).

### F4 -- dropped assertion in `test_read_request_uses_valid_asn1`
The short-form-length branch computed `len(result) - 2` as a bare expression
statement (no assert) -- the length-field check had been dropped. Fixed:
assert the declared BER length matches the actual content length for both
short and long form.

### F5 -- `test_empty_data_handling` did not check the round-trip
It encoded/decoded empty data through every transformer but discarded the
result ("should not raise"). Fixed: assert each transformer round-trips empty
input back to `b""`, catching silent corruption, not just exceptions.

## Areas verified solid (no change needed)
- Request-gating tests (coap/dns/ntp/ethernetip/http2/icmpv6/ipv6/vnc,
  cip-write-gate): 45 tests, all run (no skips), and structurally assert that
  every advertised request is gated by `is_request_enabled` -- these protect
  against the fuzzer sending dangerous traffic without a flag.
- Balance / coverage / state-coverage (`test_fuzzer_balance`,
  `test_fuzzer_coverage`, `test_state_coverage`): 380 tests, no
  protocol-availability skips in a full-extras env; the `not available` skips
  only fire when an optional dep is genuinely missing.
- Mock assertions: all `assert_*` calls are real method names and are actually
  invoked (no `.assert_called` no-op-as-statement, no misspelled matchers).
- Credential-leak guard (root conftest) attaches to the root logger and forces
  propagation, so it still catches leaks from `src.oida`-loaded code.

## Per-file tracking

| File | Tests | Notes |
|---|---:|---|
| `coverage/fuzz/test_cve_replication.py` | 1 |  |
| `integration/fuzz/test_cli_deep.py` | 16 |  |
| `integration/fuzz/test_crash_detection.py` | 4 |  |
| `integration/fuzz/test_crash_detection_real.py` | 3 |  |
| `integration/fuzz/test_database_perf.py` | 12 |  |
| `integration/fuzz/test_definition_execution.py` | 5 |  |
| `integration/fuzz/test_docker_modbus.py` | 30 |  |
| `integration/fuzz/test_fuzzer_execution.py` | 3 |  |
| `integration/fuzz/test_http_custom_headers.py` | 24 |  |
| `integration/fuzz/test_mms_cli_integration.py` | 27 |  |
| `integration/fuzz/test_mms_fuzzer_integration.py` | 33 |  |
| `integration/fuzz/test_monitor_agent.py` | 6 |  |
| `integration/fuzz/test_monitor_baseline.py` | 5 |  |
| `integration/fuzz/test_replay.py` | 13 |  |
| `integration/fuzz/test_state_machine_real.py` | 47 |  |
| `integration/fuzz/test_state_traversal.py` | 49 |  |
| `unit/ethernetip/test_fuzz_mixin.py` | 17 |  |
| `unit/fuzz/test_ads_fuzzer_ams_ports.py` | 4 | src.oida->oida |
| `unit/fuzz/test_agent_monitor.py` | 17 |  |
| `unit/fuzz/test_application.py` | 36 |  |
| `unit/fuzz/test_asn1_blocks_encoding.py` | 37 | src.oida->oida |
| `unit/fuzz/test_asn1_blocks_render.py` | 4 | src.oida->oida |
| `unit/fuzz/test_asn1_primitives.py` | 81 | src.oida->oida |
| `unit/fuzz/test_auth.py` | 30 | src.oida->oida |
| `unit/fuzz/test_calibration.py` | 21 | src.oida->oida |
| `unit/fuzz/test_coap_request_gating.py` | 5 |  |
| `unit/fuzz/test_config_extended.py` | 31 | src.oida->oida |
| `unit/fuzz/test_connections.py` | 45 | src.oida->oida |
| `unit/fuzz/test_core_abstractions.py` | 9 |  |
| `unit/fuzz/test_critical_features.py` | 13 |  |
| `unit/fuzz/test_crypto_state.py` | 38 | src.oida->oida |
| `unit/fuzz/test_database_orm.py` | 22 | src.oida->oida |
| `unit/fuzz/test_dhcp_fuzzer.py` | 8 |  |
| `unit/fuzz/test_dnp3_fuzzer.py` | 76 |  |
| `unit/fuzz/test_dns_request_gating.py` | 4 |  |
| `unit/fuzz/test_ethernetip_quick_cip_write_gate.py` | 3 |  |
| `unit/fuzz/test_ethernetip_request_gating.py` | 4 |  |
| `unit/fuzz/test_ftp_fuzzer.py` | 70 |  |
| `unit/fuzz/test_fuzz_cli.py` | 25 |  |
| `unit/fuzz/test_fuzz_cli_dispatch.py` | 40 |  |
| `unit/fuzz/test_fuzzer_balance.py` | 8 |  |
| `unit/fuzz/test_fuzzer_benchmark.py` | 9 |  |
| `unit/fuzz/test_fuzzer_coverage.py` | 11 |  |
| `unit/fuzz/test_fuzzer_definitions.py` | 1 |  |
| `unit/fuzz/test_fuzzer_execution.py` | 3 |  |
| `unit/fuzz/test_hl7_monitor_recv_cap.py` | 2 |  |
| `unit/fuzz/test_hpack_primitives.py` | 27 |  |
| `unit/fuzz/test_http2_request_gating.py` | 4 |  |
| `unit/fuzz/test_http_custom_headers.py` | 24 |  |
| `unit/fuzz/test_http_enumeration.py` | 13 |  |
| `unit/fuzz/test_icmpv6_request_gating.py` | 4 |  |
| `unit/fuzz/test_iec104_fuzzer.py` | 60 | src.oida->oida |
| `unit/fuzz/test_ipv6_request_gating.py` | 4 |  |
| `unit/fuzz/test_mms_fuzzer.py` | 69 | src.oida->oida |
| `unit/fuzz/test_mms_fuzzer_integration.py` | 33 |  |
| `unit/fuzz/test_modbus_critical_features.py` | 26 |  |
| `unit/fuzz/test_modbus_fuzzer_balance.py` | 25 |  |
| `unit/fuzz/test_modbus_rtu_fuzzer.py` | 61 |  |
| `unit/fuzz/test_modbus_tcp_fuzzer_coverage.py` | 45 |  |
| `unit/fuzz/test_modbus_tcp_unit_id_wiring.py` | 5 |  |
| `unit/fuzz/test_monitor_restart_script_validcase.py` | 34 |  |
| `unit/fuzz/test_monitors.py` | 52 |  |
| `unit/fuzz/test_monitors_impl.py` | 54 | src.oida->oida |
| `unit/fuzz/test_mutation_config.py` | 18 | src.oida->oida |
| `unit/fuzz/test_mutation_engine.py` | 9 | src.oida->oida |
| `unit/fuzz/test_ntp_request_gating.py` | 5 |  |
| `unit/fuzz/test_opcua_fuzzer_audit.py` | 65 |  |
| `unit/fuzz/test_opcua_session_lifecycle.py` | 2 |  |
| `unit/fuzz/test_primitive_types.py` | 5 |  |
| `unit/fuzz/test_protocol_define.py` | 7 |  |
| `unit/fuzz/test_protocol_initialization.py` | 11 |  |
| `unit/fuzz/test_radamsa_native.py` | 70 | src.oida->oida |
| `unit/fuzz/test_radamsa_primitives.py` | 31 | src.oida->oida |
| `unit/fuzz/test_reduced_string.py` | 32 |  |
| `unit/fuzz/test_replay_complex_states.py` | 42 | src.oida->oida |
| `unit/fuzz/test_sequence_manager.py` | 24 | src.oida->oida |
| `unit/fuzz/test_session_commands.py` | 10 | src.oida->oida |
| `unit/fuzz/test_session_final_flush_crash_preserve.py` | 3 | src.oida->oida |
| `unit/fuzz/test_smart_string.py` | 58 |  |
| `unit/fuzz/test_smtp_starttls_deferred.py` | 3 | src.oida->oida |
| `unit/fuzz/test_snmp_fuzzer.py` | 56 | src.oida->oida |
| `unit/fuzz/test_state_context.py` | 53 | src.oida->oida |
| `unit/fuzz/test_state_coverage.py` | 22 |  |
| `unit/fuzz/test_state_machine.py` | 71 | src.oida->oida |
| `unit/fuzz/test_state_machine_reachability.py` | 23 |  |
| `unit/fuzz/test_stateful_connection.py` | 19 | src.oida->oida |
| `unit/fuzz/test_stateful_fuzzer.py` | 20 | src.oida->oida |
| `unit/fuzz/test_transformers.py` | 114 | src.oida->oida |
| `unit/fuzz/test_tshark_validation.py` | 5 |  |
| `unit/fuzz/test_vnc_request_gating.py` | 8 |  |
| `unit/hl7/test_fuzz_mixin.py` | 7 |  |
| `unit/iec104/test_fuzz_commands_send.py` | 1 |  |
| `unit/modbus/test_fuzz_mixin.py` | 24 |  |
| `unit/opcua/test_fuzz_anomaly_compare.py` | 4 |  |
| `unit/opcua/test_fuzz_mixin.py` | 23 |  |
| `unit/opcua/test_fuzz_restore.py` | 1 |  |
| `unit/profinet/test_fuzz_mixin.py` | 16 |  |
| `unit/utils/test_fuzzer.py` | 36 |  |

**Total: 98 files, 2390 test functions.**
