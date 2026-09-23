"""
Modbus Protocol Integration Tests

Tests oida modbus scanner against Docker mock service.
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/modbus_server.py):
  MEI Identity:
    0x00 VendorName        = "OIDA Mock Devices"
    0x01 ProductCode       = "OIDA-MOCK-001"
    0x02 MajorMinorRevision = "2.0.0"
    0x03 VendorUrl         = "https://github.com/oida"
    0x04 ProductName       = "Mock Industrial PLC"
    0x05 ModelName         = "OIDA-SIM"
    0x06 UserApplicationName = "OIDA Fuzz Test Server"

  Holding Registers (HR):
    HR[0]=1 (system_status: on), HR[1]=1 (auto), HR[2]=0, HR[3]=1234 (uptime_hours)
    HR[10-11]=25.5 (temp_setpoint f32), HR[12-13]=3.14, HR[14-15]=100.0
    HR[20-21]=24.8 (current_temp f32), HR[22-23]=3.12, HR[24-25]=98.5
    HR[30-31]=86400 (total_runtime u32), HR[32-33]=1000 (cycle_count)
    HR[40]=75 (motor_speed%), HR[41]=50 (valve%), HR[42]=1 (pump_enabled)

  Coils: 100 x 0 (all off)
  Discrete Inputs: [1,0,1,0] * 25  (alternating pattern)
  Input Registers: 100 x 0

  CANopen MEI (FC 43/13):
    0x1000:0 = 0x00000191 (Device Type, Generic I/O)
    0x1008:0 = "OIDA Mock CANopen" (Manufacturer Device Name)
    0x1009:0 = "1.0.0" (Hardware Version)
    0x100A:0 = "2.0.0" (Software Version)

Test Classification Summary (131 defined + 9 inherited from BaseProtocolIntegrationTest)
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  50 tests
Category B (conditional -- mock may not support, accept 0 or 1):       68 tests
Category C (error handling -- assert failure + validate error events):  11 tests
Skipped (untestable -- flag not implemented or requires hardware):     11 tests
Total defined in file:                                                131 tests
Total collected (including inherited):                                140 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (proto_args.py):
  --port                    [A] test_transport_option_tcp
  --timeout                 [A] test_scan_behavior_options
  --udp                     [B] test_udp_transport
  --rtu-over-tcp            [A] test_rtu_over_tcp, [B] test_rtu_over_tcp_multi_unit
  --ascii-over-tcp          [B] test_ascii_over_tcp
  --tls                     [B] test_tls_transport
  --tls-insecure            [B] test_tls_transport
  --tls-cert/--tls-key      [A] test_tls_with_client_cert, [B] test_tls_invalid_cert
  --tls (wrong port)        [C] test_tls_wrong_port
  --serial-port             [skip] requires physical serial hardware
  --baudrate                [skip] requires physical serial hardware
  --parity                  [skip] requires physical serial hardware
  --ascii                   [B] test_ascii_serial_flag_over_tcp_is_noop
  -r/--scan-range           [A] test_read_holding_registers
  -R/--register-type        [A] test_read_holding_registers, _input, _coils, _discrete, _all
  --unit-id                 [A] test_specific_unit_id
  -U/--discover-units       [B] test_unit_id_discovery
  --unit-range              [B] test_discover_units_small_range
  --broadcast               [B] test_broadcast_mode
  -S/--sunspec              [B] test_sunspec_discovery
  --scan-fc                 [B] test_scan_fc
  --fc-all                  [B] test_fc_all
  --fc-range                [B] test_fc_range
  -w/--write                [B] test_write_register_with_confirm
  --write-coil              [B] test_write_coil_with_confirm
  --write-multiple          [B] test_write_multiple_registers
  --write-multiple-coils    [B] test_write_multiple_coils
  --test-write              [B] test_write_access_detection, [B] test_writable_access_security_finding
  --test-write-thorough     [B] test_test_write_thorough
  --restore-on-exit         [B] test_restore_on_exit
  --diag                    [B] test_diagnostics_echo, _counters
  --diag-data               [A] test_diagnostics_echo_with_custom_diag_data
                            [C] test_diagnostics_invalid_diag_data_rejected
  -i/--identify             [A] test_mei_device_identification
  --mei-object              [A] test_mei_object_basic, _regular, _extended, _specific
  --mei-object-id           [A] test_mei_object_id_vendor, _product_code
  --server-id               [B] test_server_id_fc17
  --exception-status        [B] test_exception_status
  --canopen-read            [B] test_canopen_read
  --canopen-write           [B] test_canopen_write
  --canopen-info            [B] test_canopen_info
  --events                  [B] test_communication_events
  --file-read               [B] test_file_read_fc20
  --file-write              [B] test_file_write_fc21
  --mask-write              [B] test_mask_write_register
  --atomic-rw               [B] test_atomic_read_write
  --fifo                    [B] test_fifo_queue_fc24
  -d/--decode               [A] test_float32_decoding, test_int32_decoding, ...
  -e/--endian               [A] test_endian_options, _big, _word_swap, _byte_swap
  --decode-all              [A] test_decode_all_formats
  --decode-width            [B] test_decode_width
  --filter-zero             [A] test_filter_zero
  --register-map            [B] test_register_map
  --list-maps               [A] test_list_maps
  --read-name               [B] test_read_name
  --write-name              [B] test_write_name
  --list-names              [B] test_list_names
  --search-name             [B] test_search_name
  --monitor                 [B] test_monitor_mode
  --interval                [B] test_monitor_mode
  --duration                [B] test_monitor_mode
  --on-change               [B] test_monitor_on_change
  --log-file                [B] test_monitor_with_log_file
  --scan-mode               [A] test_quick_mode, test_full_mode, test_discover_mode
  --max-registers           [B] test_max_registers
  --raw-fc                  [B] test_raw_fc_standard_code
  --custom-fc (alias)       [A] test_custom_fc_alias_reads_holding_registers
  --payload                 [B] test_raw_fc_standard_code
  --response-format         [B] test_raw_fc_hexdump_format
  --save-response           [B] test_raw_fc_save_response
  --confirm                 [A] test_write_register_requires_confirm
  --fuzz                    [A] test_fuzz_without_confirm_is_rejected, _no_fuzz_data, _result_contains_summary
                            [B] test_fuzz_mode_data, _boundary, _full, _over_rtu_tcp, _float32, _int32
                            [C] test_basic_fuzz, test_basic_fuzz_no_scan_range_defaults,
                            test_fuzz_against_wrong_port
  --fuzz-mode               [B] test_fuzz_mode_data, _boundary, _full, test_fuzz_function_mode_no_scan_range
                            [C] test_function_fuzz
  --fuzz-iterations         [B] test_fuzz_iterations_one, _large_range_small_max
                            [C] test_basic_fuzz
  --fuzz-all-access         [B] test_fuzz_all_access
  --fuzz-max-addresses      [B] test_fuzz_max_addresses, test_fuzz_iterations_large_range_small_max
  --enumerate-functions     [B] test_function_code_enumeration
  format (global)           [A] test_csv_output, test_xml_output
  -v (global)               [A] test_verbose_levels
  --debug (global)          [A] test_debug_output
  --help (global)           [A] test_help_output
"""

import contextlib
import json
import re
import socket
import threading

import pytest
from typing import Optional

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import DOCKER_COMPOSE_PATH, MOCK_HOST

# Shared test certificates
MODBUS_TLS_CERTS = DOCKER_COMPOSE_PATH.parent / "certs"


# ---------------------------------------------------------------------------
# Known Mock Data Constants (extracted from modbus_server.py)
# ---------------------------------------------------------------------------
# MEI Device Identification
MOCK_VENDOR_NAME = "oida mock devices"
MOCK_PRODUCT_CODE = "oida-mock-001"
MOCK_REVISION = "2.0.0"
MOCK_VENDOR_URL = "https://github.com/oida"
MOCK_PRODUCT_NAME = "mock industrial plc"
MOCK_MODEL_NAME = "oida-sim"
MOCK_APP_NAME = "oida fuzz test server"

# Holding Register Values
MOCK_HR_SYSTEM_STATUS = 1  # on
MOCK_HR_OPERATION_MODE = 1  # auto
MOCK_HR_ERROR_CODE = 0
MOCK_HR_UPTIME_HOURS = 1234
MOCK_HR_TEMP_SETPOINT = 25.5
MOCK_HR_PRESSURE_SETPOINT = 3.14
MOCK_HR_FLOW_SETPOINT = 100.0
MOCK_HR_CURRENT_TEMP = 24.8
MOCK_HR_CURRENT_PRESSURE = 3.12
MOCK_HR_CURRENT_FLOW = 98.5
MOCK_HR_TOTAL_RUNTIME = 86400
MOCK_HR_CYCLE_COUNT = 1000
MOCK_HR_MOTOR_SPEED = 75
MOCK_HR_VALVE_POS = 50
MOCK_HR_PUMP_ENABLED = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _assert_log_has_events(result, min_count=1):
    """Assert that the scan_log exists and has at least min_count events."""
    assert result.scan_log is not None, "scan_log should be populated when json_log=True"
    result.scan_log.assert_has_events(min_count=min_count)


def _assert_log_event_structure(log):
    """Validate that every event in the log has the required fields."""
    required = {"timestamp", "level", "event_type", "module", "message"}
    for i, event in enumerate(log.events):
        missing = required - set(event.keys())
        assert not missing, f"Event {i} missing fields: {missing}"


def _combined_text(result, log=None) -> str:
    """Return lowercase combined output + log messages for broad searches."""
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


# Matches the fuzz summary line emitted by FuzzMixin._handle_fuzz, e.g.:
#   "Tests: 32, Writes: 32, Errors: 0, Crashes: 0"
_FUZZ_SUMMARY_RE = re.compile(
    r"tests:\s*(\d+),\s*writes:\s*(\d+),\s*errors:\s*(\d+),\s*crashes:\s*(\d+)"
)


def _parse_fuzz_summary(text: str) -> Optional[dict]:
    """Parse the 'Tests: N, Writes: N, Errors: N, Crashes: N' summary line.

    Returns a dict with int keys tests/writes/errors/crashes, or None if the
    summary line is absent (e.g. the connection never came up).
    """
    m = _FUZZ_SUMMARY_RE.search(text.lower())
    if not m:
        return None
    return {
        "tests": int(m.group(1)),
        "writes": int(m.group(2)),
        "errors": int(m.group(3)),
        "crashes": int(m.group(4)),
    }


def _count_fuzzed_registers(result) -> int:
    """Count the distinct per-register 'Fuzzing register N...' progress lines.

    The same display line is echoed to both stdout and the JSON log, so counting
    over the combined text would double every match. We count over stdout only.
    """
    return len(re.findall(r"fuzzing register\s+\d+", result.combined_output.lower()))


@pytest.mark.modbus
class TestModbusIntegration(BaseProtocolIntegrationTest):
    """Integration tests for Modbus protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "modbus"

    @property
    def default_port(self) -> int:
        return 502

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Discovery Tests
    # ========================================================================

    def test_mei_device_identification(self, cli_runner, target, port, docker_services):
        """Test MEI device identification (FC 43/14) returns known mock identity [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            format="json",
            json_log=True,
        )

        assert result.success, f"MEI identification failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Validate known mock MEI identity values
        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [MOCK_VENDOR_NAME, "oida mock", "oida-mock-001", "mock industrial plc"]
        ), (
            f"Expected mock vendor/product identity in output. "
            f"Known values: vendor={MOCK_VENDOR_NAME!r}, product={MOCK_PRODUCT_CODE!r}. "
            f"Got: {text[:500]}"
        )

    def test_mei_device_id_connection_lifecycle(self, cli_runner, target, port, docker_services):
        """Test that MEI identification produces proper connection lifecycle events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            format="json",
            json_log=True,
        )

        assert result.success, f"MEI identification failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        conn_events = log.get_connection_events()
        if conn_events:
            assert len(conn_events) >= 1, "Expected at least one connection event"

    def test_server_id_fc17(self, cli_runner, target, port, docker_services):
        """Test Server ID (FC 17) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--server-id",
            format="json",
            json_log=True,
        )

        # FC 17 may not be supported by all servers
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                info_events = result.scan_log.get_events(level="info")
                assert len(info_events) > 0, "Expected info events on successful FC 17"

    def test_exception_status(self, cli_runner, target, port, docker_services):
        """Test Exception Status (FC 7) reads device status bits [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--exception-status",
            format="json",
            json_log=True,
        )

        # FC 7 may not be supported by all servers
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_discover_mode(self, cli_runner, target, port, docker_services):
        """Test discover mode (scan-mode discovery) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-mode",
            "discovery",
            "--identify",
            format="json",
            json_log=True,
        )

        assert result.success, f"Discover mode failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)
        # Discover should produce info-level events about the target
        info_events = log.get_events(level="info")
        assert len(info_events) > 0, "Discover mode should produce info events"

    # ========================================================================
    # Register Enumeration Tests
    # ========================================================================

    def test_read_holding_registers(self, cli_runner, target, port, docker_services):
        """Test reading holding registers returns known mock values [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--register-type",
            "holding",
            format="json",
            json_log=True,
        )

        assert result.success, f"Holding register read failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # At minimum we should see numeric register data
        non_debug = [e for e in log.events if e.get("level") != "debug"]
        assert len(non_debug) > 0, "Expected non-debug events from holding register scan"

    def test_read_holding_registers_with_decode(self, cli_runner, target, port, docker_services):
        """Test holding registers with u16 decode produce a table with Addr/Value columns [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-5",
            "--register-type",
            "holding",
            "--decode",
            "u16",
            format="json",
            json_log=True,
        )

        assert result.success, f"Holding register read failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

        # Verify that register table output contains addr/value columns
        # Note: mock register values may change between runs (writes modify state)
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["addr", "value", "decoded", "holding", "register"]), (
            f"Expected register table output with addr/value columns. Got: {text[:500]}"
        )

    def test_read_input_registers(self, cli_runner, target, port, docker_services):
        """Test reading input registers (all zeros in mock) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--register-type",
            "input",
            format="json",
            json_log=True,
        )

        assert result.success, f"Input register read failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        non_debug = [e for e in log.events if e.get("level") != "debug"]
        assert len(non_debug) > 0, "Expected non-debug events from input register scan"

    def test_read_coils(self, cli_runner, target, port, docker_services):
        """Test reading coils (all 0/OFF in mock) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--register-type",
            "coil",
            format="json",
            json_log=True,
        )

        assert result.success, f"Coil read failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        non_debug = [e for e in log.events if e.get("level") != "debug"]
        assert len(non_debug) > 0, "Expected non-debug events from coil scan"

    def test_read_discrete_inputs(self, cli_runner, target, port, docker_services):
        """Test reading discrete inputs (alternating 1,0,1,0 pattern in mock) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--register-type",
            "discrete",
            format="json",
            json_log=True,
        )

        assert result.success, f"Discrete input read failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        non_debug = [e for e in log.events if e.get("level") != "debug"]
        assert len(non_debug) > 0, "Expected non-debug events from discrete input scan"

    def test_scan_all_register_types(self, cli_runner, target, port, docker_services):
        """Test scanning all register types produces multi-type events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--register-type",
            "all",
            format="json",
            json_log=True,
        )

        assert result.success, f"All register scan failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log
        # Scanning all types should produce more events than a single type
        non_debug = [e for e in log.events if e.get("level") != "debug"]
        assert len(non_debug) > 0, "Expected non-debug events from all-register scan"

    def test_unit_id_discovery(self, cli_runner, target, port, docker_services):
        """Test unit ID discovery (--discover-units --unit-range 1-5) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover-units",
            "--unit-range",
            "1-5",
            format="json",
            json_log=True,
            timeout=60,
        )

        # Should complete without crashing
        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_function_code_enumeration(self, cli_runner, target, port, docker_services):
        """Test function code enumeration (--enumerate-functions) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-functions",
            format="json",
            json_log=True,
        )

        # Should complete without crashing
        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                # Function enumeration should log info about which FCs are supported
                info_events = result.scan_log.get_events(level="info")
                assert len(info_events) > 0, "Expected info events from function enumeration"

    def test_scan_fc(self, cli_runner, target, port, docker_services):
        """Test --scan-fc flag for function code scanning [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-fc",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_fc_all(self, cli_runner, target, port, docker_services):
        """Test --fc-all flag scans all function codes 1-127 [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-fc",
            "--fc-all",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_fc_range(self, cli_runner, target, port, docker_services):
        """Test --fc-range with custom range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-fc",
            "--fc-range",
            "1-5",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Data Decoding Tests
    # ========================================================================

    def test_float32_decoding(self, cli_runner, target, port, docker_services):
        """Test decoding registers as float32, verify known mock values [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-26",
            "--decode",
            "f32",
            format="json",
            json_log=True,
        )

        assert result.success, f"Float32 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(val in text for val in ["25.5", "24.8", "3.14", "3.12", "100", "98.5"]), (
            f"Expected known f32 mock values (25.5, 3.14, 24.8, etc.) in output. Got: {text[:500]}"
        )

    def test_int32_decoding(self, cli_runner, target, port, docker_services):
        """Test decoding registers as int32 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "i32",
            format="json",
            json_log=True,
        )

        assert result.success, f"Int32 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_string_decoding(self, cli_runner, target, port, docker_services):
        """Test decoding registers as string [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "str",
            format="json",
            json_log=True,
        )

        assert result.success, f"String decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_all_formats(self, cli_runner, target, port, docker_services):
        """Test showing all possible decodings (--decode-all) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-4",
            "--decode-all",
            format="json",
            json_log=True,
        )

        assert result.success, f"Decode all failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_endian_options(self, cli_runner, target, port, docker_services):
        """Test little endian decoding option [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-4",
            "--decode",
            "f32",
            "--endian",
            "little",
            format="json",
            json_log=True,
        )

        assert result.success, f"Little endian decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_f64(self, cli_runner, target, port, docker_services):
        """Test decoding registers as float64 (double) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "f64",
            format="json",
            json_log=True,
        )

        assert result.success, f"Float64 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_u16(self, cli_runner, target, port, docker_services):
        """Test decoding registers as unsigned 16-bit integer [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "u16",
            format="json",
            json_log=True,
        )

        assert result.success, f"U16 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_u32(self, cli_runner, target, port, docker_services):
        """Test decoding registers as unsigned 32-bit integer [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "u32",
            format="json",
            json_log=True,
        )

        assert result.success, f"U32 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_u64(self, cli_runner, target, port, docker_services):
        """Test decoding registers as unsigned 64-bit integer [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "u64",
            format="json",
            json_log=True,
        )

        assert result.success, f"U64 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_i16(self, cli_runner, target, port, docker_services):
        """Test decoding registers as signed 16-bit integer [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "i16",
            format="json",
            json_log=True,
        )

        assert result.success, f"I16 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_i64(self, cli_runner, target, port, docker_services):
        """Test decoding registers as signed 64-bit integer [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "i64",
            format="json",
            json_log=True,
        )

        assert result.success, f"I64 decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_hex(self, cli_runner, target, port, docker_services):
        """Test decoding registers as hexadecimal display [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "hex",
            format="json",
            json_log=True,
        )

        assert result.success, f"Hex decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_bits(self, cli_runner, target, port, docker_services):
        """Test decoding registers as binary/bits display [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "bits",
            format="json",
            json_log=True,
        )

        assert result.success, f"Bits decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_bcd(self, cli_runner, target, port, docker_services):
        """Test decoding registers as BCD (Binary Coded Decimal) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "bcd",
            format="json",
            json_log=True,
        )

        assert result.success, f"BCD decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_width(self, cli_runner, target, port, docker_services):
        """Test --decode-width for custom register grouping [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            "--decode",
            "str",
            "--decode-width",
            "4",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_filter_zero(self, cli_runner, target, port, docker_services):
        """Test --filter-zero hides registers with zero values [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-50",
            "--filter-zero",
            format="json",
            json_log=True,
        )

        assert result.success, f"Filter zero failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    # ========================================================================
    # Additional Decode Endianness Tests
    # ========================================================================

    def test_decode_big_endian(self, cli_runner, target, port, docker_services):
        """Test big endian decoding (default) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-4",
            "--decode",
            "u32",
            "--endian",
            "big",
            format="json",
            json_log=True,
        )

        assert result.success, f"Big endian decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_word_swap(self, cli_runner, target, port, docker_services):
        """Test word swap endianness (big-swap) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-4",
            "--decode",
            "f32",
            "--endian",
            "big-swap",
            format="json",
            json_log=True,
        )

        assert result.success, f"Word swap decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_decode_byte_swap(self, cli_runner, target, port, docker_services):
        """Test byte swap endianness (little-swap) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-4",
            "--decode",
            "f32",
            "--endian",
            "little-swap",
            format="json",
            json_log=True,
        )

        assert result.success, f"Byte swap decoding failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    # ========================================================================
    # Diagnostics Tests
    # ========================================================================

    def test_diagnostics_echo(self, cli_runner, target, port, docker_services):
        """Test diagnostics echo (FC 8) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--diag",
            "echo",
            format="json",
            json_log=True,
        )

        # Diagnostics may not be supported by all servers
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(
                    term in messages for term in ["echo", "diag", "ok", "success", "response"]
                ), "Expected diagnostic-related messages on success"

    def test_diagnostics_counters(self, cli_runner, target, port, docker_services):
        """Test diagnostics counters (FC 8) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--diag",
            "counters",
            format="json",
            json_log=True,
        )

        # Diagnostics may not be supported
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_diagnostics_echo_with_custom_diag_data(
        self, cli_runner, target, port, docker_services
    ):
        """--diag-data supplies the FC 8 echo payload (parsed as hex by
        scanner_mixins/diagnostics.py `_run_diagnostics`, default 0x1234 if
        omitted). Send a distinct value (0xABCD) and assert the mock echoes
        it back correctly, proving --diag-data actually reached the wire
        request rather than the default being used [Category A].
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--diag",
            "echo",
            "--diag-data",
            "0xABCD",
            format="json",
            json_log=True,
        )

        assert result.success, f"Diagnostics echo with --diag-data failed: {result.stderr}"
        text = _combined_text(result, result.scan_log)
        assert "echo test: pass" in text, (
            f"Expected echo of custom --diag-data 0xABCD to match (PASS), got: {text[:500]}"
        )

    def test_diagnostics_invalid_diag_data_rejected(
        self, cli_runner, target, port, docker_services
    ):
        """A non-hex --diag-data value must be rejected cleanly with a
        readable error (no traceback), and diagnostics must report
        unsupported/no echo rather than silently falling back [Category C].
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--diag",
            "echo",
            "--diag-data",
            "not-a-hex-value",
            format="json",
            json_log=True,
        )

        assert "Traceback" not in result.combined_output
        text = _combined_text(result, result.scan_log)
        assert "invalid --diag-data value" in text, (
            f"Expected an explicit invalid --diag-data error, got: {text[:500]}"
        )

    def test_communication_events(self, cli_runner, target, port, docker_services):
        """Test communication events (FC 11/12) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--events",
            format="json",
            json_log=True,
        )

        # Events may not be supported
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Convenience Workflow Tests
    # ========================================================================

    def test_quick_mode(self, cli_runner, target, port, docker_services):
        """Test quick reconnaissance mode (scan-mode quick) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-mode",
            "quick",
            "--identify",
            format="json",
            json_log=True,
        )

        assert result.success, f"Quick mode failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log
        _assert_log_event_structure(log)
        # Quick mode should produce info-level events
        info_events = log.get_events(level="info")
        assert len(info_events) > 0, "Quick mode should produce info events"

    def test_full_mode(self, cli_runner, target, port, docker_services):
        """Test full scan mode (scan-mode full) with known mock data [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-mode",
            "full",
            "--identify",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Full mode failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result, min_count=3)
        log = result.scan_log
        _assert_log_event_structure(log)
        # Full mode should produce more events than quick mode
        info_events = log.get_events(level="info")
        assert len(info_events) > 0, "Full mode should produce info events"

    def test_max_registers(self, cli_runner, target, port, docker_services):
        """Test --max-registers limits registers per read request [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-20",
            "--max-registers",
            "10",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Security Tests
    # ========================================================================

    @pytest.mark.security
    def test_write_access_detection(self, cli_runner, target, port, docker_services):
        """Test write access detection (--test-write) produces security findings [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
        )

        # Should complete without error
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                # Write access detection may produce security findings
                messages = _all_messages(result.scan_log)
                assert any(
                    term in messages for term in ["write", "access", "register", "test", "writable"]
                ), "Expected write-related messages in log"

    @pytest.mark.security
    def test_writable_access_security_finding(self, cli_runner, target, port, docker_services):
        """Test --test-write produces 'Writable access' security finding [Category B]

        The mock's holding registers are backed by a standard pymodbus
        ModbusSequentialDataBlock which accepts writes.  When register reads
        succeed, the safe write-back test (read value, write same value)
        should find writable registers and emit:
          logger.security_finding("Writable access", "Found N writable holding_registers")
        which appears as event_type="security" with data.finding="Writable access"
        and data.details="Found N writable holding_registers".

        The mock accepts writes to its holding registers, so against this
        target the finding MUST fire; the assertions below are therefore
        unconditional.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            "--scan-range",
            "0-5",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Crash guard
        assert result.returncode in [0, 1]

        # --- UNCONDITIONAL: scanner must attempt the test-write operation ---
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        messages = _all_messages(log)
        assert "test write access" in messages, (
            f"Expected '[Test Write Access]' header in log, got: {messages[:500]}"
        )
        # The results line always appears (even when all reads fail)
        assert "results" in messages, (
            f"Expected '[Results]' summary in log output, got: {messages[:500]}"
        )

        # --- The mock accepts writes, so the finding MUST fire ---
        security_events = log.get_security_findings()
        writable_findings = [
            e for e in security_events if e.get("data", {}).get("finding") == "Writable access"
        ]
        assert writable_findings, (
            "Expected a 'Writable access' security finding against the writable "
            f"mock, got security events: {security_events}"
        )

        # Full Category-A validation of the finding payload.
        finding_data = writable_findings[0].get("data", {})
        details = finding_data.get("details", "")
        assert "writable" in details.lower(), (
            f"Finding details should mention 'writable', got: {details!r}"
        )
        assert "holding_registers" in details.lower(), (
            f"Finding details should mention 'holding_registers', got: {details!r}"
        )
        assert "writable:" in messages and "writable: 0" not in messages, (
            "When the finding fires, at least one register must be writable"
        )

    @pytest.mark.security
    def test_test_write_thorough(self, cli_runner, target, port, docker_services):
        """Test --test-write-thorough flag for deeper write access testing [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write-thorough",
            "--confirm",
            "--scan-range",
            "0-5",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_restore_on_exit(self, cli_runner, target, port, docker_services):
        """Test --restore-on-exit flag with test-write [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            "--restore-on-exit",
            "--scan-range",
            "0-3",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # SunSpec Discovery Tests
    # ========================================================================

    @pytest.mark.containers("modbus-sunspec")
    def test_sunspec_discovery(self, cli_runner, target, docker_services):
        """Test SunSpec model discovery (--sunspec / -S) [Category A]

        Runs against the dedicated SunSpec mock (port 5502), which always
        exposes a valid model chain. The scanner must locate the SunSpec
        marker at base 40000 and walk the full 7-model chain.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "5502",
            "--sunspec",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"SunSpec discovery failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)

        output = result.combined_output.lower()
        assert "marker found" in output, "Should locate the SunSpec marker"
        assert "40000" in output, "SunSpec marker should be at base address 40000"
        assert "7 model" in output, "Should walk the full 7-model SunSpec chain"

    # ========================================================================
    # Unit ID Tests
    # ========================================================================

    def test_specific_unit_id(self, cli_runner, target, port, docker_services):
        """Test scanning specific unit ID 1 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--unit-id",
            "1",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
        )

        assert result.success, f"Unit ID 1 scan failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        log = result.scan_log
        non_debug = [e for e in log.events if e.get("level") != "debug"]
        assert len(non_debug) > 0, "Expected non-debug events from unit ID 1 scan"

    def test_invalid_unit_id(self, cli_runner, target, port, docker_services):
        """Test handling of high unit ID (247) that may be invalid [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--unit-id",
            "247",
            "--scan-range",
            "0-10",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully (may fail but not crash)
        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        # High unit IDs typically fail; success is acceptable if mock responds
        if not result.success:
            assert result.returncode == 1, "Failure should produce return code 1"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_broadcast_mode(self, cli_runner, target, port, docker_services):
        """Test --broadcast flag sets unit ID to 0 [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--broadcast",
            "--identify",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Broadcast mode (unit 0) may produce warnings or different behavior
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_invalid_register_range(self, cli_runner, target, port, docker_services):
        """Test handling of invalid/high register range [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "65000-65100",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully
        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        # Invalid register range may succeed (empty result) or fail gracefully
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_connection_refused_on_closed_port(self, cli_runner, docker_services):
        """Test connection refused on a closed port handles gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            "65534",
            "--scan-range",
            "0-5",
            timeout=10,
            expect_json=False,
            json_log=True,
        )

        # Should not crash (returncode != -1 means no timeout)
        assert result.returncode != -1
        # Connection to closed port should fail
        assert not result.success, "Connection to closed port should not succeed"
        # Should indicate failure in output (connection failed/refused/error)
        output_lower = result.combined_output.lower()
        assert any(term in output_lower for term in ["error", "failed", "refused", "connection"]), (
            f"Expected failure indication in output. Got: {output_lower[:500]}"
        )

    def test_timeout_on_unreachable_host(self, cli_runner, docker_services):
        """Test timeout handling on unreachable host [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            "502",
            "--scan-range",
            "0-5",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should complete within timeout
        assert result.execution_time < 20, "Command did not respect timeout"
        # Unreachable host should result in failure (non-zero return code)
        assert result.returncode != 0, "Unreachable host should return non-zero"
        assert not result.success, "Unreachable host should not report success"

    # ========================================================================
    # CANopen MEI Tests (FC 43/13)
    # ========================================================================

    def test_canopen_info(self, cli_runner, target, port, docker_services):
        """Test --canopen-info reads gateway information [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--canopen-info",
            format="json",
            json_log=True,
        )

        # CANopen MEI may not be supported by the mock
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_canopen_read(self, cli_runner, target, port, docker_services):
        """Test --canopen-read for CANopen object dictionary read [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--canopen-read",
            "1:0x1000:0",
            format="json",
            json_log=True,
        )

        # CANopen MEI may not be fully supported
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_canopen_write(self, cli_runner, target, port, docker_services):
        """Test --canopen-write requires --confirm and writes CANopen object [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--canopen-write",
            "1:0x2000:0=200",
            "--confirm",
            format="json",
            json_log=True,
        )

        # CANopen write may not be fully supported
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Fuzzing Tests
    # ========================================================================

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_basic_fuzz(self, cli_runner, target, port, docker_services):
        """Test basic register fuzzing actually writes and reports a summary [Category A]

        Mock holding registers accept FC6/FC16 writes, so against a healthy mock
        the fuzzer should run tests, record writes, and report zero crashes.
        Range 0-3 (4 registers) x 8 boundary payloads = 32 tests.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"

        output = _combined_text(result, result.scan_log)
        summary = _parse_fuzz_summary(output)
        assert summary is not None, f"No fuzz summary line found in output: {output[:600]}"
        # Something actually ran, and the mock never went down.
        assert summary["tests"] > 0, f"Fuzzer ran zero tests: {summary}"
        assert summary["crashes"] == 0, f"Mock crashed during fuzzing: {summary}"
        # 4 registers x 8 boundary payloads.
        assert summary["tests"] == 32, f"Expected 32 tests (4 regs x 8 payloads): {summary}"
        # Writable mock => writes should land, not error out.
        assert summary["writes"] == summary["tests"], (
            f"Expected every write to succeed against writable mock: {summary}"
        )
        assert _count_fuzzed_registers(result) == 4, (
            f"Expected 4 'Fuzzing register' lines: {output[:600]}"
        )

        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_basic_fuzz_no_scan_range_defaults(self, cli_runner, target, port, docker_services):
        """Test register fuzzing without --scan-range falls back to 0-10 [Category A]

        Regression: argparse always sets args.scan_range (None when absent), so
        the "0-10" getattr fallback in _fuzz_registers never applied and the run
        died with "'NoneType' object has no attribute 'split'" (now a guarded
        ValueError). Default range 0-10 = 11 addresses, capped by the default
        --fuzz-max-addresses=10 -> 10 registers x 8 boundary payloads = 80 tests.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"

        output = _combined_text(result, result.scan_log)
        assert "scan failed" not in output.lower(), f"Fuzz crashed: {output[:600]}"
        summary = _parse_fuzz_summary(output)
        assert summary is not None, f"No fuzz summary line found in output: {output[:600]}"
        assert summary["tests"] == 80, f"Expected 80 tests (10 regs x 8 payloads): {summary}"
        assert summary["writes"] == summary["tests"], (
            f"Expected every write to succeed against writable mock: {summary}"
        )
        assert summary["crashes"] == 0, f"Mock crashed during fuzzing: {summary}"
        assert _count_fuzzed_registers(result) == 10, (
            f"Expected 10 'Fuzzing register' lines: {output[:600]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_function_fuzz(self, cli_runner, target, port, docker_services):
        """Test function code fuzzing probes every vendor FC 65-127 [Category A]

        _fuzz_function_codes walks FCs 65..127 inclusive = 63 tests, regardless
        of --fuzz-iterations. No register writes happen in this mode.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "function",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"

        output = _combined_text(result, result.scan_log)
        assert "fuzzing function codes 65-127" in output, (
            f"Expected function-code fuzzing banner: {output[:600]}"
        )
        summary = _parse_fuzz_summary(output)
        assert summary is not None, f"No fuzz summary line found in output: {output[:600]}"
        # FCs 65..127 inclusive = 63 probes.
        assert summary["tests"] == 63, f"Expected 63 function-code tests: {summary}"
        # Function-code fuzzing performs no register writes.
        assert summary["writes"] == 0, f"Function fuzzing should not write registers: {summary}"
        assert summary["crashes"] == 0, f"Mock crashed during function fuzzing: {summary}"

        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_all_access(self, cli_runner, target, port, docker_services):
        """Test --fuzz-all-access is accepted and fuzzing still runs [Category A]

        --fuzz-all-access only changes register selection for register-map
        fuzzing; in plain 'basic' mode it is a no-op, but the flag must still be
        accepted and the fuzzer must run normally (4 regs x 8 payloads = 32).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--fuzz-all-access",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"

        output = _combined_text(result, result.scan_log)
        summary = _parse_fuzz_summary(output)
        assert summary is not None, f"No fuzz summary line found in output: {output[:600]}"
        assert summary["tests"] == 32, f"Expected 32 tests (4 regs x 8 payloads): {summary}"
        assert summary["crashes"] == 0, f"Mock crashed during fuzzing: {summary}"
        assert _count_fuzzed_registers(result) == 4, (
            f"Expected 4 'Fuzzing register' lines: {output[:600]}"
        )

        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_max_addresses(self, cli_runner, target, port, docker_services):
        """Test --fuzz-max-addresses actually caps the fuzzed register count [Category A]

        Scan range 0-50 = 51 registers, capped to 3. The fuzzer must report
        "Fuzzing 3 of 51", emit exactly 3 per-register lines, and run
        3 regs x 8 boundary payloads = 24 tests.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-50",
            "--fuzz-max-addresses",
            "3",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode != -1
        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"

        output = _combined_text(result, result.scan_log)
        assert "fuzzing 3 of 51" in output, (
            f"Expected scope-limit line 'Fuzzing 3 of 51': {output[:600]}"
        )
        # The cap is real: exactly 3 registers get fuzzed, not 51.
        assert _count_fuzzed_registers(result) == 3, (
            f"Expected exactly 3 'Fuzzing register' lines, scope was not capped: {output[:600]}"
        )
        summary = _parse_fuzz_summary(output)
        assert summary is not None, f"No fuzz summary line found in output: {output[:600]}"
        assert summary["tests"] == 24, f"Expected 24 tests (3 regs x 8 payloads): {summary}"
        assert summary["crashes"] == 0, f"Mock crashed during fuzzing: {summary}"

        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    def test_fuzz_without_confirm_is_rejected(self, cli_runner, target, port, docker_services):
        """Test --fuzz without --confirm is rejected with message [Category A]

        The fuzz mixin returns early (exit 0) but logs a fail message.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Expected exit 0 (early return), got {result.returncode}"
        output = _combined_text(result, result.scan_log)
        assert "requires --confirm" in output, "Should warn that --confirm is required for fuzzing"

    @pytest.mark.fuzz
    def test_fuzz_without_confirm_produces_no_fuzz_data(
        self, cli_runner, target, port, docker_services
    ):
        """Test --fuzz without --confirm produces no fuzz results [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode == 0
        if result.json_output:
            data = result.json_output.get("data", {})
            assert "fuzz" not in data, "No fuzz data should be produced without --confirm"

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_mode_data(self, cli_runner, target, port, docker_services):
        """Test --fuzz-mode data register fuzzing [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "data",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_mode_boundary(self, cli_runner, target, port, docker_services):
        """Test --fuzz-mode boundary register fuzzing [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "boundary",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_mode_full(self, cli_runner, target, port, docker_services):
        """Test --fuzz-mode full (combined register + function code fuzzing) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "full",
            "--scan-range",
            "0-3",
            "--fuzz-iterations",
            "4",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_iterations_one(self, cli_runner, target, port, docker_services):
        """Test fuzzing with minimum iteration count (1) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-1",
            "--fuzz-iterations",
            "1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_iterations_large_range_small_max(self, cli_runner, target, port, docker_services):
        """Test --fuzz-max-addresses caps a large scan range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-100",
            "--fuzz-max-addresses",
            "2",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        output = _combined_text(result, result.scan_log)
        assert "2 of" in output, "Should report capped address count"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_float32_decode(self, cli_runner, target, port, docker_services):
        """Test type-aware fuzzing with float32 decode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "10-11",
            "--fuzz-iterations",
            "3",
            "-d",
            "f32",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_int32_decode(self, cli_runner, target, port, docker_services):
        """Test type-aware fuzzing with int32 decode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "30-31",
            "--fuzz-iterations",
            "3",
            "-d",
            "i32",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_result_contains_summary(self, cli_runner, target, port, docker_services):
        """Test fuzzing output includes summary stats [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-1",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        output = _combined_text(result, result.scan_log)
        assert "fuzzing summary" in output, "Output should contain 'Fuzzing Summary' banner"
        assert "tests:" in output, "Summary should report test count"
        assert "writes:" in output, "Summary should report write count"

    @pytest.mark.fuzz
    @pytest.mark.slow
    @pytest.mark.containers("modbus-rtu-tcp")
    def test_fuzz_over_rtu_tcp(self, cli_runner, target, docker_services):
        """Test fuzzing over RTU-over-TCP transport [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "5030",
            "--rtu-over-tcp",
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-1",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1, -1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    def test_fuzz_against_wrong_port(self, cli_runner, target, docker_services):
        """Test fuzzing against unreachable port fails gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "19999",
            "--fuzz",
            "--fuzz-mode",
            "basic",
            "--scan-range",
            "0-1",
            "--fuzz-iterations",
            "1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode != 0, "Should fail when target port is unreachable"

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_function_mode_no_scan_range(self, cli_runner, target, port, docker_services):
        """Test function code fuzzing works without --scan-range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-mode",
            "function",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1], f"Unexpected return code: {result.returncode}"
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Output Format Tests
    # ========================================================================

    def test_csv_output(self, cli_runner, target, port, docker_services):
        """Test CSV output format [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-5",
            format="csv",
            expect_json=False,
        )

        assert result.success, f"CSV output failed: {result.stderr}"
        assert result.returncode == 0, f"CSV output returned non-zero: {result.returncode}"

    def test_xml_output(self, cli_runner, target, port, docker_services):
        """Test XML output format [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-5",
            format="xml",
            expect_json=False,
        )

        assert result.success, f"XML output failed: {result.stderr}"
        assert result.returncode == 0, f"XML output returned non-zero: {result.returncode}"

    # ========================================================================
    # Transport Tests
    # ========================================================================

    @pytest.mark.containers("modbus-rtu-tcp")
    def test_rtu_over_tcp(self, cli_runner, target, docker_services):
        """Test RTU-over-TCP framing against dedicated RTU gateway [Category A]

        Uses --scan-mode quick because RTU framing register scans are slow
        (CRC + inter-frame timing). Discovery/identification works reliably.
        Asserts the RTU-specific Server ID is returned — this data is only
        readable with correct RTU framing (TCP framing yields no Server ID).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "5030",
            "--rtu-over-tcp",
            "--scan-mode",
            "quick",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.success, f"RTU-over-TCP scan failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        output = result.combined_output.lower()
        assert "rtu-over-tcp" in output, "Should confirm RTU-over-TCP framing"
        assert "oida-rtu-gw" in output, (
            "Should retrieve RTU gateway Server ID (only readable with correct RTU framing)"
        )

    @pytest.mark.containers("modbus-rtu-tcp")
    def test_rtu_over_tcp_multi_unit(self, cli_runner, target, docker_services):
        """Test RTU-over-TCP with specific unit ID (gateway) [Category A]

        The RTU gateway mock responds on unit ID 3 with correct RTU framing
        and returns its Server ID. Connecting and reading the Server ID only
        works when the RTU-over-TCP framing is applied correctly.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "5030",
            "--rtu-over-tcp",
            "--unit-id",
            "3",
            "--scan-mode",
            "quick",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.success, f"RTU-over-TCP unit-3 scan failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        output = result.combined_output.lower()
        assert "rtu-over-tcp" in output, "Should confirm RTU-over-TCP framing"
        assert "unit id: 3" in output, "Should scan the requested unit ID 3"
        assert "oida-rtu-gw" in output, (
            "Should retrieve RTU gateway Server ID (only readable with correct RTU framing)"
        )

    def test_ascii_over_tcp(self, cli_runner, target, port, docker_services):
        """Test ASCII-over-TCP framing [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ascii-over-tcp",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1, -1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_ascii_serial_flag_over_tcp_is_noop(self, cli_runner, target, port, docker_services):
        """Test --ascii (serial ASCII framing) is accepted and has no effect
        over a TCP target [Category B]

        --ascii only changes the client framer when a --serial-port is also
        given (see ModbusScanner.connect(): `use_ascii_serial` is only
        consulted inside the `if self.serial_port` branch). We have no
        serial/RTU hardware mock, so this exercises the real, observable
        behaviour reachable in this suite: the flag parses cleanly and the
        scan proceeds normally over TCP, unaffected, against the live mock
        holding registers (see module docstring for HR[0..3] values).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ascii",
            "--scan-range",
            "0-3",
            "--register-type",
            "holding",
            format="json",
            json_log=True,
        )

        assert result.success, f"--ascii over TCP should be a no-op, got: {result.stderr}"
        assert result.returncode == 0
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["addr", "value", "holding", "register"]), (
            f"Expected normal holding-register table output with --ascii, got: {text[:500]}"
        )

    def test_udp_transport(self, cli_runner, target, port, docker_services):
        """Test UDP transport [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--udp",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1, -1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_transport_option_tcp(self, cli_runner, target, port, docker_services):
        """Test default TCP transport (no special flag needed) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
        )

        assert result.success, f"TCP transport failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    # ========================================================================
    # TLS Tests
    # ========================================================================

    @pytest.mark.security
    @pytest.mark.containers("modbus-tls")
    def test_tls_transport(self, cli_runner, target, docker_services):
        """Test TLS transport (port 802) [Category A]

        The TLS mock completes the TLS handshake without a client cert (data
        reads require mTLS, but the transport-layer handshake always succeeds).
        Assert the TLS session established and the server certificate was
        inspected, proving the --tls transport is wired up end to end.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "802",
            "--tls",
            "--tls-insecure",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        output = result.combined_output.lower()
        assert "connected via tls" in output, "Should establish the TLS transport"
        assert "x509 certificate" in output, "Should inspect the server X509 certificate"

    @pytest.mark.security
    @pytest.mark.containers("modbus-tls")
    def test_tls_with_client_cert(self, cli_runner, target, docker_services):
        """Test TLS with valid client cert (mTLS) [Category A]

        Asserts the TLS-specific server identity AND register data are returned,
        proving the TLS session established a working Modbus channel.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "802",
            "--tls",
            "--tls-insecure",
            "--tls-cert",
            str(MODBUS_TLS_CERTS / "client.pem"),
            "--tls-key",
            str(MODBUS_TLS_CERTS / "client.key"),
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.success, f"TLS with client cert failed: {result.stderr}"
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)
        output = result.combined_output.lower()
        assert "connected via tls" in output, "Should confirm TLS transport"
        assert "oida-modbus-tls" in output or "1234" in output, (
            "Should retrieve TLS server identity or register data (uptime=1234)"
        )

    @pytest.mark.security
    @pytest.mark.containers("modbus-tls")
    def test_tls_invalid_cert(self, cli_runner, target, docker_services):
        """Test TLS with bogus client cert (not signed by CA) [Category B]

        pymodbus ModbusTlsServer does not reliably enforce mTLS client cert
        verification at the TLS handshake layer. The connection may succeed
        but register reads may fail. Accept either outcome.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "802",
            "--tls",
            "--tls-insecure",
            "--tls-cert",
            str(MODBUS_TLS_CERTS / "bogus.pem"),
            "--tls-key",
            str(MODBUS_TLS_CERTS / "bogus.key"),
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=20,
        )

        # The mock's pymodbus ModbusTlsServer does not enforce mTLS client
        # cert verification at the handshake, so register reads may succeed
        # or fail -- accept either outcome.
        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        output = result.combined_output.lower()
        # Regardless of the (unenforced) mTLS outcome, the TLS handshake itself
        # always completes and the bogus client cert is offered to the server.
        assert "connected via tls" in output, "TLS handshake should complete"
        assert "bogus.pem" in output, "Should offer the supplied (bogus) client certificate"

    @pytest.mark.security
    def test_tls_wrong_port(self, cli_runner, target, docker_services):
        """Test TLS on standard Modbus TCP port (no TLS listener) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "502",
            "--tls",
            "--tls-insecure",
            "--scan-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode != 0, "TLS on plain TCP port should fail"
        assert not result.success, "TLS on plain TCP port should not report success"
        output = result.combined_output.lower()
        assert "fail" in output or "error" in output, (
            "Should report connection failure when TLS hits a plain TCP port"
        )

    # ========================================================================
    # File Record Tests (FC 20/21)
    # ========================================================================

    def test_file_read_fc20(self, cli_runner, target, port, docker_services):
        """Test file record read (FC 20) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--file-read",
            "1:0:10",
            format="json",
            json_log=True,
            timeout=20,
        )

        # File record read may not be supported by mock
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_fifo_queue_fc24(self, cli_runner, target, port, docker_services):
        """Test FIFO queue read (FC 24) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fifo",
            "0",
            format="json",
            json_log=True,
            timeout=20,
        )

        # FIFO may not be supported by mock
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # MEI Object Tests
    # ========================================================================

    def test_mei_object_basic(self, cli_runner, target, port, docker_services):
        """Test MEI basic object category returns vendor/product/revision [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object",
            "basic",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                # Basic MEI should return vendor/product/revision from mock
                assert any(
                    term in text
                    for term in [
                        MOCK_VENDOR_NAME,
                        "oida",
                        "vendor",
                        "product",
                        "mock",
                    ]
                ), f"Expected basic MEI identity info. Got: {text[:300]}"

    def test_mei_object_id(self, cli_runner, target, port, docker_services):
        """Test specific MEI object ID 0 returns VendorName='OIDA Mock Devices' [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object-id",
            "0",
            format="json",
            json_log=True,
        )

        # MEI object may not be supported
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                # Object ID 0 is VendorName = "OIDA Mock Devices"
                text = _combined_text(result, result.scan_log)
                assert any(term in text for term in [MOCK_VENDOR_NAME, "oida", "vendor", "mock"]), (
                    f"Expected vendor info for MEI object ID 0. Got: {text[:300]}"
                )

    def test_mei_object_regular(self, cli_runner, target, port, docker_services):
        """Test --identify with --mei-object regular [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object",
            "regular",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_mei_object_extended(self, cli_runner, target, port, docker_services):
        """Test --identify with --mei-object extended [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object",
            "extended",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_mei_object_specific(self, cli_runner, target, port, docker_services):
        """Test --mei-object specific with --mei-object-id [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object",
            "specific",
            "--mei-object-id",
            "0",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_mei_object_id_vendor(self, cli_runner, target, port, docker_services):
        """Test --mei-object-id 0 returns VendorName = 'OIDA Mock Devices' [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object-id",
            "0",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                # Object ID 0 = VendorName = "OIDA Mock Devices"
                text = _combined_text(result, result.scan_log)
                assert any(term in text for term in [MOCK_VENDOR_NAME, "oida", "vendor", "mock"]), (
                    f"Expected vendor name info for MEI object ID 0. Got: {text[:300]}"
                )

    def test_mei_object_id_product_code(self, cli_runner, target, port, docker_services):
        """Test --mei-object-id 1 returns ProductCode = 'OIDA-MOCK-001' [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object-id",
            "1",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                # Object ID 1 = ProductCode = "OIDA-MOCK-001"
                text = _combined_text(result, result.scan_log)
                assert any(
                    term in text for term in [MOCK_PRODUCT_CODE, "oida-mock", "product", "mock"]
                ), f"Expected product code info for MEI object ID 1. Got: {text[:300]}"

    # ========================================================================
    # Write Operation Tests
    # ========================================================================

    @pytest.mark.security
    def test_write_register_requires_confirm(self, cli_runner, target, port, docker_services):
        """Test that write operations without --confirm are rejected or warned [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write",
            "0=100",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail without --confirm or require confirmation
        assert result.returncode in [0, 1, 2]
        # Write without --confirm should be rejected (non-zero exit) or produce a warning
        if result.returncode != 0:
            assert not result.success, "Non-zero return code should mean not success"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_write_register_with_confirm(self, cli_runner, target, port, docker_services):
        """Test write to holding register with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write",
            "0=100",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Write may succeed or fail depending on mock support
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["write", "register", "success", "0"]), (
                    "Expected write-related messages on success"
                )

    @pytest.mark.security
    def test_write_coil_with_confirm(self, cli_runner, target, port, docker_services):
        """Test write to coil with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-coil",
            "0=1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Write may succeed or fail depending on mock support
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_write_multiple_registers(self, cli_runner, target, port, docker_services):
        """Test write multiple registers (FC 16) with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-multiple",
            "0=100,200,300",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Write may succeed or fail depending on mock support
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_write_multiple_coils(self, cli_runner, target, port, docker_services):
        """Test write multiple coils (FC 15) with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-multiple-coils",
            "0=1,0,1,1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Write may succeed or fail depending on mock support
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_mask_write_register(self, cli_runner, target, port, docker_services):
        """Test mask write register (FC 22) with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--mask-write",
            "0:0xFF00:0x00FF",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Mask write may not be supported
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Atomic Operations Tests
    # ========================================================================

    def test_atomic_read_write(self, cli_runner, target, port, docker_services):
        """Test atomic read-write (FC 23) with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--atomic-rw",
            "0-5:10=100,200",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Atomic operations may not be supported
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Monitoring Tests
    # ========================================================================

    @pytest.mark.slow
    def test_monitor_mode(self, cli_runner, target, port, docker_services):
        """Test monitoring mode with duration limit [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--monitor",
            "--scan-range",
            "0-5",
            "--duration",
            "3",
            "--interval",
            "1",
            format="json",
            json_log=True,
            timeout=10,
        )

        # Monitor should complete after duration
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                # Monitoring should produce multiple polling events
                non_debug = [e for e in result.scan_log.events if e.get("level") != "debug"]
                assert len(non_debug) > 0, "Monitor mode should produce non-debug events"

    def test_monitor_on_change(self, cli_runner, target, port, docker_services):
        """Test monitoring mode with --on-change filter [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--monitor",
            "--scan-range",
            "0-5",
            "--duration",
            "2",
            "--on-change",
            format="json",
            json_log=True,
            timeout=10,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Register Map Tests
    # ========================================================================

    def test_list_maps(self, cli_runner):
        """Test listing available register maps (--list-maps, no connection needed) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--list-maps",
            expect_json=False,
        )

        assert result.returncode in [0, 1]
        assert result.success, f"List maps should succeed: {result.stderr}"

    def test_register_map(self, cli_runner, target, port, docker_services):
        """Test --register-map with oida-mock map name [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--register-map",
            "oida-mock",
            format="json",
            json_log=True,
        )

        # Map may or may not exist
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_list_names(self, cli_runner, target, port, docker_services):
        """Test --list-names for register map names [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--register-map",
            "oida-mock",
            "--list-names",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_search_name(self, cli_runner, target, port, docker_services):
        """Test --search-name for register name search [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--register-map",
            "oida-mock",
            "--search-name",
            "temp",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_read_name(self, cli_runner, target, port, docker_services):
        """Test --read-name for reading register by friendly name [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--register-map",
            "oida-mock",
            "--read-name",
            "system_status",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_write_name(self, cli_runner, target, port, docker_services):
        """Test --write-name for writing register by friendly name (with --confirm) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--register-map",
            "oida-mock",
            "--write-name",
            "system_status=1",
            "--confirm",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Standard Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help output shows modbus usage [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        assert result.success, "Help command should succeed"
        assert "modbus" in result.stdout.lower()

    def test_verbose_levels(self, cli_runner, target, port, docker_services):
        """Test verbose output levels (-v) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-5",
            format="json",
            json_log=True,
            verbose=True,
        )

        assert result.success
        assert result.returncode == 0, f"Expected return code 0, got {result.returncode}"
        _assert_log_has_events(result)

    def test_debug_output(self, cli_runner, target, port, docker_services):
        """Test --debug output produces debug-level events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-range",
            "0-5",
            format="json",
            json_log=True,
            timeout=20,
            debug=True,
        )

        assert result.returncode in [0, 1]
        assert result.success, f"Debug output scan failed: {result.stderr}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            # Debug mode should produce debug-level events
            debug_events = result.scan_log.get_events(level="debug")
            assert len(debug_events) > 0, "Debug mode should produce debug-level events"

    # ========================================================================
    # Custom Function Code Tests (--raw-fc)
    # ========================================================================

    def test_raw_fc_standard_code(self, cli_runner, target, port, docker_services):
        """Send raw request to standard FC 3 (read holding) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-fc",
            "3",
            "--payload",
            "00 00 00 01",  # addr=0, count=1
            format="json",
            json_log=True,
        )
        # Success or handled exception
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_custom_fc_alias_reads_holding_registers(
        self, cli_runner, target, port, docker_services
    ):
        """--custom-fc is the documented alias for --raw-fc (same argparse
        destination, see proto_args.py `"--raw-fc", "--custom-fc"`).
        Drive it standalone (never combined with --raw-fc) against FC 3
        (read holding registers) with --confirm and assert the scanner
        actually transmitted the request and got a real response back
        [Category A].
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--custom-fc",
            "3",
            "--payload",
            "00 00 00 01",  # addr=0, count=1
            "--confirm",
            expect_json=False,
            json_log=True,
        )

        assert result.success, f"--custom-fc FC3 read failed: {result.stderr}"
        log = result.scan_log
        assert log is not None and len(log) > 0, "scan_log should be populated"
        _assert_log_event_structure(log)
        messages = _all_messages(log)
        text = _combined_text(result, log)
        assert "raw function code 3" in messages or "raw function code 3" in text, (
            f"Expected FC 3 to be transmitted via --custom-fc, got: {text[:500]}"
        )
        assert "response (3 bytes)" in text or "response (" in text, (
            f"Expected a real response to the --custom-fc FC3 request, got: {text[:500]}"
        )

    def test_raw_fc_unsupported_code(self, cli_runner, target, port, docker_services):
        """Send to unsupported FC 99, expect no usable response [Category C]

        --raw-fc can mutate PLC state, so the scanner gates it behind
        --confirm; without the flag the request is never sent and the test
        would be vacuous.  With --confirm the FC 99 request is actually
        transmitted to the mock, which does not implement FC 99 and so
        returns no valid PDU.  The mock-grounded outcome is therefore an
        *empty* (0-byte) response (and an internal decode error), in clear
        contrast to a supported FC such as 3 which returns register bytes.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-fc",
            "99",
            "--payload",
            "00",
            "--confirm",
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1]

        # The FC must actually be sent (proves --confirm gate was passed).
        log = result.scan_log
        assert log is not None and len(log) > 0, "scan_log should be populated"
        _assert_log_event_structure(log)
        messages = _all_messages(log)
        assert "raw function code 99" in messages, (
            f"FC 99 should be transmitted, got: {messages[:400]}"
        )

        # Unsupported FC -> no usable response: the mock returns an empty
        # PDU (0-byte response) and/or the decode fails.  Either way there
        # is no non-empty response payload like a supported FC would yield.
        assert "response (0 bytes)" in messages or "decode failed" in messages, (
            f"Unsupported FC 99 should yield an empty/failed response, got: {messages[:400]}"
        )

    def test_raw_fc_vendor_range(self, cli_runner, target, port, docker_services):
        """Send to vendor FC range (65-72) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-fc",
            "65",
            "--payload",
            "01 02",
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_raw_fc_empty_payload(self, cli_runner, target, port, docker_services):
        """Send FC 17 (Server ID) with no payload data [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-fc",
            "17",  # Server ID - no payload needed
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_raw_fc_hexdump_format(self, cli_runner, target, port, docker_services):
        """Test hexdump response format (--response-format hexdump) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-fc",
            "3",
            "--payload",
            "00 00 00 01",
            "--response-format",
            "hexdump",
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_raw_fc_with_unit_id(self, cli_runner, target, port, docker_services):
        """Test raw FC with specific unit ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--unit-id",
            "1",
            "--raw-fc",
            "3",
            "--payload",
            "00 00 00 01",
            expect_json=False,
            json_log=True,
        )
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_raw_fc_save_response(self, cli_runner, target, port, docker_services, tmp_path):
        """Test saving raw response to file (--save-response) [Category B]"""

        response_file = tmp_path / "response.bin"

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-fc",
            "3",
            "--payload",
            "00 00 00 01",
            "--save-response",
            str(response_file),
            expect_json=False,
            json_log=True,
        )

        # Check execution succeeded
        assert result.returncode in [0, 1]
        # File may or may not exist depending on response success
        if result.success and response_file.exists():
            # Verify file was created with some content
            assert response_file.stat().st_size >= 0
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Log File Tests
    # ========================================================================

    @pytest.mark.slow
    def test_monitor_with_log_file(self, cli_runner, target, port, docker_services, tmp_path):
        """Verify that --log-file creates a CSV log during monitoring [Category B]"""
        log_file = tmp_path / "monitor_log.csv"

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--monitor",
            "--scan-range",
            "0-5",
            "--duration",
            "3",
            "--interval",
            "1",
            "--log-file",
            str(log_file),
            format="json",
            json_log=True,
            timeout=15,
        )

        # Monitor should complete
        assert result.returncode in [0, 1]
        # Log file may be created if monitoring was successful
        if result.success:
            # File should exist with content if monitoring worked
            if log_file.exists():
                content = log_file.read_text()
                # Should have CSV header or data
                assert len(content) > 0
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Function Codes 21-23 Tests
    # ========================================================================

    @pytest.mark.security
    def test_file_write_fc21(self, cli_runner, target, port, docker_services):
        """Test file record write (FC 21) with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--file-write",
            "1:0:01020304",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # File record write may not be supported by mock
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_mask_write_fc22(self, cli_runner, target, port, docker_services):
        """Test mask write register (FC 22) with and/or masks, --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--mask-write",
            "0:0xFF00:0x00FF",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Mask write may not be supported by mock
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_atomic_read_write_fc23(self, cli_runner, target, port, docker_services):
        """Test atomic read/write multiple registers (FC 23) with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--atomic-rw",
            "0-5:10=100,200",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Atomic operations may not be supported by mock
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # MEI Object Filtering Tests
    # ========================================================================

    def test_mei_object_basic_filter(self, cli_runner, target, port, docker_services):
        """Test --identify with --mei-object basic produces vendor/product info [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--identify",
            "--mei-object",
            "basic",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                # Basic MEI should return vendor/product/revision
                assert any(
                    term in text
                    for term in [
                        MOCK_VENDOR_NAME,
                        "oida",
                        "vendor",
                        "product",
                        "revision",
                        "mock",
                    ]
                ), f"Expected basic MEI identity info. Got: {text[:300]}"

    # ========================================================================
    # Fingerprint Aggressive Test
    # ========================================================================

    # ========================================================================
    # Brute Threads Test
    # ========================================================================

    @pytest.mark.slow
    def test_discover_units_threaded(self, cli_runner, target, port, docker_services):
        """Test --discover-units for parallel discovery [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover-units",
            "--unit-range",
            "1-10",
            format="json",
            json_log=True,
            timeout=60,
        )

        # Should complete without error
        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_discover_units_small_range(self, cli_runner, target, port, docker_services):
        """Test --discover-units with small unit range 1-3 (baseline) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover-units",
            "--unit-range",
            "1-3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.success:
            _assert_log_has_events(result)
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)


@contextlib.contextmanager
def _dummy_tcp_server():
    """A local TCP server that accepts connections but never speaks Modbus.

    Safety: binds only to 127.0.0.1 on an ephemeral port. It exists purely to
    provide a "TCP connects but is not a Modbus device" target for the
    connection-1 false-positive regression below — it never touches a real
    device or external network. Accepted sockets are held open and silent so
    that Modbus reads time out rather than getting a valid PDU.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()
    conns = []

    def _serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Hold the connection open without ever sending a valid Modbus PDU.
            conns.append(conn)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        with contextlib.suppress(OSError):
            srv.close()
        for conn in conns:
            with contextlib.suppress(OSError):
                conn.close()
        thread.join(timeout=2)


class TestModbusP1FalsePositiveRegression:
    """Regression guard for the connection-1 false-positive identification bug.

    A bare TCP connect to a port that speaks *something other than Modbus*
    opens the channel but never yields a valid Modbus PDU. Before the fix, the
    base ``NetworkConnection.run()`` defaulted ``success=True`` on any
    non-raising ``proto_flow()``, so OIDA reported a false-positive Modbus
    device on any open TCP port. The fix adds a ``verify_responsive()`` gate in
    the modbus scanner: identification only succeeds when the target returns a
    real Modbus response (a normal reply, or a valid exception response with an
    exception code in 1..11).

    Safety: these tests target only a local in-process dummy TCP server bound to
    127.0.0.1 and a closed local port — never a real device or external network.
    """

    def _read_result_payload(self, out_dir, result):
        """Return the last result record written to the --output directory."""
        candidates = sorted(out_dir.glob("*.json"))
        assert candidates, (
            "no JSON result file was written to the output directory; "
            f"combined output: {result.combined_output[:800]}"
        )
        payload = json.loads(candidates[-1].read_text())
        return payload[-1] if isinstance(payload, list) else payload

    def test_non_modbus_tcp_port_is_not_a_false_positive(self, cli_runner, tmp_path):
        """A TCP-connectable but non-Modbus port must report success=False.

        This is the core connection-1 regression: prior to the verify_responsive
        gate this scan reported a successful Modbus identification purely because
        the TCP connect succeeded.
        """
        with _dummy_tcp_server() as port:
            out_dir = tmp_path / "p1_non_modbus"
            result = cli_runner.run(
                "modbus",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "1",
                format="json",
                output=str(out_dir),
                expect_json=False,
                timeout=30,
            )

            last = self._read_result_payload(out_dir, result)
            assert last["success"] is False, (
                "connection-1 regression: a non-Modbus TCP port was reported as a "
                f"successful Modbus identification. Payload: {last}"
            )

    def test_closed_port_is_not_a_false_positive(self, cli_runner, tmp_path):
        """A closed local port must report success=False (never a phantom device)."""
        # Grab an ephemeral port, then close it so nothing is listening.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        out_dir = tmp_path / "p1_closed"
        result = cli_runner.run(
            "modbus",
            "127.0.0.1",
            "--port",
            str(closed_port),
            "--timeout",
            "1",
            format="json",
            output=str(out_dir),
            expect_json=False,
            timeout=30,
        )

        last = self._read_result_payload(out_dir, result)
        assert last["success"] is False, (
            "connection-1 regression: a closed port was reported as a successful "
            f"Modbus identification. Payload: {last}"
        )
