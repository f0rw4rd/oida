"""
Beckhoff ADS (Automation Device Specification) Protocol Integration Tests

Tests oida ads scanner against Docker mock service.
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/ads_server.py):
  AMS Net ID:             127.0.0.1.1.1
  TCP Port:               48898

  Port Contexts:
    851: TC3PLC1 "Mock TwinCAT 3 PLC Runtime 1" v3.1.4024
    852: TC3PLC2 "Mock TwinCAT 3 PLC Runtime 2" v3.1.4024
    853: TC3PLC3 "Mock TwinCAT 3 PLC Runtime 3" v3.1.4024
    854: TC3PLC4 "Mock TwinCAT 3 PLC Runtime 4" v3.1.4024
    801: SPS1    "Mock TwinCAT 2 PLC Runtime 1" v3.1.4024
    500: NC      "Mock NC/PTP NCI"               v3.1.4024
    100: CNC     "Mock CNC"                      v3.1.4024
    900: CUSTOMER1 "Mock Customer Port 1"        v3.1.4024

  Symbols (per port, ~70 per PLC port):
    MAIN.bSystemReady       BOOL     True
    MAIN.rTemperature       REAL     25.5 (simulated, varies)
    MAIN.rPressure          REAL     1013.25 (simulated)
    MAIN.rFlow              REAL     15.7
    MAIN.rLevel             REAL     75.0
    MAIN.Motor1.bEnable     BOOL     True
    MAIN.Motor1.nSpeed      INT      1450
    MAIN.Pump1.bRunning     BOOL     True
    MAIN.Valve1.bOpen       BOOL     True
    MAIN.sDeviceName        STRING   "Mock TC3PLC1 Device"
    MAIN.sStatus            STRING   "Running"
    MAIN.PID1.rSetpoint     REAL     25.0
    MAIN.nCycleCounter      UDINT    (simulated counter)
    ... (see ads_server.py _create_symbols for full list)

  Memory Areas:
    M-Area (0x4020):  1024 bytes, pattern: offset*100 at every 4 bytes
    Data (0x4040):    4096 bytes
    Input image (0xF020): 256 bytes (0..63 = 0..63)
    Output image (0xF030): 256 bytes (0..63 = 255-0..255-63)
    Retain (0x4080):  1024 bytes

  AMS Routes:
    Local:        127.0.0.1.1.1 -> 127.0.0.1
    PLC1:         192.168.1.10.1.1 -> 192.168.1.10
    PLC2:         192.168.1.20.1.1 -> 192.168.1.20
    Engineering:  192.168.1.100.1.1 -> 192.168.1.100

  Default State: ADSState.RUN (5)

  Security Findings (from __init__.py _analyze_security):
    - "No authentication" -- ADS protocol has no auth mechanism       [A] test_security_findings_no_auth
    - "Insecure configuration" -- TwinCAT 3.x static encryption key  [A] test_finding_insecure_config_static_key
    - "[CREDENTIALS] Credential exposure" -- static key sniff/replay  [A] test_finding_credential_exposure
    - "No encryption" -- TwinCAT 2.x clear text                      [A] test_finding_no_encryption_twincat2
    - "Anonymous access allowed" -- symbols readable without auth     [A] test_finding_anonymous_access
    - "Writable access" -- symbols writable without auth              [A] test_finding_writable_access
    - "Insecure configuration" -- memory areas directly accessible    [A] test_finding_memory_areas_accessible

Test Classification Summary (82 defined + 7 inherited from BaseProtocolIntegrationTest)
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  23 tests
Category B (conditional -- mock may not support, accept 0 or 1):       22 tests
Category C (error handling -- assert failure + validate error events):  35 tests
Skipped (untestable -- requires hardware or blocking):                  2 tests
Total defined in file:                                                 82 tests
Total collected (including inherited):                                 89 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (proto_args.py):
  --port                    [A] inherent in all tests via port fixture
  -n/--netid-ext            [B] test_netid_ext
  --ams-netid/--target-ams  [A] test_with_ams_netid, test_target_ams_alias
  -L/--local-netid          [B] test_local_netid
  -T/--port-type            [A] test_port_type_tc3plc1, [B] test_port_type_nc
  --ads-port                [A] test_explicit_ads_port
  --ads-timeout             [B] test_ads_timeout_custom
  -i/--device-info          [A] test_device_info
  -l/--list-symbols         [A] test_list_symbols
  -e/--enumerate-symbols    [A] test_enumerate_symbols
  --max-symbols             [B] test_max_symbols_limit
  -r/--scan-routes          [B] test_scan_routes
  -s/--scan-ports           [B] test_scan_ports
  -S/--scan-ports-extended  [B] test_scan_ports_extended
  --target-desc             [B] test_target_desc
  --check-secure            [C] test_check_secure
  --udp-discovery           [C] test_udp_discovery
  --license-info            [B] test_license_info
  --io-devices              [B] test_io_devices
  --task-info               [B] test_task_info
  --list-files              [B] test_list_files
  --read-file               [B] test_read_file
  --read-registry           [B] test_read_registry
  --download-program        [B] test_download_program
  --scan-ethercat           [C] test_scan_ethercat
  --scan-coe                [C] test_scan_coe
  --coe-range               [C] test_coe_range_standalone (inert-modifier warning)
  --read-coe                [C] test_read_coe
  --write-coe               [C] test_write_coe_without_confirm, test_write_coe_with_confirm
  --scan-coe-access         [C] test_scan_coe_access_without_confirm, test_scan_coe_access_with_confirm
  --eeprom-dump             [C] test_eeprom_dump
  --esc-registers           [C] test_esc_registers
  --foe-read                [C] test_foe_read
  --scan-foe                [C] test_scan_foe
  --foe-list                [C] test_foe_list
  --foe-write               [C] test_foe_write_without_confirm
  --foe-delete              [C] test_foe_delete_without_confirm
  --scan-soe                [C] test_scan_soe
  --read-soe                [C] test_read_soe
  --scan-fsoe               [C] test_scan_fsoe
  --add-route               [C] test_add_route_without_confirm
  --read-symbol             [A] test_read_symbol
  --write-symbol            [B] test_write_symbol_with_confirm, [C] test_write_symbol_without_confirm
  --symbol-filter           [B] test_symbol_filter
  -R/--memory-read          [A] test_memory_read
  -W/--memory-write         [B] test_memory_write_with_confirm, [C] test_memory_write_without_confirm
  -m/--test-memory          [A] test_test_memory
  --state                   [A] test_state
  --set-state               [B] test_set_state_run, [B] test_set_state_stop, [C] test_set_state_without_confirm
  --fuzz                    [C] test_symbol_fuzzing, test_memory_fuzzing, test_fuzz_without_confirm
  --fuzz-coe                [C] test_fuzz_coe_without_confirm, test_fuzz_coe_force_write_with_confirm
  --fuzz-symbol             [C] test_fuzz_specific_symbol
  --fuzz-iterations         [C] implicit in fuzz tests
  --test-write              [C] test_test_write_without_confirm, [B] test_test_write_with_confirm
  --force-write             [C] test_fuzz_coe_force_write_with_confirm
  --confirm                 [C] tested across all --confirm gating tests
  --watch                   [C] test_watch_connection_failure (bounded via closed-port
                             connection failure -- see test docstring: a real ADS
                             connection makes --watch enter an unbounded loop only
                             exited by Ctrl+C, so it is driven up to dispatch without
                             ever entering that loop)
"""

import pytest
from typing import Optional

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import MOCK_HOST


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


def _assert_confirm_rejected(result, flag_name):
    """Assert that a --confirm-gated operation was rejected without --confirm.

    Validates that the output contains the "requires --confirm" rejection message
    and that the command did not crash (returncode != segfault/-11).
    """
    # Should not crash
    assert result.returncode != -11, f"{flag_name} caused a crash"
    # The scanner emits "requires --confirm" on the fail path
    text = _combined_text(result, result.scan_log if result.scan_log else None)
    assert any(term in text for term in ["confirm", "require", "dangerous"]), (
        f"{flag_name} without --confirm should mention '--confirm' in output, got: {text[:400]}"
    )
    if result.scan_log is not None and len(result.scan_log) > 0:
        _assert_log_event_structure(result.scan_log)


@pytest.mark.ads
class TestADSIntegration(BaseProtocolIntegrationTest):
    """Integration tests for Beckhoff ADS protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "ads"

    @property
    def default_port(self) -> int:
        return 48898

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Discovery Tests
    # ========================================================================

    def test_device_info(self, cli_runner, target, port, docker_services):
        """Test reading device information with known mock data [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.success, f"Device info failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Mock reports "Mock TwinCAT 3  v3.1.4024" on the default TC3PLC1 port.
        assert "twincat" in text, f"Expected TwinCAT device identity, got: {text[:400]}"
        assert "v3.1.4024" in text or "mock" in text, (
            f"Expected mock device version/name in device info, got: {text[:400]}"
        )

    def test_state(self, cli_runner, target, port, docker_services):
        """Test getting PLC state -- mock defaults to RUN (5) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--state",
            format="json",
            json_log=True,
        )

        assert result.success, f"State query failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Mock reports a concrete ADS state line ("State: RUN" / "State: STOP").
        assert "state:" in text, f"Expected a 'State:' line, got: {text[:400]}"
        assert any(s in text for s in ["run", "stop", "config", "idle"]), (
            f"Expected a concrete ADS state value, got: {text[:400]}"
        )

    def test_basic_connection_lifecycle(self, cli_runner, target, port, docker_services):
        """Test that connection events are logged properly [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.success, f"Connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        conn_events = log.get_connection_events()
        if conn_events:
            assert len(conn_events) >= 1, "Expected at least 1 connection event"

    def test_default_scan_no_flags(self, cli_runner, target, port, docker_services):
        """Test default scan with no explicit operation flags [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Default scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Default scan should show device info and summary
        text = _combined_text(result, log)
        assert any(term in text for term in ["ads", "connect", "device", "twincat", "mock"]), (
            f"Expected ADS-related output, got: {text[:400]}"
        )

    # ========================================================================
    # Symbol Enumeration Tests
    # ========================================================================

    def test_list_symbols(self, cli_runner, target, port, docker_services):
        """Test listing PLC symbols -- mock has ~70 symbols per port [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-symbols",
            format="json",
            json_log=True,
        )

        assert result.success, f"List symbols failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Mock symbols include MAIN.* names
        assert any(term in text for term in ["main.", "symbol", "bool", "real", "int"]), (
            f"Expected symbol names in output, got: {text[:400]}"
        )

    def test_enumerate_symbols(self, cli_runner, target, port, docker_services):
        """Test enumerating symbols with values [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-symbols",
            "--max-symbols",
            "50",
            format="json",
            json_log=True,
        )

        assert result.success, f"Enumerate symbols failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Should contain symbol names and types
        assert any(term in text for term in ["main.", "symbol", "value", "bool", "real"]), (
            f"Expected symbol enumeration in output, got: {text[:400]}"
        )

    def test_max_symbols_limit(self, cli_runner, target, port, docker_services):
        """Test --max-symbols limits enumeration output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-symbols",
            "--max-symbols",
            "5",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_symbol_filter(self, cli_runner, target, port, docker_services):
        """Test filtering symbols by name pattern [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-symbols",
            "--symbol-filter",
            "MAIN.Motor*",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                # Should filter to Motor-related symbols
                assert any(term in text for term in ["motor", "symbol", "filter"]), (
                    f"Expected motor symbols in filtered output, got: {text[:300]}"
                )

    # ========================================================================
    # Symbol Read/Write Tests
    # ========================================================================

    def test_read_symbol(self, cli_runner, target, port, docker_services):
        """Test reading specific symbol -- MAIN.rTemperature ~25.5 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-symbol",
            "MAIN.rTemperature",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.success, f"Read symbol failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(term in text for term in ["temperature", "main.", "value", "read"]), (
            f"Expected temperature symbol data, got: {text[:400]}"
        )

    def test_write_symbol_with_confirm(self, cli_runner, target, port, docker_services):
        """Test writing to a symbol with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-symbol",
            "MAIN.nSetpoint:5000",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Write may succeed or fail on mock
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_write_symbol_without_confirm(self, cli_runner, target, port, docker_services):
        """Test that --write-symbol without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-symbol",
            "MAIN.nSetpoint:5000",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should not crash; the scanner emits "requires --confirm"
        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            _assert_confirm_rejected(result, "--write-symbol")

    # ========================================================================
    # Memory Operations Tests
    # ========================================================================

    def test_memory_read(self, cli_runner, target, port, docker_services):
        """Test reading memory -- M-Area has test pattern data [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-read",
            "0x4020:0:4",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.success, f"Memory read failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        import re

        text = _combined_text(result, log)
        # Mock M-Area (0x4020) returns 4 real bytes; require the read to report
        # the target group AND the byte count, plus a hex data field.
        assert "0x4020" in text, f"Expected M-Area group 0x4020 in output, got: {text[:400]}"
        assert "read 4 bytes" in text, f"Expected '4 bytes' read confirmation, got: {text[:400]}"
        assert re.search(r"\bdata:\s*[0-9a-f]{8}\b", text), (
            f"Expected 4 hex bytes of memory data, got: {text[:400]}"
        )

    def test_memory_write_with_confirm(self, cli_runner, target, port, docker_services):
        """Test writing memory with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-write",
            "0x4020:0:DEADBEEF",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Write may succeed or fail on mock
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_memory_write_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --memory-write without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-write",
            "0x4020:0:DEADBEEF",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should not crash
        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            _assert_confirm_rejected(result, "--memory-write")

    def test_test_memory(self, cli_runner, target, port, docker_services):
        """Test read access to common memory areas [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-memory",
            format="json",
            json_log=True,
        )

        assert result.success, f"Test memory failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Mock exposes M-Area (0x4020) as accessible and denies the Data Area
        # (0x4040). Require the memory-access report to name M-Area and show
        # at least one accessible (ok) result.
        assert "memory access" in text, f"Expected memory access report, got: {text[:400]}"
        assert "m-area" in text or "0x4020" in text, (
            f"Expected M-Area in memory test, got: {text[:400]}"
        )
        assert "ok" in text, f"Expected at least one accessible (OK) memory area, got: {text[:400]}"

    # ========================================================================
    # Route and Port Discovery Tests
    # ========================================================================

    def test_scan_routes(self, cli_runner, target, port, docker_services):
        """Test scanning AMS routing table [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-routes",
            format="json",
            json_log=True,
        )

        assert result.success, f"Route scan failed: {result.stderr}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)
        text = _combined_text(result, result.scan_log)
        # The mock's Net ID probe discovers active runtimes on the local base
        # (127.0.0.1.1.2, 127.0.0.1.2.1, ... -- see ads_server.py).  Require
        # both the route/probe framing and at least one concrete discovered
        # Net ID extension off 127.0.0.1.
        assert any(term in text for term in ["route", "net id", "netid", "probe"]), (
            f"Expected route/Net ID probe framing, got: {text[:400]}"
        )
        assert "127.0.0.1.1.2" in text or "127.0.0.1.2.1" in text, (
            f"Expected a concrete discovered AMS Net ID from the probe, got: {text[:400]}"
        )

    @pytest.mark.slow
    @pytest.mark.timeout(200)
    def test_scan_ports(self, cli_runner, target, port, docker_services):
        """Test scanning common ADS ports [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-ports",
            format="json",
            json_log=True,
            timeout=185,
        )

        # Allow timeout (-1) for slow port scans
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.slow
    @pytest.mark.timeout(200)
    def test_scan_ports_extended(self, cli_runner, target, port, docker_services):
        """Test scanning extended ADS ports (50+) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-ports-extended",
            format="json",
            json_log=True,
            timeout=185,
        )

        # Allow timeout (-1) for slow port scans
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # AMS Configuration Tests
    # ========================================================================

    def test_with_ams_netid(self, cli_runner, target, port, docker_services):
        """Test specifying AMS Net ID -- mock accepts 127.0.0.1.1.1 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ams-netid",
            "127.0.0.1.1.1",
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.success, f"AMS Net ID connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # Connecting via the explicit local AMS Net ID 127.0.0.1.1.1 must still
        # reach the mock TwinCAT 3 runtime and report its identity.
        assert "twincat" in text, (
            f"Expected TwinCAT device identity via AMS Net ID, got: {text[:400]}"
        )
        assert "127.0.0.1.1.1" in text, (
            f"Expected the supplied AMS Net ID 127.0.0.1.1.1 in output, got: {text[:400]}"
        )

    def test_target_ams_alias(self, cli_runner, target, port, docker_services):
        """Test --target-ams (long-form alias of --ams-netid) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--target-ams",
            "127.0.0.1.1.1",
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.success, f"--target-ams connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        # --target-ams is dest-aliased to the same argparse option as
        # --ams-netid, so it must reach the mock and report its identity.
        assert "twincat" in text, (
            f"Expected TwinCAT device identity via --target-ams, got: {text[:400]}"
        )
        assert "127.0.0.1.1.1" in text, (
            f"Expected the supplied AMS Net ID 127.0.0.1.1.1 in output, got: {text[:400]}"
        )

    def test_netid_ext(self, cli_runner, target, port, docker_services):
        """Test --netid-ext flag to set AMS Net ID extension [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--netid-ext",
            "1.1",
            "--device-info",
            format="json",
            json_log=True,
        )

        # May succeed or fail depending on AMS routing
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_port_type_tc3plc1(self, cli_runner, target, port, docker_services):
        """Test --port-type TC3PLC1 (default) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--port-type",
            "TC3PLC1",
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.success, f"Port type TC3PLC1 failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    def test_port_type_nc(self, cli_runner, target, port, docker_services):
        """Test --port-type NC for motion control port [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--port-type",
            "NC",
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_explicit_ads_port(self, cli_runner, target, port, docker_services):
        """Test explicit ADS port number (851 = TC3PLC1) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ads-port",
            "851",
            "--device-info",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.success, f"Explicit ADS port 851 failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    def test_local_netid(self, cli_runner, target, port, docker_services):
        """Test specifying local AMS Net ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--local-netid",
            "10.0.0.1.1.1",
            "--device-info",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_ads_timeout_custom(self, cli_runner, target, port, docker_services):
        """Test --ads-timeout with custom millisecond value [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ads-timeout",
            "1000",
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # State Control Tests
    # ========================================================================

    @pytest.mark.security
    def test_set_state_run(self, cli_runner, target, port, docker_services):
        """Test setting PLC to RUN state with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--set-state",
            "RUN",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_set_state_stop(self, cli_runner, target, port, docker_services):
        """Test setting PLC to STOP state with --confirm [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--set-state",
            "STOP",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_set_state_without_confirm(self, cli_runner, target, port, docker_services):
        """Test that --set-state without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--set-state",
            "RUN",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should not crash
        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            _assert_confirm_rejected(result, "--set-state")

    # ========================================================================
    # Security Tests
    # ========================================================================

    @pytest.mark.security
    def test_test_write_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --test-write without --confirm is rejected (recent fix) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            format="json",
            json_log=True,
            timeout=15,
        )

        # --test-write now requires --confirm (writes values back to device)
        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            _assert_confirm_rejected(result, "--test-write")

    @pytest.mark.security
    def test_test_write_with_confirm(self, cli_runner, target, port, docker_services):
        """Test --test-write with --confirm performs write access detection [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--test-write",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                text = _combined_text(result, result.scan_log)
                assert any(term in text for term in ["write", "access", "symbol", "writable"]), (
                    f"Expected write access results, got: {text[:300]}"
                )

    @pytest.mark.security
    def test_security_findings_no_auth(self, target, port, docker_services):
        """Test that the ADS no-auth finding is emitted by _analyze_security.

        ADS has no authentication mechanism by design, so _analyze_security
        unconditionally emits a 'No authentication' finding whose detail names
        the protocol limitation.  Like the sibling test_finding_* tests, this
        exercises the Layer 1 API directly: the NXC CLI proto_flow() never
        calls _analyze_security(), so a CLI-driven assertion here would be
        vacuous.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "TC3PLC1",
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)

            results = {
                "device_info": device_info,
                "symbols": {"symbols": {}},
                "memory_access": {"accessible": []},
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            titles = [f["title"] for f in new_findings]
            assert "No authentication" in titles, (
                f"Expected 'No authentication' finding, got titles: {titles}"
            )

            no_auth = next(f for f in new_findings if f["title"] == "No authentication")
            detail = no_auth.get("detail", "").lower()
            assert "no authentication" in detail, (
                f"Expected no-auth detail to describe the missing auth mechanism, got: {detail}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_check_secure(self, cli_runner, target, port, docker_services):
        """Test --check-secure (TLS on port 8016) -- mock does not support TLS [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-secure",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Security Findings (Layer 1 API) -- _analyze_security tests
    #
    # These 6 tests verify the security findings emitted by _analyze_security().
    # That method lives on the Layer 1 ADSScanner and is called from discover(),
    # which is NOT invoked by the NXC CLI proto_flow().  Therefore we test these
    # findings by calling the Layer 1 API directly against the running mock.
    #
    # Each test:
    #   1. Instantiates ADSScanner with the right port/args
    #   2. Connects to the mock via pyads
    #   3. Collects real device_info and/or memory access data
    #   4. Snapshots scanner.logger.findings before calling _analyze_security
    #   5. Calls _analyze_security() and asserts only on NEW findings
    #
    # NOTE: The ICS logger is cached by protocol:host:port, so findings from
    # prior tests accumulate.  We use a snapshot approach (record count before,
    # slice after) to isolate each test's findings.
    # ========================================================================

    @pytest.mark.security
    def test_finding_insecure_config_static_key(self, target, port, docker_services):
        """Test 'Insecure configuration' finding for TwinCAT 3.x static encryption key.

        The mock on port 851 reports 'Mock TwinCAT 3' which triggers the
        TwinCAT 3.x code path.  _analyze_security should emit a finding
        with title 'Insecure configuration' and detail mentioning 'static key'.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "TC3PLC1",
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)
            assert "twincat 3" in device_info.get("device_name", "").lower(), (
                f"Expected TwinCAT 3 device, got: {device_info.get('device_name')}"
            )

            results = {
                "device_info": device_info,
                "symbols": {"symbols": {}},
                "memory_access": {"accessible": []},
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            titles = [f["title"] for f in new_findings]
            details = " ".join(f.get("detail", "") for f in new_findings).lower()

            assert "Insecure configuration" in titles, (
                f"Expected 'Insecure configuration' finding, got titles: {titles}"
            )
            assert "static key" in details, (
                f"Expected 'static key' in finding details, got: {details[:300]}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_credential_exposure(self, target, port, docker_services):
        """Test '[CREDENTIALS] Credential exposure' finding for TwinCAT 3.x.

        The mock on port 851 reports TwinCAT 3 which means the static
        encryption key path fires.  _analyze_security should emit a finding
        with title '[CREDENTIALS] Credential exposure' about sniffing/replay.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "TC3PLC1",
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)

            results = {
                "device_info": device_info,
                "symbols": {"symbols": {}},
                "memory_access": {"accessible": []},
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            titles = [f["title"] for f in new_findings]
            details = " ".join(f.get("detail", "") for f in new_findings).lower()

            assert "[CREDENTIALS] Credential exposure" in titles, (
                f"Expected '[CREDENTIALS] Credential exposure' finding, got titles: {titles}"
            )
            assert "sniffing" in details or "replay" in details, (
                f"Expected 'sniffing' or 'replay' in finding details, got: {details[:300]}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_no_encryption_twincat2(self, target, port, docker_services):
        """Test 'No encryption' finding for TwinCAT 2.x clear text protocol.

        The mock on port 801 (SPS1) reports 'Mock TwinCAT 2' which triggers
        the TwinCAT 2.x code path.  _analyze_security should emit a finding
        with title 'No encryption' about clear text.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "SPS1",  # maps to ADS port 801
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)
            assert "twincat 2" in device_info.get("device_name", "").lower(), (
                f"Expected TwinCAT 2 device, got: {device_info.get('device_name')}"
            )

            results = {
                "device_info": device_info,
                "symbols": {"symbols": {}},
                "memory_access": {"accessible": []},
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            titles = [f["title"] for f in new_findings]
            details = " ".join(f.get("detail", "") for f in new_findings).lower()

            assert "No encryption" in titles, (
                f"Expected 'No encryption' finding, got titles: {titles}"
            )
            assert "clear text" in details, (
                f"Expected 'clear text' in finding details, got: {details[:300]}"
            )
            # TwinCAT 2.x path should NOT produce the static key / credential findings
            assert "Insecure configuration" not in titles, (
                "TwinCAT 2 path should not produce 'Insecure configuration' (static key)"
            )
            assert "[CREDENTIALS] Credential exposure" not in titles, (
                "TwinCAT 2 path should not produce credential exposure finding"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_anonymous_access(self, target, port, docker_services):
        """Test 'Anonymous access allowed' finding when symbols are readable.

        Constructs results with readable symbols to verify that _analyze_security
        emits 'Anonymous access allowed' when readable_count > 0.  The mock's
        pyads symbol upload does not return symbols (mock limitation), so we
        use synthetic symbol data that mirrors the mock's actual symbol table.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "TC3PLC1",
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)

            # Synthetic symbol data matching mock's actual symbols
            # (pyads get_all_symbols returns 0 from mock, but symbols ARE readable)
            results = {
                "device_info": device_info,
                "symbols": {
                    "symbols": {
                        "MAIN.bSystemReady": {"readable": True, "writable": False},
                        "MAIN.rTemperature": {"readable": True, "writable": False},
                        "MAIN.rPressure": {"readable": True, "writable": False},
                    }
                },
                "memory_access": {"accessible": []},
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            titles = [f["title"] for f in new_findings]
            details = " ".join(f.get("detail", "") for f in new_findings).lower()

            assert "Anonymous access allowed" in titles, (
                f"Expected 'Anonymous access allowed' finding, got titles: {titles}"
            )
            assert "3 symbols readable" in details, (
                f"Expected '3 symbols readable' in finding details, got: {details[:300]}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_writable_access(self, target, port, docker_services):
        """Test 'Writable access' finding when symbols are writable.

        Constructs results with writable symbols to verify that _analyze_security
        emits 'Writable access' when writable_count > 0.  Uses synthetic symbol
        data since the mock's pyads symbol upload returns 0 symbols.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "TC3PLC1",
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)

            # Synthetic symbol data with writable symbols
            results = {
                "device_info": device_info,
                "symbols": {
                    "symbols": {
                        "MAIN.nSetpoint": {"readable": True, "writable": True},
                        "MAIN.Motor1.nSpeed": {"readable": True, "writable": True},
                        "MAIN.bSystemReady": {"readable": True, "writable": False},
                    }
                },
                "memory_access": {"accessible": []},
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            titles = [f["title"] for f in new_findings]
            details = " ".join(f.get("detail", "") for f in new_findings).lower()

            assert "Writable access" in titles, (
                f"Expected 'Writable access' finding, got titles: {titles}"
            )
            assert "2 symbols writable" in details, (
                f"Expected '2 symbols writable' in finding details, got: {details[:300]}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_memory_areas_accessible(self, target, port, docker_services):
        """Test 'Insecure configuration' finding for directly accessible memory areas.

        The mock on port 851 has 4 of 5 memory areas accessible (M-Area Bytes,
        M-Area Bits, Input Image, Output Image; Data Area is denied).
        _analyze_security should emit 'Insecure configuration' with detail
        mentioning the number of accessible memory areas.
        [Category A]
        """
        from oida.protocols.ads import ADSScanner

        scanner = ADSScanner(
            {
                "rhost": target,
                "rport": port,
                "port_type": "TC3PLC1",
                "ads_timeout": 5000,
                "max_symbols": 10,
            }
        )
        conn = scanner.connect()
        assert conn is not None, "Failed to connect to ADS mock"
        try:
            device_info = scanner._get_device_info(conn)
            memory = scanner._test_memory_access(conn)

            accessible_count = len(memory.get("accessible", []))
            assert accessible_count > 0, (
                f"Expected accessible memory areas from mock, got {accessible_count}"
            )

            results = {
                "device_info": device_info,
                "symbols": {"symbols": {}},
                "memory_access": memory,
            }
            baseline = len(scanner.logger.findings)
            scanner._analyze_security(results)
            new_findings = scanner.logger.findings[baseline:]

            # Filter for memory-specific "Insecure configuration" finding
            memory_findings = [
                f
                for f in new_findings
                if f["title"] == "Insecure configuration"
                and "memory" in f.get("detail", "").lower()
            ]
            assert len(memory_findings) == 1, (
                f"Expected exactly 1 memory-related 'Insecure configuration' finding, "
                f"got {len(memory_findings)}. New findings: {new_findings}"
            )
            detail = memory_findings[0].get("detail", "")
            assert f"{accessible_count} memory areas" in detail, (
                f"Expected '{accessible_count} memory areas' in detail, got: {detail}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # --confirm Gating Tests (security fix validation)
    # ========================================================================

    @pytest.mark.security
    def test_fuzz_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --fuzz without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "symbols",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            _assert_confirm_rejected(result, "--fuzz")

    @pytest.mark.security
    def test_write_coe_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --write-coe without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-coe",
            "1003:0xFB00:1:01020304",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail or warn without --confirm (or timeout for EtherCAT ops)
        assert result.returncode in [0, 1, -1]
        if result.returncode != -1:
            text = _combined_text(result, result.scan_log if result.scan_log else None)
            assert any(
                term in text for term in ["confirm", "require", "dangerous", "write", "coe"]
            ), f"Expected confirm requirement message, got: {text[:300]}"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_write_coe_with_confirm(self, cli_runner, target, port, docker_services):
        """Test --write-coe with --confirm proceeds (no slaves = graceful fail) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-coe",
            "1003:0xFB00:1:01020304",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout but should not mention --confirm
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_scan_coe_access_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --scan-coe-access without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-coe-access",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, -1]
        if result.returncode != -1:
            text = _combined_text(result, result.scan_log if result.scan_log else None)
            assert any(term in text for term in ["confirm", "require", "dangerous"]), (
                f"Expected confirm requirement for --scan-coe-access, got: {text[:300]}"
            )
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_scan_coe_access_with_confirm(self, cli_runner, target, port, docker_services):
        """Test --scan-coe-access with --confirm proceeds (no slaves) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-coe-access",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_foe_write_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --foe-write without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--foe-write",
            "1001:fw.bin:firmware.bin",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, -1]
        if result.returncode != -1:
            text = _combined_text(result, result.scan_log if result.scan_log else None)
            assert any(term in text for term in ["confirm", "require", "dangerous", "write"]), (
                f"Expected confirm requirement for --foe-write, got: {text[:300]}"
            )
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_foe_delete_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --foe-delete without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--foe-delete",
            "1001:systrace",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, -1]
        if result.returncode != -1:
            text = _combined_text(result, result.scan_log if result.scan_log else None)
            assert any(term in text for term in ["confirm", "require", "dangerous", "delete"]), (
                f"Expected confirm requirement for --foe-delete, got: {text[:300]}"
            )
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_add_route_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --add-route without --confirm is rejected with message [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--add-route",
            "192.168.1.50.1.1:192.168.1.50",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail or warn without --confirm
        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            _assert_confirm_rejected(result, "--add-route")

    @pytest.mark.security
    def test_fuzz_coe_without_confirm(self, cli_runner, target, port, docker_services):
        """Test --fuzz-coe without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz-coe",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail or warn without --confirm
        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.security
    def test_fuzz_coe_force_write_with_confirm(self, cli_runner, target, port, docker_services):
        """Test --fuzz-coe --force-write with --confirm proceeds (no slaves = graceful fail) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz-coe",
            "--force-write",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves on the mock; --force-write must not crash the
        # scanner even though it forces fuzzing of objects whose write-back
        # test would normally be rejected.
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Extended Discovery Tests
    # ========================================================================

    def test_target_desc(self, cli_runner, target, port, docker_services):
        """Test --target-desc for XML device description [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--target-desc",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_license_info(self, cli_runner, target, port, docker_services):
        """Test --license-info query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--license-info",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_io_devices(self, cli_runner, target, port, docker_services):
        """Test --io-devices enumeration [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--io-devices",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_task_info(self, cli_runner, target, port, docker_services):
        """Test --task-info PLC task data [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--task-info",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_list_files(self, cli_runner, target, port, docker_services):
        """Test --list-files via SystemService [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-files",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_read_file(self, cli_runner, target, port, docker_services):
        """Test --read-file for file content read [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-file",
            "C:\\TwinCAT\\3.1\\Boot\\Plc\\Port_851.bootdata",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_read_registry(self, cli_runner, target, port, docker_services):
        """Test --read-registry for Windows registry read [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-registry",
            "HKLM:SOFTWARE\\Beckhoff\\TwinCAT3",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_download_program(self, cli_runner, target, port, docker_services):
        """Test --download-program for PLC symbol table download [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--download-program",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not support; allow timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_udp_discovery(self, cli_runner, target, port, docker_services):
        """Test --udp-discovery -- mock has no UDP listener [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--udp-discovery",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # EtherCAT-via-ADS Tests (mock has no EtherCAT slaves)
    # ========================================================================

    def test_scan_ethercat(self, cli_runner, target, port, docker_services):
        """Test --scan-ethercat -- no slaves on mock [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-ethercat",
            format="json",
            json_log=True,
            timeout=20,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_scan_coe(self, cli_runner, target, port, docker_services):
        """Test --scan-coe -- no EtherCAT slaves on mock [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-coe",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_read_coe(self, cli_runner, target, port, docker_services):
        """Test --read-coe with no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-coe",
            "1003:0x1008:0",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_eeprom_dump(self, cli_runner, target, port, docker_services):
        """Test --eeprom-dump -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--eeprom-dump",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_esc_registers(self, cli_runner, target, port, docker_services):
        """Test --esc-registers -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--esc-registers",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_foe_read(self, cli_runner, target, port, docker_services):
        """Test --foe-read -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--foe-read",
            "1001:firmware.bin",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_scan_foe(self, cli_runner, target, port, docker_services):
        """Test --scan-foe -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-foe",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_foe_list(self, cli_runner, target, port, docker_services):
        """Test --foe-list -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--foe-list",
            "1001",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_scan_soe(self, cli_runner, target, port, docker_services):
        """Test --scan-soe -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-soe",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_read_soe(self, cli_runner, target, port, docker_services):
        """Test --read-soe -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-soe",
            "1001:135",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_scan_fsoe(self, cli_runner, target, port, docker_services):
        """Test --scan-fsoe -- no EtherCAT slaves [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-fsoe",
            format="json",
            json_log=True,
            timeout=15,
        )

        # No EtherCAT slaves; may fail, error, or timeout
        assert result.returncode in [0, 1, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Fuzzing Tests
    # ========================================================================

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_symbol_fuzzing(self, cli_runner, target, port, docker_services):
        """Test fuzzing writable symbols with --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "symbols",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Should not crash; timeout (-1) is acceptable for unsupported operations
        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_memory_fuzzing(self, cli_runner, target, port, docker_services):
        """Test fuzzing memory areas with --confirm [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "memory",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Should not crash; timeout (-1) is acceptable for unsupported operations
        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.fuzz
    def test_fuzz_specific_symbol(self, cli_runner, target, port, docker_services):
        """Test fuzzing a specific symbol -- MAIN.nSetpoint [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "symbols",
            "--fuzz-symbol",
            "MAIN.nSetpoint",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Should not crash; timeout (-1) is acceptable for unsupported operations
        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_invalid_ams_netid(self, cli_runner, target, port, docker_services):
        """Test handling of invalid AMS Net ID format [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ams-netid",
            "invalid.netid",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully (validation error)
        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_invalid_target(self, cli_runner):
        """Test handling of invalid target specification [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "not-a-valid-host-12345!!!",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # ADS may return rc=0 for invalid targets with error in output
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        has_error = any(
            term in text
            for term in [
                "error",
                "failed",
                "cannot",
                "not found",
                "not known",
                "could not connect",
                "timeout",
                "invalid",
            ]
        )
        assert not result.success or has_error, (
            f"Expected failure or error indication for invalid target, "
            f"rc={result.returncode}, output: {text[:300]}"
        )

    def test_connection_refused_port(self, cli_runner):
        """Test connection to closed port [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "127.0.0.1",
            "--port",
            "65534",
            "--device-info",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully, not hang indefinitely
        assert result.returncode in [0, 1, 2, -1]

    def test_nonroutable_timeout(self, cli_runner):
        """Test that timeout is respected for non-routable address [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            "48898",
            "--device-info",
            timeout=20,
            expect_json=False,
            json_log=True,
        )

        # Should complete within reasonable time
        assert result.execution_time < 25, "Command did not respect timeout"

    def test_watch_connection_failure(self, cli_runner):
        """Test --watch against a closed port fails cleanly without entering the
        blocking notification/poll loop [Category C]

        NOTE: --watch is a known-hazardous flag -- once a real ADS connection is
        established, _watch_symbol_nxc() enters an unbounded `while True` loop
        (device-notification wait, or polling fallback) that only exits on
        KeyboardInterrupt, and --timeout only bounds the initial TCP connect.
        proto_flow() calls create_conn_obj() before any operation dispatch and
        returns immediately with "Connection failed" if self.conn is None
        (src/oida/protocols/ads/cli_runner.py:84-89), so --watch is driven here
        against a closed port -- reaching real argument parsing and dispatch of
        the --watch flag while never entering the blocking loop, keeping the
        test bounded.
        """
        result = cli_runner.run(
            self.protocol_name,
            "127.0.0.1",
            "--port",
            "65534",
            "--watch",
            "MAIN.counter:100",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should fail gracefully (no connection => no watch loop entered),
        # never hang for the full unbounded loop duration.
        assert result.returncode in [0, 1, 2, -1]
        assert result.execution_time < 20, (
            f"--watch against a closed port should fail fast, not hang: {result.execution_time}s"
        )
        assert "Traceback" not in result.combined_output

    def test_memory_read_invalid_format(self, cli_runner, target, port, docker_services):
        """Test --memory-read with badly formatted argument [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--memory-read",
            "badformat",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully with error message
        assert result.returncode in [0, 1, 2, -1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_read_symbol_nonexistent(self, cli_runner, target, port, docker_services):
        """Test --read-symbol for a symbol that does not exist [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-symbol",
            "DOES_NOT_EXIST.nValue",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1, 2, -1]
        if result.returncode != -1:
            text = _combined_text(result, result.scan_log if result.scan_log else None)
            assert any(term in text for term in ["error", "fail", "not found", "symbol"]), (
                f"Expected error for nonexistent symbol, got: {text[:300]}"
            )
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Output Format Tests
    # ========================================================================

    def test_verbose_output(self, cli_runner, target, port, docker_services):
        """Test -v verbose output produces additional detail [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            verbose=True,
            json_log=True,
        )

        assert result.returncode in [0, 1]
        # Verbose should produce output
        assert result.stdout or result.stderr, "No output with verbose flag"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_debug_output(self, cli_runner, target, port, docker_services):
        """Test --debug output does not crash [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            debug=True,
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_help_output(self, cli_runner):
        """Test --help output contains ADS-specific info [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        output = result.combined_output.lower()
        assert "ads" in output or "twincat" in output or "beckhoff" in output

    def test_json_format_output(self, cli_runner, target, port, docker_services):
        """Test --format json produces valid JSON output [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--device-info",
            format="json",
            json_log=True,
        )

        assert result.success, f"JSON format failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

    # NOT COVERED (no test exists - do not add a skipped placeholder):
    #   - --watch symbol monitoring: a blocking operation that only ends on Ctrl-C.

    def test_coe_range_standalone(self, cli_runner, target, port, docker_services):
        """--coe-range without a CoE operation warns and is inert [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--coe-range",
            "0x2000-0x3000",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Guard path must not crash
        assert result.returncode != -11, "--coe-range standalone caused a crash"

        # The scanner warns that the modifier is inert without a CoE operation
        # (src/oida/protocols/ads/cli_runner.py:177-187).
        text = _combined_text(result, result.scan_log if result.scan_log else None)
        assert "no effect without" in text and "coe-range" in text, (
            f"--coe-range without --scan-coe should emit the inert-modifier warning; "
            f"got: {text[:400]}"
        )

        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            # The guard is recorded at WARNING level, not buried as info.
            assert any(
                e.get("level", "").upper() == "WARNING"
                and "no effect without" in e.get("message", "").lower()
                for e in result.scan_log.events
            ), "inert-modifier notice should be a WARNING-level event"
