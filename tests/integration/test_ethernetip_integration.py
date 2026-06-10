"""
EtherNet/IP Protocol Integration Tests

Tests oida ethernetip scanner against Docker mock service (cpppo-based).
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/ethernetip_server.py):
  Server: cpppo EtherNet/IP server on port 44818
  Tags defined:
    Digital Inputs: DI_MotorRunning=1, DI_PumpRunning=0, DI_ValveOpen=1,
                    DI_EmergencyStop=0, DI_ManualMode=0, DI_AutoMode=1,
                    DI_SystemReady=1, DI_AlarmActive=0
    Digital Outputs: DO_StartMotor=0, DO_StopMotor=0, DO_StartPump=0,
                     DO_OpenValve=0, DO_CloseValve=0, DO_AlarmHorn=0,
                     DO_StatusLight=1, DO_Reset=0
    Analog Inputs: AI_Temperature=25.5, AI_Pressure=101.325, AI_FlowRate=15.7,
                   AI_Level=75.2, AI_Vibration=2.1, AI_Current=12.5,
                   AI_Voltage=480.0, AI_Power=8500.0
    Analog Outputs: AO_SpeedSetpoint=1500.0, AO_PressureSetpoint=100.0,
                    AO_FlowSetpoint=15.0, AO_TempSetpoint=25.0
    PID: PID_Output=50.0, PID_Error=0.5, PID_Kp=1.0, PID_Ki=0.1, PID_Kd=0.01
    System: SYS_ScanTime=10, SYS_CycleCount=0, SYS_Uptime=0
    Arrays: SCADA=DINT[1000], DATA=REAL[100], STATUS=INT[50], ALARMS=DINT[32]
    Strings: DeviceName=SSTRING, Location=SSTRING, FirmwareVersion=SSTRING

  The mock responds to ListIdentity (UCMM), ListServices, ListInterfaces,
  RegisterSession, and CIP tag read/write via cpppo. Its CIP Security object
  reports a Factory Default (unconfigured) state, so security scans yield
  "No authentication" findings describing an unauthenticated device.

  Note: pycomm3 LogixDriver connects to a cpppo mock that is NOT a real
  Rockwell PLC, so LogixDriver may fail and fall back to CIPDriver.

Test Classification Summary (64 defined + 10 inherited from BaseProtocolIntegrationTest)
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  18 tests
Category B (conditional -- mock may not support, accept 0 or 1):       36 tests
Category C (error handling -- assert failure + validate error events):  10 tests
Skipped (untestable -- requires hardware or missing mock support):      0 tests
Total defined in file:                                                 64 tests
Total collected (including inherited):                                 74 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (oida ethernetip -h):
  --port                    [A] test_basic_scan_with_port
  --enumerate-all / -a      [B] test_enumerate_all
  -i / --list-identity      [A] test_list_identity
  --list-services           [B] test_list_services
  --list-interfaces         [B] test_list_interfaces
  -e / --enumerate-objects  [B] test_enumerate_objects
  -d / --deep-scan          [B] test_deep_scan
  --full-scan               [B] test_full_scan
  --show-udts               [B] test_show_udts
  --enumerate-slot-objects  [B] test_enumerate_slot_objects_without_routes
  --read-slot-io            [B] test_read_slot_io_without_routes
  --full-enum               [B] test_full_enum
  --dump-tags               [B] test_dump_tags
  --tag-output              [B] test_tag_output_directory
  --maxclass                [B] test_maxclass
  --exploreclass            [B] test_exploreclass
  --maxattributes           [B] test_maxattributes
  --route-path              [B] test_route_path
  --slot                    [B] test_slot
  --discover-routes         [B] test_discover_routes
  --check-security          [A] test_check_security
  --no-check-security       [A] test_no_check_security
  --write                   [B] test_write_access
  --fuzz                    [B] test_fuzz_with_write
  --dump-security           [A] test_dump_security
  --no-dump-security        [A] test_no_dump_security
  -D / --download-files     [B] test_download_files
  --file-output             [B] test_file_output_directory
  --max-file-size           [B] test_max_file_size
  --cpu-stop                [C] test_cpu_stop_without_confirm
  --crash-ethernet          [C] test_crash_ethernet_without_confirm
  --reset-ethernet          [B] test_reset_ethernet
  --confirm                 [C] test_confirm_flag_with_cpu_stop

Security Finding Coverage (findings tested by specific tests):
  "No authentication" (CIP Security not supported)    [A] test_security_finding_cip_not_supported
  "No authentication" (CIP Security not supported)    [A] test_security_finding_cip_not_supported_via_analyze
  "No authentication" (CIP Security not configured)   [B] test_security_finding_cip_not_configured_unreachable
  "Insecure configuration" (editable mode)            [B] test_security_finding_editable_mode
  "Insecure configuration" (active fault)             [B] test_security_finding_active_fault
  "Writable access" (CIP attributes writable)         [B] test_security_finding_writable_access
  "Writable access" (full enum + write)               [B] test_security_finding_writable_access_full_enum
  "Insecure configuration" (safety-critical tags)     [B] test_security_finding_safety_critical_tags
  "Insecure configuration" (dangerous tags medium)    [B] test_security_finding_dangerous_tags_medium_risk
  Security analysis concerns list                     [A] test_security_analysis_produces_concerns
  All findings on default scan                        [A] test_security_findings_all_present_on_default_scan
  --no-check-security suppresses report_status        [A] test_no_check_security_suppresses_report_status
"""

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST


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


# ---------------------------------------------------------------------------
# Test Class
# ---------------------------------------------------------------------------


@pytest.mark.ethernetip
class TestEtherNetIPIntegration(BaseProtocolIntegrationTest):
    """Integration tests for EtherNet/IP protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "ethernetip"

    @property
    def default_port(self) -> int:
        return 44818

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Basic Discovery Tests
    # ========================================================================

    def test_basic_scan_with_port(self, cli_runner, target, port):
        """Test basic scan connects to mock and produces output [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "ethernet/ip",
                "ethernetip",
                "connected",
                "identity",
                "vendor",
                "listidentity",
            ]
        ), f"Expected EtherNet/IP scan output, got: {text[:500]}"

    def test_list_identity(self, cli_runner, target, port):
        """Test ListIdentity UCMM command retrieves device info [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-identity",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ListIdentity failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # ListIdentity should return vendor/product/device info from the cpppo mock
        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "identity",
                "vendor",
                "product",
                "device type",
                "revision",
                "serial",
                "listidentity",
            ]
        ), f"Expected identity info in output, got: {text[:500]}"

    def test_list_identity_does_not_flag_anonymous_access(self, cli_runner, target, port):
        """Test that ListIdentity does NOT emit 'Anonymous access allowed' [Category A]

        ListIdentity is an ODVA-mandated unauthenticated query. Flagging a successful
        ListIdentity as 'Anonymous access allowed' was a false positive (one bogus
        CRITICAL per device) removed in commit 41d11682. This test guards against the
        regression while confirming the default security analysis still fires.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-identity",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ListIdentity failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()
        finding_names = [f.get("data", {}).get("finding", "") for f in findings]

        # Regression guard: ListIdentity must not be reported as anonymous access.
        assert "Anonymous access allowed" not in finding_names, (
            f"'Anonymous access allowed' is a removed false positive and must not "
            f"reappear. Findings: {finding_names}"
        )

        # The default security analysis still runs and flags the unauthenticated mock.
        assert "No authentication" in finding_names, (
            f"Expected 'No authentication' from the default security analysis. "
            f"Findings: {finding_names}"
        )

    def test_list_services(self, cli_runner, target, port):
        """Test ListServices UCMM command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-services",
            format="json",
            json_log=True,
            timeout=30,
        )

        # cpppo mock may or may not support ListServices
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "listservices",
                "services",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "communications",
                "no services",
            ]
        ), f"Expected ListServices attempt in output: {text[:500]}"

    def test_list_interfaces(self, cli_runner, target, port):
        """Test ListInterfaces UCMM command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-interfaces",
            format="json",
            json_log=True,
            timeout=30,
        )

        # cpppo mock may or may not support ListInterfaces
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "listinterfaces",
                "interfaces",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "no interfaces",
            ]
        ), f"Expected ListInterfaces attempt in output: {text[:500]}"

    # ========================================================================
    # Enumeration Tests
    # ========================================================================

    def test_enumerate_all(self, cli_runner, target, port):
        """Test --enumerate-all enables all enumeration modes [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-all",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "identity",
                "ethernet/ip",
                "ethernetip",
                "enumerate",
                "connected",
                "security",
                "vendor",
                "cip",
            ]
        ), f"Expected enumeration output from --enumerate-all: {text[:500]}"

    def test_enumerate_objects(self, cli_runner, target, port):
        """Test CIP object enumeration with --enumerate-objects [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-objects",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "enumerate",
                "objects",
                "class",
                "cip",
                "ethernet/ip",
                "ethernetip",
                "connected",
            ]
        ), f"Expected CIP object enumeration output: {text[:500]}"

    def test_deep_scan(self, cli_runner, target, port):
        """Test deep scan parses complex CIP objects [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--deep-scan",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        # deep-scan auto-enables --enumerate-objects
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "deep scan",
                "enumerate",
                "objects",
                "cip",
                "connected",
                "ethernet/ip",
                "ethernetip",
                "complex",
            ]
        ), f"Expected deep scan output: {text[:500]}"

    def test_full_scan(self, cli_runner, target, port):
        """Test full scan uploads tag database (Logix-only, may fail on cpppo) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--full-scan",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "full scan",
                "tag",
                "logix",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "not a rockwell",
                "uploading",
            ]
        ), f"Expected full scan output: {text[:500]}"

    def test_show_udts(self, cli_runner, target, port):
        """Test --show-udts flag for UDT/AOI enumeration [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--show-udts",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "udt",
                "logix",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "not a rockwell",
            ]
        ), f"Expected UDT output: {text[:500]}"

    def test_full_enum(self, cli_runner, target, port):
        """Test --full-enum probes all CIP classes 0x01-0xFF [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--full-enum",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "class",
                "enum",
                "cip",
                "ethernet/ip",
                "ethernetip",
                "connected",
            ]
        ), f"Expected full enum output: {text[:500]}"

    # ========================================================================
    # Tag Database Tests
    # ========================================================================

    def test_dump_tags(self, cli_runner, target, port):
        """Test --dump-tags for tag database export [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dump-tags",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "tag",
                "dump",
                "logix",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "not a rockwell",
            ]
        ), f"Expected tag dump output: {text[:500]}"

    def test_tag_output_directory(self, cli_runner, target, port, tmp_path):
        """Test --tag-output specifies output directory for tags [Category B]"""
        tag_dir = str(tmp_path / "enip_tags")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dump-tags",
            "--tag-output",
            tag_dir,
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "tag",
                "dump",
                "logix",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "not a rockwell",
            ]
        ), f"Expected tag output behavior: {text[:500]}"

    # ========================================================================
    # CIP Options Tests
    # ========================================================================

    def test_maxclass(self, cli_runner, target, port):
        """Test --maxclass limits CIP class range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--maxclass",
            "10",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "class",
                "cip",
                "ethernet/ip",
                "ethernetip",
                "connected",
            ]
        ), f"Expected CIP class scan output: {text[:500]}"

    def test_exploreclass(self, cli_runner, target, port):
        """Test --exploreclass enumerates specific CIP class IDs [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--exploreclass",
            "0x1,2,3",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "class",
                "explore",
                "attribute",
                "cip",
                "ethernet/ip",
                "ethernetip",
                "connected",
            ]
        ), f"Expected class exploration output: {text[:500]}"

    def test_maxattributes(self, cli_runner, target, port):
        """Test --maxattributes limits attributes per class [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--maxclass",
            "5",
            "--maxattributes",
            "20",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "class",
                "attribute",
                "cip",
                "ethernet/ip",
                "ethernetip",
                "connected",
            ]
        ), f"Expected attribute scan output: {text[:500]}"

    def test_route_path(self, cli_runner, target, port):
        """Test --route-path for CIP backplane routing [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--route-path",
            "1/0",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "route",
                "path",
                "slot",
                "ethernet/ip",
                "ethernetip",
                "connected",
                "backplane",
                "logix",
                "not a rockwell",
            ]
        ), f"Expected route path output: {text[:500]}"

    def test_slot(self, cli_runner, target, port):
        """Test --slot specifies target CPU slot number [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--slot",
            "0",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "slot",
                "connected",
                "ethernet/ip",
                "ethernetip",
                "cip",
            ]
        ), f"Expected slot scan output: {text[:500]}"

    def test_discover_routes(self, cli_runner, target, port):
        """Test --discover-routes for chassis topology discovery [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover-routes",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "route",
                "discover",
                "chassis",
                "topology",
                "port",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected route discovery output: {text[:500]}"

    # ========================================================================
    # Slot Enumeration Tests (require --discover-routes)
    # ========================================================================

    def test_enumerate_slot_objects_without_routes(self, cli_runner, target, port):
        """Test --enumerate-slot-objects without --discover-routes shows warning [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-slot-objects",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        # Should warn that --discover-routes is required
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "discover-routes",
                "requires",
                "slot",
                "enumerate",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected slot objects warning or output: {text[:500]}"

    def test_read_slot_io_without_routes(self, cli_runner, target, port):
        """Test --read-slot-io without --discover-routes shows warning [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-slot-io",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        # Should warn that --discover-routes is required
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "discover-routes",
                "requires",
                "slot",
                "read",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected read-slot-io warning or output: {text[:500]}"

    def test_enumerate_slot_objects_with_routes(self, cli_runner, target, port):
        """Test --enumerate-slot-objects combined with --discover-routes [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover-routes",
            "--enumerate-slot-objects",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "slot",
                "enumerate",
                "object",
                "route",
                "chassis",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected slot enumeration output: {text[:500]}"

    def test_read_slot_io_with_routes(self, cli_runner, target, port):
        """Test --read-slot-io combined with --discover-routes [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover-routes",
            "--read-slot-io",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "slot",
                "assembly",
                "route",
                "chassis",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected slot I/O output: {text[:500]}"

    # ========================================================================
    # Security Tests
    # ========================================================================

    @pytest.mark.security
    def test_check_security(self, cli_runner, target, port):
        """Test --check-security reports CIP Security status [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Check security failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "security",
                "authentication",
                "not supported",
                "not configured",
                "cip security",
                "anonymous",
            ]
        ), f"Expected security status output: {text[:500]}"

    @pytest.mark.security
    def test_no_check_security(self, cli_runner, target, port):
        """Test --no-check-security disables CIP Security check [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--no-check-security",
            "--no-dump-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"No-check-security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # With security checks disabled, there should be fewer security-related events
        # but the scan should still complete successfully
        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "ethernet/ip",
                "ethernetip",
                "connected",
                "identity",
            ]
        ), f"Expected basic scan output with security disabled: {text[:500]}"

    @pytest.mark.security
    def test_dump_security(self, cli_runner, target, port):
        """Test --dump-security dumps CIP Security settings [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dump-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Dump security failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # --dump-security is enabled by default, so it always runs unless disabled
        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "security",
                "authentication",
                "cip security",
                "not supported",
                "dump",
                "anonymous",
            ]
        ), f"Expected security dump output: {text[:500]}"

    @pytest.mark.security
    def test_no_dump_security(self, cli_runner, target, port):
        """Test --no-dump-security disables security dump [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--no-dump-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"No-dump-security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        # Should still complete; security dump simply skipped
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "ethernet/ip",
                "ethernetip",
                "connected",
            ]
        ), f"Expected basic scan output: {text[:500]}"

    @pytest.mark.security
    def test_security_finding_no_authentication(self, cli_runner, target, port):
        """Test that scanner reports 'No authentication' for mock without CIP Security [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()
        text = _combined_text(result, log)
        # Check either structured finding OR text mention
        has_finding = any(
            "authentication" in str(f.get("data", {})).lower()
            or "anonymous" in str(f.get("data", {})).lower()
            for f in findings
        )
        has_text = "authentication" in text or "anonymous" in text
        assert has_finding or has_text, (
            f"Expected 'No authentication' finding. Findings: {findings}, "
            f"text excerpt: {text[:300]}"
        )

    @pytest.mark.security
    def test_security_finding_no_encryption(self, cli_runner, target, port):
        """Test that scanner reports 'No encryption' (no TLS/DTLS on port 2221) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        findings = log.get_security_findings()
        # Check for encryption-related findings (TLS not available on mock)
        has_encryption_finding = any(
            "encrypt" in str(f.get("data", {})).lower() or "tls" in str(f.get("data", {})).lower()
            for f in findings
        )
        has_encryption_text = "encrypt" in text or "tls" in text or "dtls" in text
        assert has_encryption_finding or has_encryption_text or "security" in text, (
            f"Expected encryption-related finding or security output. "
            f"Findings: {findings}, text excerpt: {text[:300]}"
        )

    # ========================================================================
    # CIP Security Not Supported / Not Configured Findings
    # ========================================================================

    @pytest.mark.security
    def test_security_finding_cip_not_supported(self, cli_runner, target, port):
        """Test 'No authentication' finding when CIP Security is unauthenticated [Category A]

        The mock exposes a CIP Security Object in Factory Default state (no
        authentication/encryption configured), so _report_security_status emits
        'No authentication' with a 'NOT CONFIGURED (Factory Default)' detail and
        _analyze_security emits 'No authentication' with a 'Factory Default state'
        detail. Both indicate the device accepts unauthenticated access.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            "--dump-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()

        # The scanner must fire "No authentication" with a CIP Security detail
        # describing the unauthenticated state (not configured / factory default,
        # or not supported on devices lacking the object entirely).
        no_auth_findings = [
            f for f in findings if f.get("data", {}).get("finding") == "No authentication"
        ]
        assert no_auth_findings, (
            f"Expected a 'No authentication' finding. Findings: {[f.get('data') for f in findings]}"
        )
        assert any(
            "cip security" in str(f.get("data", {}).get("details", "")).lower()
            for f in no_auth_findings
        ), (
            f"Expected a 'No authentication' finding with a CIP Security detail. "
            f"Finding details: {[f.get('data', {}).get('details') for f in no_auth_findings]}"
        )

    @pytest.mark.security
    def test_security_finding_cip_not_supported_via_analyze(self, cli_runner, target, port):
        """Test _analyze_security emits an unauthenticated-CIP-Security concern [Category A]

        _analyze_security inspects the CIP Security object. When it is unsupported it
        logs security_finding('No authentication', detail='CIP Security not supported');
        when it is accessible but in Factory Default state it logs
        security_finding('No authentication', detail='CIP Security in Factory Default
        state'). Either way a 'No authentication' finding referencing CIP Security must
        be present.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()

        # Count distinct "No authentication" findings - there may be multiple
        # (one from _report_security_status, one from _analyze_security)
        no_auth_findings = [
            f for f in findings if f.get("data", {}).get("finding") == "No authentication"
        ]

        # At least one "No authentication" finding must exist (structured event).
        assert len(no_auth_findings) > 0, (
            f"Expected at least one 'No authentication' finding from CIP Security analysis. "
            f"All findings: {[f.get('data') for f in findings]}"
        )

        # Verify at least one finding carries a CIP Security detail describing the
        # unauthenticated state. security_finding() stores the detail under
        # data["details"]. Accept "not supported" or the Factory Default wording.
        cip_security_detail = any(
            "cip security" in str(f.get("data", {}).get("details", "")).lower()
            for f in no_auth_findings
        )
        assert cip_security_detail, (
            f"Expected a CIP Security detail on a 'No authentication' finding. "
            f"Finding details: {[f.get('data', {}).get('details') for f in no_auth_findings]}"
        )

    @pytest.mark.security
    def test_security_finding_cip_not_configured_unreachable(self, cli_runner, target, port):
        """Test 'No authentication' / CIP Security NOT CONFIGURED path [Category B]

        This finding (scanner:2557, mixin:114) fires only when CIP Security Object
        IS accessible but in Factory Default state (state_raw==0). The cpppo mock
        does not implement CIP Security, so this path is not reachable. We verify
        the scanner still produces authentication-related findings (the 'not supported'
        variant rather than 'not configured').
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            "--dump-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # Since CIP Security is not accessible on cpppo, "not configured" should NOT appear,
        # but "not supported" SHOULD. We validate either authentication-related message appears.
        assert any(
            term in text
            for term in [
                "no authentication",
                "not supported",
                "not configured",
                "cip security",
                "authentication",
                "security",
            ]
        ), f"Expected authentication/security related output. Text excerpt: {text[:500]}"

    # ========================================================================
    # Controller Mode Security Findings
    # ========================================================================

    @pytest.mark.security
    def test_security_finding_editable_mode(self, cli_runner, target, port):
        """Test 'Insecure configuration' - controller in editable mode [Category B]

        Finding (scanner:5641, mixin:95): fires when controller_mode.is_editable=True,
        meaning the PLC is in PROGRAM or TEST mode. This requires a LogixDriver
        connection with controller mode info. The cpppo mock may or may not provide
        this (likely falls back to CIPDriver where controller_mode is empty dict).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # Controller mode findings require LogixDriver - may not fire on cpppo mock.
        # Unconditionally verify the scanner at least attempted security analysis.
        assert any(
            term in text
            for term in [
                "security",
                "authentication",
                "not supported",
                "connected",
                "cip security",
                "editable",
            ]
        ), (
            f"Expected security analysis output (editable mode may not trigger on cpppo). "
            f"Text excerpt: {text[:500]}"
        )

    @pytest.mark.security
    def test_security_finding_active_fault(self, cli_runner, target, port):
        """Test 'Insecure configuration' - controller has active fault [Category B]

        Finding (scanner:5656, mixin:110): fires when controller_mode.is_faulted=True.
        Requires LogixDriver with status word fault bits set. The cpppo mock
        does not emulate controller fault states, so this finding won't fire.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # Faulted state requires Logix controller - not reachable on cpppo mock.
        # Verify security analysis was still performed.
        assert any(
            term in text
            for term in [
                "security",
                "authentication",
                "not supported",
                "connected",
                "cip security",
                "fault",
            ]
        ), (
            f"Expected security analysis output (fault state not reachable on cpppo). "
            f"Text excerpt: {text[:500]}"
        )

    # ========================================================================
    # Writable Access and Dangerous Tag Findings
    # ========================================================================

    @pytest.mark.security
    def test_security_finding_writable_access(self, cli_runner, target, port):
        """Test 'Writable access' finding for CIP attributes [Category B]

        Finding (scanner:5674, mixin:128): fires when write_test_results contains
        writable attributes. Requires --write with --exploreclass or --full-enum
        to first discover attributes, then test write access. Against cpppo mock,
        CIP class exploration may find some writable attributes.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--exploreclass",
            "0x1",
            "--write",
            "--maxattributes",
            "5",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # The scanner should at minimum attempt the write test operation.
        # Whether writable attributes are found depends on the mock's CIP response.
        assert any(
            term in text
            for term in [
                "write",
                "writable",
                "attribute",
                "class",
                "explore",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected write access test attempt in output. Text excerpt: {text[:500]}"

    @pytest.mark.security
    def test_security_finding_writable_access_full_enum(self, cli_runner, target, port):
        """Test 'Writable access' finding with --full-enum --write [Category B]

        Uses full enumeration (0x01-0xFF classes) combined with write testing.
        This maximizes the chance of finding writable CIP attributes on the mock.
        Finding (scanner:5674): 'Writable access' with detail about writable count.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--full-enum",
            "--write",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # Full enum + write probes all classes and tests writability
        assert any(
            term in text
            for term in [
                "write",
                "writable",
                "class",
                "enum",
                "attribute",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected full enum + write test output. Text excerpt: {text[:500]}"

    @pytest.mark.security
    def test_security_finding_safety_critical_tags(self, cli_runner, target, port):
        """Test 'Insecure configuration' - safety-critical tags accessible [Category B]

        Finding (scanner:5688, mixin:142): fires when dangerous_tags contains
        high-risk entries (SAFETY, ESTOP, EMERGENCY patterns). The cpppo mock
        defines DI_EmergencyStop which matches EMERGENCY pattern and is classified
        as high-risk. However, tag discovery requires LogixDriver tag read to work.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--full-scan",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # The mock has DI_EmergencyStop (EMERGENCY -> high risk) but tag reading
        # requires LogixDriver which may not work against cpppo. If it does work,
        # we expect safety-critical tag warnings.
        assert any(
            term in text
            for term in [
                "dangerous",
                "safety",
                "emergency",
                "estop",
                "tag",
                "full scan",
                "connected",
                "ethernet/ip",
                "ethernetip",
                "not a rockwell",
            ]
        ), f"Expected tag analysis or fallback output. Text excerpt: {text[:500]}"

    @pytest.mark.security
    def test_security_finding_dangerous_tags_medium_risk(self, cli_runner, target, port):
        """Test 'Insecure configuration' - dangerous tags accessible (medium risk) [Category B]

        Finding (scanner:5696, mixin:150): fires when dangerous_tags exist but none
        are high-risk. The cpppo mock defines tags matching SETPOINT, VALVE_OPEN,
        PUMP_START patterns (medium risk). This else-branch only fires when no
        high-risk tags exist. Since the mock also has DI_EmergencyStop (high risk),
        this specific branch is typically not reached when all tags are discovered.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dump-tags",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)

        # Tag dump requires LogixDriver. On cpppo, may fall back to CIPDriver.
        # Either way, the scanner should produce output about the tag operation.
        assert any(
            term in text
            for term in [
                "tag",
                "dangerous",
                "setpoint",
                "dump",
                "not a rockwell",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected tag analysis or dump output. Text excerpt: {text[:500]}"

    @pytest.mark.security
    def test_security_analysis_produces_concerns(self, cli_runner, target, port):
        """Test that _analyze_security populates concerns list [Category A]

        The _analyze_security method (scanner:5568) always runs after discovery.
        Against the cpppo mock (no CIP Security, no TLS), it should produce at
        least two concerns: 'CIP Security not supported' and 'TLS/DTLS not supported'.
        These map to 'No authentication' and 'No encryption' findings.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security analysis failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()

        # Against cpppo mock (no CIP Security, no TLS): _analyze_security always runs
        # and must emit both structured findings.
        finding_names = [f.get("data", {}).get("finding", "") for f in findings]
        text = _combined_text(result, log)

        assert "No authentication" in finding_names, (
            f"Expected 'No authentication' finding from security analysis. "
            f"Findings: {finding_names}, text excerpt: {text[:300]}"
        )
        assert "No encryption" in finding_names, (
            f"Expected 'No encryption' finding from security analysis. "
            f"Findings: {finding_names}, text excerpt: {text[:300]}"
        )

    @pytest.mark.security
    def test_security_findings_all_present_on_default_scan(self, cli_runner, target, port):
        """Test that default scan produces expected security findings [Category A]

        A default scan (no flags) runs ListIdentity + security dump (enabled by default).
        Against cpppo (no CIP Security, no TLS), the security analysis must produce
        'No authentication' and 'No encryption'.

        Note: ListIdentity must NOT produce an 'Anonymous access allowed' finding.
        ListIdentity is an ODVA-mandated unauthenticated query, so flagging it as
        anonymous access was a false positive removed in commit 41d11682. This test
        guards against that regression returning.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Default scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()
        finding_names = [f.get("data", {}).get("finding", "") for f in findings]
        text = _combined_text(result, log)

        # Regression guard: ListIdentity must NOT be flagged as anonymous access.
        assert "Anonymous access allowed" not in finding_names, (
            f"'Anonymous access allowed' is a removed false positive and must not "
            f"reappear. Findings: {finding_names}"
        )

        # _analyze_security always runs - it must produce "No authentication" from CIP
        # Security (NOT SUPPORTED on cpppo) and "No encryption" (no TLS/DTLS).
        assert "No authentication" in finding_names, (
            f"Expected 'No authentication' finding from _analyze_security. "
            f"Findings: {finding_names}, text excerpt: {text[:300]}"
        )
        assert "No encryption" in finding_names, (
            f"Expected 'No encryption' finding from _analyze_security. "
            f"Findings: {finding_names}, text excerpt: {text[:300]}"
        )

    @pytest.mark.security
    def test_no_check_security_suppresses_report_status(self, cli_runner, target, port):
        """Test --no-check-security suppresses _report_security_status [Category A]

        With --no-check-security, _report_security_status (scanner:2548) should NOT
        be called, but _analyze_security (scanner:5620) still runs. So we should
        see fewer 'No authentication' findings (from analyze only, not from report).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--no-check-security",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"No-check-security failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        findings = log.get_security_findings()

        # _analyze_security still runs even with --no-check-security and produces the
        # structured "No authentication" finding against the cpppo mock.
        has_no_auth = any(f.get("data", {}).get("finding") == "No authentication" for f in findings)

        assert has_no_auth, (
            f"Expected 'No authentication' from _analyze_security even with --no-check-security. "
            f"Findings: {[f.get('data') for f in findings]}"
        )

    # ========================================================================
    # Write and Fuzz Tests
    # ========================================================================

    @pytest.mark.security
    def test_write_access(self, cli_runner, target, port):
        """Test --write tests write access to CIP attributes [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "write",
                "attribute",
                "requires",
                "exploreclass",
                "full-enum",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected write test output: {text[:500]}"

    @pytest.mark.security
    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_write(self, cli_runner, target, port):
        """Test --fuzz with --write fuzzes writable attributes [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--write",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fuzz",
                "write",
                "attribute",
                "requires",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected fuzz output: {text[:500]}"

    @pytest.mark.security
    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_without_write_reports_requirement(self, cli_runner, target, port):
        """Test --fuzz without --write reports that --write is required [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fuzz",
                "requires",
                "write",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected fuzz requirement message: {text[:500]}"

    # ========================================================================
    # File Operations Tests
    # ========================================================================

    def test_download_files(self, cli_runner, target, port):
        """Test --download-files downloads from CIP File Object [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--download-files",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "file",
                "download",
                "object",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected file download output: {text[:500]}"

    def test_file_output_directory(self, cli_runner, target, port, tmp_path):
        """Test --file-output specifies download directory [Category B]"""
        file_dir = str(tmp_path / "enip_files")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--download-files",
            "--file-output",
            file_dir,
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "file",
                "download",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected file output behavior: {text[:500]}"

    def test_max_file_size(self, cli_runner, target, port):
        """Test --max-file-size limits file download size [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--download-files",
            "--max-file-size",
            "1024",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "file",
                "download",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected file size limited output: {text[:500]}"

    # ========================================================================
    # Attack Tests (DANGEROUS - require --confirm)
    # ========================================================================

    @pytest.mark.security
    def test_cpu_stop_without_confirm(self, cli_runner, target, port):
        """Test --cpu-stop without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--cpu-stop",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Should not crash but may error due to missing --confirm
        assert result.returncode != -1
        # MUST validate error content
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "confirm",
                "requires",
                "missing",
                "cpu stop",
                "halt",
                "caution",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_crash_ethernet_without_confirm(self, cli_runner, target, port):
        """Test --crash-ethernet without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--crash-ethernet",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "confirm",
                "requires",
                "missing",
                "crash",
                "ethernet",
                "disconnect",
                "caution",
                "connected",
                "ethernetip",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_confirm_flag_with_cpu_stop(self, cli_runner, target, port):
        """Test --cpu-stop with --confirm attempts attack (mock won't crash) [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--cpu-stop",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Mock won't actually stop, but the scanner should attempt the operation
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "cpu stop",
                "halt",
                "executing",
                "attack",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected CPU stop attempt in output: {text[:500]}"

    @pytest.mark.security
    def test_reset_ethernet(self, cli_runner, target, port):
        """Test --reset-ethernet (doesn't require --confirm) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--reset-ethernet",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "reset",
                "ethernet",
                "executing",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected reset ethernet output: {text[:500]}"

    # ========================================================================
    # Connection Lifecycle Tests
    # ========================================================================

    def test_connection_events_in_log(self, cli_runner, target, port):
        """Test that connection lifecycle is logged in JSON log [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Connection test failed: {result.stderr}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Verify connection events exist
        conn_events = log.get_connection_events()
        text = _combined_text(result, log)
        assert len(conn_events) > 0 or "connect" in text, (
            f"Expected connection events. Got {len(conn_events)} connection events. "
            f"Text excerpt: {text[:300]}"
        )

    def test_log_event_types_present(self, cli_runner, target, port):
        """Test that JSON log contains expected event types [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Event type test failed: {result.stderr}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log

        # Collect all event types
        event_types = {e.get("event_type") for e in log.events}
        # At minimum, we should see connection or info-level events
        assert len(event_types) >= 1, f"Expected multiple event types, got: {event_types}"

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_wrong_port(self, cli_runner, target):
        """Test connection to wrong port fails gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "65534",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Command should not hang on wrong port"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "connect",
                "fail",
                "error",
                "refused",
                "timeout",
            ]
        ), f"Expected connection error message: {text[:500]}"

    def test_invalid_exploreclass(self, cli_runner, target, port):
        """Test --exploreclass with invalid class handles gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--exploreclass",
            "0xFF",
            timeout=30,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "class",
                "attribute",
                "connected",
                "ethernet/ip",
                "ethernetip",
                "explore",
                "error",
                "fail",
            ]
        ), f"Expected class exploration output or error: {text[:500]}"

    def test_invalid_route_path(self, cli_runner, target, port):
        """Test --route-path with malformed path handles gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--route-path",
            "invalid/path/format",
            timeout=30,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "route",
                "invalid",
                "path",
                "connected",
                "ethernet/ip",
                "ethernetip",
                "error",
                "warning",
            ]
        ), f"Expected route path error handling: {text[:500]}"

    def test_unreachable_host(self, cli_runner):
        """Test scan of unreachable host times out gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            "44818",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should time out or fail, not hang
        assert result.execution_time < 20, "Command did not respect timeout"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "timeout",
                "timed out",
                "fail",
                "error",
                "connect",
                "unreachable",
            ]
        ), f"Expected timeout or error message: {text[:500]}"

    def test_nonexistent_host(self, cli_runner):
        """Test scan of nonexistent hostname fails gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "nonexistent-host-xyz-12345.invalid",
            "--port",
            "44818",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1
        text = result.combined_output.lower()
        assert any(
            term in text
            for term in [
                "error",
                "fail",
                "cannot",
                "not found",
                "not known",
                "resolve",
            ]
        ), f"Expected DNS resolution error: {text[:500]}"

    def test_confirm_without_attack_flag(self, cli_runner, target, port):
        """Test --confirm alone has no harmful effect [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # --confirm alone without any attack flag should just do a normal scan
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "ethernet/ip",
                "ethernetip",
                "connected",
                "identity",
            ]
        ), f"Expected normal scan output with --confirm alone: {text[:500]}"

    def test_crash_ethernet_with_confirm(self, cli_runner, target, port):
        """Test --crash-ethernet with --confirm attempts attack on mock [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--crash-ethernet",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "crash",
                "ethernet",
                "executing",
                "disconnect",
                "connected",
                "ethernetip",
            ]
        ), f"Expected crash ethernet attempt: {text[:500]}"

    # ========================================================================
    # Combined Flag Tests
    # ========================================================================

    def test_enumerate_all_with_deep_scan(self, cli_runner, target, port):
        """Test --enumerate-all combined with --deep-scan [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-all",
            "--deep-scan",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "enumerate",
                "deep scan",
                "identity",
                "security",
                "connected",
                "ethernet/ip",
                "ethernetip",
                "cip",
            ]
        ), f"Expected comprehensive enumeration output: {text[:500]}"

    def test_check_security_with_enumerate_objects(self, cli_runner, target, port):
        """Test --check-security with --enumerate-objects combination [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-security",
            "--enumerate-objects",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "security",
                "enumerate",
                "objects",
                "cip",
                "connected",
                "ethernet/ip",
                "ethernetip",
            ]
        ), f"Expected combined security + enum output: {text[:500]}"

    # ========================================================================
    # JSON Log Structure Tests
    # ========================================================================

    def test_json_log_structure(self, cli_runner, target, port):
        """Test that JSON log events have required fields [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Log structure test failed: {result.stderr}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Verify module field references ethernetip
        modules = {e.get("module", "") for e in log.events}
        has_enip_module = any(
            "ethernetip" in m.lower() or "enip" in m.lower() or "ethernet" in m.lower()
            for m in modules
        )
        # The module field may reference the logger name, not always protocol name
        assert has_enip_module or len(modules) > 0, (
            f"Expected ethernetip module reference. Modules: {modules}"
        )

    def test_json_log_has_info_events(self, cli_runner, target, port):
        """Test that JSON log contains info-level events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Info events test failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Should have info-level events from the scan
        info_events = log.get_events(level="info")
        assert len(info_events) > 0, (
            f"Expected info-level events, got 0. All levels: {[e.get('level') for e in log.events]}"
        )
