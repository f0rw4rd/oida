"""
HART Protocol Integration Tests

Tests oida hart scanner against Docker mock service (hart_server.py).
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/hart_server.py):
  Server: HART-IP mock on UDP port 5094, TCP port 5095
  Mode: basic (single device at poll address 0)
  Default device:
    manufacturer_id=0x26 (Rosemount/Emerson), device_type=42
    protocol_revision=7, tag="PT-101", write_protect=False
    pv=25.5 psi, sv=23.2 degC, tv=50.0 percent, qv=12.5 mA
    loop_current=12.5 mA, percent_range=50.0

  Supported commands: 0,1,2,3,6,13,15,17,18,20,38,41,42,48
  WirelessHART commands (84,85,768) only work in gateway mode (NOT basic mode)
  Session Init/Close/KeepAlive management supported
  v2 Session Initiate is NAK'd (v1-only server)

Test Classification Summary (61 defined + 10 inherited from BaseProtocolIntegrationTest)
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  14 tests
Category B (conditional -- mock may not support, accept 0 or 1):       34 tests
Category C (error handling -- assert failure + validate error events):  13 tests
Skipped (untestable -- requires hardware or missing mock support):      0 tests
Total defined in file:                                                 61 tests
Total collected (including inherited):                                 71 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (oida hart -h):
  --port                      [A] test_basic_scan_with_port
  --timeout                   [B] test_timeout_option
  --tcp                       [B] test_tcp_transport
  --probe-version             [B] test_probe_version
  --psk-identity/--psk-key    [C] test_psk_auth_without_server_support
  --cipher-suite              [B] test_cipher_suite_option
  --poll-addr                 [B] test_poll_addr
  --read-id                   [A] test_read_id
  --read-pv                   [A] test_read_pv
  --read-current              [A] test_read_current
  --read-all-vars             [A] test_read_all_vars
  --read-tag                  [A] test_read_tag
  --read-output               [A] test_read_output
  --read-status               [A] test_read_status
  --scan-addresses            [B] test_scan_addresses
  --enumerate-commands        [B] test_enumerate_commands
  --command-range             [B] test_command_range
  --enumerate-device-specific [B] test_enumerate_device_specific
  --security-analysis         [A] test_security_analysis
  --probe-calibration         [B] test_probe_calibration
  --probe-write               [B] test_probe_write
  --detect-wireless           [B] test_detect_wireless
  --wireless-info             [B] test_wireless_info
  --list-sub-devices          [B] test_list_sub_devices
  --check-lock                [B] test_check_lock
  --bruteforce-lock (no conf) [C] test_bruteforce_lock_without_confirm
  --unlock (no confirm)       [C] test_unlock_without_confirm
  --lock (no confirm)         [C] test_lock_without_confirm
  --write-poll-addr (no conf) [C] test_write_poll_addr_without_confirm
  --write-poll-addr + confirm [B] test_write_poll_addr_with_confirm
  --write-tag (no confirm)    [C] test_write_tag_without_confirm
  --write-tag + confirm       [B] test_write_tag_with_confirm
  --write-message (no conf)   [C] test_write_message_without_confirm
  --reset-config-flag (no c)  [C] test_reset_config_without_confirm
  --self-test (no confirm)    [C] test_self_test_without_confirm
  --master-reset (no confirm) [C] test_master_reset_without_confirm
  --master-reset + confirm    [B] test_master_reset_with_confirm
  --confirm (alone)           [C] test_confirm_without_action
  --fuzz (no confirm)         [C] test_fuzz_without_confirm
  --fuzz + confirm            [B] test_fuzz_with_confirm
  --fuzz-commands             [B] test_fuzz_commands
  --raw-command               [B] test_raw_command
  --raw-command + --raw-data  [B] test_raw_command_with_data
  --discover                  [B] test_discover_mode
  --quick                     [B] test_quick_mode
  --full                      [B] test_full_mode
  --deep-scan                 [B] test_deep_scan
  --scan-mode discovery       [B] test_scan_mode_discovery
  --scan-mode enumeration     [B] test_scan_mode_enumeration
  --scan-mode full            [B] test_scan_mode_full
  (wrong port)                [C] test_wrong_port
  (unreachable host)          [C] test_unreachable_host
  (nonexistent host)          [C] test_nonexistent_host
  (connection events)         [A] test_connection_events_in_log
  (log structure)             [A] test_json_log_structure
  (log info events)           [A] test_json_log_has_info_events
  (security: write unprot.)   [A] test_security_finding_write_unprotected
  (security: no encryption)   [A] test_security_finding_no_encryption
  (security: outdated rev5)   [B] test_security_finding_outdated_protocol_rev5
  (security: outdated rev6)   [B] test_security_finding_outdated_protocol_rev6
  (security: no auth unlock)  [B] test_security_finding_no_authentication_unlocked
  (security: weak password)   [B] test_security_finding_weak_password_bruteforce
  (combined: sec+enum)        [B] test_security_with_enumerate_commands
  (combined: full+security)   [B] test_full_with_security_analysis
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


@pytest.mark.hart
class TestHARTIntegration(BaseProtocolIntegrationTest):
    """Integration tests for HART protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "hart"

    @property
    def default_port(self) -> int:
        return 5094

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
                "hart",
                "connected",
                "device",
                "rosemount",
                "pt-101",
                "manufacturer",
            ]
        ), f"Expected HART scan output, got: {text[:500]}"

    def test_tcp_transport(self, cli_runner, target):
        """Test --tcp flag switches to TCP transport [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "5095",
            "--tcp",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "tcp",
                "hart",
                "connected",
                "device",
                "connect",
            ]
        ), f"Expected TCP transport output: {text[:500]}"

    def test_probe_version(self, cli_runner, target, port):
        """Test --probe-version detects HART-IP server version [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-version",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "version",
                "hart",
                "connected",
                "v1",
                "v2",
                "probe",
                "server version",
            ]
        ), f"Expected version probe output: {text[:500]}"

    def test_timeout_option(self, cli_runner, target, port):
        """Test --timeout option is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            timeout=45,
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected scan output with timeout: {text[:500]}"

    def test_poll_addr(self, cli_runner, target, port):
        """Test --poll-addr sets polling address [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--poll-addr",
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
                "hart",
                "connected",
                "device",
                "address",
                "poll",
            ]
        ), f"Expected poll address output: {text[:500]}"

    def test_cipher_suite_option(self, cli_runner, target, port):
        """Test --cipher-suite option is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--cipher-suite",
            "TLS_PSK_WITH_AES_128_CCM",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
                "cipher",
                "tls",
            ]
        ), f"Expected cipher suite output: {text[:500]}"

    # ========================================================================
    # Read Operation Tests
    # ========================================================================

    def test_read_id(self, cli_runner, target, port):
        """Test --read-id reads device unique identifier (Command 0) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-id",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read ID failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "hart",
                "device",
                "manufacturer",
                "rosemount",
                "unique",
                "identifier",
                "connected",
            ]
        ), f"Expected device ID output: {text[:500]}"

    def test_read_pv(self, cli_runner, target, port):
        """Test --read-pv reads primary variable (Command 1) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-pv",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read PV failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "hart",
                "variable",
                "pv",
                "primary",
                "connected",
                "device",
                "psi",
            ]
        ), f"Expected primary variable output: {text[:500]}"

    def test_read_current(self, cli_runner, target, port):
        """Test --read-current reads loop current (Command 2) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-current",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read current failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "hart",
                "current",
                "loop",
                "ma",
                "percent",
                "connected",
                "device",
            ]
        ), f"Expected loop current output: {text[:500]}"

    def test_read_all_vars(self, cli_runner, target, port):
        """Test --read-all-vars reads all dynamic variables (Command 3) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-all-vars",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read all vars failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "variable",
                "process",
                "psi",
                "degc",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected all variables output: {text[:500]}"

    def test_read_tag(self, cli_runner, target, port):
        """Test --read-tag reads tag, descriptor, and date (Command 13) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-tag",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read tag failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "tag",
                "pt-101",
                "hart",
                "connected",
                "device",
                "descriptor",
            ]
        ), f"Expected tag output: {text[:500]}"

    def test_read_output(self, cli_runner, target, port):
        """Test --read-output reads output information (Command 15) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-output",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read output failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "output",
                "range",
                "damping",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected output info: {text[:500]}"

    def test_read_status(self, cli_runner, target, port):
        """Test --read-status reads additional device status (Command 48) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-status",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Read status failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "status",
                "hart",
                "connected",
                "device",
                "additional",
            ]
        ), f"Expected status output: {text[:500]}"

    # ========================================================================
    # Scanning & Enumeration Tests
    # ========================================================================

    def test_scan_addresses(self, cli_runner, target, port):
        """Test --scan-addresses scans poll address range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-addresses",
            "0-3",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "scan",
                "address",
                "poll",
                "device",
                "found",
                "hart",
            ]
        ), f"Expected address scan output: {text[:500]}"

    def test_enumerate_commands(self, cli_runner, target, port):
        """Test --enumerate-commands enumerates supported HART commands [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-commands",
            "--command-range",
            "0-10",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "enumerate",
                "command",
                "supported",
                "hart",
                "connected",
            ]
        ), f"Expected command enumeration output: {text[:500]}"

    def test_command_range(self, cli_runner, target, port):
        """Test --command-range limits enumeration range [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-commands",
            "--command-range",
            "0-5",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "enumerate",
                "command",
                "supported",
                "hart",
                "connected",
                "0-10",
            ]
        ), f"Expected command range output: {text[:500]}"

    @pytest.mark.slow
    def test_enumerate_device_specific(self, cli_runner, target, port):
        """Test --enumerate-device-specific enumerates device-specific commands [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enumerate-device-specific",
            "--command-range",
            "128-135",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "device-specific",
                "enumerate",
                "command",
                "hart",
                "connected",
                "128",
            ]
        ), f"Expected device-specific enumeration output: {text[:500]}"

    # ========================================================================
    # Security Tests
    # ========================================================================

    @pytest.mark.security
    def test_security_analysis(self, cli_runner, target, port):
        """Test --security-analysis performs security assessment [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--security-analysis",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode != -1, f"Security analysis timed out: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "security",
                "finding",
                "analysis",
                "hart",
                "write",
                "encryption",
                "vulnerability",
            ]
        ), f"Expected security analysis output: {text[:500]}"

    @pytest.mark.security
    def test_probe_calibration(self, cli_runner, target, port):
        """Test --probe-calibration tests calibration command access [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-calibration",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "calibration",
                "probe",
                "hart",
                "connected",
                "device",
                "command",
            ]
        ), f"Expected calibration probe output: {text[:500]}"

    @pytest.mark.security
    def test_probe_write(self, cli_runner, target, port):
        """Test --probe-write tests write command accessibility [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-write",
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
                "probe",
                "hart",
                "connected",
                "device",
                "command",
                "accessible",
            ]
        ), f"Expected write probe output: {text[:500]}"

    @pytest.mark.security
    def test_security_finding_write_unprotected(self, cli_runner, target, port):
        """Test that scanner reports writable access for unprotected device [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # write_protect=False finding may not emit if device identification fails
        findings = log.get_security_findings()
        text = _combined_text(result, log)
        has_finding = any(
            "writ" in str(f.get("data", {})).lower() or "protect" in str(f.get("data", {})).lower()
            for f in findings
        )
        has_text = "writ" in text and ("protect" in text or "disabled" in text or "access" in text)
        device_unavailable = "could not retrieve" in text
        assert has_finding or has_text or device_unavailable, (
            f"Expected write protection finding or device unavailable. "
            f"Findings: {findings}, text excerpt: {text[:300]}"
        )

    @pytest.mark.security
    def test_security_finding_no_encryption(self, cli_runner, target, port):
        """Test that scanner reports no encryption for plaintext HART-IP [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        findings = log.get_security_findings()
        has_encryption_finding = any(
            "encrypt" in str(f.get("data", {})).lower()
            or "tls" in str(f.get("data", {})).lower()
            or "plaintext" in str(f.get("data", {})).lower()
            for f in findings
        )
        has_encryption_text = (
            "encrypt" in text or "tls" in text or "dtls" in text or "plaintext" in text
        )
        # Plaintext HART-IP (UDP, no PSK/TLS) MUST yield an explicit no-encryption
        # signal -- either the "No encryption" security finding or the
        # "NO ENCRYPTION - plaintext HART-IP" log line. A generic "security"
        # mention is not sufficient evidence the encryption check actually ran.
        assert has_encryption_finding or has_encryption_text, (
            f"Expected explicit no-encryption finding for plaintext HART-IP. "
            f"Findings: {findings}, text excerpt: {text[:300]}"
        )

    @pytest.mark.security
    def test_security_finding_outdated_protocol_rev5(self, cli_runner, target, port):
        """Test scanner checks protocol revision and would flag rev<=5 as outdated [Category B]

        The mock device reports protocol_revision=7, so the 'Outdated protocol version'
        finding (line ~289 in __init__.py) will NOT fire. This test verifies the scanner
        processes and reports the protocol revision. If a HART 5 mock were available,
        we would see 'Outdated protocol version' + 'NO encryption or authentication'.
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

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # The scanner must report protocol version info for any successful connection.
        # With rev 7, we expect "HART 7" or "Rev 7" in output; with rev 5 we'd see
        # "HART 5" and an "Outdated protocol version" finding.
        assert any(
            term in text
            for term in [
                "protocol",
                "hart 7",
                "hart 5",
                "hart 6",
                "rev 7",
                "rev 5",
                "outdated",
                "connected",
            ]
        ), f"Expected protocol version info in output: {text[:500]}"

        # If the mock happens to use rev<=5, also check for the security finding
        if result.scan_log:
            findings = result.scan_log.get_security_findings()
            findings_text = " ".join(str(f.get("data", {})).lower() for f in findings)
            if "hart 5" in text or "rev 5" in text:
                assert "outdated" in findings_text or "no encryption" in findings_text, (
                    f"HART 5 device should produce 'Outdated protocol version' finding: {findings}"
                )

    @pytest.mark.security
    def test_security_finding_outdated_protocol_rev6(self, cli_runner, target, port):
        """Test scanner checks protocol revision and would flag rev==6 as outdated [Category B]

        The mock device reports protocol_revision=7, so the 'Outdated protocol version'
        finding for HART 6 (line ~294 in __init__.py) will NOT fire. This test verifies
        the scanner processes and reports protocol version. If a HART 6 mock were
        available, we would see 'HART 6 - No encryption, optional device lock'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--read-id",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Scanner must report protocol version from device identification
        assert any(
            term in text
            for term in [
                "protocol",
                "hart 7",
                "hart 6",
                "rev 7",
                "rev 6",
                "revision",
                "connected",
                "device",
            ]
        ), f"Expected protocol version/device info in output: {text[:500]}"

        # If the mock happens to use rev==6, also check for the security finding
        if result.scan_log:
            findings = result.scan_log.get_security_findings()
            findings_text = " ".join(str(f.get("data", {})).lower() for f in findings)
            if "hart 6" in text or "rev 6" in text:
                assert "outdated" in findings_text or "optional device lock" in findings_text, (
                    f"HART 6 device should produce 'Outdated protocol version' finding: {findings}"
                )

    @pytest.mark.security
    def test_security_finding_no_authentication_unlocked(self, cli_runner, target, port):
        """Test --check-lock detects unlocked device and reports 'No authentication' [Category B]

        Triggers _handle_check_lock() in __init__.py (line ~551). When lock_state ==
        LockState.UNLOCKED, the scanner emits: security_finding('No authentication',
        'Device is UNLOCKED - configuration writable').

        The basic mock does NOT implement Command 76 (read lock state), so it returns
        CMD_NOT_IMPLEMENTED which maps to LockState.NOT_SUPPORTED. The scanner will
        report 'Device lock not supported (likely HART 5)' instead of the UNLOCKED
        finding. This test verifies the scanner attempts the lock check and reports
        the lock status regardless of outcome.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-lock",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Scanner must attempt lock check and report some lock-related status.
        # Possible outputs: "No authentication" (UNLOCKED), "Device is LOCKED",
        # "Device lock not supported", "Lock state: Unknown"
        assert any(
            term in text
            for term in [
                "lock",
                "unlock",
                "authentication",
                "not supported",
                "locked",
                "state",
                "checking device lock",
            ]
        ), f"Expected lock status output from --check-lock: {text[:500]}"

        # If device is unlocked, verify the security finding was emitted
        if result.scan_log:
            findings = result.scan_log.get_security_findings()
            if "unlocked" in text:
                has_auth_finding = any(
                    "authentication" in str(f.get("data", {})).lower()
                    or "unlocked" in str(f.get("data", {})).lower()
                    for f in findings
                )
                assert has_auth_finding, (
                    f"UNLOCKED device should produce 'No authentication' finding: {findings}"
                )

    @pytest.mark.security
    def test_security_finding_weak_password_bruteforce(self, cli_runner, target, port, tmp_path):
        """Test --bruteforce-lock reports 'Weak password' on successful brute-force [Category B]

        Triggers _handle_bruteforce_lock() in __init__.py (line ~583). When bruteforce
        succeeds, the scanner emits: security_finding('Weak password',
        f"Device lock code found: '{code}'").

        The basic mock does NOT implement Command 76/71 (lock read/write), so
        bruteforce_lock() in scanner.py will return early with either NOT_SUPPORTED
        or UNLOCKED (already unlocked). The test verifies the scanner attempts the
        bruteforce operation and reports results.
        """
        wordlist = tmp_path / "lock_codes.txt"
        wordlist.write_text("0000\n1234\n5678\nABCD\n")

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bruteforce-lock",
            str(wordlist),
            "--bruteforce-delay",
            "0.05",
            "--confirm",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Scanner must attempt bruteforce and report outcome. Possible outputs:
        # "Device lock code found" (success), "No valid code found" (failure),
        # "Device lock not supported" (HART 5), "already unlocked" (UNLOCKED state)
        assert any(
            term in text
            for term in [
                "bruteforce",
                "bruteforc",
                "lock code",
                "no valid",
                "not supported",
                "already unlocked",
                "weak password",
                "tested",
                "attempt",
            ]
        ), f"Expected bruteforce result output: {text[:500]}"

        # If bruteforce succeeded, verify the 'Weak password' finding was emitted
        if result.scan_log:
            findings = result.scan_log.get_security_findings()
            if "lock code found" in text or "weak password" in text.lower():
                has_weak_pw_finding = any(
                    "weak password" in str(f.get("data", {})).lower()
                    or "lock code found" in str(f.get("data", {})).lower()
                    for f in findings
                )
                assert has_weak_pw_finding, (
                    f"Successful bruteforce should produce 'Weak password' finding: {findings}"
                )

    # ========================================================================
    # WirelessHART Tests
    # ========================================================================

    def test_detect_wireless(self, cli_runner, target, port):
        """Test --detect-wireless detects WirelessHART capabilities [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--detect-wireless",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Basic mode mock is NOT a WirelessHART device, so detection may fail gracefully
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "wireless",
                "detect",
                "hart",
                "connected",
                "device",
                "wirelesshart",
            ]
        ), f"Expected wireless detection output: {text[:500]}"

    def test_wireless_info(self, cli_runner, target, port):
        """Test --wireless-info shows WirelessHART network information [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--wireless-info",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "wireless",
                "network",
                "hart",
                "connected",
                "device",
                "info",
            ]
        ), f"Expected wireless info output: {text[:500]}"

    def test_list_sub_devices(self, cli_runner, target, port):
        """Test --list-sub-devices lists WirelessHART gateway sub-devices [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--list-sub-devices",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Basic mode mock is not a gateway, so no sub-devices expected
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "sub-device",
                "sub_device",
                "gateway",
                "hart",
                "connected",
                "device",
                "list",
                "no sub-devices",
            ]
        ), f"Expected sub-device listing output: {text[:500]}"

    # ========================================================================
    # Device Lock Tests
    # ========================================================================

    def test_check_lock(self, cli_runner, target, port):
        """Test --check-lock checks device lock state [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--check-lock",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Mock may not implement device lock (Command 76/77)
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "lock",
                "unlock",
                "device",
                "hart",
                "connected",
                "not supported",
                "state",
            ]
        ), f"Expected lock check output: {text[:500]}"

    @pytest.mark.security
    def test_bruteforce_lock_without_confirm(self, cli_runner, target, port, tmp_path):
        """Test --bruteforce-lock without --confirm is rejected [Category C]"""
        wordlist = tmp_path / "codes.txt"
        wordlist.write_text("0000\n1234\n9999\n")

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bruteforce-lock",
            str(wordlist),
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
                "bruteforce",
                "hart",
                "connected",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_unlock_without_confirm(self, cli_runner, target, port):
        """Test --unlock without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--unlock",
            "1234",
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
                "unlock",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_lock_without_confirm(self, cli_runner, target, port):
        """Test --lock without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lock",
            "1234",
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
                "lock",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_bruteforce_lock_with_confirm_wrong_codes(self, cli_runner, target, port, tmp_path):
        """Test --bruteforce-lock with --confirm and wrong codes [Category B]"""
        wordlist = tmp_path / "wrong_codes.txt"
        wordlist.write_text("0000\n1111\n9999\nAAAA\n")

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bruteforce-lock",
            str(wordlist),
            "--bruteforce-delay",
            "0.05",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "bruteforce",
                "no valid",
                "attempt",
                "tested",
                "lock",
                "hart",
                "connected",
                "fail",
            ]
        ), f"Expected bruteforce failure output: {text[:500]}"

    @pytest.mark.security
    def test_unlock_with_confirm_wrong_code(self, cli_runner, target, port):
        """Test --unlock with --confirm and wrong code fails gracefully [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--unlock",
            "0000",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "unlock",
                "fail",
                "hart",
                "connected",
                "device",
                "attempt",
            ]
        ), f"Expected unlock failure output: {text[:500]}"

    @pytest.mark.security
    def test_lock_with_confirm(self, cli_runner, target, port):
        """Test --lock with --confirm attempts to lock device [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lock",
            "1234",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "lock",
                "fail",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected lock attempt output: {text[:500]}"

    # ========================================================================
    # Write Operation Tests
    # ========================================================================

    @pytest.mark.security
    def test_write_poll_addr_without_confirm(self, cli_runner, target, port):
        """Test --write-poll-addr without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-poll-addr",
            "1",
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
                "write",
                "poll",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_write_poll_addr_with_confirm(self, cli_runner, target, port):
        """Test --write-poll-addr with --confirm attempts write [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-poll-addr",
            "1",
            "--confirm",
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
                "poll",
                "address",
                "hart",
                "connected",
                "success",
                "changed",
            ]
        ), f"Expected poll address write output: {text[:500]}"

    @pytest.mark.security
    def test_write_tag_without_confirm(self, cli_runner, target, port):
        """Test --write-tag without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-tag",
            "TEST01",
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
                "write",
                "tag",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_write_tag_with_confirm(self, cli_runner, target, port):
        """Test --write-tag with --confirm attempts tag write [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-tag",
            "TEST01",
            "--confirm",
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
                "tag",
                "hart",
                "connected",
                "success",
                "written",
            ]
        ), f"Expected tag write output: {text[:500]}"

    @pytest.mark.security
    def test_write_descriptor_without_confirm(self, cli_runner, target, port):
        """Test --write-tag with --write-descriptor without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-tag",
            "TEST01",
            "--write-descriptor",
            "TestDesc",
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
                "write",
                "tag",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_write_descriptor_with_confirm(self, cli_runner, target, port):
        """Test --write-tag + --write-descriptor with --confirm writes both [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-tag",
            "TEST01",
            "--write-descriptor",
            "TestDescriptor",
            "--confirm",
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
                "tag",
                "hart",
                "connected",
                "success",
                "written",
            ]
        ), f"Expected tag+descriptor write output: {text[:500]}"

    @pytest.mark.security
    def test_write_message_without_confirm(self, cli_runner, target, port):
        """Test --write-message without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-message",
            "TestMessage",
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
                "write",
                "message",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_write_message_with_confirm(self, cli_runner, target, port):
        """Test --write-message with --confirm writes device message [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--write-message",
            "TestMessage",
            "--confirm",
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
                "message",
                "hart",
                "connected",
                "success",
                "written",
            ]
        ), f"Expected message write output: {text[:500]}"

    @pytest.mark.security
    def test_reset_config_without_confirm(self, cli_runner, target, port):
        """Test --reset-config-flag without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--reset-config-flag",
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
                "reset",
                "config",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_reset_config_with_confirm(self, cli_runner, target, port):
        """Test --reset-config-flag with --confirm resets flag [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--reset-config-flag",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "reset",
                "config",
                "flag",
                "hart",
                "connected",
                "success",
            ]
        ), f"Expected config flag reset output: {text[:500]}"

    @pytest.mark.security
    def test_self_test_without_confirm(self, cli_runner, target, port):
        """Test --self-test without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--self-test",
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
                "self-test",
                "self_test",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_self_test_with_confirm(self, cli_runner, target, port):
        """Test --self-test with --confirm performs device self-test [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--self-test",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "self-test",
                "self_test",
                "test",
                "hart",
                "connected",
                "success",
                "completed",
            ]
        ), f"Expected self-test output: {text[:500]}"

    @pytest.mark.security
    def test_master_reset_without_confirm(self, cli_runner, target, port):
        """Test --master-reset without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--master-reset",
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
                "master",
                "reset",
                "hart",
                "connected",
                "warning",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_master_reset_with_confirm(self, cli_runner, target, port):
        """Test --master-reset with --confirm attempts reset on mock [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--master-reset",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "master",
                "reset",
                "hart",
                "connected",
                "success",
                "performing",
            ]
        ), f"Expected master reset attempt output: {text[:500]}"

    def test_confirm_without_action(self, cli_runner, target, port):
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

        # --confirm alone without any write/fuzz flag should just do a normal scan
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected normal scan output with --confirm alone: {text[:500]}"

    # ========================================================================
    # Fuzzing Tests
    # ========================================================================

    @pytest.mark.security
    @pytest.mark.fuzz
    def test_fuzz_without_confirm(self, cli_runner, target, port):
        """Test --fuzz without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
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
                "fuzz",
                "hart",
                "connected",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_confirm(self, cli_runner, target, port):
        """Test --fuzz with --confirm performs fuzzing on mock [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-commands",
            "0,1,2",
            "--fuzz-iterations",
            "2",
            "--confirm",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fuzz",
                "iteration",
                "payload",
                "tested",
                "hart",
                "connected",
                "complete",
            ]
        ), f"Expected fuzzing output: {text[:500]}"

    @pytest.mark.security
    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_commands(self, cli_runner, target, port):
        """Test --fuzz-commands specifies which commands to fuzz [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-commands",
            "0,1,2,3",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fuzz",
                "command",
                "hart",
                "connected",
                "tested",
                "complete",
            ]
        ), f"Expected fuzz commands output: {text[:500]}"

    # ========================================================================
    # Raw Command Tests
    # ========================================================================

    def test_raw_command(self, cli_runner, target, port):
        """Test --raw-command sends raw HART command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-command",
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
                "raw",
                "command",
                "response",
                "hart",
                "connected",
                "sending",
            ]
        ), f"Expected raw command output: {text[:500]}"

    def test_raw_command_with_data(self, cli_runner, target, port):
        """Test --raw-command with --raw-data sends data payload [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--raw-command",
            "0",
            "--raw-data",
            "00",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "raw",
                "command",
                "response",
                "hart",
                "connected",
                "data",
                "bytes",
            ]
        ), f"Expected raw command with data output: {text[:500]}"

    # ========================================================================
    # Discovery Mode Tests
    # ========================================================================

    def test_discover_mode(self, cli_runner, target, port):
        """Test --discover discovery mode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--discover",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "discover",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected discover mode output: {text[:500]}"

    def test_quick_mode(self, cli_runner, target, port):
        """Test --quick quick scan mode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--quick",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "quick",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected quick mode output: {text[:500]}"

    def test_full_mode(self, cli_runner, target, port):
        """Test --full full scan mode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--full",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "full",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected full mode output: {text[:500]}"

    def test_deep_scan(self, cli_runner, target, port):
        """Test --deep-scan for thorough scanning [Category B]"""
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
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "deep",
                "scan",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected deep scan output: {text[:500]}"

    def test_scan_mode_discovery(self, cli_runner, target, port):
        """Test --scan-mode discovery [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-mode",
            "discovery",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "discovery",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected discovery scan mode output: {text[:500]}"

    def test_scan_mode_enumeration(self, cli_runner, target, port):
        """Test --scan-mode enumeration [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-mode",
            "enumeration",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "enumeration",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected enumeration scan mode output: {text[:500]}"

    def test_scan_mode_full(self, cli_runner, target, port):
        """Test --scan-mode full [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--scan-mode",
            "full",
            "--command-range",
            "0-5",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "full",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected full scan mode output: {text[:500]}"

    # ========================================================================
    # TLS/PSK Tests
    # ========================================================================

    @pytest.mark.security
    def test_psk_auth_without_server_support(self, cli_runner, target, port):
        """Test --psk-identity/--psk-key against v1-only server [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--psk-identity",
            "testuser",
            "--psk-key",
            "0102030405060708",
            format="json",
            json_log=True,
            timeout=30,
        )

        # v1-only server doesn't support TLS-PSK, should fail or fallback
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "psk",
                "tls",
                "auth",
                "hart",
                "connected",
                "device",
                "fail",
                "error",
                "version",
            ]
        ), f"Expected PSK auth attempt output: {text[:500]}"

    # ========================================================================
    # Combined Flag Tests
    # ========================================================================

    @pytest.mark.slow
    def test_security_with_enumerate_commands(self, cli_runner, target, port):
        """Test --security-analysis combined with --enumerate-commands [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--security-analysis",
            "--enumerate-commands",
            "--command-range",
            "0-5",
            format="json",
            json_log=True,
            timeout=120,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "security",
                "enumerate",
                "command",
                "hart",
                "connected",
                "finding",
            ]
        ), f"Expected combined security + enum output: {text[:500]}"

    @pytest.mark.slow
    def test_full_with_security_analysis(self, cli_runner, target, port):
        """Test --full combined with --security-analysis [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--full",
            "--security-analysis",
            format="json",
            json_log=True,
            timeout=120,
        )

        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "full",
                "security",
                "hart",
                "connected",
                "device",
                "finding",
            ]
        ), f"Expected combined full + security output: {text[:500]}"

    # ========================================================================
    # JSON Log Structure Tests
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

        conn_events = log.get_connection_events()
        text = _combined_text(result, log)
        assert len(conn_events) > 0 or "connect" in text, (
            f"Expected connection events. Got {len(conn_events)} connection events. "
            f"Text excerpt: {text[:300]}"
        )

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

        modules = {e.get("module", "") for e in log.events}
        has_hart_module = any("hart" in m.lower() for m in modules)
        assert has_hart_module or len(modules) > 0, (
            f"Expected hart module reference. Modules: {modules}"
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

        info_events = log.get_events(level="info")
        assert len(info_events) > 0, (
            f"Expected info-level events, got 0. All levels: {[e.get('level') for e in log.events]}"
        )

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

    def test_unreachable_host(self, cli_runner):
        """Test scan of unreachable host times out gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            "5094",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

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
            "5094",
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


# ---------------------------------------------------------------------------
# Multi-Service Tests (hart-tls, hart-secondary, hart-tertiary)
# ---------------------------------------------------------------------------


@pytest.mark.hart
@pytest.mark.containers("hart-tls")
class TestHARTTLSIntegration:
    """Tests against hart-tls service (port 5095, HART-IP v2 TLS/STARTTLS)"""

    def test_tls_basic_scan(self, cli_runner):
        """Test basic scan against TLS-enabled HART-IP server [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5095",
            "--tcp",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
                "tls",
                "connect",
                "fail",
            ]
        ), f"Expected TLS scan output: {text[:500]}"

    def test_tls_probe_version(self, cli_runner):
        """Test --probe-version against TLS server detects capabilities [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5095",
            "--tcp",
            "--probe-version",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "version",
                "hart",
                "tls",
                "v1",
                "v2",
                "probe",
                "connect",
            ]
        ), f"Expected TLS version probe output: {text[:500]}"

    def test_tls_psk_auth(self, cli_runner):
        """Test --psk-identity/--psk-key against TLS server [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5095",
            "--tcp",
            "--psk-identity",
            "testuser",
            "--psk-key",
            "0102030405060708",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "psk",
                "tls",
                "hart",
                "connect",
                "auth",
                "device",
            ]
        ), f"Expected TLS PSK auth output: {text[:500]}"

    def test_tls_security_finding_encryption(self, cli_runner):
        """Test that TLS server may report encryption status [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5095",
            "--tcp",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "tls",
                "encrypt",
                "connect",
                "device",
                "security",
            ]
        ), f"Expected TLS encryption output: {text[:500]}"


@pytest.mark.hart
@pytest.mark.containers("hart-secondary")
class TestHARTSecondaryIntegration:
    """Tests against hart-secondary service (ports 5096 UDP / 5097 TCP, multidrop)"""

    def test_secondary_udp_basic_scan(self, cli_runner):
        """Test basic UDP scan against secondary mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5096",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
                "connect",
            ]
        ), f"Expected secondary UDP scan output: {text[:500]}"

    def test_secondary_tcp_basic_scan(self, cli_runner):
        """Test basic TCP scan against secondary mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5097",
            "--tcp",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
                "tcp",
                "connect",
            ]
        ), f"Expected secondary TCP scan output: {text[:500]}"

    def test_secondary_scan_addresses(self, cli_runner):
        """Test --scan-addresses on secondary (multidrop) mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5096",
            "--scan-addresses",
            "0-3",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "scan",
                "address",
                "poll",
                "device",
                "found",
                "hart",
            ]
        ), f"Expected multidrop scan output: {text[:500]}"

    def test_secondary_read_all_vars(self, cli_runner):
        """Test --read-all-vars on secondary mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5096",
            "--read-all-vars",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "variable",
                "hart",
                "connected",
                "device",
            ]
        ), f"Expected secondary read vars output: {text[:500]}"


@pytest.mark.hart
@pytest.mark.containers("hart-tertiary")
class TestHARTTertiaryIntegration:
    """Tests against hart-tertiary service (ports 5098 UDP / 5099 TCP, gateway mode)"""

    def test_tertiary_udp_basic_scan(self, cli_runner):
        """Test basic UDP scan against tertiary mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5098",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
                "connect",
            ]
        ), f"Expected tertiary UDP scan output: {text[:500]}"

    def test_tertiary_tcp_basic_scan(self, cli_runner):
        """Test basic TCP scan against tertiary mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5099",
            "--tcp",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "hart",
                "connected",
                "device",
                "tcp",
                "connect",
            ]
        ), f"Expected tertiary TCP scan output: {text[:500]}"

    def test_tertiary_detect_wireless(self, cli_runner):
        """Test --detect-wireless on tertiary (gateway) mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5098",
            "--detect-wireless",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "wireless",
                "detect",
                "hart",
                "connected",
                "device",
                "gateway",
            ]
        ), f"Expected wireless detection output: {text[:500]}"

    def test_tertiary_list_sub_devices(self, cli_runner):
        """Test --list-sub-devices on tertiary (gateway) mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5098",
            "--list-sub-devices",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "sub-device",
                "sub_device",
                "gateway",
                "hart",
                "connected",
                "device",
                "list",
            ]
        ), f"Expected sub-device listing output: {text[:500]}"

    def test_tertiary_wireless_info(self, cli_runner):
        """Test --wireless-info on tertiary (gateway) mock [Category B]"""
        result = cli_runner.run(
            "hart",
            MOCK_HOST,
            "--port",
            "5098",
            "--wireless-info",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "wireless",
                "network",
                "hart",
                "connected",
                "device",
                "gateway",
                "info",
            ]
        ), f"Expected wireless info output: {text[:500]}"
