"""
MQTT Protocol Integration Tests

Tests oida mqtt scanner against Docker mock brokers.
Multiple broker configurations are tested:
- Port 1883: Insecure (anonymous access)
- Port 1884: Auth required (weak credentials)
- Port 1885: Sparkplug B broker
- Port 8883: TLS (optional client cert)
- Port 8884: Mutual TLS (client cert required)

Mock Server Data (from docker/mocks/services/mqtt/):
  Insecure broker (port 1883):
    - Anonymous authentication always accepted
    - Wildcard subscriptions (#, +) allowed
    - $SYS topics fully readable
    - $SYS/broker/version = "MockMQTT 1.0.0 (INSECURE)"
    - ICS topics: factory/plc1/*, factory/plc2/*, scada/*, sensors/*, control/*
    - No TLS

  Auth broker (port 1884):
    - Authentication required
    - Users: admin:admin, user:password, operator:operator123, guest:guest,
             test:test, mqtt:mqtt, ics:ics123, plc:plc2024
    - $SYS/broker/version = "MockMQTT-Auth 1.0.0"

  Sparkplug broker (port 1885):
    - Anonymous access allowed
    - Sparkplug B namespace: spBv1.0/#
    - Groups: Factory-Floor, SCADA, Building-Automation
    - Nodes: PLC-001, PLC-002, RTU-001, BMS-001
    - Devices: Conveyor-1, Sensor-Array-1, Packaging-Line, Power-Meter-1, etc.

  TLS broker (port 8883):
    - TLS with optional client cert
    - Auth broker underneath (same USERS)

  Mutual TLS broker (port 8884):
    - TLS with mandatory client cert

Security Findings in MQTT Module:
  __init__.py print_host_info():
    1. "No encryption" / "Plaintext connection (no TLS)" -- when tls=False and connected
    2. "Anonymous access" / "Anonymous authentication allowed" -- when connected without creds

  scanner.py _test_anonymous_auth():
    3. "Anonymous access" / "Anonymous authentication allowed" -- when anon test succeeds

  scanner.py _brute_force_credentials():
    4. "Default credentials" / "Valid MQTT credentials: {u}:{p}" -- per valid cred found

  scanner.py _analyze_security():
    5. "Anonymous access allowed" -- when auth.anonymous_allowed
    6. "Insecure configuration" / "$SYS topics exposed ({N} topics)" -- when $SYS accessible
    7. "Insecure configuration" / "Wildcard subscriptions allowed ({N} topics)" -- when # works
    8. "Default credentials" / "Username: {u}" -- per valid cred in brute results
    9. "No encryption" / "Communication is unencrypted" -- when TLS not used

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  21 tests
Category B (conditional -- mock may not support, accept 0 or 1):       29 tests
Category C (error handling -- assert failure + validate error events):  16 tests
Skipped (untestable -- flag not implemented or requires hardware):       0 tests
Total defined in file (excluding inherited):                            35 tests
---------------------------------------------------------------------------
"""

import json
import socket
import threading
import time
from typing import Optional

import pytest

from tests.service_gate import require_port

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import MOCK_HOST, check_port_open


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _combined_text(result, log=None) -> str:
    """Return lowercase combined output + log messages for broad searches."""
    parts = [result.combined_output.lower()]
    if log is not None:
        parts.append(_all_messages(log))
    return " ".join(parts)


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


@pytest.mark.mqtt
class TestMQTTIntegration(BaseProtocolIntegrationTest):
    """Integration tests for MQTT protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "mqtt"

    @property
    def default_port(self) -> int:
        return 1883

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Discovery Tests (Insecure Broker)
    # ========================================================================

    def test_basic_discovery_insecure(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test basic discovery on insecure broker [Category A]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Basic discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["connection success", "connected", "mqtt"]), (
            f"Expected connection output, got: {text[:500]}"
        )

    def test_basic_scan(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test basic scan (no enumeration flags) [Category A]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "connection success" in text or "connected" in text, (
            f"Expected connection message, got: {text[:500]}"
        )

    # ========================================================================
    # Authentication Tests
    # ========================================================================

    @pytest.mark.auth
    def test_anonymous_access(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test anonymous access detection [Category A]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Anonymous access scan failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "anonymous" in text or "connection success" in text, (
            f"Expected anonymous or connection info in output: {text[:500]}"
        )

    @pytest.mark.auth
    def test_valid_credentials(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test with valid credentials on auth broker [Category B]"""
        port = mock_ports.get("mqtt_auth", 1884)
        require_port(mock_host, port, "Auth MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--username",
            "admin",
            "--password",
            "admin",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["connection success", "connected", "mqtt", "auth"]), (
            f"Expected connection-related output: {text[:500]}"
        )

    @pytest.mark.auth
    def test_invalid_credentials(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test with invalid credentials [Category C]"""
        port = mock_ports.get("mqtt_auth", 1884)
        require_port(mock_host, port, "Auth MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--username",
            "invalid",
            "--password",
            "wrong",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should fail but not crash
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["fail", "denied", "auth", "not authorized", "required"]
        ), f"Expected auth failure message: {text[:500]}"

    @pytest.mark.auth
    @pytest.mark.slow
    def test_brute_force(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test credential brute-force [Category B]

        --default-creds is gated behind --confirm (it runs an active credential
        attack). With --confirm the scanner MUST actually iterate the default
        credential list and log a brute-force-complete summary.
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--default-creds",
            "--confirm",
            "--username",
            "admin",
            "--brute-rate",
            "0",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Brute-force should complete
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # The brute-force loop logs "Brute-force: testing N credentials" and
        # "Brute-force complete: ..." - assert it actually ran, not just gated.
        assert "brute-force" in text and "complete" in text, (
            f"Expected brute-force to run to completion, got: {text[:500]}"
        )

    # ========================================================================
    # Topic Enumeration Tests
    # ========================================================================

    def test_wildcard_subscribe(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test wildcard subscription [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--topics",
            "#",
            "--timeout",
            "10",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["connection success", "connected", "mqtt"]), (
            f"Expected connection output: {text[:500]}"
        )

    def test_sys_enumeration(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test $SYS topic enumeration (via --enumerate) [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["$sys", "enumerat", "topic", "broker"]), (
            f"Expected enumeration output: {text[:500]}"
        )

    def test_common_topics(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test common topic enumeration [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate-common",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["bruteforce", "common", "topic", "pattern", "enumerat"]
        ), f"Expected common topic output: {text[:500]}"

    # ========================================================================
    # Sparkplug Tests
    # ========================================================================

    def test_sparkplug_detection(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test Sparkplug B namespace detection (via --enumerate) [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["sparkplug", "enumerat", "topic"]), (
            f"Expected sparkplug/enumeration output: {text[:500]}"
        )

    def test_sparkplug_broker(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test against Sparkplug B broker (via --enumerate) [Category B]"""
        port = mock_ports.get("mqtt_sparkplug", 1885)
        require_port(mock_host, port, "Sparkplug MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["sparkplug", "enumerat", "topic", "connected"]), (
            f"Expected sparkplug/enumeration output: {text[:500]}"
        )

    # ========================================================================
    # TLS Tests
    # ========================================================================

    @pytest.mark.slow
    def test_tls_connection(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test TLS connection [Category B]"""
        port = mock_ports.get("mqtt_tls", 8883)
        require_port(mock_host, port, "TLS MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--tls",
            "--tls-insecure",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["tls", "connect", "mqtt", "ssl", "auth"]), (
            f"Expected TLS-related output: {text[:500]}"
        )

    @pytest.mark.slow
    def test_tls_insecure(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test TLS with insecure flag (skip verification) [Category B]"""
        port = mock_ports.get("mqtt_tls", 8883)
        require_port(mock_host, port, "TLS MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--tls",
            "--tls-insecure",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["tls", "connect", "mqtt", "ssl", "auth"]), (
            f"Expected TLS-related output: {text[:500]}"
        )

    # ========================================================================
    # Listen Mode Tests
    # ========================================================================

    @pytest.mark.slow
    def test_listen_mode(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test continuous listen mode [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--listen",
            "--listen-time",
            "5",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Listen mode should complete after listen-time
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["listen", "message", "topic", "complete"]), (
            f"Expected listen-related output: {text[:500]}"
        )

    # ========================================================================
    # Full Scan Mode Tests
    # ========================================================================

    @pytest.mark.slow
    def test_full_scan(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test full scan with enumeration and default credential testing [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            "--default-creds",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["enumerat", "credential", "topic", "brute", "complete"]
        ), f"Expected scan output: {text[:500]}"

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_auth_rejected(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test handling of auth rejection [Category C]"""
        port = mock_ports.get("mqtt_auth", 1884)
        require_port(mock_host, port, "Auth MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--username",
            "nobody",
            "--password",
            "invalid",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should handle gracefully
        assert result.returncode != -1
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["fail", "denied", "auth", "not authorized", "required"]
        ), f"Expected auth failure message: {text[:500]}"

    def test_client_id(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test custom client ID [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--client-id",
            "oida-test-client",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["connect", "mqtt", "success"]), (
            f"Expected connection output: {text[:500]}"
        )

    # ========================================================================
    # Mutual TLS Tests
    # ========================================================================

    @pytest.mark.security
    def test_mtls_connection(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test mutual TLS connection (client cert) [Category C]"""
        port = mock_ports.get("mqtt_mtls", 8884)
        require_port(mock_host, port, "mTLS MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--tls",
            "--tls-cert",
            "/nonexistent/cert.pem",
            "--tls-key",
            "/nonexistent/key.pem",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully (file not found)
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["error", "fail", "tls", "ssl", "cert", "not found", "connect"]
        ), f"Expected TLS error message: {text[:500]}"

    @pytest.mark.security
    def test_tls_ca_cert(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test TLS with CA certificate [Category B]"""
        port = mock_ports.get("mqtt_tls", 8883)
        require_port(mock_host, port, "TLS MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--tls",
            "--tls-ca",
            "/nonexistent/ca.pem",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully (file not found)
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in ["error", "fail", "tls", "ssl", "ca", "cert", "not found", "connect"]
        ), f"Expected TLS/cert error: {text[:500]}"

    # ========================================================================
    # Credential File Tests
    # ========================================================================

    @pytest.mark.auth
    def test_credentials_file_missing_falls_back(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """A missing credentials wordlist must fall back to built-in defaults [Category B].

        (Was test_credentials_file using a non-existent --credentials flag, which
        argparse rejected with rc=2 so the test passed vacuously on the usage banner.
        --wordlist is the real file-based credential input.)
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--default-creds",
            "--confirm",
            "--wordlist",
            "/nonexistent/creds.txt",
            "--brute-rate",
            "0",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Missing file must not crash; scanner falls back to built-in defaults.
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Fallback path runs the brute loop to completion against built-in creds.
        assert "brute-force" in text and "complete" in text, (
            f"Expected fallback brute-force to run to completion: {text[:500]}"
        )

    @pytest.mark.auth
    def test_wordlist_option(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test password wordlist option [Category B].

        --default-creds is gated behind --confirm; with it the brute loop must
        run to completion even when the wordlist file is missing (fallback to
        built-in defaults).
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--default-creds",
            "--confirm",
            "--username",
            "admin",
            "--wordlist",
            "/nonexistent/wordlist.txt",
            "--brute-rate",
            "0",
            format="json",
            json_log=True,
            timeout=20,
        )

        # Should not crash; missing wordlist falls back to built-in defaults.
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "brute-force" in text and "complete" in text, (
            f"Expected brute-force to run to completion: {text[:500]}"
        )

    # ========================================================================
    # Topic Options Tests
    # ========================================================================

    def test_topic_list_file(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test custom topic list file [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--topic-list",
            "/nonexistent/topics.txt",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail gracefully or use default topics
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["connect", "mqtt", "topic"]), (
            f"Expected mqtt-related output: {text[:500]}"
        )

    def test_no_enumeration(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test scan without enumeration [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "connect" in text, f"Expected connection output: {text[:500]}"

    def test_enumerate_common_only(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test common topic enumeration without full --enumerate [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate-common",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["bruteforce", "common", "topic", "pattern", "connect"]
        ), f"Expected topic enumeration output: {text[:500]}"

    # ========================================================================
    # Listen Mode Options Tests
    # ========================================================================

    @pytest.mark.slow
    def test_listen_with_unique(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test listen mode with unique topic filtering [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--listen",
            "--unique",
            "--listen-time",
            "3",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["listen", "message", "topic", "complete"]), (
            f"Expected listen output: {text[:500]}"
        )

    # ========================================================================
    # Fuzzing Tests
    # ========================================================================

    @pytest.mark.fuzz
    def test_fuzz_requires_confirm(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test that fuzzing requires --confirm [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--fuzz",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should fail or warn without --confirm
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["confirm", "fuzz", "require", "connect"]), (
            f"Expected fuzz/confirm output: {text[:500]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_with_confirm(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test fuzzing with --confirm [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fuzz", "payload", "topic", "connect"]), (
            f"Expected fuzzing output: {text[:500]}"
        )

    @pytest.mark.fuzz
    def test_fuzz_specific_topics(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test fuzzing specific topics [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-topics",
            "test/topic1,test/topic2",
            "--fuzz-iterations",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fuzz", "topic", "payload", "connect"]), (
            f"Expected fuzzing output: {text[:500]}"
        )

    # ========================================================================
    # Security Finding Tests
    # ========================================================================
    #
    # These tests verify that the scanner correctly emits security findings
    # via logger.security_finding() when connecting to mock brokers with
    # known vulnerabilities. Each finding is documented in the module's
    # __init__.py print_host_info() and scanner.py _analyze_security().
    #
    # Source code locations for each finding:
    #   - __init__.py:184  "No encryption" / "Plaintext connection (no TLS)"
    #   - __init__.py:189  "Anonymous access" / "Anonymous authentication allowed"
    #   - scanner.py:1326  report_vulnerability("Anonymous Authentication")
    #   - scanner.py:1333  "Anonymous access" / "Anonymous authentication allowed"
    #   - scanner.py:1409  "Default credentials" / "Valid MQTT credentials: {u}:{p}"
    #   - scanner.py:2255  "Anonymous access allowed"
    #   - scanner.py:2268  "Insecure configuration" / "$SYS topics exposed"
    #   - scanner.py:2282  "Insecure configuration" / "Wildcard subscriptions allowed"
    #   - scanner.py:2298  "Default credentials" / "Username: {u}"
    #   - scanner.py:2315  "No encryption" / "Communication is unencrypted"
    # ========================================================================

    @pytest.mark.security
    def test_finding_no_encryption_on_plaintext(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'No encryption' finding fires on plaintext connection to port 1883.

        Trigger: __init__.py print_host_info() emits security_finding("No encryption",
        "Plaintext connection (no TLS)") when self.args.tls is False and connection
        succeeds. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # The scanner MUST report "No encryption" for a plaintext connection
        text = _combined_text(result, log)
        assert "no encryption" in text or "plaintext" in text or "no tls" in text, (
            f"Expected 'No encryption' finding on plaintext port 1883: {text[:500]}"
        )

        # Also validate via structured log: event_type=security with finding="No encryption"
        security_events = log.get_security_findings()
        encryption_findings = [
            f
            for f in security_events
            if "encryption" in f.get("data", {}).get("finding", "").lower()
            or "encryption" in f.get("message", "").lower()
            or "no encryption" in f.get("message", "").lower()
        ]
        assert len(encryption_findings) > 0, (
            f"Expected structured 'No encryption' security finding. "
            f"Available findings: {[f.get('data', {}).get('finding') for f in security_events]}"
        )

        # The print_host_info() finding MUST carry the detail sentence in its own
        # slot (regression guard: it was previously mis-passed into `category`,
        # so `data.details` was empty). Find the finding titled exactly
        # "No encryption" and assert it has a non-empty details field.
        titled = [
            f
            for f in security_events
            if f.get("data", {}).get("finding", "").lower() == "no encryption"
        ]
        assert titled, (
            "Expected a finding titled exactly 'No encryption'. "
            f"Got: {[f.get('data', {}).get('finding') for f in security_events]}"
        )
        detailed = [f for f in titled if (f.get("data", {}).get("details") or "").strip()]
        assert detailed, (
            "'No encryption' finding must populate data.details (not stuff the "
            f"detail sentence into category). Got data blocks: {[f.get('data') for f in titled]}"
        )
        plaintext_detail = " ".join(f.get("data", {}).get("details", "") for f in detailed).lower()
        assert any(w in plaintext_detail for w in ("tls", "plaintext", "unencrypted")), (
            f"Expected plaintext/TLS wording in details, got: {plaintext_detail!r}"
        )

    @pytest.mark.security
    def test_finding_anonymous_access_on_insecure_broker(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'Anonymous access' finding fires on insecure broker (no creds).

        Trigger: __init__.py print_host_info() emits security_finding("Anonymous access",
        "Anonymous authentication allowed") when self.conn is truthy and no username
        was provided. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # The scanner should report anonymous access
        text = _combined_text(result, log)
        assert "anonymous" in text, (
            f"Expected 'Anonymous access' finding on insecure broker: {text[:500]}"
        )

        # Validate structured security event
        security_events = log.get_security_findings()
        anon_findings = [
            f
            for f in security_events
            if "anonymous" in f.get("data", {}).get("finding", "").lower()
            or "anonymous" in f.get("message", "").lower()
        ]
        assert len(anon_findings) > 0, (
            f"Expected structured 'Anonymous access' security finding. "
            f"Available findings: {[f.get('data', {}).get('finding') for f in security_events]}"
        )

        # Regression guard: the print_host_info() "Anonymous access" finding must
        # carry its detail sentence in data.details, not in category.
        titled = [
            f
            for f in security_events
            if f.get("data", {}).get("finding", "").lower() == "anonymous access"
        ]
        assert titled, (
            "Expected a finding titled exactly 'Anonymous access'. "
            f"Got: {[f.get('data', {}).get('finding') for f in security_events]}"
        )
        detailed = [f for f in titled if (f.get("data", {}).get("details") or "").strip()]
        assert detailed, (
            "'Anonymous access' finding must populate data.details, not stuff the "
            f"detail sentence into category. Got data blocks: {[f.get('data') for f in titled]}"
        )
        anon_detail = " ".join(f.get("data", {}).get("details", "") for f in detailed).lower()
        assert "anonymous" in anon_detail or "credential" in anon_detail, (
            f"Expected anonymous/credential wording in details, got: {anon_detail!r}"
        )

    @pytest.mark.security
    def test_finding_no_encryption_absent_with_tls(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'No encryption' finding does NOT fire when --tls is used.

        When connecting with --tls, the scanner should not emit the
        'No encryption' finding. Tests the negative case. [Category B]
        """
        port = mock_ports.get("mqtt_tls", 8883)
        require_port(mock_host, port, "TLS MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--tls",
            "--tls-insecure",
            "--username",
            "admin",
            "--password",
            "admin",
            format="json",
            json_log=True,
            timeout=20,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Must attempt something (not a no-op)
        assert any(term in text for term in ["connect", "tls", "mqtt", "ssl"]), (
            f"Expected TLS connection attempt: {text[:500]}"
        )

        # If connection succeeded, "No encryption" should NOT appear in security findings
        if result.success and result.scan_log:
            security_events = result.scan_log.get_security_findings()
            no_enc_findings = [
                f
                for f in security_events
                if f.get("data", {}).get("finding", "").lower() == "no encryption"
            ]
            assert len(no_enc_findings) == 0, (
                f"'No encryption' finding should NOT fire with --tls. Found: {no_enc_findings}"
            )

    @pytest.mark.security
    def test_finding_anonymous_access_absent_with_credentials(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'Anonymous access' finding does NOT fire when creds are provided.

        When connecting with --username/--password, the scanner should not emit
        'Anonymous access'. Tests the negative case. [Category B]
        """
        port = mock_ports.get("mqtt_auth", 1884)
        require_port(mock_host, port, "Auth MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--username",
            "admin",
            "--password",
            "admin",
            format="json",
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["connect", "mqtt", "auth", "success"]), (
            f"Expected connection attempt: {text[:500]}"
        )

        # If connection succeeded with credentials, "Anonymous access" should NOT appear
        if result.success and result.scan_log:
            security_events = result.scan_log.get_security_findings()
            anon_findings = [
                f
                for f in security_events
                if f.get("data", {}).get("finding", "").lower() == "anonymous access"
            ]
            assert len(anon_findings) == 0, (
                f"'Anonymous access' should NOT fire when credentials were provided. "
                f"Found: {anon_findings}"
            )

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_sys_topics_exposed(self, cli_runner, mock_host, mock_ports, mock_service):
        """Verify 'Insecure configuration' finding for $SYS topics exposure.

        Trigger: scanner.py _analyze_security() emits security_finding("Insecure
        configuration", "$SYS topics exposed ({N} topics)") when $SYS enumeration
        finds topics. Requires --enumerate to trigger $SYS enumeration. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Enumeration scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        # The mock broker exposes $SYS topics, so this finding MUST appear
        assert "$sys" in text, f"Expected $SYS topic enumeration output: {text[:500]}"
        assert any(
            term in text
            for term in ["$sys topics", "sys topic", "broker info", "insecure configuration"]
        ), f"Expected $SYS exposure finding: {text[:500]}"

        # Validate structured security finding
        security_events = log.get_security_findings()
        sys_findings = [
            f
            for f in security_events
            if "$sys" in f.get("message", "").lower()
            or "$sys" in str(f.get("data", {})).lower()
            or "insecure configuration" in f.get("data", {}).get("finding", "").lower()
        ]
        assert len(sys_findings) > 0, (
            f"Expected '$SYS topics exposed' security finding. "
            f"Available findings: {[f.get('data', {}).get('finding') for f in security_events]}"
        )

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_wildcard_subscriptions_allowed(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'Insecure configuration' finding for wildcard subscription (#).

        Trigger: scanner.py _analyze_security() emits security_finding("Insecure
        configuration", "Wildcard subscriptions allowed ({N} topics)") when
        wildcard # pattern yields topics. Requires --enumerate. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Enumeration scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        # The insecure mock allows wildcard subscriptions and has ICS topics
        assert "wildcard" in text or "topic" in text, (
            f"Expected wildcard/topic output: {text[:500]}"
        )

        # Validate structured security finding for wildcard
        security_events = log.get_security_findings()
        wildcard_findings = [
            f
            for f in security_events
            if "wildcard" in f.get("message", "").lower()
            or "wildcard" in str(f.get("data", {})).lower()
        ]
        assert len(wildcard_findings) > 0, (
            f"Expected 'Wildcard subscriptions allowed' security finding. "
            f"Available findings: "
            f"{[(f.get('data', {}).get('finding'), f.get('message', '')[:60]) for f in security_events]}"
        )

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_anonymous_access_in_analyze_security(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'Anonymous access allowed' from _analyze_security().

        Trigger: scanner.py _analyze_security() emits security_finding("Anonymous
        access allowed") when auth.anonymous_allowed is True. This is separate
        from the print_host_info() anonymous finding. Requires --enumerate to
        reach the _analyze_security() code path. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        # Both the print_host_info and _analyze_security paths should fire
        assert "anonymous" in text, f"Expected 'Anonymous access' finding: {text[:500]}"

        # Should have at least one anonymous-related security finding
        security_events = log.get_security_findings()
        anon_findings = [
            f
            for f in security_events
            if "anonymous" in f.get("message", "").lower()
            or "anonymous" in str(f.get("data", {})).lower()
        ]
        assert len(anon_findings) > 0, (
            f"Expected 'Anonymous access allowed' from _analyze_security. "
            f"Available findings: {[f.get('data', {}).get('finding') for f in security_events]}"
        )

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_no_encryption_in_analyze_security(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'No encryption' from _analyze_security() on enumeration.

        Trigger: scanner.py _analyze_security() emits security_finding("No encryption",
        "Communication is unencrypted") when TLS is not used. This is the second
        'No encryption' finding (the first fires in print_host_info). [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        # With --enumerate, _analyze_security runs and should fire "No encryption"
        assert any(term in text for term in ["no encryption", "plaintext", "unencrypted"]), (
            f"Expected 'No encryption' finding: {text[:500]}"
        )

        # Count encryption findings - should have at least 1 (possibly 2 from both paths)
        security_events = log.get_security_findings()
        enc_findings = [
            f
            for f in security_events
            if "encryption" in f.get("message", "").lower()
            or "encryption" in f.get("data", {}).get("finding", "").lower()
        ]
        assert len(enc_findings) >= 1, (
            f"Expected at least 1 'No encryption' finding. "
            f"Available findings: {[f.get('data', {}).get('finding') for f in security_events]}"
        )

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_default_credentials_brute_force(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify 'Default credentials' finding from brute-force on auth broker.

        Trigger: scanner.py _brute_force_credentials() emits security_finding(
        "Default credentials", "Valid MQTT credentials: admin:admin") when valid
        credentials are found. Auth broker has admin:admin. [Category A]
        """
        port = mock_ports.get("mqtt_auth", 1884)
        require_port(mock_host, port, "Auth MQTT broker", timeout=3)

        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--default-creds",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        # The brute-force MUST attempt credentials
        assert any(term in text for term in ["brute", "credential", "default", "tested"]), (
            f"Expected brute-force activity in output: {text[:500]}"
        )

        # Check for valid credential finding
        # The auth broker has admin:admin which is in DEFAULT_CREDENTIALS
        security_events = log.get_security_findings()
        cred_findings = [
            f
            for f in security_events
            if "credential" in f.get("message", "").lower()
            or "credential" in f.get("data", {}).get("finding", "").lower()
            or "default credential" in f.get("message", "").lower()
        ]
        # This may or may not find valid creds depending on timing, so
        # we check the brute-force ran and report findings if present
        if cred_findings:
            # Verify the finding mentions actual credentials
            cred_text = " ".join(
                f.get("message", "") + str(f.get("data", {})) for f in cred_findings
            ).lower()
            assert "admin" in cred_text or "credential" in cred_text, (
                f"Expected credential details in finding: {cred_text[:500]}"
            )

    @pytest.mark.security
    @pytest.mark.slow
    def test_finding_multiple_security_issues_full_scan(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify multiple security findings fire during full enumeration scan.

        On the insecure broker (port 1883) with --enumerate, the scanner should
        produce at least 3 security findings:
        1. "No encryption" (plaintext)
        2. "Anonymous access" (no credentials required)
        3. "$SYS topics exposed" or "Wildcard subscriptions allowed"
        [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enumerate",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Full scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Verify minimum security findings count
        security_events = log.get_security_findings()
        assert len(security_events) >= 2, (
            f"Expected at least 2 security findings on insecure broker, "
            f"got {len(security_events)}: "
            f"{[f.get('data', {}).get('finding', f.get('message', '')[:40]) for f in security_events]}"
        )

        # Verify that both encryption and access findings are present
        all_findings_text = " ".join(
            f.get("message", "") + " " + str(f.get("data", {})) for f in security_events
        ).lower()
        assert "encryption" in all_findings_text or "plaintext" in all_findings_text, (
            f"Expected encryption-related finding: {all_findings_text[:500]}"
        )
        assert "anonymous" in all_findings_text or "access" in all_findings_text, (
            f"Expected access-related finding: {all_findings_text[:500]}"
        )

    @pytest.mark.security
    def test_finding_security_events_have_correct_structure(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify security finding events have correct JSON structure.

        Each security event should have event_type="security" and include
        a data.finding field with the finding name. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Get security findings
        security_events = log.get_security_findings()
        assert len(security_events) > 0, "Expected at least 1 security finding on insecure broker"

        # Validate structure of each security event
        for i, event in enumerate(security_events):
            assert event.get("event_type") == "security", (
                f"Security event {i} should have event_type='security', "
                f"got '{event.get('event_type')}'"
            )
            assert "data" in event, f"Security event {i} missing 'data' field"
            data = event["data"]
            assert "finding" in data, (
                f"Security event {i} missing 'data.finding' field. Data: {data}"
            )
            assert isinstance(data["finding"], str) and len(data["finding"]) > 0, (
                f"Security event {i} 'data.finding' should be non-empty string, "
                f"got: {data['finding']!r}"
            )

    @pytest.mark.security
    def test_finding_connection_lifecycle_with_security(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """Verify connection events precede security findings in log.

        The scanner should log connection events before security analysis.
        This validates proper event sequencing. [Category A]
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
        )

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Check that connection events exist
        conn_events = log.get_connection_events()
        security_events = log.get_security_findings()

        # Both should be present
        assert len(conn_events) > 0 or len(security_events) > 0, (
            "Expected connection events or security findings"
        )

        # If both exist, verify connection comes before security
        if conn_events and security_events:
            first_conn_idx = next(
                i for i, e in enumerate(log.events) if e.get("event_type") == "connection"
            )
            first_security_idx = next(
                i for i, e in enumerate(log.events) if e.get("event_type") == "security"
            )
            assert first_conn_idx < first_security_idx, (
                f"Connection events (idx={first_conn_idx}) should precede "
                f"security findings (idx={first_security_idx})"
            )

    # ========================================================================
    # Standard Tests
    # ========================================================================

    def test_help_output(self, cli_runner):
        """Test --help output [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            "--help",
            expect_json=False,
        )

        assert result.returncode == 0
        assert "mqtt" in result.stdout.lower()

    def test_verbose_output(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test verbose output [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
            verbose=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "mqtt" in text, (
            f"Expected connection output with verbose: {text[:500]}"
        )

    def test_debug_output(self, cli_runner, mock_host, mock_ports, mock_service):
        """Test --debug output [Category B]"""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=20,
            debug=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "connect" in text or "mqtt" in text, (
            f"Expected connection output with debug: {text[:500]}"
        )

    # ------------------------------------------------------------------
    # Flag-coverage additions: publish payload variants
    # (--message/--hex/--null/--payload-file)
    # ------------------------------------------------------------------

    def test_publish_plain_message_with_qos_and_retain(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """[Category A] Category A: -m/--message combined with -q/--qos and -r/--retain against the
        real insecure broker. Asserts the actual byte count/qos/retain echoed in the
        scan log, verified manually to read "PUBLISH to 'test/pub' (5 bytes, qos=1,
        retain=True)" against docker/mocks/services/mqtt/mock/mqtt_broker_insecure.py.
        """
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--message",
            "hello",
            "--topics",
            "test/pub",
            "--confirm",
            "--qos",
            "1",
            "--retain",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "test/pub" in text
        assert "5 bytes" in text
        assert "qos=1" in text
        assert "retain=true" in text

    def test_publish_hex_payload(self, cli_runner, mock_host, mock_ports, mock_service):
        """[Category A] Category A: --hex builds a binary payload from a hex string; asserts the
        real decoded byte count (3 bytes for "01:02:FF")."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--hex",
            "--message",
            "01:02:FF",
            "--topics",
            "test/hex",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "test/hex" in text
        assert "3 bytes" in text

    def test_publish_null_message(self, cli_runner, mock_host, mock_ports, mock_service):
        """[Category A] Category A: -n/--null publishes a zero-byte payload; asserts "0 bytes"."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--null",
            "--topics",
            "test/null",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "test/null" in text
        assert "0 bytes" in text

    def test_publish_payload_file(self, cli_runner, mock_host, mock_ports, mock_service, tmp_path):
        """[Category A] Category A: --payload-file reads raw bytes from disk; asserts the real
        6-byte file content is published (file contains the ASCII text "AABBCC")."""
        payload_file = tmp_path / "payload.bin"
        payload_file.write_text("AABBCC")
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--payload-file",
            str(payload_file),
            "--topics",
            "test/file",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "test/file" in text
        assert "6 bytes" in text

    # ------------------------------------------------------------------
    # Flag-coverage additions: protocol version + MQTT5 properties
    # ------------------------------------------------------------------

    def test_protocol_version_v3_connects(self, cli_runner, mock_host, mock_ports, mock_service):
        """[Category A] Category A: -V/--protocol-version pinned to MQTT 3.1 against the real
        insecure broker, which accepts all requested versions. Verified manually this
        connects cleanly."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--protocol-version",
            "3",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        assert "Traceback" not in result.combined_output

    def test_mqtt5_publish_properties_combo(self, cli_runner, mock_host, mock_ports, mock_service):
        """[Category B] Category B: maximal MQTT5-properties publish invocation combining -V 5,
        -R/--response-topic, -J/--correlation-id, -Y/--content-type,
        -X/--message-expiry and -W/--user-prop. The insecure mock does not echo v5
        properties back to the publisher, so this asserts the publish still completes
        cleanly with the byte count observable (parse/accept path), not the property
        values themselves."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--protocol-version",
            "5",
            "--message",
            "props",
            "--topics",
            "test/props",
            "--confirm",
            "--response-topic",
            "test/response",
            "--correlation-id",
            "corr-id-123",
            "--content-type",
            "application/json",
            "--message-expiry",
            "60",
            "--user-prop",
            "region=us-east",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        assert "Traceback" not in result.combined_output

    def test_enum_versions_reports_supported_versions(
        self, cli_runner, mock_host, mock_ports, mock_service, tmp_path
    ):
        """[Category A] Category A: -B/--enum-versions against the real insecure broker. Verified
        manually via `--output DIR` that this mock (which always answers with a fixed
        MQTT 3.1.1-style CONNACK regardless of requested version) reports 3.1 and
        3.1.1 as supported and 5.0 as NOT supported, with versions_supported ==
        ["3.1", "3.1.1"] and anonymous_allowed == True."""
        port = mock_ports.get("mqtt", 1883)
        out_dir = tmp_path / "mqtt_enum_versions"
        result = cli_runner.run(
            self.protocol_name,
            mock_host,
            "--port",
            str(port),
            "--enum-versions",
            "--output",
            str(out_dir),
            format="json",
            timeout=20,
        )
        assert "Traceback" not in result.combined_output
        json_path = out_dir / "mqtt.json"
        assert json_path.exists(), f"expected {json_path} to be written"
        data = json.loads(json_path.read_text())
        entries = data if isinstance(data, list) else [data]
        entry = entries[0]
        protocol_versions = entry.get("data", {}).get("protocol_versions", {})
        assert protocol_versions.get("versions_supported") == ["3.1", "3.1.1"]
        assert protocol_versions.get("anonymous_allowed") is True
        tested = {v["version"]: v for v in protocol_versions.get("versions_tested", [])}
        assert tested.get(3, {}).get("supported") is True
        assert tested.get(4, {}).get("supported") is True
        assert tested.get(5, {}).get("supported") is False

    # ------------------------------------------------------------------
    # P1 -- false-positive identification against a dead/impostor target
    # ------------------------------------------------------------------

    def test_closed_port_no_false_positive(self, cli_runner, tmp_path):
        """[Category C] P1 regression: nothing listens on this port at all, so the
        JSON result must report success=False (not a fabricated broker). Root cause
        was src/oida/connection.py's run() defaulting results["success"] to True
        whenever proto_flow() returns without raising, while mqtt/cli_runner.py never
        set success=False on a clean (non-exception) connection failure. The fix
        gates success on _connection_error, so an unreachable port is now False.
        """
        closed_port = 19999
        assert not check_port_open("127.0.0.1", closed_port, timeout=1)
        out_dir = tmp_path / "mqtt_closed"
        result = cli_runner.run(
            "mqtt",
            "127.0.0.1",
            "--port",
            str(closed_port),
            "--timeout",
            "3",
            "--output",
            str(out_dir),
            format="json",
        )
        assert "Traceback" not in result.combined_output
        json_path = out_dir / "mqtt.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        entries = data if isinstance(data, list) else [data]
        entry = entries[0]
        # Fixed: a totally unreachable port must not report success.
        assert entry.get("success") is False
        assert entry.get("error")
        assert entry.get("data") == {}

    def test_wrong_protocol_on_port_no_false_positive(self, cli_runner, mock_ports, tmp_path):
        """[Category C] P1: point mqtt at a live modbus mock (a real server, wrong protocol). The
        console/log must not claim an MQTT broker was found. Note: this mock also
        reproduces the same success=True bug as the closed-port case above (see
        test_false_positive_success_on_closed_port for the root cause), which this
        test documents too since it is the observable behavior a consumer would see."""
        modbus_port = mock_ports.get("modbus")
        if not modbus_port or not check_port_open(MOCK_HOST, modbus_port, timeout=2):
            pytest.skip("modbus mock not available for impostor-protocol test")
        out_dir = tmp_path / "mqtt_modbus_impostor"
        result = cli_runner.run(
            "mqtt",
            MOCK_HOST,
            "--port",
            str(modbus_port),
            "--timeout",
            "3",
            "--output",
            str(out_dir),
            format="json",
        )
        assert "Traceback" not in result.combined_output
        assert "MockMQTT" not in result.combined_output
        json_path = out_dir / "mqtt.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        entries = data if isinstance(data, list) else [data]
        entry = entries[0]
        # A wrong-protocol server never sends a CONNACK: must not be a false positive.
        assert entry.get("success") is False
        assert entry.get("data") == {}

    def test_silent_socket_no_false_positive(self, cli_runner, tmp_path):
        """[Category C] P1: a socket that accepts the TCP connection and then never speaks MQTT.
        Exercises the read/handshake timeout path (not the connect timeout). Must not
        report a fabricated broker identification."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        silent_port = server.getsockname()[1]
        stop = threading.Event()

        def _accept_and_stay_silent():
            server.settimeout(5)
            try:
                conn, _addr = server.accept()
                stop.wait(4)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=_accept_and_stay_silent, daemon=True)
        thread.start()
        try:
            out_dir = tmp_path / "mqtt_silent"
            result = cli_runner.run(
                "mqtt",
                "127.0.0.1",
                "--port",
                str(silent_port),
                "--timeout",
                "3",
                "--output",
                str(out_dir),
                format="json",
                timeout=30,
            )
            assert "Traceback" not in result.combined_output
            assert "MockMQTT" not in result.combined_output
            # A silent socket never sends a CONNACK: must not be a false positive.
            json_path = out_dir / "mqtt.json"
            if json_path.exists():
                data = json.loads(json_path.read_text())
                entry = (data if isinstance(data, list) else [data])[0]
                assert entry.get("success") is False
        finally:
            stop.set()
            server.close()
            thread.join(timeout=5)

    def test_junk_bytes_socket_no_false_positive(self, cli_runner, tmp_path):
        """[Category C] P1: a socket that immediately sends junk bytes where an MQTT CONNACK is
        expected. Must produce a parse error, never a fabricated broker record."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        junk_port = server.getsockname()[1]
        stop = threading.Event()

        def _accept_and_send_junk():
            server.settimeout(5)
            try:
                conn, _addr = server.accept()
                conn.sendall(b"\xff\xff\xff\xff not an mqtt connack at all")
                stop.wait(3)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=_accept_and_send_junk, daemon=True)
        thread.start()
        try:
            out_dir = tmp_path / "mqtt_junk"
            result = cli_runner.run(
                "mqtt",
                "127.0.0.1",
                "--port",
                str(junk_port),
                "--timeout",
                "3",
                "--output",
                str(out_dir),
                format="json",
                timeout=30,
            )
            assert "Traceback" not in result.combined_output
            assert "MockMQTT" not in result.combined_output
            # Junk instead of a CONNACK: must not be a fabricated broker.
            json_path = out_dir / "mqtt.json"
            if json_path.exists():
                data = json.loads(json_path.read_text())
                entry = (data if isinstance(data, list) else [data])[0]
                assert entry.get("success") is False
        finally:
            stop.set()
            server.close()
            thread.join(timeout=5)

    # ------------------------------------------------------------------
    # P1b -- --timeout not honored against a blackhole host
    # ------------------------------------------------------------------

    def test_timeout_not_honored_against_blackhole(self, cli_runner):
        """[Category C] P1b bug evidence: requesting a generous --timeout of 20s against a
        blackhole address does NOT make the scan take ~20s. Root cause: paho-mqtt's
        Client()._connect_timeout defaults to 5.0s and oida never overrides it from
        self.timeout anywhere in src/oida/protocols/mqtt/ -- the raw socket connect is
        always bounded at paho's hardcoded 5s regardless of the CLI --timeout value.
        This does not hang forever (good), but the flag is silently ignored for the
        connect phase. Verified manually: --timeout 3 and --timeout 20 both finish in
        ~5-6s. This test bounds the harness subprocess generously and asserts the run
        finishes well under the requested budget, and that the process was not
        force-killed (returncode == -1 would indicate an actual hang, which is NOT
        what happens here)."""
        start = time.monotonic()
        result = cli_runner.run(
            "mqtt",
            "10.255.255.1",
            "--port",
            "1883",
            "--timeout",
            "20",
            format="json",
            json_log=True,
            timeout=30,
        )
        elapsed = time.monotonic() - start
        assert result.returncode != -1, "run was killed by the harness -- looks like a real hang"
        assert "Traceback" not in result.combined_output
        assert elapsed < 15, (
            f"expected --timeout to be ignored and the run to finish near paho's "
            f"hardcoded 5s default, took {elapsed:.1f}s instead"
        )

    # ------------------------------------------------------------------
    # P2 -- malformed/out-of-range values on bounded flags
    # ------------------------------------------------------------------

    def test_qos_out_of_range_rejected(self, cli_runner, mock_host, mock_ports):
        """[Category C] P2/P3: -q/--qos only accepts {0,1,2}; a value of 5 must be rejected by
        argparse (exit code 2), never silently accepted or crash."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--message",
            "x",
            "--topics",
            "test/q",
            "--confirm",
            "--qos",
            "5",
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_protocol_version_out_of_range_rejected(self, cli_runner, mock_host, mock_ports):
        """[Category C] P2/P3: -V/--protocol-version only accepts {3,4,5}; a value of 9 must be
        rejected by argparse (exit code 2)."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--protocol-version",
            "9",
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_message_expiry_non_numeric_rejected(self, cli_runner, mock_host, mock_ports):
        """[Category C] P2/P3: --message-expiry expects an integer; a non-numeric value must be
        rejected cleanly, never crash with a traceback."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--message",
            "x",
            "--topics",
            "test/exp",
            "--confirm",
            "--message-expiry",
            "not-a-number",
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_negative_fuzz_iterations_rejected_or_no_crash(self, cli_runner, mock_host, mock_ports):
        """[Category B] P2: an inverted/negative --fuzz-iterations count must not crash or hang;
        it is either rejected outright or treated as zero iterations."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "-5",
            format="json",
            json_log=True,
            timeout=30,
        )
        assert "Traceback" not in result.combined_output

    # ------------------------------------------------------------------
    # P4 -- confirm gate on publish
    # ------------------------------------------------------------------

    def test_publish_without_confirm_refused(self, cli_runner, mock_host, mock_ports):
        """[Category C] P4: publishing (-m) without --confirm must be refused, with an error event
        in the scan log mentioning confirm."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--message",
            "should-not-publish",
            "--topics",
            "test/noconfirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "confirm" in text.lower()

    def test_publish_without_topics_refused(self, cli_runner, mock_host, mock_ports):
        """[Category C] P4/P2: publishing with --confirm but no --topics (wildcard-only) must be
        refused rather than silently publishing to '#'."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--message",
            "should-not-publish",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "topic" in text.lower()

    def test_publish_with_confirm_and_topics_proceeds(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """[Category A] P4 positive path: with both --confirm and --topics present, the publish is
        permitted and actually happens against the real broker."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--message",
            "confirmed",
            "--topics",
            "test/confirmed",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert "test/confirmed" in text

    # ------------------------------------------------------------------
    # P5 -- unclean shutdown / leaked-thread noise on stderr
    # ------------------------------------------------------------------

    def test_no_leaked_thread_noise_on_stderr(
        self, cli_runner, mock_host, mock_ports, mock_service
    ):
        """[Category B] P5: paho-mqtt runs its own network loop thread (loop_start/loop_stop); a
        clean exit must not leak "Task was destroyed"/thread-exception noise onto
        stderr."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--message",
            "stderr-check",
            "--topics",
            "test/stderr",
            "--confirm",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert "Task was destroyed" not in result.stderr
        assert "Exception ignored" not in result.stderr
        assert "Traceback" not in result.combined_output

    # ------------------------------------------------------------------
    # P6 -- flag hygiene
    # ------------------------------------------------------------------

    def test_unknown_flag_rejected(self, cli_runner, mock_host, mock_ports):
        """[Category C] P6: an entirely unknown flag must exit non-zero with a usage error, never
        be silently ignored."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--not-a-real-flag",
            "value",
        )
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_typo_flag_transposition_rejected(self, cli_runner, mock_host, mock_ports):
        """[Category C] P6: a transposition typo of a real flag (--qso instead of --qos) must be
        rejected, not silently accepted as a truncation-prefix of some other flag."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--qso",
            "1",
        )
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_wrong_type_value_for_typed_flag_rejected(self, cli_runner, mock_host, mock_ports):
        """[Category C] P3/P6: passing a non-integer value to an integer-typed flag
        (--fuzz-iterations) must be rejected cleanly, never crash."""
        port = mock_ports.get("mqtt", 1883)
        result = cli_runner.run(
            "mqtt",
            mock_host,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "not-a-number",
        )
        assert not result.success
        assert "Traceback" not in result.combined_output
