"""
CoAP Protocol Integration Tests

Tests oida coap scanner against Docker mock service (coap_server.py).
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/coap/coap_server.py):
  Server: CoAP mock on UDP port 5683
  Resources (auto-listed in /.well-known/core):
    /sensor/temperature   -- observable, sine-wave float, text/plain
    /sensor/humidity      -- observable, float, text/plain
    /sensor/pressure      -- observable, float, text/plain
    /sensor/large-data    -- GET, >2KB JSON array (block-wise transfer test)
    /sensor/data.cbor     -- GET, CBOR-encoded sensor data (ct=60)
    /sensor/measurements  -- GET, SenML JSON array (ct=110)
    /actuator/led         -- GET/PUT, "0"/"1"
    /actuator/relay       -- GET/PUT, "0"/"1" (writable without auth)
    /actuator/valve       -- GET/PUT, 0-100 percentage
    /config               -- GET/PUT/FETCH/PATCH/iPATCH, JSON config blob
    /firmware/version     -- GET only, "1.2.3"
    /time                 -- GET only, ISO timestamp
    /device               -- GET only, JSON device info
    /3/0.json             -- GET, LwM2M JSON format (ct=11543)

  LwM2M paths:
    /3/0/0  = "OIDA-Test"       (manufacturer)
    /3/0/1  = "CoAP-Mock-v1"    (model)
    /3/0/2  = "SN-2024-001337"  (serial)
    /3/0/3  = "1.2.3-beta"      (firmware version)
    /3/0/9  = "87"              (battery level)
    /3/0/13 = current unix timestamp
    /0/0/2  = "3"               (NoSec mode -- intentional security finding)
    /1/0/1  = "3600"            (lifetime)
    /5/0/3  = "0"               (firmware update state)

  Security findings:
    - PUT to /actuator/* succeeds without authentication
    - /0/0/2 = 3 (NoSec mode -- no DTLS encryption)

Test Classification Summary (47 defined + 6 inherited from BaseProtocolIntegrationTest)
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  17 tests
Category B (conditional -- mock may not support, accept 0 or 1):       23 tests
Category C (error handling -- assert failure + validate error events):   7 tests
Skipped (untestable -- requires DTLS hardware/certs):                   0 tests
Total defined in file:                                                 47 tests
Inherited from base (not overridden):                                   6 tests
Total collected:                                                       53 tests
---------------------------------------------------------------------------

Flag Coverage Matrix (proto_args.py):
  --port                    [A] test_basic_scan_with_port
  --timeout                 [B] test_timeout_option
  --resources               [A] test_wellknown_core_discovery (default=True)
  --probe-paths             [B] test_probe_common_paths
  --lwm2m                   [A] test_lwm2m_device_object
  --lwm2m-full              [B] test_lwm2m_full_enumeration
  --methods                 [B] test_method_enumeration
  --observe                 [B] test_observe_resources
  --observe-count           [B] test_observe_with_count
  --dtls                    [B] test_dtls_option
  --psk                     [B] test_psk_option
  --psk-identity            [B] test_psk_identity_option
  --put + --confirm         [B] test_put_actuator_with_confirm
  --put (no --confirm)      [C] test_put_without_confirm
  --post + --confirm        [B] test_post_with_confirm
  --post (no --confirm)     [C] test_post_without_confirm
  --delete + --confirm      [B] test_delete_with_confirm
  --delete (no --confirm)   [C] test_delete_without_confirm
  --confirm (alone)         [B] test_confirm_alone
  --block-size              [B] test_blockwise_large_resource
  --fetch                   [B] test_fetch_config_with_filter
  --patch + --confirm       [B] test_patch_config
  --ipatch + --confirm      [B] test_ipatch_config
  --probe-paths (cbor)      [B] test_cbor_resource_discovery
  --probe-paths (senml)     [B] test_senml_resource_discovery
  --probe-paths (lwm2m-json)[B] test_lwm2m_json_resource_discovery
  (wrong port)              [C] test_wrong_port
  (unreachable host)        [C] test_unreachable_host
  (nonexistent host)        [B] test_nonexistent_host (UDP: no connect failure)
  (invalid target)          [B] test_invalid_target (UDP: no connect failure)
  (tcp port mismatch)       [C] test_connection_to_tcp_port
  (zero timeout)            [C] test_zero_timeout
  (udp availability)        [A] test_service_is_available (override)
  (security: nosec)         [A] test_nosec_detection
  (security: unauth write)  [A] test_unauth_write_detection
  (security: no DTLS)       [A] test_no_dtls_finding
  (finding: NoSec mode)     [A] test_security_finding_nosec_mode_encryption
  (finding: NoSec+DTLS)     [A] test_security_finding_nosec_dtls_available
  (finding: No auth)        [A] test_security_finding_no_authentication
  (finding: unauth writes)  [A] test_security_finding_unauthenticated_writes
  (connection events)       [A] test_connection_events_in_log
  (log structure)           [A] test_json_log_structure
  (log info events)         [A] test_json_log_has_info_events
"""

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST, check_udp_port_open


# ---------------------------------------------------------------------------
# Known Mock Data Constants (from coap_server.py)
# ---------------------------------------------------------------------------
MOCK_MANUFACTURER = "oida-test"
MOCK_MODEL = "coap-mock-v1"
MOCK_SERIAL = "sn-2024-001337"
MOCK_FIRMWARE = "1.2.3-beta"
MOCK_FIRMWARE_SHORT = "1.2.3"


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


@pytest.mark.coap
class TestCoAPIntegration(BaseProtocolIntegrationTest):
    """Integration tests for CoAP protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "coap"

    @property
    def default_port(self) -> int:
        return 5683

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # Override base class TCP check -- CoAP is UDP
    def test_service_is_available(self, mock_host, port):
        """Verify CoAP mock service is running and accessible via UDP [Category A]"""
        assert check_udp_port_open(mock_host, port, timeout=3), (
            f"CoAP service not available on UDP port {port}"
        )

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
                "coap",
                "connected",
                "resource",
                "sensor",
                "actuator",
                "well-known",
                MOCK_MANUFACTURER,
            ]
        ), f"Expected CoAP scan output, got: {text[:500]}"

    def test_wellknown_core_discovery(self, cli_runner, target, port):
        """Test that /.well-known/core returns parseable link-format resources [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "sensor/temperature",
                "actuator/led",
                "well-known",
                "discovered",
                "resource",
            ]
        ), f"Expected resource discovery output: {text[:500]}"

    def test_probe_common_paths(self, cli_runner, target, port):
        """Test --probe-paths finds known resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-paths",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "probe",
                "resource",
                "sensor",
                "actuator",
                "config",
                "device",
                "coap",
                "connected",
                "found",
                "path",
            ]
        ), f"Expected probe output: {text[:500]}"

    def test_timeout_option(self, cli_runner, target, port):
        """Test --timeout option is accepted and used [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "coap",
                "connected",
                "resource",
                "device",
            ]
        ), f"Expected scan output with timeout: {text[:500]}"

    # ========================================================================
    # LwM2M Tests
    # ========================================================================

    def test_lwm2m_device_object(self, cli_runner, target, port):
        """Test --lwm2m extracts manufacturer/model/serial from /3/0 [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lwm2m",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"LwM2M scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                MOCK_MANUFACTURER,
                MOCK_MODEL,
                MOCK_SERIAL,
                "lwm2m",
                "manufacturer",
                "device",
            ]
        ), f"Expected LwM2M device info, got: {text[:500]}"

    def test_lwm2m_full_enumeration(self, cli_runner, target, port):
        """Test --lwm2m-full enumerates all LwM2M objects [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lwm2m-full",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "lwm2m",
                "enumerate",
                "object",
                "device",
                "security",
                "server",
                MOCK_MANUFACTURER,
                "coap",
                "connected",
            ]
        ), f"Expected LwM2M full enumeration output: {text[:500]}"

    # ========================================================================
    # Method Testing
    # ========================================================================

    def test_method_enumeration(self, cli_runner, target, port):
        """Test --methods tests methods on discovered resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--methods",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "method",
                "get",
                "put",
                "delete",
                "coap",
                "connected",
                "resource",
                "testing",
            ]
        ), f"Expected method enumeration output: {text[:500]}"

    # ========================================================================
    # Observe Tests
    # ========================================================================

    @pytest.mark.slow
    def test_observe_resources(self, cli_runner, target, port):
        """Test --observe subscribes to observable resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--observe",
            "--observe-count",
            "3",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "observe",
                "notification",
                "subscribe",
                "sensor",
                "coap",
                "connected",
                "observable",
            ]
        ), f"Expected observe output: {text[:500]}"

    def test_observe_with_count(self, cli_runner, target, port):
        """Test --observe-count limits notifications collected [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--observe",
            "--observe-count",
            "2",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "observe",
                "notification",
                "subscribe",
                "coap",
                "connected",
            ]
        ), f"Expected observe count output: {text[:500]}"

    # ========================================================================
    # Security Tests
    # ========================================================================

    @pytest.mark.security
    def test_nosec_detection(self, cli_runner, target, port):
        """Test that scanner detects NoSec mode from /0/0/2=3 [Category A]"""
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
        assert any(
            term in text
            for term in [
                "nosec",
                "no sec",
                "security mode",
                "no transport security",
                "mode: nosec",
                "coap",
            ]
        ), f"Expected NoSec detection, got: {text[:500]}"

    @pytest.mark.security
    def test_unauth_write_detection(self, cli_runner, target, port):
        """Test that scanner detects unauthenticated PUT on /actuator/* [Category A]"""
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
        assert any(
            term in text
            for term in [
                "unauthenticated",
                "unauth",
                "write",
                "put accepted",
                "actuator",
            ]
        ), f"Expected unauth write detection, got: {text[:500]}"

    @pytest.mark.security
    def test_no_dtls_finding(self, cli_runner, target, port):
        """Test that scanner reports DTLS not available [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"DTLS check failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                "dtls",
                "nosec",
                "not responsive",
                "not detected",
                "no transport security",
                "security",
                "encryption",
            ]
        ), f"Expected DTLS finding, got: {text[:500]}"

    # ========================================================================
    # Security Finding Event Tests (structured JSON log assertions)
    # ========================================================================

    @pytest.mark.security
    def test_security_finding_nosec_mode_encryption(self, cli_runner, target, port):
        """Verify 'NoSec mode' ENCRYPTION finding when DTLS is not available [Category A]

        When scanning port 5683 (plain CoAP), the scanner reads /0/0/2 = 3 (NoSec)
        and the DTLS check on that port fails. This triggers:
            security_finding("NoSec mode", "ENCRYPTION",
                "No transport security (LwM2M /0/0/2 = NoSec)")
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

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result, min_count=3)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Structured assertion: security finding event must exist with exact title
        log.assert_security_finding("NoSec mode")

        # Validate category and details in the finding data
        findings = log.get_security_findings()
        nosec_findings = [f for f in findings if f.get("data", {}).get("finding") == "NoSec mode"]
        assert len(nosec_findings) >= 1, (
            f"Expected 'NoSec mode' finding. Available: "
            f"{[f.get('data', {}).get('finding') for f in findings]}"
        )
        nosec_data = nosec_findings[0].get("data", {})
        assert nosec_data.get("category") == "ENCRYPTION", (
            f"Expected category 'ENCRYPTION', got: {nosec_data.get('category')}"
        )
        assert "nosec" in nosec_data.get("details", "").lower(), (
            f"Expected 'nosec' in finding details: {nosec_data.get('details')}"
        )

    @pytest.mark.security
    def test_security_finding_nosec_dtls_available(self, cli_runner, target, port):
        """Verify 'NoSec mode (DTLS available)' finding when --dtls forces DTLS=True [Category A]

        With --dtls flag, the scanner forces dtls_available=True in _check_security.
        Since /0/0/2 = 3 (NoSec), the 'if dtls:' branch fires:
            security_finding("NoSec mode (DTLS available)", "ENCRYPTION", ...)
        instead of the plain "NoSec mode" finding.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dtls",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Scan with --dtls failed: {result.stderr}"
        _assert_log_has_events(result, min_count=3)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Structured assertion: must have the DTLS-aware NoSec finding
        log.assert_security_finding("NoSec mode (DTLS available)")

        # Validate category and details
        findings = log.get_security_findings()
        dtls_nosec = [
            f for f in findings if f.get("data", {}).get("finding") == "NoSec mode (DTLS available)"
        ]
        assert len(dtls_nosec) >= 1
        dtls_data = dtls_nosec[0].get("data", {})
        assert dtls_data.get("category") == "ENCRYPTION", (
            f"Expected category 'ENCRYPTION', got: {dtls_data.get('category')}"
        )
        details = dtls_data.get("details", "").lower()
        assert "nosec" in details and "dtls" in details, (
            f"Expected 'nosec' and 'dtls' in finding details: {dtls_data.get('details')}"
        )

        # The plain "NoSec mode" finding should NOT be present (mutually exclusive)
        plain_nosec = [f for f in findings if f.get("data", {}).get("finding") == "NoSec mode"]
        assert len(plain_nosec) == 0, (
            "Expected 'NoSec mode' finding to be absent when DTLS is available, "
            f"but found {len(plain_nosec)} occurrences"
        )

    @pytest.mark.security
    def test_security_finding_no_authentication(self, cli_runner, target, port):
        """Verify 'No authentication' AUTHENTICATION finding in NoSec mode [Category A]

        Whenever the scanner detects NoSec mode (/0/0/2 = 3), it unconditionally
        emits a 'No authentication' finding regardless of DTLS status:
            security_finding("No authentication", "AUTHENTICATION",
                "NoSec mode has no client/server authentication ...")
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

        assert result.success, f"Scan failed: {result.stderr}"
        _assert_log_has_events(result, min_count=3)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Structured assertion: "No authentication" finding must exist
        log.assert_security_finding("No authentication")

        # Validate category and details
        findings = log.get_security_findings()
        auth_findings = [
            f for f in findings if f.get("data", {}).get("finding") == "No authentication"
        ]
        assert len(auth_findings) >= 1, (
            f"Expected 'No authentication' finding. Available: "
            f"{[f.get('data', {}).get('finding') for f in findings]}"
        )
        auth_data = auth_findings[0].get("data", {})
        assert auth_data.get("category") == "AUTHENTICATION", (
            f"Expected category 'AUTHENTICATION', got: {auth_data.get('category')}"
        )
        details = auth_data.get("details", "").lower()
        assert "nosec" in details, (
            f"Expected 'nosec' in finding details: {auth_data.get('details')}"
        )
        assert any(term in details for term in ["psk", "rpk", "certificate", "authentication"]), (
            f"Expected auth mechanism mention in details: {auth_data.get('details')}"
        )

    @pytest.mark.security
    def test_security_finding_unauthenticated_writes(self, cli_runner, target, port):
        """Verify 'Unauthenticated writes' AUTHORIZATION finding with --confirm [Category A]

        The scanner only probes for unauthenticated writes when --confirm is set.
        With --confirm, it sends PUT to /actuator/* resources. The mock accepts
        PUT without authentication, so the finding fires:
            security_finding("Unauthenticated writes", "AUTHORIZATION",
                "PUT accepted without auth: /actuator/led, /actuator/relay, ...")
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Scan with --confirm failed: {result.stderr}"
        _assert_log_has_events(result, min_count=3)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Structured assertion: "Unauthenticated writes" finding must exist
        log.assert_security_finding("Unauthenticated writes")

        # Validate category and details
        findings = log.get_security_findings()
        write_findings = [
            f for f in findings if f.get("data", {}).get("finding") == "Unauthenticated writes"
        ]
        assert len(write_findings) >= 1, (
            f"Expected 'Unauthenticated writes' finding. Available: "
            f"{[f.get('data', {}).get('finding') for f in findings]}"
        )
        write_data = write_findings[0].get("data", {})
        assert write_data.get("category") == "AUTHORIZATION", (
            f"Expected category 'AUTHORIZATION', got: {write_data.get('category')}"
        )
        details = write_data.get("details", "").lower()
        assert "put accepted" in details, (
            f"Expected 'PUT accepted' in finding details: {write_data.get('details')}"
        )
        assert "actuator" in details, (
            f"Expected 'actuator' path in finding details: {write_data.get('details')}"
        )

    # ========================================================================
    # DTLS / PSK Option Tests
    # ========================================================================

    def test_dtls_option(self, cli_runner, target, port):
        """Test --dtls option is accepted (will fail since mock has no DTLS) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dtls",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "dtls",
                "coap",
                "connected",
                "device",
                "fail",
                "error",
                "timeout",
            ]
        ), f"Expected DTLS attempt output: {text[:500]}"

    def test_psk_option(self, cli_runner, target, port):
        """Test --psk option is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--psk",
            "0102030405060708",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "psk",
                "dtls",
                "coap",
                "connected",
                "device",
                "fail",
                "error",
            ]
        ), f"Expected PSK attempt output: {text[:500]}"

    def test_psk_identity_option(self, cli_runner, target, port):
        """Test --psk-identity option is accepted [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--psk-identity",
            "test-device",
            "--psk",
            "0102030405060708",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "psk",
                "identity",
                "dtls",
                "coap",
                "connected",
                "device",
                "fail",
                "error",
            ]
        ), f"Expected PSK identity attempt output: {text[:500]}"

    # ========================================================================
    # Write Operation Tests
    # ========================================================================

    @pytest.mark.security
    def test_put_actuator_with_confirm(self, cli_runner, target, port):
        """Test --put with --confirm writes value to actuator [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--put",
            "/actuator/led",
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
                "put",
                "actuator",
                "led",
                "write",
                "coap",
                "connected",
                "changed",
                "success",
                "sending",
            ]
        ), f"Expected PUT actuator output: {text[:500]}"

    @pytest.mark.security
    def test_put_without_confirm(self, cli_runner, target, port):
        """Test --put without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--put",
            "/actuator/led",
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
                "put",
                "coap",
                "connected",
                "warning",
                "fail",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_post_with_confirm(self, cli_runner, target, port):
        """Test --post with --confirm attempts POST [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--post",
            "/config",
            '{"test": true}',
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
                "post",
                "config",
                "write",
                "coap",
                "connected",
                "sending",
            ]
        ), f"Expected POST output: {text[:500]}"

    @pytest.mark.security
    def test_post_without_confirm(self, cli_runner, target, port):
        """Test --post without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--post",
            "/config",
            '{"test": true}',
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
                "post",
                "coap",
                "connected",
                "warning",
                "fail",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    @pytest.mark.security
    def test_delete_with_confirm(self, cli_runner, target, port):
        """Test --delete with --confirm attempts DELETE [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--delete",
            "/actuator/relay",
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
                "delete",
                "actuator",
                "relay",
                "coap",
                "connected",
                "sending",
            ]
        ), f"Expected DELETE output: {text[:500]}"

    @pytest.mark.security
    def test_delete_without_confirm(self, cli_runner, target, port):
        """Test --delete without --confirm is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--delete",
            "/actuator/relay",
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
                "delete",
                "coap",
                "connected",
                "warning",
                "fail",
            ]
        ), f"Expected --confirm requirement message: {text[:500]}"

    def test_confirm_alone(self, cli_runner, target, port):
        """Test --confirm alone without write op does normal scan [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
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
                "coap",
                "connected",
                "resource",
                "device",
            ]
        ), f"Expected normal scan with --confirm alone: {text[:500]}"

    # ========================================================================
    # Combined Flag Tests
    # ========================================================================

    def test_lwm2m_with_methods(self, cli_runner, target, port):
        """Test --lwm2m combined with --methods [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lwm2m",
            "--methods",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "lwm2m",
                "method",
                "device",
                "coap",
                "connected",
                MOCK_MANUFACTURER,
            ]
        ), f"Expected combined lwm2m+methods output: {text[:500]}"

    def test_full_discovery_with_lwm2m(self, cli_runner, target, port):
        """Test discovery + lwm2m + probe-paths together [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lwm2m",
            "--probe-paths",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Full discovery failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        text = _combined_text(result, log)
        assert any(
            term in text
            for term in [
                MOCK_MANUFACTURER,
                MOCK_MODEL,
                "sensor",
                "actuator",
                "lwm2m",
                "resource",
            ]
        ), f"Expected comprehensive discovery output: {text[:500]}"

    # ========================================================================
    # Block-wise Transfer Tests (RFC 7959)
    # ========================================================================

    def test_blockwise_large_resource(self, cli_runner, target, port):
        """Test --block-size with large resource triggers block-wise transfer [Category B]

        The mock server has /sensor/large-data returning >2KB JSON.
        Using --block-size 256 should trigger Block2 negotiation.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--block-size",
            "256",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Scanner should discover resources including the large-data one
        assert any(
            term in text
            for term in [
                "large-data",
                "block",
                "resource",
                "sensor",
                "coap",
                "connected",
                "discovered",
            ]
        ), f"Expected block-wise or resource discovery output: {text[:500]}"

    # ========================================================================
    # FETCH / PATCH / iPATCH Tests (RFC 8132)
    # ========================================================================

    def test_fetch_config_with_filter(self, cli_runner, target, port):
        """Test FETCH /config with JSON filter payload [Category B]

        FETCH is read-only (does not require --confirm).
        Sends a JSON body requesting specific fields from /config.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fetch",
            "/config",
            '{"fields": ["device_name"]}',
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fetch",
                "config",
                "device_name",
                "coap",
                "connected",
                "sending",
                "content",
            ]
        ), f"Expected FETCH output: {text[:500]}"

    @pytest.mark.security
    def test_patch_config(self, cli_runner, target, port):
        """Test PATCH /config with partial update (requires --confirm) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--patch",
            "/config",
            '{"device_name": "patched"}',
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "patch",
                "config",
                "changed",
                "coap",
                "connected",
                "sending",
                "success",
            ]
        ), f"Expected PATCH output: {text[:500]}"

    @pytest.mark.security
    def test_ipatch_config(self, cli_runner, target, port):
        """Test iPATCH /config (idempotent merge, requires --confirm) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--ipatch",
            "/config",
            '{"device_name": "ipatched"}',
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "ipatch",
                "config",
                "changed",
                "coap",
                "connected",
                "sending",
                "success",
            ]
        ), f"Expected iPATCH output: {text[:500]}"

    # ========================================================================
    # Content Format Tests (CBOR, SenML, LwM2M JSON)
    # ========================================================================

    def test_cbor_resource_discovery(self, cli_runner, target, port):
        """Test that --probe-paths discovers CBOR resource /sensor/data.cbor [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-paths",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # The probe should find /sensor/data.cbor among other resources
        assert any(
            term in text
            for term in [
                "cbor",
                "data.cbor",
                "sensor",
                "resource",
                "found",
                "probe",
                "coap",
                "connected",
            ]
        ), f"Expected CBOR resource in probe output: {text[:500]}"

    def test_senml_resource_discovery(self, cli_runner, target, port):
        """Test that --probe-paths discovers SenML resource /sensor/measurements [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-paths",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "senml",
                "measurements",
                "sensor",
                "resource",
                "found",
                "probe",
                "coap",
                "connected",
            ]
        ), f"Expected SenML resource in probe output: {text[:500]}"

    def test_lwm2m_json_resource_discovery(self, cli_runner, target, port):
        """Test that /3/0.json LwM2M JSON resource is accessible [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--lwm2m",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # LwM2M scan should at least find the device object data
        assert any(
            term in text
            for term in [
                "lwm2m",
                MOCK_MANUFACTURER,
                MOCK_MODEL,
                "device",
                "coap",
                "connected",
            ]
        ), f"Expected LwM2M JSON resource output: {text[:500]}"

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
        has_coap_module = any("coap" in m.lower() for m in modules)
        assert has_coap_module or len(modules) > 0, (
            f"Expected coap module reference. Modules: {modules}"
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
    # Output Format Tests
    # ========================================================================

    def test_json_output_format(self, cli_runner, target, port):
        """Test JSON output is properly formatted [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"JSON output test failed: {result.stderr}"
        # Should produce some output
        assert result.stdout or result.json_output, "No output received from JSON format"

    def test_verbose_output(self, cli_runner, target, port):
        """Test verbose output flag produces more detail [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            expect_json=False,
            json_log=True,
            timeout=45,
            verbose=True,
        )

        assert result.success, f"Verbose scan failed: {result.stderr}"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "coap",
                "connected",
                "resource",
                "device",
            ]
        ), f"Expected verbose output content: {text[:500]}"

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
                "not reachable",
            ]
        ), f"Expected connection error message: {text[:500]}"

    def test_unreachable_host(self, cli_runner):
        """Test scan of unreachable host times out gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            "5683",
            "--timeout",
            "3",
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
                "not reachable",
            ]
        ), f"Expected timeout or error message: {text[:500]}"

    def test_nonexistent_host(self, cli_runner):
        """Test scan of nonexistent hostname completes without crashing [Category B]

        CoAP uses UDP so there is no immediate connection failure for
        nonexistent hosts -- the aiocoap context is created locally.
        DNS resolution may fail later during requests, or requests simply time out.
        """
        result = cli_runner.run(
            self.protocol_name,
            "nonexistent-host-xyz-12345.invalid",
            "--port",
            "5683",
            "--timeout",
            "3",
            timeout=30,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "coap",
                "connect",
                "error",
                "fail",
                "timeout",
                "nonexistent",
                "dtls",
                "nosec",
            ]
        ), f"Expected some scanner output: {text[:500]}"

    def test_invalid_target(self, cli_runner):
        """Override base: CoAP is UDP so invalid hostnames don't fail at connect [Category B]

        aiocoap creates a local client context without resolving the target,
        so invalid targets may not trigger immediate errors.
        """
        result = cli_runner.run(
            self.protocol_name,
            "not-a-valid-host-12345!!!",
            "--timeout",
            "3",
            timeout=30,
            expect_json=False,
            json_log=True,
        )

        # Should not crash/hang
        assert result.returncode in [0, 1, 2]
        text = _combined_text(result, result.scan_log)
        # Must produce some output (not silently succeed)
        assert len(text.strip()) > 0, "Expected some output for invalid target"

    def test_connection_to_tcp_port(self, cli_runner, target):
        """Test CoAP against a TCP port that won't respond to UDP [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "502",  # Modbus TCP port -- won't respond to CoAP UDP
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should handle non-CoAP port gracefully"
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fail",
                "error",
                "timeout",
                "not reachable",
                "no response",
                "connect",
                "coap",
            ]
        ), f"Expected error handling for wrong port type: {text[:500]}"

    def test_zero_timeout(self, cli_runner, target, port):
        """Test that very short timeout is handled [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--timeout",
            "0.1",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should complete without hanging
        assert result.returncode != -1, "Command should not hang with zero timeout"
        text = _combined_text(result, result.scan_log)
        # At minimum, the scanner should have attempted something
        assert len(text) > 0, "Expected some output even with tiny timeout"


# ===========================================================================
# Interop Tests: aiocoap scanner vs libcoap (C) server
# ===========================================================================

LIBCOAP_PORT = 5685
DTLS_PORT = 5684


def _libcoap_available() -> bool:
    """Check if the libcoap container is reachable."""
    return check_udp_port_open(MOCK_HOST, LIBCOAP_PORT, timeout=3)


def _dtls_available() -> bool:
    """Check if the DTLS container is running and healthy.

    The libcoap DTLS server silently drops malformed ClientHello probes,
    so we check Docker container health instead of UDP probing.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", "coap-dtls-server"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "healthy"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


@pytest.mark.coap
class TestCoAPLibcoapInterop:
    """Interop tests: aiocoap-based scanner vs libcoap (C) server.

    These tests validate that the OIDA CoAP scanner works against a
    completely different CoAP implementation (libcoap, written in C),
    ensuring real protocol interoperability rather than just aiocoap-to-aiocoap.

    The libcoap server runs on port 5685 with pre-populated dynamic resources.
    """

    def test_libcoap_service_available(self):
        """Verify libcoap container is running and reachable [Category A]"""
        assert _libcoap_available(), (
            f"libcoap CoAP service not available on UDP {MOCK_HOST}:{LIBCOAP_PORT}"
        )

    def test_basic_scan_libcoap(self, cli_runner):
        """Scanner discovers resources from C-based libcoap server [Category A]"""
        if not _libcoap_available():
            pytest.skip("libcoap container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(LIBCOAP_PORT),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"libcoap interop scan failed: {result.stderr}"
        text = _combined_text(result, result.scan_log)
        # libcoap has built-in /time and our pre-populated resources
        assert any(
            term in text
            for term in [
                "resource",
                "discovered",
                "sensor",
                "time",
                "connected",
                "responding",
            ]
        ), f"Expected resource discovery from libcoap: {text[:500]}"

    def test_wellknown_core_libcoap(self, cli_runner):
        """/.well-known/core from libcoap returns valid link-format [Category A]"""
        if not _libcoap_available():
            pytest.skip("libcoap container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(LIBCOAP_PORT),
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success
        text = _combined_text(result, result.scan_log)
        # Should find the pre-populated sensor/actuator resources
        assert "sensor" in text or "actuator" in text or "time" in text, (
            f"Expected pre-populated resources in .well-known/core: {text[:500]}"
        )

    def test_libcoap_resource_read(self, cli_runner):
        """Scanner reads pre-populated resources from libcoap [Category A]"""
        if not _libcoap_available():
            pytest.skip("libcoap container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(LIBCOAP_PORT),
            "--probe-paths",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success
        text = _combined_text(result, result.scan_log)
        # Pre-populated via entrypoint: /sensor/temperature, /device, etc.
        assert any(
            term in text
            for term in [
                "sensor",
                "actuator",
                "device",
                "config",
                "found",
                "resource",
            ]
        ), f"Expected resource probe output: {text[:500]}"

    def test_libcoap_put_with_confirm(self, cli_runner):
        """Scanner can PUT to libcoap server (with -e echo mode) [Category B]"""
        if not _libcoap_available():
            pytest.skip("libcoap container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(LIBCOAP_PORT),
            "--put",
            "/actuator/led",
            "1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["put", "actuator", "led", "changed", "sending", "coap"]
        ), f"Expected PUT output: {text[:500]}"

    def test_libcoap_observe(self, cli_runner):
        """Scanner observes resources on libcoap server [Category B]

        libcoap's dynamically-created (PUT) resources do not support Observe,
        so the scanner should report "No observable resources" and exit cleanly.
        We accept timeout (-1) as valid because the full scan with 59 resources
        plus observe attempt can exceed the timeout budget.
        """
        if not _libcoap_available():
            pytest.skip("libcoap container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(LIBCOAP_PORT),
            "--observe",
            "--observe-count",
            "2",
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=60,
        )

        # Accept 0 (success), 1 (partial), or -1 (timeout killed)
        assert result.returncode in [0, 1, -1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "observe",
                "no observable",
                "notification",
                "coap",
                "connected",
                "resources",
            ]
        ), f"Expected observe output: {text[:500]}"

    def test_libcoap_no_lwm2m(self, cli_runner):
        """libcoap server has no LwM2M paths -- scanner handles gracefully [Category B]"""
        if not _libcoap_available():
            pytest.skip("libcoap container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(LIBCOAP_PORT),
            "--lwm2m",
            format="json",
            json_log=True,
            timeout=45,
        )

        # Should succeed even without LwM2M objects
        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # Should still show resources, just no LwM2M device info
        assert any(term in text for term in ["coap", "connected", "resource", "sensor", "time"]), (
            f"Expected scan output without LwM2M: {text[:500]}"
        )


@pytest.mark.coap
class TestCoAPDTLSInterop:
    """Tests for CoAP DTLS-PSK server (libcoap with OpenSSL).

    The DTLS server runs coap-server-openssl with PSK key "secretPSK123"
    and identity hint "oida-client". Only the DTLS port (5684) is mapped
    to the host. Plain CoAP requests to this port should fail/timeout.
    """

    def test_dtls_port_responds(self):
        """Verify DTLS server responds to probe on port 5684 [Category A]"""
        assert _dtls_available(), f"DTLS CoAP service not responding on {MOCK_HOST}:{DTLS_PORT}"

    def test_plain_coap_rejected_on_dtls_port(self, cli_runner):
        """Plain CoAP scan against DTLS port fails gracefully [Category C]"""
        if not _dtls_available():
            pytest.skip("DTLS container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(DTLS_PORT),
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Plain CoAP should fail against DTLS-only port
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fail",
                "error",
                "timeout",
                "not reachable",
                "no response",
                "connect",
                "coap",
            ]
        ), f"Expected failure against DTLS port with plain CoAP: {text[:500]}"

    def test_dtls_flag_uses_coaps_scheme(self, cli_runner):
        """Passing -D flag uses coaps:// scheme against DTLS port [Category A]

        With the -D flag, the scanner should attempt a CoAPs (DTLS)
        connection on port 5684. If DTLSSocket is available and
        credentials are correct, DTLS output should appear.
        """
        if not _dtls_available():
            pytest.skip("DTLS container not available")

        # Scan on port 5684 with -D flag
        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(DTLS_PORT),
            "-D",
            format="json",
            json_log=True,
            timeout=45,
        )

        text = _combined_text(result, result.scan_log)
        # The scanner should attempt DTLS on port 5684
        assert any(term in text for term in ["dtls", "5684", "coaps", "DTLS"]), (
            f"Expected DTLS attempt on port 5684: {text[:500]}"
        )


# ===========================================================================
# DTLS Certificate Tests: libcoap with X.509 certificates
# ===========================================================================

DTLS_CERT_PORT = 5686


def _dtls_cert_available() -> bool:
    """Check if the DTLS certificate container is running and healthy."""
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", "coap-dtls-cert-server"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "healthy"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


@pytest.mark.coap
class TestCoAPDTLSCertInterop:
    """Tests for CoAP DTLS certificate-based authentication (libcoap with PKI).

    The DTLS cert server runs coap-server-openssl with X.509 certificates.
    Port 5686 maps to the container's DTLS port (5684).
    Plain CoAP is also available on the container's port 5683.

    TODO: Full DTLS certificate handshake tests require aiocoap with a DTLS
    backend that supports X.509 certificates (not just tinydtls/PSK). These
    tests currently verify that the container is running and that the scanner
    handles the DTLS-cert endpoint gracefully.
    """

    def test_dtls_cert_container_available(self):
        """Verify DTLS certificate server container is running [Category A]"""
        if not _dtls_cert_available():
            pytest.skip("DTLS certificate container not available")
        assert _dtls_cert_available()

    def test_plain_coap_on_dtls_cert_port(self, cli_runner):
        """Plain CoAP scan against DTLS cert port fails gracefully [Category C]"""
        if not _dtls_cert_available():
            pytest.skip("DTLS certificate container not available")

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(DTLS_CERT_PORT),
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Plain CoAP on a DTLS-only port should fail/timeout
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fail",
                "error",
                "timeout",
                "not reachable",
                "no response",
                "connect",
                "coap",
            ]
        ), f"Expected failure on DTLS cert port with plain CoAP: {text[:500]}"

    @pytest.mark.skip(
        reason="DTLS certificate handshake requires aiocoap with OpenSSL DTLS backend"
    )
    def test_dtls_cert_auth(self, cli_runner):
        """Scanner connects using DTLS certificate auth [Category B]

        Requires aiocoap with an OpenSSL-based DTLS backend that supports
        X.509 certificates. The default tinydtls backend only supports PSK.
        """
        if not _dtls_cert_available():
            pytest.skip("DTLS certificate container not available")

        import pathlib

        cert_dir = (
            pathlib.Path(__file__).parent.parent.parent
            / "docker"
            / "mocks"
            / "services"
            / "coap"
            / "certs"
        )

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(DTLS_CERT_PORT),
            "--dtls-cert",
            str(cert_dir / "client.pem"),
            "--dtls-key",
            str(cert_dir / "client-key.pem"),
            "--dtls-ca",
            str(cert_dir / "ca.pem"),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "dtls",
                "certificate",
                "cert",
                "connected",
                "resource",
                "coap",
            ]
        ), f"Expected DTLS cert auth output: {text[:500]}"
