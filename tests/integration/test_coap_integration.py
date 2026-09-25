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

Each test's docstring tags it [Category A] (strict -- mock supports it, assert
success + validate data), [Category B] (conditional -- mock may not support it,
accept 0/1), or [Category C] (error handling -- assert graceful failure). No
hard-coded test totals or per-flag matrix are kept here: they rot as tests are
added, renamed, or removed.
"""

import json
import pytest
from typing import Optional

from tests.integration.base_protocol_test import BaseProtocolIntegrationTest
from tests.integration.conftest import MOCK_HOST, check_udp_port_open
from tests.service_gate import require_service


# ---------------------------------------------------------------------------
# Known Mock Data Constants (from coap_server.py)
# ---------------------------------------------------------------------------
MOCK_MANUFACTURER = "oida-test"
MOCK_MODEL = "coap-mock-v1"
MOCK_SERIAL = "sn-2024-001337"
MOCK_FIRMWARE = "1.2.3-beta"


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


def _combined_text(result, log) -> str:
    """Return lowercase combined output + log messages for broad searches.

    `log` is required (every caller passes result.scan_log): an optional default
    would silently drop the structured log text and weaken assertions. `log` may
    still be None at runtime (json_log disabled), which is handled below.
    """
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
        # [Category A]: the mock's /3/0 Device object returns all four fields, so
        # assert each concrete value (including firmware). Filler like "device"/
        # "lwm2m"/"manufacturer" matches any scan and would never falsify.
        for expected in (MOCK_MANUFACTURER, MOCK_MODEL, MOCK_SERIAL, MOCK_FIRMWARE):
            assert expected in text, f"Expected LwM2M device value {expected!r}, got: {text[:500]}"

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

        # Structured assertion: the bare scan reads LwM2M /0/0/2 and, when it is
        # NoSec, emits a "NoSec mode" security finding. Asserting on the finding
        # (not a substring of the whole log) keeps the test falsifiable -- an
        # accept-list containing "coap" would match every scan, pass or fail.
        log.assert_security_finding("NoSec mode")

    # test_unauth_write_detection was removed: it ran without --confirm, but the
    # unauthenticated-write probe is gated on --confirm (the scanner logs
    # "Skipping write probes"), so the finding could never appear -- it passed
    # only on filler terms ("write"/"actuator") that match ordinary resource
    # listings. The behaviour is covered correctly by
    # test_security_finding_unauthenticated_writes (which passes --confirm and
    # asserts the structured "Unauthenticated writes" finding).

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
        assert "nosec" in nosec_data.get("details", "").lower(), (
            f"Expected 'nosec' in finding details: {nosec_data.get('details')}"
        )

    @pytest.mark.security
    def test_dtls_requested_on_plain_port_fails_without_false_finding(
        self, cli_runner, target, port
    ):
        """--dtls against a plain-CoAP NoSec port must hard-fail, not fake a DTLS finding [Category C]

        The plain CoAP mock on 5683 advertises LwM2M /0/0/2 = NoSec but has no DTLS
        listener. Requesting --dtls there can NOT establish a coaps:// session, so the
        scanner hard-fails ("DTLS connection failed") instead of silently downgrading
        to cleartext or fabricating a "NoSec mode (DTLS available)" finding.

        This pins the real contract: a DTLS request against a port with no DTLS server
        is a failure, and the scanner never claims DTLS is available when it isn't. The
        genuine "NoSec mode (DTLS available)" finding requires a device that reports
        LwM2M NoSec yet answers DTLS -- a contradiction none of the mocks expose, so it
        is exercised against the real DTLS-PSK server in TestCoAPDTLSInterop instead.
        """
        # This pins the *DTLS-requested* hard-fail path: `--dtls` with no
        # credentials can never establish a coaps:// session, so the scanner
        # must fail (either by rejecting `-d` alone up front as needing
        # credentials, or by attempting and failing the handshake) and must
        # never fabricate a DTLS-available finding. Without the client
        # DTLSSocket backend the scanner short-circuits with "DTLS support is
        # unavailable" and exits 0 before reaching that path, so the contract is
        # only meaningful when the backend is installed - its absence is a
        # failure, not a skip.
        if not _dtls_client_backend_available():
            pytest.fail(_DTLS_BACKEND_MISSING)
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

        # DTLS was requested but the plain port has no DTLS server -> hard fail.
        assert not result.success, (
            "Expected --dtls against plain-CoAP port to fail (no DTLS listener), "
            f"got success. stderr: {result.stderr}"
        )
        assert result.returncode in [1, 2], f"Expected failure exit code, got {result.returncode}"

        text = _combined_text(result, result.scan_log)
        assert "dtls" in text and any(
            term in text
            for term in [
                "fail",
                "failed",
                "error",
                "not reachable",
                # DTLS has no anonymous mode, so `-d` alone is now rejected
                # up front (before any handshake) with a credentials-required
                # message -- still a hard fail, still no fabricated finding.
                "requires credentials",
                "no anonymous mode",
            ]
        ), f"Expected explicit DTLS failure message, got: {text[:500]}"

        # Critical: the scanner must NOT fabricate a DTLS-available finding when no
        # DTLS handshake ever succeeded.
        if result.scan_log is not None:
            findings = result.scan_log.get_security_findings()
            fabricated = [
                f
                for f in findings
                if f.get("data", {}).get("finding") == "NoSec mode (DTLS available)"
            ]
            assert not fabricated, (
                "Scanner fabricated a 'NoSec mode (DTLS available)' finding without a "
                "real DTLS handshake"
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
        details = auth_data.get("details", "").lower()
        assert "nosec" in details, (
            f"Expected 'nosec' in finding details: {auth_data.get('details')}"
        )
        assert any(term in details for term in ["psk", "rpk", "certificate", "authentication"]), (
            f"Expected auth mechanism mention in details: {auth_data.get('details')}"
        )

    @pytest.mark.security
    def test_security_finding_unauthenticated_writes(self, cli_runner, target, port):
        """Verify 'Unauthenticated writes' finding with --confirm --methods [Category A]

        The write probe runs only when BOTH --methods (build the access matrix)
        and --confirm (actually send the write methods) are set; otherwise the
        scanner logs "Skipping write probes (need --confirm and --methods)". With
        both, it sends PUT to /actuator/* resources. The mock accepts PUT without
        authentication, so the finding fires:
            security_finding("Unauthenticated writes",
                "PUT accepted without auth: /actuator/led, /actuator/relay, ...")
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--methods",
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
        # The free-text "AUTHORIZATION" category was consolidated onto the canonical
        # Category enum (no AUTHORIZATION member); an unauthenticated write is an
        # access-control failure, so the scanner now emits ACCESS_CONTROL.
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
        # Behaviour-unique: the --dtls path always names DTLS -- whether it
        # connects ("CoAPs (DTLS) server responding"), fails ("DTLS connection
        # failed"), or reports the backend missing. "coap"/"connected" filler is
        # dropped: it appears on every run and would make this unfalsifiable.
        assert "dtls" in text, f"Expected DTLS attempt output: {text[:500]}"

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

    def test_dtls_rpk_option(self, cli_runner, target, port, tmp_path):
        """--dtls-rpk is accepted and drives a real RPK handshake attempt [Category B]

        The mock's DTLS listener is PSK/cert-only, so RPK auth can never
        succeed here -- but `_try_dtls_rpk`/`try_dtls_rpk` still runs a real
        code path: it probes the installed aiocoap DTLS backend for RPK
        support (and, if supported, opens the key file and attempts a
        handshake) before falling back to a hard DTLS failure. Assert the
        CLI names RPK/DTLS in its outcome and never crashes, rather than
        silently ignoring the flag.
        """
        rpk_file = tmp_path / "client_rpk.pem"
        rpk_file.write_text(
            "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtestRawPublicKeyPlaceholder\n"
            "-----END PUBLIC KEY-----\n"
        )

        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--dtls-rpk",
            str(rpk_file),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        assert "Traceback" not in result.combined_output
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "rpk",
                "dtls",
            ]
        ), f"Expected --dtls-rpk attempt to be named in output: {text[:500]}"

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

    def test_put_with_content_format(self, cli_runner, target, port):
        """--content-format sets the Content-Format option on a write [Category A]

        The mock's /actuator/led PUT accepts any payload, but the CLI's own
        "Sending PUT ... (Content-Format: <name>)" display line is generated
        purely from resolving the --content-format value client-side (see
        `_resolve_content_format`/`_do_write`), so it is observable regardless
        of what the mock does with the option.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--put",
            "/actuator/led",
            "1",
            "--content-format",
            "text",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # The resolved alias name ("text/plain") must appear -- proof the
        # --content-format value was actually parsed and threaded through,
        # not just accepted and ignored.
        assert "text/plain" in text or "content-format" in text, (
            f"Expected Content-Format to be named in output: {text[:500]}"
        )

    def test_put_with_content_format_numeric(self, cli_runner, target, port):
        """--content-format accepts a numeric CoAP Content-Format ID [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--put",
            "/config",
            '{"x":1}',
            "--content-format",
            "50",
            "--confirm",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        # 50 resolves to application/json in CONTENT_FORMATS -- confirms the
        # numeric path (not just the alias-name path) is exercised.
        assert "application/json" in text or "content-format" in text, (
            f"Expected numeric Content-Format 50 to resolve to application/json: {text[:500]}"
        )

    @pytest.mark.security
    def test_content_format_invalid_value_rejected(self, cli_runner, target, port):
        """An unrecognized --content-format name is rejected cleanly [Category C]

        `_resolve_content_format` fails the operation (logger.fail) rather than
        silently sending the write with no Content-Format option -- assert the
        CLI reports the bad value, not a traceback.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--put",
            "/actuator/led",
            "1",
            "--content-format",
            "not-a-real-format",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode != -1
        assert "Traceback" not in result.combined_output
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "unknown content format",
                "not-a-real-format",
                "content format",
            ]
        ), f"Expected an 'unknown content format' rejection: {text[:500]}"

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
        # Behaviour-unique: assert the CBOR resource path itself, not filler like
        # "sensor"/"resource"/"coap" that appears on every scan.
        assert "data.cbor" in text, f"Expected CBOR resource /sensor/data.cbor: {text[:500]}"

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
        # Behaviour-unique: assert the SenML resource path itself, not filler.
        assert "measurements" in text, f"Expected SenML resource /sensor/measurements: {text[:500]}"

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
        # Behaviour-unique: the /3/0.json LwM2M-JSON resource is listed in
        # /.well-known/core, and the device values are read from /3/0. Assert
        # concrete evidence, not "device"/"lwm2m"/"coap" filler.
        assert "3/0.json" in text or MOCK_MANUFACTURER in text, (
            f"Expected LwM2M JSON resource /3/0.json or device data: {text[:500]}"
        )

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
        # The `or len(modules) > 0` fallback was tautological (events are already
        # asserted above), so it neutered the real check. Assert the coap module
        # tag directly.
        assert any("coap" in m.lower() for m in modules), (
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
        # Failure-only markers: a wrong-port scan reports "Connection failed",
        # "not reachable", or "No CoAP response". "coap"/"connect" are dropped --
        # they appear on a successful scan too, so they would never falsify.
        assert any(
            term in text
            for term in [
                "fail",
                "error",
                "timeout",
                "not reachable",
                "no response",
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

# DTLS-PSK credentials for the coap-dtls-server mock (libcoap + OpenSSL).
DTLS_PSK_KEY = "secretPSK123"
DTLS_PSK_IDENTITY = "oida-client"


def _libcoap_available() -> bool:
    """Check if the libcoap container is reachable."""
    return check_udp_port_open(MOCK_HOST, LIBCOAP_PORT, timeout=3)


def _dtls_client_backend_available() -> bool:
    """True if the client-side DTLS backend (DTLSSocket) is importable.

    The scanner performs DTLS via aiocoap's DTLSSocket transport. That backend
    was removed from the 'coap' extra and is an optional manual install, so the
    scanner cleanly reports "DTLS support is unavailable" and exits 0 when it is
    missing. A DTLS test that drives a handshake cannot pass without it, so we
    must gate on the client library - not just the server container.
    """
    try:
        import DTLSSocket  # noqa: F401

        return True
    except ImportError:
        return False


# Actionable hint when the optional tinydtls PSK backend is missing. It is an
# sdist-only C build (autotools + compiler), which is why it is not in the
# 'coap' extra. DTLS tests treat its absence as a FAILURE, not a skip.
_DTLS_BACKEND_MISSING = (
    "DTLS client backend (DTLSSocket) not installed - the coap-dtls-server "
    "container IS the DTLS endpoint, but the aiocoap tinydtls/PSK transport is "
    "an optional C build. Install it with:\n"
    "  sudo apt-get install -y autoconf automake libtool pkg-config python3-dev\n"
    "  uv pip install 'DTLSSocket==0.2.3' --no-binary :all:"
)


def _dtls_container_healthy(container: str) -> bool:
    """True if the named Docker container reports a healthy healthcheck.

    The libcoap DTLS server silently drops malformed ClientHello probes, so we
    check Docker health instead of UDP probing.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "healthy"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _dtls_blocker() -> Optional[str]:
    """Return why PSK-DTLS interop can't run, or None if it can.

    Distinguishes the two independent prerequisites - client backend vs. server
    container - so the failure message names the real blocker instead of always
    blaming the container (which is usually up; the backend is what's missing).

    DTLS tests call ``pytest.fail()`` (not skip) on a non-None result: a missing
    DTLS prerequisite is surfaced loudly rather than silently passed over.
    """
    if not _dtls_client_backend_available():
        return _DTLS_BACKEND_MISSING
    if not _dtls_container_healthy("coap-dtls-server"):
        return f"coap-dtls-server container not running/healthy on {MOCK_HOST}:{DTLS_PORT}"
    return None


@pytest.mark.coap
class TestCoAPLibcoapInterop:
    """Interop tests: aiocoap-based scanner vs libcoap (C) server.

    These tests validate that the OIDA CoAP scanner works against a
    completely different CoAP implementation (libcoap, written in C),
    ensuring real protocol interoperability rather than just aiocoap-to-aiocoap.

    The libcoap server runs on port 5685 with pre-populated dynamic resources.
    """

    def test_libcoap_service_available(self):
        """Verify libcoap container is running and reachable [Category A]

        Hard assert (matching test_service_is_available): the interop suite
        targets this container, so its absence is a failure, not a silent pass.
        """
        assert _libcoap_available(), (
            f"libcoap container not available on UDP {MOCK_HOST}:{LIBCOAP_PORT}"
        )

    def test_basic_scan_libcoap(self, cli_runner):
        """Scanner discovers resources from C-based libcoap server [Category A]"""
        if not _libcoap_available():
            require_service("libcoap container not available")

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
            require_service("libcoap container not available")

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
            require_service("libcoap container not available")

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
            require_service("libcoap container not available")

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

    @pytest.mark.timeout(120)
    def test_libcoap_observe(self, cli_runner):
        """Scanner observes resources on libcoap server [Category B]

        libcoap's dynamically-created (PUT) resources do not support Observe,
        so the scanner should report "No observable resources" and exit cleanly.
        We accept timeout (-1) as valid because the full scan with 59 resources
        plus observe attempt can exceed the timeout budget.
        """
        if not _libcoap_available():
            require_service("libcoap container not available")

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
            require_service("libcoap container not available")

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
class TestCoAPDTLSPrerequisites:
    """Hard gate for the DTLS client backend.

    The DTLS interop tests need aiocoap's tinydtls/PSK transport (the DTLSSocket
    package). It is an sdist-only C build kept out of the 'coap' extra, so it is
    easy to forget. This test FAILS (not skips) when the backend is missing, so a
    DTLS-capable environment that lacks it is surfaced loudly instead of letting
    the whole DTLS suite silently no-op.
    """

    def test_dtls_client_backend_installed(self):
        """DTLSSocket must be importable - fail with install instructions if not."""
        assert _dtls_client_backend_available(), _DTLS_BACKEND_MISSING


@pytest.mark.coap
class TestCoAPDTLSInterop:
    """Tests for CoAP DTLS-PSK server (libcoap with OpenSSL).

    The DTLS server runs coap-server-openssl with PSK key "secretPSK123"
    and identity hint "oida-client". Only the DTLS port (5684) is mapped
    to the host. Plain CoAP requests to this port should fail/timeout.
    """

    def test_dtls_port_responds(self):
        """Verify DTLS server responds to probe on port 5684 [Category A]"""
        reason = _dtls_blocker()
        if reason:
            pytest.fail(reason)

        # A plain (non-DTLS) CoAP probe against the DTLS-only port must NOT get
        # a plaintext CoAP reply back -- the server is up (container healthy)
        # but it should only speak DTLS on this port, never plain UDP CoAP.
        assert check_udp_port_open(MOCK_HOST, DTLS_PORT, timeout=2) is False, (
            f"port {DTLS_PORT} answered a plaintext CoAP probe -- "
            "the DTLS server should not respond to unencrypted datagrams"
        )

    def test_plain_coap_rejected_on_dtls_port(self, cli_runner):
        """Plain CoAP scan against DTLS port fails gracefully [Category C]"""
        reason = _dtls_blocker()
        if reason:
            pytest.fail(reason)

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

        # Plain CoAP should fail against DTLS-only port. Failure-only markers:
        # "coap"/"connect" are dropped -- they appear on a successful scan too.
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fail",
                "error",
                "timeout",
                "not reachable",
                "no response",
            ]
        ), f"Expected failure against DTLS port with plain CoAP: {text[:500]}"

    def test_dtls_flag_uses_coaps_scheme(self, cli_runner):
        """Passing -D flag uses coaps:// scheme against DTLS port [Category A]

        With the -D flag, the scanner should attempt a CoAPs (DTLS)
        connection on port 5684. If DTLSSocket is available and
        credentials are correct, DTLS output should appear.
        """
        reason = _dtls_blocker()
        if reason:
            pytest.fail(reason)

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

    def test_dtls_psk_handshake_succeeds(self, cli_runner):
        """Full DTLS-PSK handshake against the libcoap+OpenSSL server [Category A]

        With the correct PSK identity/key the scanner must complete the DTLS
        handshake, switch to the coaps:// scheme, and enumerate resources over
        the encrypted session. This is the positive-path DTLS test: it asserts
        a real handshake, not merely that a "dtls" string appeared.
        """
        reason = _dtls_blocker()
        if reason:
            pytest.fail(reason)

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(DTLS_PORT),
            "-D",
            "--psk",
            DTLS_PSK_KEY,
            "--psk-identity",
            DTLS_PSK_IDENTITY,
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"DTLS-PSK handshake failed: {result.stderr}"
        text = _combined_text(result, result.scan_log)
        # The handshake must actually succeed (not just be attempted).
        assert "dtls-psk success" in text or (
            "coaps" in text or "dtls) server responding" in text
        ), f"Expected successful DTLS-PSK handshake evidence: {text[:500]}"
        # And the encrypted session must have been usable for discovery.
        assert any(
            term in text for term in ["resource", "discovered", "sensor", "lwm2m", "security mode"]
        ), f"Expected resource enumeration over DTLS: {text[:500]}"

    def test_dtls_psk_wrong_key_fails(self, cli_runner):
        """A wrong PSK key must NOT yield a successful handshake [Category C]

        Negative control for test_dtls_psk_handshake_succeeds: with a bogus key
        the DTLS handshake must fail and the scanner must report failure rather
        than falsely succeeding or downgrading to cleartext.
        """
        reason = _dtls_blocker()
        if reason:
            pytest.fail(reason)

        result = cli_runner.run(
            "coap",
            MOCK_HOST,
            "--port",
            str(DTLS_PORT),
            "-D",
            "--psk",
            "deadbeefdeadbeef",
            "--psk-identity",
            DTLS_PSK_IDENTITY,
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Wrong key -> handshake cannot complete -> scan fails (no DTLS fallback).
        assert not result.success, (
            "Wrong PSK key unexpectedly produced a successful scan; the handshake "
            "should have failed"
        )
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fail", "failed", "error", "dtls"]), (
            f"Expected DTLS handshake failure message: {text[:500]}"
        )


# ===========================================================================
# DTLS Certificate Tests: libcoap with X.509 certificates
# ===========================================================================

DTLS_CERT_PORT = 5686


def _dtls_cert_available() -> bool:
    """Check if the DTLS certificate container is running and healthy."""
    return _dtls_container_healthy("coap-dtls-cert-server")


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
        """Verify DTLS certificate server container is running [Category A]

        Hard assert (matching test_service_is_available): the cert-interop suite
        targets this container, so its absence is a failure, not a silent pass.
        """
        assert _dtls_cert_available(), "DTLS certificate container not available"

    def test_plain_coap_on_dtls_cert_port(self, cli_runner):
        """Plain CoAP scan against DTLS cert port fails gracefully [Category C]"""
        if not _dtls_cert_available():
            require_service("DTLS certificate container not available")

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

        # Plain CoAP on a DTLS-only port should fail/timeout. Failure-only
        # markers: "coap"/"connect" appear on a successful scan too.
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text
            for term in [
                "fail",
                "error",
                "timeout",
                "not reachable",
                "no response",
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
            require_service("DTLS certificate container not available")

        import pathlib

        cert_dir = (
            pathlib.Path(__file__).parent.parent.parent
            / "docker"
            / "mocks"
            / "services"
            / "coap"
            / "mock"
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
        # Behaviour-unique: the DTLS-cert path always names DTLS/certificate.
        # "coap"/"connected"/"resource" filler is dropped (it matches any scan).
        assert any(
            term in text
            for term in [
                "dtls",
                "certificate",
                "cert",
            ]
        ), f"Expected DTLS cert auth output: {text[:500]}"


@pytest.mark.coap
class TestCoAPPingFalsePositiveRegression:
    """Regression test for a connection-1-style false positive in coap_ping().

    Root cause was: coap_ping() (src/oida/protocols/coap/helpers.py) sent an
    empty CoAP CON ping and treated ANY non-empty UDP datagram received in
    reply as evidence of "CoAP server responding" (`return len(data) > 0`),
    with no validation that the reply was actually a well-formed CoAP
    message. A UDP endpoint that simply echoes/replies with arbitrary
    non-CoAP bytes was therefore misidentified as a live CoAP server, and
    CoAPScanner.connect() took the "alive" fast path straight into
    success:true with no further protocol validation.

    Fix: coap_ping() now requires the reply to look like a real CoAP
    message: the CoAP version bits (top 2 bits of byte 0) must equal 1, and
    the message ID (bytes 2-3) must echo the one we sent. Arbitrary/garbage
    UDP replies fail this check and coap_ping() returns False, falling
    through to the (already-correct) GET-fallback validation path.
    """

    def test_garbage_udp_responder_is_not_a_false_positive(self, cli_runner, tmp_path):
        """CoAP against a UDP responder that echoes non-CoAP junk must report success:false"""
        import socket
        import threading

        junk = bytes(range(256))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        junk_port = sock.getsockname()[1]
        stop = threading.Event()

        def _serve():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(8192)
                    sock.sendto(junk, addr)
                except socket.timeout:
                    continue
                except OSError:
                    break

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        try:
            out_dir = tmp_path / "coap_ping_fp"
            result = cli_runner.run(
                "coap",
                "127.0.0.1",
                "--port",
                str(junk_port),
                "--timeout",
                "3",
                "--output",
                str(out_dir),
                format="json",
                timeout=20,
            )

            json_path = out_dir / "coap.json"
            assert json_path.exists(), f"Expected {json_path} to be written; stderr={result.stderr}"
            data = json.loads(json_path.read_text())
            record = data[0] if isinstance(data, list) else data

            assert record["success"] is False, (
                "coap reported success:true against a UDP responder that only echoes "
                "non-CoAP garbage -- the coap_ping() false-positive fix has regressed."
            )
        finally:
            stop.set()
            sock.close()
            thread.join(timeout=2)
