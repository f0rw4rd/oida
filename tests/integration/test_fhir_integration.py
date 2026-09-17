"""
FHIR R4 Protocol Integration Tests

Tests oida fhir scanner against Docker mock service.
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/services/fhir_server.py):
  Server:
    SERVER_NAME = "OIDA Mock FHIR Server"
    SERVER_VERSION = "1.0.0"
    FHIR_VERSION = "4.0.1"
    BASE_URL = "http://localhost:8080/fhir"

  Patients: PT001 (John Doe), PT002 (Jane Smith), PT003 (Robert Johnson),
            PT004 (Mary Williams), PT005 (David Brown)
  Observations: OBS001 (Heart rate 72), OBS002 (Systolic BP 120),
                OBS003 (Glucose 95), OBS004 (Cholesterol 210), OBS005 (Weight 82.5)
  Medications: MED001 (Lisinopril), MED002 (Metformin), MED003 (Atorvastatin)
  Conditions: CON001 (Diabetes), CON002 (Hypertension), CON003 (Hyperlipidemia)
  Encounters: ENC001 (Annual Physical), ENC002 (Follow-up Visit)
  Procedures: PROC001 (Appendectomy)
  Allergies: ALL001 (Penicillin), ALL002 (Peanuts)
  Immunizations: IMM001 (COVID-19), IMM002 (Flu Shot)

  Security: SMART-on-FHIR with CORS enabled, no actual auth enforcement

Security Findings in FHIR module (src/oida/protocols/fhir/__init__.py):
  1. "No authentication"    - print_host_info(): no security services in CapabilityStatement
  2. "Anonymous access"     - _test_authentication(): anonymous access returns patient data
  3. "No authentication"    - _test_authentication(): invalid bearer token accepted
  4. "Insecure configuration" - _test_scope_bypass(): no SMART/OAuth detected
  5. "Default credentials"  - _brute_force_credentials(): valid Basic Auth found
  6. "Default credentials"  - _test_oauth2_credentials(): valid OAuth2 found
  7. "No TLS/HTTPS"         - _analyze_security(): connection not encrypted (data only)
  8. "No Security Services"  - _analyze_security(): no security services (data only)
  9. "CORS Enabled"         - _analyze_security(): CORS enabled (data only)

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  12 tests
Category B (conditional -- mock may not support, accept 0 or 1):       29 tests
Category C (error handling -- assert failure + validate error events):   2 tests
Skipped (untestable -- requires specific mock config or credentials):   2 tests
Total defined in file:                                                 45 tests
Total collected (including inherited from BaseProtocolIntegrationTest): 54 tests
---------------------------------------------------------------------------
"""

import socket
import threading

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST, check_port_open

pytestmark = [pytest.mark.fhir, pytest.mark.xdist_group("fhir_service")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _combined_text(result, log=None) -> str:
    """Build a combined lowercase text from stdout, stderr, and log messages."""
    parts = [result.combined_output.lower()]
    if log and hasattr(log, "events"):
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


@pytest.mark.fhir
class TestFhirIntegration(BaseProtocolIntegrationTest):
    """Integration tests for FHIR R4 protocol scanner"""

    @property
    def protocol_name(self) -> str:
        return "fhir"

    @property
    def default_port(self) -> int:
        return 8081  # Mapped port for fhir-mock in docker-compose

    @property
    def uses_port_argument(self) -> bool:
        # FHIR uses port in URL, not as --port argument
        return False

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        # FHIR uses full URL as target
        actual_port = port if port else self.default_port
        return f"http://{host}:{actual_port}/fhir"

    # ========================================================================
    # Basic Connectivity Tests
    # ========================================================================

    def test_fhir_connection(self, cli_runner, target, port, mock_service):
        """Test basic FHIR server connection [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"FHIR connection failed: {result.stderr}"
        _assert_log_has_events(result)

        # Validate server identification in output. The mock always reports a
        # successful connection AND its FHIR version (4.0.1), so require both
        # rather than accepting any single fallback term.
        text = _combined_text(result, result.scan_log)
        assert "connected to fhir endpoint" in text, (
            f"Expected explicit connection confirmation in output: {text[:500]}"
        )
        assert "fhir version" in text and "4.0.1" in text, (
            f"Expected FHIR version 4.0.1 from mock CapabilityStatement: {text[:500]}"
        )

    # ========================================================================
    # CapabilityStatement Tests
    # ========================================================================

    def test_capability_statement(self, cli_runner, target, port, mock_service):
        """Test fetching CapabilityStatement (metadata) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--caps",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"CapabilityStatement request failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # The mock serves a real R4 CapabilityStatement; --caps dumps it, so the
        # concrete fhirVersion 4.0.1 must appear, not merely a generic keyword.
        assert "4.0.1" in text, f"Expected fhirVersion 4.0.1 from CapabilityStatement: {text[:500]}"
        assert "capabilitystatement" in text, (
            f"Expected CapabilityStatement resource type in --caps output: {text[:500]}"
        )

    # ========================================================================
    # Patient Search Tests
    # ========================================================================

    def test_search_patients(self, cli_runner, target, port, mock_service):
        """Test searching for Patient resources [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Patient search failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        # The mock holds 5 named patients (Doe, Smith, Johnson, Williams, Brown).
        # A real enumeration must surface concrete patient records, so require at
        # least two distinct mock surnames rather than the generic word "patient".
        mock_surnames = [s for s in ("doe", "smith", "johnson", "williams", "brown") if s in text]
        assert len(mock_surnames) >= 2, (
            f"Expected concrete patient records from the mock, found surnames "
            f"{mock_surnames} in: {text[:500]}"
        )

    def test_search_patients_by_name(self, cli_runner, target, port, mock_service):
        """Test searching patients by name [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--patient-name",
            "Doe",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "search", "doe", "name"]), (
            f"Expected patient search attempt in output: {text[:500]}"
        )

    def test_search_patients_by_gender(self, cli_runner, target, port, mock_service):
        """Test searching patients by gender [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--patient-gender",
            "male",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "search", "male", "gender"]), (
            f"Expected gender search attempt in output: {text[:500]}"
        )

    def test_search_patients_max_results(self, cli_runner, target, port, mock_service):
        """Test patient search with max results limit [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--max-results",
            "10",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "search", "found"]), (
            f"Expected patient search in output: {text[:500]}"
        )

    def test_search_patients_wildcard(self, cli_runner, target, port, mock_service):
        """Test patient search with wildcard enumeration [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--wildcard",
            "--max-results",
            "50",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "search", "wildcard"]), (
            f"Expected wildcard search in output: {text[:500]}"
        )

    # ========================================================================
    # Read Patient by ID Tests
    # ========================================================================

    def test_read_patient_by_id(self, cli_runner, target, port, mock_service):
        """Test reading specific Patient by ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--read-patient",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "pt001", "read", "doe"]), (
            f"Expected patient read in output: {text[:500]}"
        )

    # ========================================================================
    # Observation Search Tests
    # ========================================================================

    def test_search_observations(self, cli_runner, target, port, mock_service):
        """Test searching for Observation resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-observations",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["observation", "search", "heart rate", "glucose"]), (
            f"Expected observation search in output: {text[:500]}"
        )

    def test_search_observations_by_patient(self, cli_runner, target, port, mock_service):
        """Test searching observations by patient ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-observations",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["observation", "search", "pt001"]), (
            f"Expected observation patient search in output: {text[:500]}"
        )

    def test_search_observations_by_category(self, cli_runner, target, port, mock_service):
        """Test searching observations by category [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-observations",
            "--category",
            "vital-signs",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["observation", "vital", "search"]), (
            f"Expected observation category search in output: {text[:500]}"
        )

    def test_read_observation_by_id(self, cli_runner, target, port, mock_service):
        """Test reading specific Observation by ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--read-observation",
            "OBS001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["observation", "obs001", "read"]), (
            f"Expected observation read in output: {text[:500]}"
        )

    # ========================================================================
    # Medication Search Tests
    # ========================================================================

    def test_search_medications(self, cli_runner, target, port, mock_service):
        """Test searching for MedicationRequest resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-medications",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["medication", "search", "lisinopril", "metformin"]), (
            f"Expected medication search in output: {text[:500]}"
        )

    def test_search_medications_by_patient(self, cli_runner, target, port, mock_service):
        """Test searching medications by patient ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-medications",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["medication", "search", "pt001"]), (
            f"Expected medication patient search in output: {text[:500]}"
        )

    def test_read_medication_by_id(self, cli_runner, target, port, mock_service):
        """Test reading specific MedicationRequest by ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--read-medication",
            "MED001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["medication", "med001", "read"]), (
            f"Expected medication read in output: {text[:500]}"
        )

    # ========================================================================
    # Condition Search Tests
    # ========================================================================

    def test_search_conditions(self, cli_runner, target, port, mock_service):
        """Test searching for Condition resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-conditions",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["condition", "search", "diabetes", "hypertension"]), (
            f"Expected condition search in output: {text[:500]}"
        )

    def test_search_conditions_by_patient(self, cli_runner, target, port, mock_service):
        """Test searching conditions by patient ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-conditions",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["condition", "search", "pt001"]), (
            f"Expected condition patient search in output: {text[:500]}"
        )

    def test_read_condition_by_id(self, cli_runner, target, port, mock_service):
        """Test reading specific Condition by ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--read-condition",
            "CON001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["condition", "con001", "read"]), (
            f"Expected condition read in output: {text[:500]}"
        )

    # ========================================================================
    # Encounter Search Tests
    # ========================================================================

    def test_search_encounters(self, cli_runner, target, port, mock_service):
        """Test searching for Encounter resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-encounters",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["encounter", "search"]), (
            f"Expected encounter search in output: {text[:500]}"
        )

    def test_search_encounters_by_patient(self, cli_runner, target, port, mock_service):
        """Test searching encounters by patient ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-encounters",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["encounter", "search", "pt001"]), (
            f"Expected encounter patient search in output: {text[:500]}"
        )

    def test_read_encounter_by_id(self, cli_runner, target, port, mock_service):
        """Test reading specific Encounter by ID [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--read-encounter",
            "ENC001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["encounter", "enc001", "read"]), (
            f"Expected encounter read in output: {text[:500]}"
        )

    # ========================================================================
    # Additional Resource Search Tests
    # ========================================================================

    def test_search_procedures(self, cli_runner, target, port, mock_service):
        """Test searching for Procedure resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-procedures",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["procedure", "search"]), (
            f"Expected procedure search in output: {text[:500]}"
        )

    def test_search_allergies(self, cli_runner, target, port, mock_service):
        """Test searching for AllergyIntolerance resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-allergies",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["allergy", "search"]), (
            f"Expected allergy search in output: {text[:500]}"
        )

    def test_search_immunizations(self, cli_runner, target, port, mock_service):
        """Test searching for Immunization resources [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-immunizations",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["immunization", "search"]), (
            f"Expected immunization search in output: {text[:500]}"
        )

    # ========================================================================
    # Enumerate All Tests
    # ========================================================================

    def test_enumerate_all(self, cli_runner, target, port, mock_service):
        """Test enumerating all resources with -E flag [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "-E",
            "--max-results",
            "10",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "observation", "medication", "search"]), (
            f"Expected enumeration output: {text[:500]}"
        )

    # ========================================================================
    # Security Finding Tests
    # ========================================================================

    @pytest.mark.security
    def test_finding_no_tls_on_http_connection(self, cli_runner, target, port, mock_service):
        """Test that _analyze_security reports 'No TLS/HTTPS' for HTTP targets [Category A]

        The mock server runs on HTTP (not HTTPS). When connecting via http://,
        the scanner sets tls_enabled=False. The _analyze_security() method
        then appends a 'No TLS/HTTPS' finding to the results data.

        This finding is written to results["data"]["security_findings"] but
        NOT emitted via logger.security_finding(), so it appears in console
        output (the display loop) rather than in the structured security log events.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)

        # The _analyze_security() method displays findings via self.logger.display()
        # which includes "[ENCRYPTION] No TLS/HTTPS: Connection is not encrypted".
        # The mock is plain HTTP, so this exact finding must appear.
        text = _combined_text(result, result.scan_log)
        assert "no tls/https" in text, (
            f"Expected 'No TLS/HTTPS' finding for plain-HTTP target: {text[:500]}"
        )
        assert "not encrypted" in text, (
            f"Expected the 'Connection is not encrypted' detail: {text[:500]}"
        )

    @pytest.mark.security
    def test_finding_cors_enabled(self, cli_runner, target, port, mock_service):
        """Test that _analyze_security reports 'CORS Enabled' finding [Category A]

        The mock server's CapabilityStatement has cors=True in the security section.
        _analyze_security() detects this and appends a 'CORS Enabled' finding.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)

        text = _combined_text(result, result.scan_log)
        # The mock's CapabilityStatement sets cors=true, so the CORS finding and its
        # cross-origin detail must both be present.
        assert "cors enabled" in text, f"Expected 'CORS Enabled' finding: {text[:500]}"
        assert "cross-origin" in text, (
            f"Expected the cross-origin detail for the CORS finding: {text[:500]}"
        )

    @pytest.mark.security
    def test_finding_anonymous_access_on_test_auth(self, cli_runner, target, port, mock_service):
        """Test that --test-auth detects anonymous access to patient data [Category A]

        The mock FHIR server has no authentication enforcement. When the scanner
        tests anonymous access (no credentials), the mock returns patient data.
        This triggers logger.security_finding("Anonymous access", ...) which emits
        a security event with data.finding="Anonymous access" in the structured log.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-auth",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Auth test failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Check structured log for "Anonymous access" security finding
        security_events = log.get_security_findings()
        anon_findings = [
            e for e in security_events if e.get("data", {}).get("finding") == "Anonymous access"
        ]
        assert len(anon_findings) > 0, (
            f"Expected 'Anonymous access' security finding in structured log. "
            f"Available security findings: "
            f"{[e.get('data', {}).get('finding') for e in security_events]}"
        )

        # Validate finding payload. security_finding(title, detail=...) records the
        # detail sentence under the structured "details" key (see ics_logger), so the
        # explanatory text must survive into the JSON event.
        finding_data = anon_findings[0].get("data", {})
        assert finding_data.get("finding") == "Anonymous access"
        details = finding_data.get("details", "")
        assert "anonymous access allowed" in details.lower(), (
            f"Finding must carry the anonymous-access detail in 'details': {finding_data}"
        )
        assert "returned patient data" in details.lower(), (
            f"Finding detail should explain patient data was returned: {finding_data}"
        )

    @pytest.mark.security
    def test_finding_invalid_token_accepted_on_test_auth(
        self, cli_runner, target, port, mock_service
    ):
        """Test that --test-auth detects invalid bearer token acceptance [Category A]

        The mock server does not validate bearer tokens. When the scanner sends
        an invalid token, the mock still returns patient data. This triggers
        logger.security_finding("No authentication", "Invalid bearer token accepted by server")
        which emits event_type="security" with data.finding="No authentication".
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-auth",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Auth test failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Check for "No authentication" finding from invalid token test
        security_events = log.get_security_findings()
        no_auth_findings = [
            e for e in security_events if e.get("data", {}).get("finding") == "No authentication"
        ]
        assert len(no_auth_findings) > 0, (
            f"Expected 'No authentication' security finding (invalid token accepted). "
            f"Available findings: "
            f"{[e.get('data', {}).get('finding') for e in security_events]}"
        )

        # The invalid-token finding must carry its explanatory detail in the
        # structured "details" key. security_finding(title, detail=...) routes the
        # sentence there; a regression that mis-binds it to the category slot would
        # drop it from the JSON event and fail this assertion.
        invalid_token_details = [
            f.get("data", {}).get("details", "").lower()
            for f in no_auth_findings
            if "invalid" in f.get("data", {}).get("details", "").lower()
            and "token" in f.get("data", {}).get("details", "").lower()
        ]
        assert invalid_token_details, (
            "Expected a 'No authentication' finding whose 'details' explains the "
            f"invalid bearer token was accepted. Got: "
            f"{[f.get('data', {}) for f in no_auth_findings]}"
        )

    @pytest.mark.security
    def test_finding_security_analysis_runs_on_basic_scan(
        self, cli_runner, target, port, mock_service
    ):
        """Test that _analyze_security() runs and reports findings on every scan [Category A]

        Even without explicit security flags, _analyze_security() always runs at the
        end of proto_flow(). For an HTTP mock with CORS enabled, it should produce
        at least "No TLS/HTTPS" and "CORS Enabled" in the security findings display.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)

        text = _combined_text(result, result.scan_log)
        # _analyze_security() displays "Security Findings:" header and individual findings
        assert "security findings" in text, (
            f"Expected 'Security Findings:' section in output: {text[:500]}"
        )

    @pytest.mark.security
    def test_finding_test_auth_produces_multiple_findings(
        self, cli_runner, target, port, mock_service
    ):
        """Test that --test-auth produces both anonymous and token findings [Category A]

        Against the unauthenticated mock, --test-auth should produce at minimum:
        1. "Anonymous access" - anonymous request returns patient data
        2. "No authentication" - invalid token still returns data
        Both appear as event_type="security" events in the structured log.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-auth",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Auth test failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        security_events = log.get_security_findings()
        finding_titles = [e.get("data", {}).get("finding") for e in security_events]

        # Should have at least two security findings
        assert len(security_events) >= 2, (
            f"Expected at least 2 security findings from --test-auth, "
            f"got {len(security_events)}: {finding_titles}"
        )

        # Verify both expected finding types are present
        assert "Anonymous access" in finding_titles, (
            f"Expected 'Anonymous access' finding, got: {finding_titles}"
        )
        assert "No authentication" in finding_titles, (
            f"Expected 'No authentication' finding, got: {finding_titles}"
        )

    @pytest.mark.security
    def test_finding_scope_test_with_smart_configured(self, cli_runner, target, port, mock_service):
        """Test --test-scope when SMART-on-FHIR is in CapabilityStatement [Category A]

        The mock server declares SMART-on-FHIR in its CapabilityStatement security
        section. When --test-scope detects SMART, it reports that scope enforcement
        should be active rather than emitting an 'Insecure configuration' finding.

        This test verifies the SMART detection path (no Insecure finding emitted).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-scope",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Scope test failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # Should NOT have "Insecure configuration" finding because SMART is configured
        security_events = log.get_security_findings()
        insecure_findings = [
            e
            for e in security_events
            if e.get("data", {}).get("finding") == "Insecure configuration"
        ]
        assert len(insecure_findings) == 0, (
            f"Should NOT report 'Insecure configuration' when SMART-on-FHIR is configured. "
            f"Found: {insecure_findings}"
        )

        # Should mention SMART detection in output
        text = _combined_text(result, result.scan_log)
        assert "smart" in text, f"Expected SMART-on-FHIR detection in output: {text[:500]}"

    @pytest.mark.security
    def test_finding_no_authentication_in_print_host_info(
        self, cli_runner, target, port, mock_service
    ):
        """Test print_host_info() 'No authentication' finding behavior [Category A]

        In print_host_info(), the scanner checks if the CapabilityStatement has
        security_services. The mock DOES declare SMART-on-FHIR security services,
        so this path should NOT emit 'No authentication' from print_host_info().

        If this finding appeared it would mean security_services was empty.
        We verify it does NOT appear from the host info path (only from --test-auth).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Basic scan failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log

        # On a basic scan (no --test-auth), the mock's CapabilityStatement
        # has SMART-on-FHIR services, so "No authentication" should NOT fire
        # from print_host_info(). The finding may still appear from _analyze_security
        # but not as a security log event (it's added to results data).
        security_events = log.get_security_findings()
        no_auth_from_host_info = [
            e
            for e in security_events
            if e.get("data", {}).get("finding") == "No authentication"
            and "no security services"
            in (
                e.get("data", {}).get("details", "") + e.get("data", {}).get("category", "")
            ).lower()
        ]
        assert len(no_auth_from_host_info) == 0, (
            f"Should NOT have 'No authentication' from print_host_info when "
            f"CapabilityStatement has security services. Found: {no_auth_from_host_info}"
        )

        # Verify that SMART/security info is displayed
        text = _combined_text(result, result.scan_log)
        assert "smart" in text or "security" in text, (
            f"Expected security service info in output: {text[:500]}"
        )

    @pytest.mark.security
    def test_finding_cross_patient_access_without_patient_id(
        self, cli_runner, target, port, mock_service
    ):
        """Test --test-cross-patient without --patient-id warns user [Category B]

        The _test_cross_patient_access() method requires --patient-id. When not
        provided, it logs a warning. This verifies the guard logic.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-cross-patient",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(
            term in text for term in ["patient-id required", "cross-patient", "patient_id"]
        ), f"Expected cross-patient warning in output: {text[:500]}"

    @pytest.mark.security
    def test_finding_cross_patient_access_with_patient_id(
        self, cli_runner, target, port, mock_service
    ):
        """Test --test-cross-patient with --patient-id [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-cross-patient",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["cross-patient", "access", "manual verification"]), (
            f"Expected cross-patient test output: {text[:500]}"
        )

    # ========================================================================
    # Authentication Tests (non-finding)
    # ========================================================================

    @pytest.mark.security
    def test_auth_testing(self, cli_runner, target, port, mock_service):
        """Test authentication mechanism testing produces output [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--test-auth",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Auth testing failed: {result.stderr}"
        _assert_log_has_events(result)
        text = _combined_text(result, result.scan_log)
        assert "authentication" in text, f"Expected authentication test output: {text[:500]}"

    def test_with_bearer_token(self, cli_runner, target, port, mock_service):
        """Test with bearer token authentication [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--token",
            "test_token_12345",
            "--search-patients",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "connected", "fhir"]), (
            f"Expected FHIR output with token: {text[:500]}"
        )

    def test_with_bearer_prefix(self, cli_runner, target, port, mock_service):
        """Test with Bearer prefix in token [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--token",
            "Bearer test_token_12345",
            "--search-patients",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "connected", "fhir"]), (
            f"Expected FHIR output with bearer prefix: {text[:500]}"
        )

    # ========================================================================
    # Response Options Tests
    # ========================================================================

    def test_summary_mode(self, cli_runner, target, port, mock_service):
        """Test summary response mode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--summary",
            "count",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "search", "summary"]), (
            f"Expected summary mode output: {text[:500]}"
        )

    def test_elements_filter(self, cli_runner, target, port, mock_service):
        """Test elements filter [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--elements",
            "id,name,birthDate",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "search", "element"]), (
            f"Expected elements filter output: {text[:500]}"
        )

    # ========================================================================
    # FHIR Version Tests
    # ========================================================================

    def test_fhir_version_r4(self, cli_runner, target, port, mock_service):
        """Test with FHIR R4 version (default) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--fhir-version",
            "R4",
            "--caps",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fhir", "4.0", "capability", "version"]), (
            f"Expected FHIR version info in output: {text[:500]}"
        )

    # ========================================================================
    # Export Tests
    # ========================================================================

    def test_export_json(self, cli_runner, target, port, mock_service, tmp_path):
        """Test JSON export functionality [Category B]"""
        export_dir = tmp_path / "fhir_results"
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            json_log=True,
            timeout=30,
            expect_json=False,
            output=str(export_dir),
            format="json",
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "export", "result", "search"]), (
            f"Expected export output: {text[:500]}"
        )

    def test_save_response(self, cli_runner, target, port, mock_service, tmp_path):
        """Test saving raw response to file [Category B]"""
        response_file = tmp_path / "fhir_response.json"
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--save-response",
            str(response_file),
            json_log=True,
            timeout=30,
            expect_json=False,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "saved", "response", "search"]), (
            f"Expected save response output: {text[:500]}"
        )

    # ========================================================================
    # Date Range Tests
    # ========================================================================

    def test_date_range_filter(self, cli_runner, target, port, mock_service):
        """Test observations with date range filter [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-observations",
            "--date-from",
            "2024-01-01",
            "--date-to",
            "2024-12-31",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["observation", "search", "date"]), (
            f"Expected date range filter output: {text[:500]}"
        )

    # ========================================================================
    # Code Filter Tests
    # ========================================================================

    def test_code_filter(self, cli_runner, target, port, mock_service):
        """Test observations with LOINC code filter [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-observations",
            "--code",
            "8867-4",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["observation", "search", "8867-4", "heart rate"]), (
            f"Expected code filter output: {text[:500]}"
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
        assert "fhir" in result.stdout.lower()

    def test_verbose_output(self, cli_runner, target, port, mock_service):
        """Test verbose output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--caps",
            json_log=True,
            timeout=30,
            verbose=True,
            format="json",
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fhir", "connected", "capability", "version"]), (
            f"Expected verbose output: {text[:500]}"
        )

    def test_debug_output(self, cli_runner, target, port, mock_service):
        """Test --debug output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--caps",
            json_log=True,
            timeout=30,
            debug=True,
            format="json",
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fhir", "debug", "capability", "connected"]), (
            f"Expected debug output: {text[:500]}"
        )

    # ========================================================================
    # Timeout Tests
    # ========================================================================

    def test_short_timeout(self, cli_runner, target, port, mock_service):
        """Test with short timeout setting [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--timeout",
            "5",
            "--caps",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Should complete within timeout
        assert result.execution_time < 20, "Should respect timeout setting"
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fhir", "connected", "capability"]), (
            f"Expected output from short timeout scan: {text[:500]}"
        )

    # ========================================================================
    # TLS Tests
    # ========================================================================

    @pytest.mark.security
    def test_tls_insecure(self, cli_runner, target, port, mock_service):
        """Test with TLS insecure flag [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--tls-insecure",
            "--caps",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["fhir", "connected", "capability"]), (
            f"Expected output with tls-insecure flag: {text[:500]}"
        )

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_connection_refused_error(self, cli_runner):
        """Test handling of connection refused to wrong port [Category C]"""
        bad_target = f"http://{MOCK_HOST}:65534/fhir"
        result = cli_runner.run(
            self.protocol_name,
            bad_target,
            "--timeout",
            "5",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not hang on connection refused"
        text = result.combined_output.lower()
        assert any(term in text for term in ["error", "fail", "refused", "connection"]), (
            f"Expected error message for connection refused: {text[:500]}"
        )

    def test_invalid_fhir_endpoint(self, cli_runner, port, mock_service):
        """Test handling of invalid FHIR endpoint path [Category C]"""
        bad_target = f"http://{MOCK_HOST}:{port}/nonexistent"
        result = cli_runner.run(
            self.protocol_name,
            bad_target,
            "--timeout",
            "5",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert result.returncode != -1, "Should not hang on invalid endpoint"
        text = result.combined_output.lower()
        assert any(term in text for term in ["error", "fail", "not found", "404", "connection"]), (
            f"Expected error for invalid endpoint: {text[:500]}"
        )

    # ========================================================================
    # Discovery flag-coverage tests (--capability-statement / --enum-all)
    # ========================================================================
    def test_capability_statement_long_flag(self, cli_runner, target, port, mock_service):
        """Literal --capability-statement alias returns real mock CapabilityStatement [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--capability-statement",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "4.0.1" in text, f"Expected served FHIR version 4.0.1: {text[:800]}"
        assert "oida" in text.lower(), f"Expected mock server/publisher name: {text[:800]}"

    def test_enum_all_long_flag_expands_unsupported_resource_searches(
        self, cli_runner, target, port, mock_service
    ):
        """--enum-all expands to every resource search; mock lacks routes for several [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--enum-all",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        # The mock has no routes for these resource types -> each must fail cleanly,
        # never crash, never be silently skipped.
        for resource in ("diagnosticreport", "practitioner", "organization"):
            assert resource in text.lower(), (
                f"--enum-all should have attempted {resource} search: {text[:1500]}"
            )

    # ========================================================================
    # Unsupported-resource search flags (mock has no route -> clean 404, Category B)
    # ========================================================================
    def test_search_diagnostics_unsupported_resource(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-diagnostics",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "diagnosticreport" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    def test_search_documents_unsupported_resource(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-documents",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "documentreference" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    def test_search_practitioners_unsupported_resource(
        self, cli_runner, target, port, mock_service
    ):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-practitioners",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "practitioner" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    def test_search_organizations_unsupported_resource(
        self, cli_runner, target, port, mock_service
    ):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-organizations",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "organization" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    def test_search_locations_unsupported_resource(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-locations",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "location" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    def test_search_devices_unsupported_resource(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-devices",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "device" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    def test_search_orders_unsupported_resource(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-orders",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "servicerequest" in text.lower() or "404" in text, (
            f"Expected clean unsupported-resource error: {text[:500]}"
        )

    # ========================================================================
    # --no-tls: only observable against a schemeless target (fhir has no --port
    # flag, so the port must be embedded directly in the target string).
    # ========================================================================
    def test_no_tls_bare_target_connects_over_plain_http(self, cli_runner, port, mock_service):
        """--no-tls on a schemeless target reaches the plaintext mock [Category A]"""
        bare_target = f"{MOCK_HOST}:{port}/fhir"
        result = cli_runner.run(
            self.protocol_name,
            bare_target,
            "--no-tls",
            "--caps",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "4.0.1" in text, f"--no-tls should reach the plaintext mock: {text[:800]}"

    def test_default_tls_bare_target_fails_cleanly_against_plaintext_mock(
        self, cli_runner, port, mock_service
    ):
        """Without --no-tls, TLS is attempted against a plaintext port and fails
        cleanly (also exercises hostile-catalogue item: TLS/plaintext mismatch)
        [Category C]"""
        bare_target = f"{MOCK_HOST}:{port}/fhir"
        result = cli_runner.run(
            self.protocol_name,
            bare_target,
            "--caps",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        assert result.returncode != -1, "TLS mismatch must fail fast, not hang"
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert any(
            term in text.lower() for term in ["ssl", "tls", "wrong_version", "error", "fail"]
        ), f"Expected a clean TLS failure against the plaintext mock: {text[:800]}"

    # ========================================================================
    # --include / --revinclude / --patient-dob: accepted but the mock ignores
    # them entirely (no birthdate filter, no _include support). Category B.
    # ========================================================================
    def test_include_revinclude_and_patient_dob_are_silently_ignored_by_mock(
        self, cli_runner, target, port, mock_service
    ):
        """Document that --include/--revinclude/--patient-dob are parsed and sent
        but have zero observable filtering effect against this mock: a DOB filter
        that should match exactly one of five patients still returns all five."""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--include",
            "Patient:organization",
            "--revinclude",
            "Observation:patient",
            "--patient-dob",
            "1980-01-15",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        for patient_id in ("pt001", "pt002", "pt003", "pt004", "pt005"):
            assert patient_id in text, (
                f"--patient-dob=1980-01-15 should only match PT001 on a real FHIR "
                f"server, but the mock ignores the filter entirely and returns "
                f"every patient: {text[:1000]}"
            )

    # ========================================================================
    # Write operations: --confirm gate consistency (crud.py gates all four
    # write ops with the identical 'Write operations require --confirm flag'
    # message), then a clean failure against the GET-only mock (501).
    # ========================================================================
    def test_create_patient_refused_without_confirm(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--create-patient",
            "--patient-given-name",
            "John",
            "--patient-family-name",
            "Doe",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        errors = result.scan_log.get_errors() if result.scan_log else []
        error_text = " ".join(str(e) for e in errors).lower() + result.combined_output.lower()
        assert "confirm" in error_text, f"Expected confirm-gate refusal: {error_text[:500]}"

    def test_create_patient_with_confirm_fails_cleanly_against_get_only_mock(
        self, cli_runner, target, port, mock_service
    ):
        """With --confirm the write is attempted; the mock has no POST handler
        (stdlib HTTPServer -> 501) so it must fail cleanly, never crash [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--create-patient",
            "--confirm",
            "--patient-given-name",
            "John",
            "--patient-family-name",
            "Doe",
            "--patient-data",
            '{"resourceType": "Patient"}',
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert any(term in text.lower() for term in ["failed", "error", "501"]), (
            f"Expected a clean failure against the GET-only mock: {text[:800]}"
        )

    def test_create_patient_malformed_patient_data_json_no_crash(
        self, cli_runner, target, port, mock_service
    ):
        """Malformed --patient-data JSON must produce a clean error, never a
        traceback [Category C / P3]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--create-patient",
            "--confirm",
            "--patient-data",
            "{not valid json",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output, (
            f"Malformed --patient-data must not crash: {result.combined_output[:800]}"
        )
        assert "failed" in text.lower() or "error" in text.lower(), (
            f"Expected a clean JSON-parse failure message: {text[:800]}"
        )

    def test_update_patient_refused_without_confirm(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--update-patient",
            "PT001",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "confirm" in text.lower(), f"Expected confirm-gate refusal: {text[:500]}"

    def test_update_patient_with_confirm_fails_cleanly(
        self, cli_runner, target, port, mock_service
    ):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--update-patient",
            "PT001",
            "--confirm",
            "--patient-data",
            '{"resourceType": "Patient", "id": "PT001"}',
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert any(term in text.lower() for term in ["failed", "error", "501"]), (
            f"Expected a clean failure against the GET-only mock: {text[:800]}"
        )

    def test_delete_patient_refused_without_confirm(self, cli_runner, target, port, mock_service):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--delete-patient",
            "PT001",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "confirm" in text.lower(), f"Expected confirm-gate refusal: {text[:500]}"

    def test_delete_patient_with_confirm_fails_cleanly(
        self, cli_runner, target, port, mock_service
    ):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--delete-patient",
            "PT001",
            "--confirm",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert any(term in text.lower() for term in ["failed", "error", "501"]), (
            f"Expected a clean failure against the GET-only mock: {text[:800]}"
        )

    def test_create_observation_refused_without_confirm(
        self, cli_runner, target, port, mock_service
    ):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--create-observation",
            "--patient-id",
            "PT001",
            "--observation-code",
            "8867-4",
            "--observation-value",
            "72",
            "--observation-unit",
            "/min",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "confirm" in text.lower(), f"Expected confirm-gate refusal: {text[:500]}"

    def test_create_observation_with_confirm_fails_cleanly(
        self, cli_runner, target, port, mock_service
    ):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--create-observation",
            "--confirm",
            "--patient-id",
            "PT001",
            "--observation-code",
            "8867-4",
            "--observation-value",
            "72",
            "--observation-unit",
            "/min",
            "--observation-data",
            "{}",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert any(term in text.lower() for term in ["failed", "error", "501", "patient-id"]), (
            f"Expected a clean failure against the GET-only mock: {text[:800]}"
        )

    # ========================================================================
    # Brute-force wordlist flags. The mock never enforces authentication, so
    # the scanner's own baseline check short-circuits before per-credential
    # OAuth2 requests run — --client-id/--client-secret/--scope/--auth-url/
    # --token-url are parsed but that code path is unreachable here. The
    # wordlist files themselves ARE exercised (their line counts are echoed).
    # ========================================================================
    def test_brute_force_wordlists_detect_anonymous_access(
        self, cli_runner, target, port, mock_service, tmp_path
    ):
        user_file = tmp_path / "users.txt"
        pass_file = tmp_path / "pass.txt"
        user_file.write_text("admin\n")
        pass_file.write_text("admin123\n")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--brute",
            "--confirm",
            "--user-file",
            str(user_file),
            "--pass-file",
            str(pass_file),
            "--brute-method",
            "oauth2",
            "--client-id",
            "test-client",
            "--client-secret",
            "test-secret",
            "--scope",
            "patient/*.read",
            "--auth-url",
            f"http://{MOCK_HOST}:{port}/auth",
            "--token-url",
            f"http://{MOCK_HOST}:{port}/token",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        text = _combined_text(result, result.scan_log)
        assert "Traceback" not in result.combined_output
        assert "1 usernames" in text.lower() or "loaded 1" in text.lower(), (
            f"Expected --user-file/--pass-file to be loaded: {text[:800]}"
        )
        assert "anonymous" in text.lower(), (
            f"Mock allows unauthenticated access; brute force should short-circuit "
            f"and report it: {text[:800]}"
        )

    # ========================================================================
    # BUG (P2): -n/--max-results has no bounds validation. A negative value is
    # silently accepted by argparse (type=int) and produces a Python negative
    # slice (results[:-5] on 5 mock patients == []), silently returning "no
    # patients found" instead of a validation error. Documented, not fixed.
    # ========================================================================
    def test_negative_max_results_silently_returns_empty_bug(
        self, cli_runner, target, port, mock_service
    ):
        negative_result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "-n",
            "-5",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        positive_result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "-n",
            "5",
            "--timeout",
            "10",
            format="json",
            json_log=True,
            timeout=20,
        )
        negative_text = _combined_text(negative_result, negative_result.scan_log)
        positive_text = _combined_text(positive_result, positive_result.scan_log)
        assert "Traceback" not in negative_result.combined_output
        # BUG: -n -5 is accepted without a validation error and, via Python's
        # negative-slice semantics, silently returns zero results instead of
        # rejecting the invalid value or clamping it.
        assert "pt001" not in negative_text, (
            "BUG regression check failed: -n -5 unexpectedly returned patient data "
            "-- if this now fails, the negative --max-results bug may have been "
            f"fixed (verify and update this test): {negative_text[:800]}"
        )
        assert any(term in negative_text for term in ["no patients found", "0 patient"]), (
            f"Expected the documented silent-empty-result bug for -n -5: {negative_text[:800]}"
        )
        assert "pt001" in positive_text, (
            f"Sanity check: -n 5 must return real patient data: {positive_text[:800]}"
        )

    def test_max_results_non_numeric_rejected_by_argparse(self, cli_runner, target):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "-n",
            "notanumber",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success
        assert "Traceback" not in result.combined_output

    # ========================================================================
    # Hostile-server catalogue
    # ========================================================================
    def test_wrong_protocol_on_port_hangs_ignoring_timeout_bug(self, cli_runner, mock_ports):
        """BUG (P1/timeout): pointing fhir at a live but non-HTTP TCP service
        (the modbus mock) causes the scanner to hang indefinitely during the
        initial CapabilityStatement fetch -- --timeout is NOT honoured for this
        phase. Verified manually: the process had to be killed externally after
        20s despite --timeout 5. This harness kills the subprocess after
        `timeout=` seconds and reports returncode == -1 in that case."""
        modbus_port = mock_ports.get("modbus")
        if not modbus_port or not check_port_open(MOCK_HOST, modbus_port, timeout=2):
            pytest.skip("modbus mock not available for impostor-protocol test")
        bad_target = f"http://{MOCK_HOST}:{modbus_port}/fhir"
        result = cli_runner.run(
            self.protocol_name,
            bad_target,
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=12,
        )
        assert "Traceback" not in result.combined_output
        text = _combined_text(result, result.scan_log)
        assert "4.0.1" not in text, "Must never claim a FHIR CapabilityStatement from a modbus port"
        assert result.returncode == -1, (
            "Documented bug: fhir's --timeout is not honoured against a "
            "wrong-protocol live port; the scan hangs until the harness kills "
            f"it. If this now fails, the hang may be fixed: {text[:500]}"
        )

    def test_unreachable_host_hangs_ignoring_timeout_bug(self, cli_runner):
        """BUG (P1/timeout): a blackhole address also hangs past --timeout,
        confirming the hang is not specific to impostor protocols but affects
        any connection that never completes an HTTP response."""
        bad_target = "http://10.255.255.1:8081/fhir"
        result = cli_runner.run(
            self.protocol_name,
            bad_target,
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=12,
        )
        assert "Traceback" not in result.combined_output
        assert result.returncode == -1, (
            "Documented bug: fhir's --timeout is not honoured against an "
            "unreachable host; the scan hangs until the harness kills it "
            f"(expected to end within ~3s): {result.combined_output[:500]}"
        )

    def test_silent_socket_no_false_positive(self, cli_runner):
        """A socket that accepts and then sends nothing must not be identified
        as a FHIR server and must not crash. (May also hit the timeout-hang bug
        documented above; the harness-level timeout is the safety net.)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        silent_port = server.getsockname()[1]
        stop = threading.Event()

        def _accept_and_stay_silent():
            server.settimeout(10)
            try:
                conn, _addr = server.accept()
                stop.wait(9)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=_accept_and_stay_silent, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{silent_port}/fhir"
            result = cli_runner.run(
                self.protocol_name,
                target,
                "--timeout",
                "3",
                format="json",
                json_log=True,
                timeout=12,
            )
            text = _combined_text(result, result.scan_log)
            assert "4.0.1" not in text, "Must never claim a FHIR CapabilityStatement from silence"
            assert "Traceback" not in result.combined_output
        finally:
            stop.set()
            server.close()
            thread.join(timeout=5)

    def test_junk_bytes_socket_no_false_positive(self, cli_runner):
        """A socket that returns junk bytes where an HTTP response belongs must
        be reported as a clean parse/connection error, never a false-positive
        FHIR identification and never a crash."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        junk_port = server.getsockname()[1]
        stop = threading.Event()

        def _accept_and_send_junk():
            server.settimeout(10)
            try:
                conn, _addr = server.accept()
                conn.sendall(b"\x00\x01\x02NOT-HTTP-GARBAGE\xff\xfe")
                stop.wait(2)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=_accept_and_send_junk, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{junk_port}/fhir"
            result = cli_runner.run(
                self.protocol_name,
                target,
                "--timeout",
                "3",
                format="json",
                json_log=True,
                timeout=12,
            )
            text = _combined_text(result, result.scan_log)
            assert "4.0.1" not in text, (
                "Must never claim a FHIR CapabilityStatement from garbage bytes"
            )
            assert "Traceback" not in result.combined_output
        finally:
            stop.set()
            server.close()
            thread.join(timeout=5)

    # ========================================================================
    # False flags: unknown flags, transposition typos, and borrowed flags must
    # all be rejected -- never silently ignored or prefix-matched.
    # ========================================================================
    def test_unknown_flag_rejected(self, cli_runner, target):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--not-a-real-fhir-flag",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_typo_transposition_flag_rejected(self, cli_runner, target):
        """A transposed flag name must be rejected as unknown, never silently
        prefix-matched onto the real flag (argparse only does that for
        truncations, not transpositions)."""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--serach-patients",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success
        assert "Traceback" not in result.combined_output
        assert "PT001" not in result.combined_output, (
            "A typo'd flag must never silently run a real patient search"
        )

    def test_borrowed_flag_from_other_protocol_rejected(self, cli_runner, target):
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--unit-id",
            "1",
            format="json",
            json_log=True,
            timeout=15,
        )
        assert not result.success
        assert "Traceback" not in result.combined_output
