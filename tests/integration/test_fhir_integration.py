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

    @pytest.mark.security
    @pytest.mark.skip(
        reason="Brute force requires --confirm and credential files; "
        "mock has no auth to validate against"
    )
    def test_finding_default_credentials_basic_auth(self, cli_runner, target, port, mock_service):
        """Test that brute force detects valid Basic Auth credentials [Category B - skip]

        Would require --brute --default-creds --confirm flags and the mock
        to support HTTP Basic Auth validation. The mock accepts all requests
        regardless of auth, so this would always find 'Default credentials'.
        """
        pass

    @pytest.mark.security
    @pytest.mark.skip(
        reason="OAuth2 brute force requires token endpoint and credentials; "
        "mock has no OAuth2 token endpoint"
    )
    def test_finding_default_credentials_oauth2(self, cli_runner, target, port, mock_service):
        """Test that brute force detects valid OAuth2 credentials [Category B - skip]

        Would require the mock to implement an OAuth2 token endpoint at
        /fhir/auth/token. The mock's CapabilityStatement advertises this URL
        but it is not actually implemented.
        """
        pass

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

    def test_extract_response(self, cli_runner, target, port, mock_service):
        """Test response extraction [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--search-patients",
            "--extract-response",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        text = _combined_text(result, result.scan_log)
        assert any(term in text for term in ["patient", "extract", "response", "search"]), (
            f"Expected response extraction output: {text[:500]}"
        )

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
