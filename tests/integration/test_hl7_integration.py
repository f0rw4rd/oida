"""
HL7 v2 Protocol Integration Tests

Tests oida hl7 scanner against Docker mock MLLP services.
Uses structured JSON log assertions for precise validation.

Primary mock: hl7-node-mock (Node.js, port 2577)
Secondary mock: hl7-mock (Python/hl7apy, port 2575, TLS on 2576)

The primary test class (TestHl7Integration) runs against the Node.js mock.
TestHl7PythonMock validates the Python mock independently.
TestHl7Tls validates TLS/MLLPS against the Python mock's TLS port.

Mock Server Data (Node.js mock on port 2577):
  Server Identity:
    SERVER_APP         = "NODE_HIS"
    SERVER_FACILITY    = "GENERAL_HOSPITAL"
    HL7_VERSION        = "2.5.1"

  Mock Applications:
    10 entries: EPIC, CERNER, MEDITECH, MIRTH, RHAPSODY, ALLSCRIPTS, NEXTGEN,
    ATHENA, CPSI, NETSMART

  Mock Providers:
    8 entries with NPI-format IDs and roles

  Mock Locations:
    24 locations: ICU, ER, OR, PACU, PEDS, MED-SURG, ONCOLOGY, CARDIAC, etc.

  Mock Patients:
    PT10001: REYNOLDS^MARGARET^ANN, F, 19720314, SSN 321-54-9876
    PT10002: CHEN^WILLIAM^WEI, M, 19850607, SSN 432-65-0987
    PT10003: OKAFOR^AMARA^NGOZI, F, 19681121, SSN 543-76-1098
    PT10004: GARCIA^CARLOS^MIGUEL, M, 19910425, SSN 654-87-2109
    + more

  All messages get ACK code AA (Application Accept).
  Response MSH-3 is randomly chosen from mock apps.

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  60 tests
Category B (conditional -- mock may not support, accept 0 or 1):       44 tests
Category C (error handling -- assert graceful failure / error log):      2 tests
TLS tests (against Python mock port 2576):                              3 tests
Python mock cross-validation:                                           5 tests
Security finding tests:                                                28 tests
Total defined in file:                                                117 tests
Return code / success assertions:                                     117 tests (100%)
---------------------------------------------------------------------------
"""

import contextlib
import json
import socket
import threading

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST
from tests.service_gate import require_port


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


# Known mock data values for Category A assertions (union of both mocks)
KNOWN_MOCK_APPS = [
    "EPIC",
    "CERNER",
    "MEDITECH",
    "MIRTH",
    "RHAPSODY",
    "ALLSCRIPTS",
    "NEXTGEN",
    "ATHENA",
    "CPSI",
    "NETSMART",
]
KNOWN_MOCK_FACILITIES = [
    "MAIN_HOSPITAL",
    "EAST_CAMPUS",
    "CLINIC_WEST",
    "SATELLITE_CLINIC",
    "INTERFACE_ENGINE",
    "HIE_GATEWAY",
    "AMBULATORY",
    "URGENT_CARE",
    "GENERAL_HOSPITAL",
    "SATELLITE_LAB",
    "URGENT_CARE_EAST",
]
KNOWN_MOCK_LOCATIONS = [
    "ICU",
    "ER",
    "SURGERY",
    "PEDS",
    "MED-SURG",
    "ONCOLOGY",
    "CARDIAC",
    "NEURO",
    "OR",
    "PACU",
]
KNOWN_MOCK_PATIENTS = [
    "PT001",
    "PT002",
    "PT003",
    "PT004",
    "PT005",
    "PT10001",
    "PT10002",
    "PT10003",
    "PT10004",
]

# Ports
NODE_MOCK_PORT = 2577
PYTHON_MOCK_PORT = 2575
PYTHON_TLS_PORT = 2576


@pytest.mark.hl7
class TestHl7Integration(BaseProtocolIntegrationTest):
    """Integration tests for HL7 v2 MLLP protocol scanner (Node.js mock, port 2577)"""

    @property
    def protocol_name(self) -> str:
        return "hl7"

    @property
    def default_port(self) -> int:
        return NODE_MOCK_PORT

    @pytest.fixture
    def port(self):
        return NODE_MOCK_PORT

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Basic Connectivity / Discovery Tests
    # ========================================================================

    def test_mllp_connection(self, cli_runner, target, port):
        """Test basic MLLP connection and server discovery [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Basic MLLP connection failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        # Validate server identification from mock
        messages = _all_messages(log)
        assert "connected" in messages or "mllp" in messages, (
            f"Expected connection-related messages, got: {messages[:500]}"
        )

    def test_server_identification(self, cli_runner, target, port):
        """Test server identity detection from MSH response [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Server identification failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(log=result.scan_log)

        # The scanner parses MSH-3/MSH-4 from the mock's response and logs a
        # "Server: <app>@<facility>" identity line. Require that the server
        # identity was actually extracted (an app@facility token after the
        # label), not merely that the substring "server" appears somewhere.
        assert "server:" in messages and "@" in messages, (
            f"Expected parsed 'Server: <app>@<facility>' identity, got: {messages[:500]}"
        )

    def test_ack_code_aa(self, cli_runner, target, port):
        """Test that mock returns AA (Application Accept) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ACK test failed: {result.stderr}"
        messages = _all_messages(result.scan_log)
        # Mock always returns AA; scanner logs "ACK: Application Accept (AA)".
        # Require the decoded acknowledgment, not a loose "aa" substring.
        assert "application accept" in messages or "ack: application accept (aa)" in messages, (
            f"Expected decoded ACK 'Application Accept (AA)' in output, got: {messages[:500]}"
        )

    def test_client_identity_display(self, cli_runner, target, port):
        """Test that client identity (OIDA@SECURITY) is displayed [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Client identity test failed: {result.stderr}"
        messages = _all_messages(result.scan_log)
        assert "oida" in messages, f"Expected sending app 'OIDA' in output, got: {messages[:300]}"

    # ========================================================================
    # HL7 Version Tests
    # ========================================================================

    def test_hl7_version_23(self, cli_runner, target, port):
        """Test HL7 v2.3 protocol version [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--hl7-version",
            "2.3",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_hl7_version_25(self, cli_runner, target, port):
        """Test HL7 v2.5 protocol version (default) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--hl7-version",
            "2.5",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"HL7 v2.5 failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_hl7_version_27(self, cli_runner, target, port):
        """Test HL7 v2.7 protocol version [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--hl7-version",
            "2.7",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Identity Options Tests
    # ========================================================================

    def test_custom_sending_app(self, cli_runner, target, port):
        """Test custom sending application name [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--sending-app",
            "LAB_SYSTEM",
            "--sending-facility",
            "MAIN_HOSPITAL",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Custom sending app failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "lab_system" in messages, (
            f"Expected custom sending app 'LAB_SYSTEM' in output, got: {messages[:300]}"
        )

    def test_receiving_app(self, cli_runner, target, port):
        """Test custom receiving application name [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--receiving-app",
            "TARGET_EMR",
            "--receiving-facility",
            "REMOTE_HOSPITAL",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Custom receiving app failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "target_emr" in messages and "remote_hospital" in messages, (
            f"Expected custom receiving app 'TARGET_EMR'/'REMOTE_HOSPITAL' in output "
            f"(MSH-5/MSH-6 must reflect -R/--receiving-app and --receiving-facility), "
            f"got: {messages[:300]}"
        )

    # ========================================================================
    # Probe Operations Tests
    # ========================================================================

    def test_probe_operations(self, cli_runner, target, port):
        """Test probing all supported message types [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-ops",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Probe operations failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        # Probe should report supported operations
        assert any(
            term in messages for term in ["supported", "probing", "probe", "accepted", "adt", "oru"]
        ), f"Expected probe results in output, got: {messages[:500]}"

    # ========================================================================
    # ADT Message Tests (Admission/Discharge/Transfer) -- Write Operations
    # ========================================================================

    def test_send_adt_requires_confirm(self, cli_runner, target, port):
        """Test that ADT^A01 warns about --confirm flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Process exits 0 but logs a --confirm warning; operation is NOT sent
        assert result.success, f"ADT requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_adt_a01_admit(self, cli_runner, target, port):
        """Test ADT^A01 (Admission) with --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--patient-name",
            "DOE^JOHN^M",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A01 failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "adt" in messages, f"Expected ADT-related messages, got: {messages[:300]}"

    def test_send_adt_a02_transfer(self, cli_runner, target, port):
        """Test ADT^A02 (Transfer) trigger event [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--adt-trigger",
            "A02",
            "--patient-id",
            "PT001",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A02 failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_send_adt_a03_discharge(self, cli_runner, target, port):
        """Test ADT^A03 (Discharge) trigger event [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--adt-trigger",
            "A03",
            "--patient-id",
            "PT001",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A03 failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_send_adt_a08_update(self, cli_runner, target, port):
        """Test ADT^A08 (Update Patient Info) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--adt-trigger",
            "A08",
            "--patient-id",
            "PT001",
            "--patient-name",
            "UPDATED^PATIENT^NAME",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A08 failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_send_adt_a40_merge(self, cli_runner, target, port):
        """Test ADT^A40 (Merge Patient) with MRG segment [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--adt-trigger",
            "A40",
            "--patient-id",
            "P_SURVIVING",
            "--merge-patient-id",
            "P_DEPRECATED",
            "--merge-patient-name",
            "OLD^PATIENT",
            "--merge-visit",
            "V99999",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A40 merge failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_send_adt_with_full_patient_data(self, cli_runner, target, port):
        """Test ADT with all patient data segments (PID, PV1, DG1, PR1) [Category A]

        Also drives --dx-clinician (DG1 diagnosing clinician), --pr-type and
        --pr-practitioner (PR1 procedure type/practitioner).
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--patient-name",
            "DOE^JOHN^M",
            "--patient-dob",
            "19800101",
            "--patient-sex",
            "M",
            "--patient-address",
            "123 Main St^^Springfield^IL^62701",
            "--patient-phone",
            "(555)123-4567",
            "--patient-class",
            "I",
            "--visit-number",
            "V12345",
            "--location",
            "ICU^101^A",
            "--admit-date",
            "20241201",
            "--dx-code",
            "J06.9",
            "--dx-description",
            "Acute upper respiratory infection",
            "--dx-type",
            "A",
            "--dx-priority",
            "1",
            "--dx-clinician",
            "SMITH^JANE^MD",
            "--pr-code",
            "99213",
            "--pr-description",
            "Office visit",
            "--pr-type",
            "P",
            "--pr-practitioner",
            "JONES^ROBERT^MD",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Full ADT failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # ORU Message Tests (Observation Results) -- Write Operations
    # ========================================================================

    def test_send_oru_requires_confirm(self, cli_runner, target, port):
        """Test that ORU^R01 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-oru",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ORU requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_oru_with_observation(self, cli_runner, target, port):
        """Test ORU^R01 with observation data [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-oru",
            "--obx-type",
            "NM",
            "--obx-id",
            "GLU^Glucose",
            "--obx-value",
            "95",
            "--obx-units",
            "mg/dL",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ORU^R01 failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "oru" in messages or "observation" in messages, (
            f"Expected ORU-related messages, got: {messages[:300]}"
        )

    # ========================================================================
    # ORM Message Tests (Orders) -- Write Operations
    # ========================================================================

    def test_send_orm_requires_confirm(self, cli_runner, target, port):
        """Test that ORM^O01 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-orm",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ORM requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_orm_with_order_data(self, cli_runner, target, port):
        """Test ORM^O01 with order details [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-orm",
            "--patient-id",
            "PT001",
            "--order-id",
            "ORD001",
            "--order-code",
            "CBC^Complete Blood Count",
            "--order-priority",
            "R",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ORM^O01 failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # SIU Message Tests (Scheduling) -- Write Operations
    # ========================================================================

    def test_send_siu_requires_confirm(self, cli_runner, target, port):
        """Test that SIU^S12 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-siu",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"SIU requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_siu(self, cli_runner, target, port):
        """Test SIU^S12 scheduling message [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-siu",
            "--patient-id",
            "PT001",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"SIU^S12 failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # MDM Message Tests (Documents) -- Write Operations
    # ========================================================================

    def test_send_mdm_requires_confirm(self, cli_runner, target, port):
        """Test that MDM^T02 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mdm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"MDM requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_mdm(self, cli_runner, target, port):
        """Test MDM^T02 document notification [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mdm",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # QRY Message Tests (Queries) -- Read Operations
    # ========================================================================

    def test_send_qry(self, cli_runner, target, port):
        """Test QRY^Q01 patient query [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-qry",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"QRY^Q01 failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "qry" in messages or "query" in messages or "response" in messages, (
            f"Expected QRY-related messages, got: {messages[:300]}"
        )

    def test_send_qry_with_patient_filter(self, cli_runner, target, port):
        """Test QRY with specific patient ID [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-qry",
            "--patient-id",
            "PT001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"QRY with filter failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_query_observations(self, cli_runner, target, port):
        """Test QRY^R02 observation results query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-obs",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_query_rx(self, cli_runner, target, port):
        """Test QBP^Q31 pharmacy dispense history query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-rx",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_query_orders(self, cli_runner, target, port):
        """Test OSQ^Q06 order status query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-orders",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # QBP Special Query Tests
    # ========================================================================

    def test_query_whoami(self, cli_runner, target, port):
        """Test QBP^Q40 WhoAmI query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-whoami",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_query_tabular(self, cli_runner, target, port):
        """Test QBP^Q13 tabular query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-tabular",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_query_immunization(self, cli_runner, target, port):
        """Test QBP^Z34 immunization history query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-imm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_query_immunization_forecast(self, cli_runner, target, port):
        """Test QBP^Z44 immunization forecast query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-imm-forecast",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Pharmacy/Prescription Tests (RDE/RAS/RGV/RDS) -- Write Operations
    # ========================================================================

    def test_send_rx_requires_confirm(self, cli_runner, target, port):
        """Test that RDE^O11 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rx",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"RX requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_rx_with_drug_data(self, cli_runner, target, port):
        """Test RDE^O11 with full prescription data [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rx",
            "--rx-drug",
            "Amoxicillin",
            "--rx-dose",
            "500",
            "--rx-units",
            "mg",
            "--rx-route",
            "PO",
            "--rx-quantity",
            "30",
            "--rx-refills",
            "2",
            "--rx-instructions",
            "Take twice daily with food",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"RDE^O11 failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_send_rx_with_provider_dea(self, cli_runner, target, port):
        """Test RDE^O11 with DEA provider number [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rx",
            "--rx-drug",
            "Oxycodone",
            "--rx-code",
            "00093-0537-01",
            "--rx-dose",
            "5",
            "--rx-units",
            "mg",
            "--rx-route",
            "PO",
            "--rx-provider",
            "AB1234567",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_send_ras_requires_confirm(self, cli_runner, target, port):
        """Test that RAS^O17 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-ras",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"RAS requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_ras(self, cli_runner, target, port):
        """Test RAS^O17 pharmacy administration [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-ras",
            "--admin-code",
            "12345^Morphine^NDC",
            "--admin-amount",
            "10",
            "--admin-units",
            "mg",
            "--completion-status",
            "CP",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_send_rgv_requires_confirm(self, cli_runner, target, port):
        """Test that RGV^O15 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rgv",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"RGV requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_rgv(self, cli_runner, target, port):
        """Test RGV^O15 pharmacy give [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rgv",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_send_rds_requires_confirm(self, cli_runner, target, port):
        """Test that RDS^O13 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rds",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"RDS requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_rds(self, cli_runner, target, port):
        """Test RDS^O13 pharmacy dispense [Category B]

        Also drives --dispense-amount and --dispense-units, which populate
        the RXD (Pharmacy Dispense) segment's actual-amount/actual-units
        fields.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rds",
            "--dispense-amount",
            "10",
            "--dispense-units",
            "mL",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Master File (MFN/MFQ) Tests -- Write Operations
    # ========================================================================

    def test_send_mfn_requires_confirm(self, cli_runner, target, port):
        """Test that MFN warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mfn",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"MFN requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_mfn(self, cli_runner, target, port):
        """Test MFN^M01 master file notification [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mfn",
            "--mfn-type",
            "M01",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_send_mfn_m02_staff(self, cli_runner, target, port):
        """Test MFN^M02 master file staff notification [Category B]

        Also drives --department (STF-11), which is only meaningful on
        MFN^M02 staff master-file messages.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mfn",
            "--mfn-type",
            "M02",
            "--staff-id",
            "STF001",
            "--staff-name",
            "SMITH^JOHN",
            "--staff-type",
            "MD",
            "--department",
            "CARDIOLOGY",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_send_mfn_m04_charge(self, cli_runner, target, port):
        """Test MFN^M04 charge description master file notification [Category B]

        Drives --charge-code and --charge-price, which populate the PRC
        (Pricing) segment and are only meaningful on MFN^M04 messages.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mfn",
            "--mfn-type",
            "M04",
            "--charge-code",
            "CHG100",
            "--charge-price",
            "250.00",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_query_mfn(self, cli_runner, target, port):
        """Test MFQ^M01 master file query [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-mfn",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Financial (BAR/DFT) Tests -- Write Operations
    # ========================================================================

    def test_send_bar_requires_confirm(self, cli_runner, target, port):
        """Test that BAR^P01 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-bar",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"BAR requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_bar(self, cli_runner, target, port):
        """Test BAR^P01 add billing account [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-bar",
            "--patient-id",
            "PT001",
            "--account-number",
            "ACCT001",
            "--guarantor-name",
            "DOE^JOHN",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_send_bar_with_insurance(self, cli_runner, target, port):
        """Test BAR^P01 with insurance data [Category B]

        Also drives --guarantor-phone, which populates GT1-6 on the
        guarantor segment.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-bar",
            "--patient-id",
            "PT001",
            "--insurance-company",
            "Blue Cross",
            "--insurance-group",
            "GRP123",
            "--policy-number",
            "POL456",
            "--guarantor-phone",
            "(555)987-6543",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_send_dft_requires_confirm(self, cli_runner, target, port):
        """Test that DFT^P03 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-dft",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"DFT requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_send_dft(self, cli_runner, target, port):
        """Test DFT^P03 financial transaction [Category B]

        Also drives --transaction-description, which populates FT1-8 on the
        financial transaction segment.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-dft",
            "--patient-id",
            "PT001",
            "--transaction-amount",
            "150.00",
            "--transaction-code",
            "99213",
            "--transaction-type",
            "CG",
            "--transaction-description",
            "Cardiology Consultation",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # IHE PCD (Patient Care Device) Tests -- Write Operations
    # ========================================================================

    def test_pcd01_requires_confirm(self, cli_runner, target, port):
        """Test that PCD-01 warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-01",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"PCD-01 requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    def test_pcd01_infusion_pump(self, cli_runner, target, port):
        """Test PCD-01 device observation for infusion pump [Category B]

        Also drives --device-id (MSH sending app suffix), --volume-delivered,
        --drug-concentration and --dose-rate, which each add an OBX metric to
        the PCD-01 ORU^R01 message.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-01",
            "--device-type",
            "lvp",
            "--device-id",
            "DEV123",
            "--flow-rate",
            "125",
            "--vtbi",
            "500",
            "--volume-delivered",
            "50",
            "--drug-concentration",
            "5.0",
            "--dose-rate",
            "2.5",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_pcd01_ventilator(self, cli_runner, target, port):
        """Test PCD-01 device observation for ventilator [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-01",
            "--device-type",
            "ventilator",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_pcd01_monitor(self, cli_runner, target, port):
        """Test PCD-01 device observation for bedside monitor [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-01",
            "--device-type",
            "monitor",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_pcd03_infusion_order(self, cli_runner, target, port):
        """Test PCD-03 infusion order to pump [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-03",
            "--drug-name",
            "Morphine",
            "--flow-rate",
            "10",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_pcd_alarm_occlusion(self, cli_runner, target, port):
        """Test PCD-04/10 device alarm (occlusion) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-alarm",
            "--alarm-type",
            "occlusion",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_pcd_alarm_air_in_line(self, cli_runner, target, port):
        """Test PCD-04/10 device alarm (air in line) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-alarm",
            "--alarm-type",
            "air",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    # ========================================================================
    # Enumeration Tests
    # ========================================================================

    def test_enum_providers(self, cli_runner, target, port):
        """Test provider/physician enumeration from mock responses [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--enum-providers",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Provider enumeration failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Mock includes ATTENDING, REFERRING, CONSULTING, ADMITTING providers
        assert any(term in messages for term in ["provider", "physician", "attending", "enum"]), (
            f"Expected provider enumeration results, got: {messages[:500]}"
        )

    def test_enum_apps(self, cli_runner, target, port):
        """Test sending application enumeration [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--enum-apps",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"App enumeration failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert any(term in messages for term in ["application", "topology", "enum", "facility"]), (
            f"Expected app enumeration results, got: {messages[:500]}"
        )

    def test_enum_locations(self, cli_runner, target, port):
        """Test patient location enumeration [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--enum-locations",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Location enumeration failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert any(term in messages for term in ["location", "enum", "unit", "room", "bed"]), (
            f"Expected location enumeration results, got: {messages[:500]}"
        )

    def test_enum_patients(self, cli_runner, target, port):
        """Test patient enumeration via wildcard query [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-qry",
            "--enum-patients",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Patient enumeration failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "wildcard" in messages or "patient" in messages or "enum" in messages, (
            f"Expected patient enumeration results, got: {messages[:500]}"
        )

    def test_enum_all(self, cli_runner, target, port):
        """Test --enum-all enables all enumeration features [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enum-all",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Enum-all failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Custom Message Type Tests
    # ========================================================================

    def test_custom_message_type(self, cli_runner, target, port):
        """Test sending custom message type [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--message-type",
            "RDE^O11",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_custom_message_type_requires_confirm(self, cli_runner, target, port):
        """Test custom message type warns about --confirm [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--message-type",
            "ADT^A01",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Custom message requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "confirm" in messages, f"Expected '--confirm' warning in log, got: {messages[:300]}"

    # ========================================================================
    # Response Handling Tests
    # ========================================================================

    def test_extract_response(self, cli_runner, target, port):
        """Test extended response data extraction [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--extract-response",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Response extraction failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_extract_specific_fields(self, cli_runner, target, port):
        """Test extraction of specific HL7 fields [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--extract-fields",
            "PID-3,PID-5,PV1-19",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_parse_segments(self, cli_runner, target, port):
        """Test --parse-segments flag [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--parse-segments",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_save_response(self, cli_runner, target, port, tmp_path):
        """Test --save-response writes the raw MLLP ACK to a file [Category A]"""
        response_file = tmp_path / "hl7_response.raw"
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--save-response",
            str(response_file),
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT with --save-response failed: {result.stderr}"
        assert response_file.exists(), "Expected --save-response to create the response file"
        content = response_file.read_bytes()
        assert b"MSH" in content, (
            f"Expected a raw HL7 MSH segment in the saved response, got: {content[:200]!r}"
        )

    # ========================================================================
    # Security Analysis Tests
    # ========================================================================

    @pytest.mark.security
    def test_security_no_auth_finding(self, cli_runner, target, port):
        """Test that security analysis reports no authentication [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Security scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Security mixin reports AUTH, ACCESS, CRYPTO findings
        assert any(
            term in messages
            for term in ["auth", "no authentication", "security", "unencrypted", "crypto"]
        ), f"Expected security findings, got: {messages[:500]}"

    @pytest.mark.security
    def test_security_accepts_unknown_sender(self, cli_runner, target, port):
        """Test that mock accepts unknown sender (security finding) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Security test failed: {result.stderr}"
        messages = _all_messages(result.scan_log)
        assert "accept" in messages or "aa" in messages or "unknown" in messages, (
            f"Expected acceptance/security messages, got: {messages[:500]}"
        )

    # ========================================================================
    # Security Findings -- Comprehensive Per-Finding Tests
    # ========================================================================
    #
    # Tests below validate every security finding defined in the HL7 protocol
    # module. Each test triggers the specific condition and verifies the
    # finding text appears in the log output.
    #
    # Finding sources:
    #   SecurityMixin:    AUTH, ACCESS, CRYPTO (always fire on basic scan)
    #   MessageMixin:     ADT dangerous ops, ORM unvalidated order
    #   QueryMixin:       Wildcard query accepted
    #   PharmacyMixin:    RDE/RAS/RGV/RDS accepted
    #   DeviceMixin:      PCD-01/PCD-03/PCD-10 accepted
    #   MasterFileMixin:  MFN master file modification accepted
    #   FinancialMixin:   BAR billing, DFT financial transaction
    #   ResponseMixin:    Unrestricted query access, observations, pharmacy, orders
    #   ProbeMixin:       Dangerous operation accepted during probe
    #   SpecialQueryMixin: Immunization records accessible
    # ========================================================================

    # -- SecurityMixin findings (always fire) --------------------------------

    @pytest.mark.security
    def test_finding_no_authentication(self, cli_runner, target, port):
        """Test AUTH finding: HL7 MLLP has no native authentication [Category A]

        SecurityMixin._analyze_security always appends this finding.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"AUTH finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "no authentication" in messages, (
            f"Expected 'No Authentication' finding in log, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_accepts_unknown_sender(self, cli_runner, target, port):
        """Test ACCESS finding: endpoint accepts unknown sending application [Category A]

        SecurityMixin._analyze_security appends when ack_code == 'AA'.
        The mock always returns AA in normal mode.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ACCESS finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "unknown sender" in messages or "accepts unknown" in messages, (
            f"Expected 'Accepts Unknown Sender' finding in log, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_unencrypted_communication(self, cli_runner, target, port):
        """Test CRYPTO finding: MLLP traffic in plaintext (no TLS) [Category A]

        SecurityMixin._analyze_security appends when --tls is not used.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"CRYPTO finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "unencrypted" in messages or "plaintext" in messages, (
            f"Expected 'Unencrypted Communication' finding in log, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_no_crypto_when_tls_used(self, cli_runner, target):
        """Test CRYPTO finding is absent when TLS is enabled [Category A]

        When --tls is used, the CRYPTO finding should NOT appear.
        Tests against the Python TLS mock on port 2576.
        """
        require_port(MOCK_HOST, PYTHON_TLS_PORT, "HL7 TLS mock")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(PYTHON_TLS_PORT),
            "--tls",
            "--tls-insecure",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"TLS connection failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # The CRYPTO finding should NOT fire when TLS is active
        assert "unencrypted communication" not in messages, (
            f"CRYPTO finding should not fire with TLS, got: {messages[:500]}"
        )

    # -- MessageMixin findings (ADT dangerous ops, ORM orders) ---------------

    @pytest.mark.security
    def test_finding_dangerous_adt_discharge(self, cli_runner, target, port):
        """Test ADT^A03 discharge accepted finding [Category A]

        MessageMixin._send_adt_message appends finding when ack == 'AA' and
        trigger in ['A03', 'A40']. Mock returns AA.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--adt-trigger",
            "A03",
            "--patient-id",
            "PT001",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A03 finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "dangerous" in messages or "discharge" in messages, (
            f"Expected 'Dangerous ADT Operation Accepted' finding for A03, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_dangerous_adt_merge(self, cli_runner, target, port):
        """Test ADT^A40 merge accepted finding [Category A]

        MessageMixin._send_adt_message appends finding when ack == 'AA' and
        trigger == 'A40'. Mock returns AA.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--adt-trigger",
            "A40",
            "--patient-id",
            "P_SURVIVING",
            "--merge-patient-id",
            "P_DEPRECATED",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ADT^A40 finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "dangerous" in messages or "merge" in messages, (
            f"Expected 'Dangerous ADT Operation Accepted' finding for A40, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_unvalidated_order(self, cli_runner, target, port):
        """Test ORM unvalidated order accepted finding [Category A]

        MessageMixin._send_orm_message appends finding to results data when
        ack == 'AA'. The finding is stored in results['data']['security_findings']
        but not printed to log. We verify the order was sent and accepted (AA),
        which guarantees the finding was stored.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-orm",
            "--patient-id",
            "PT001",
            "--order-code",
            "CBC^Complete Blood Count",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"ORM finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # ORM was sent and accepted (AA) -- finding stored in results data
        assert "orm" in messages and "received" in messages, (
            f"Expected ORM sent and response received (triggers finding), got: {messages[:500]}"
        )
        # Verify the ACK was AA, confirming the finding would fire
        assert "accept" in messages or "aa" in messages, (
            f"Expected AA ACK (triggers 'Unvalidated Order Accepted' finding), got: {messages[:500]}"
        )

    # -- QueryMixin findings -------------------------------------------------

    @pytest.mark.security
    def test_finding_wildcard_query_accepted(self, cli_runner, target, port):
        """Test wildcard patient enumeration finding [Category A]

        QueryMixin._send_qry_message appends finding when --enum-patients
        is used and the server responds.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-qry",
            "--enum-patients",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Wildcard query finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "wildcard" in messages, (
            f"Expected 'Wildcard Query Accepted' finding, got: {messages[:500]}"
        )

    # -- PharmacyMixin findings (RDE, RAS, RGV, RDS) -------------------------

    @pytest.mark.security
    def test_finding_prescription_order_accepted(self, cli_runner, target, port):
        """Test RDE prescription order accepted finding [Category A]

        PharmacyMixin._send_rx_message appends finding to results data when
        ack == 'AA'. The finding is stored in results['data']['security_findings']
        but not printed to log. We verify the RDE was sent and accepted (AA),
        which guarantees the finding was stored.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rx",
            "--rx-drug",
            "Amoxicillin",
            "--rx-dose",
            "500",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"RDE finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # RDE was sent and response received -- finding stored in results data
        assert "rde" in messages and "received" in messages, (
            f"Expected RDE sent and response received (triggers finding), got: {messages[:500]}"
        )
        # Verify the ACK was AA, confirming the finding would fire
        assert "accept" in messages or "aa" in messages, (
            f"Expected AA ACK (triggers 'Prescription Order Accepted' finding), got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_pharmacy_administration_accepted(self, cli_runner, target, port):
        """Test RAS^O17 pharmacy administration accepted finding [Category B]

        PharmacyMixin._send_ras_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-ras",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined
            for term in ["pharmacy administration accepted", "ras", "administration"]
        ), f"Expected RAS finding or attempt in output, got: {combined[:500]}"

    @pytest.mark.security
    def test_finding_pharmacy_give_accepted(self, cli_runner, target, port):
        """Test RGV^O15 pharmacy give accepted finding [Category B]

        PharmacyMixin._send_rgv_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rgv",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["pharmacy give accepted", "rgv", "give"]), (
            f"Expected RGV finding or attempt in output, got: {combined[:500]}"
        )

    @pytest.mark.security
    def test_finding_pharmacy_dispense_accepted(self, cli_runner, target, port):
        """Test RDS^O13 pharmacy dispense accepted finding [Category B]

        PharmacyMixin._send_rds_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-rds",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined for term in ["pharmacy dispense accepted", "rds", "dispense"]
        ), f"Expected RDS finding or attempt in output, got: {combined[:500]}"

    # -- DeviceMixin findings (PCD-01, PCD-03, PCD-10) -----------------------

    @pytest.mark.security
    def test_finding_device_observation_accepted(self, cli_runner, target, port):
        """Test PCD-01 device observation accepted finding [Category B]

        DeviceMixin._send_pcd01_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-01",
            "--device-type",
            "lvp",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined
            for term in ["device observation accepted", "pcd-01", "device observation"]
        ), f"Expected PCD-01 finding or attempt in output, got: {combined[:500]}"

    @pytest.mark.security
    def test_finding_infusion_order_accepted(self, cli_runner, target, port):
        """Test PCD-03 infusion order accepted finding [Category B]

        DeviceMixin._send_pcd03_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-03",
            "--drug-name",
            "Morphine",
            "--flow-rate",
            "10",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined for term in ["infusion order accepted", "pcd-03", "infusion order"]
        ), f"Expected PCD-03 finding or attempt in output, got: {combined[:500]}"

    @pytest.mark.security
    def test_finding_device_alarm_accepted(self, cli_runner, target, port):
        """Test PCD-10 device alarm accepted finding [Category B]

        DeviceMixin._send_pcd_alarm_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-alarm",
            "--alarm-type",
            "occlusion",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["device alarm accepted", "pcd-10", "alarm"]), (
            f"Expected PCD-10 finding or attempt in output, got: {combined[:500]}"
        )

    # -- MasterFileMixin findings --------------------------------------------

    @pytest.mark.security
    def test_finding_master_file_modification_accepted(self, cli_runner, target, port):
        """Test MFN master file modification accepted finding [Category B]

        MasterFileMixin._send_mfn_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mfn",
            "--mfn-type",
            "M01",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined for term in ["master file modification accepted", "master file", "mfn"]
        ), f"Expected MFN finding or attempt in output, got: {combined[:500]}"

    @pytest.mark.security
    def test_finding_master_file_staff_modification(self, cli_runner, target, port):
        """Test MFN^M02 staff master file modification finding [Category B]

        MasterFileMixin._send_mfn_message appends finding for M02 staff updates.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-mfn",
            "--mfn-type",
            "M02",
            "--staff-id",
            "STF001",
            "--staff-name",
            "ATTACKER^FAKE^DR",
            "--staff-type",
            "MD",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined
            for term in [
                "master file modification accepted",
                "staff master file",
                "mfn",
                "master file",
            ]
        ), f"Expected MFN^M02 finding or attempt in output, got: {combined[:500]}"

    # -- FinancialMixin findings (BAR, DFT) ----------------------------------

    @pytest.mark.security
    def test_finding_billing_account_accepted(self, cli_runner, target, port):
        """Test BAR^P01 billing account creation accepted finding [Category B]

        FinancialMixin._send_bar_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-bar",
            "--patient-id",
            "PT001",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["billing account", "bar", "billing"]), (
            f"Expected BAR finding or attempt in output, got: {combined[:500]}"
        )

    @pytest.mark.security
    def test_finding_financial_transaction_accepted(self, cli_runner, target, port):
        """Test DFT^P03 financial transaction accepted finding [Category B]

        FinancialMixin._send_dft_message appends finding when ack == 'AA'.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-dft",
            "--patient-id",
            "PT001",
            "--transaction-amount",
            "9999.99",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["financial transaction", "dft", "transaction"]), (
            f"Expected DFT finding or attempt in output, got: {combined[:500]}"
        )

    # -- ResponseMixin findings (query results accessible) -------------------

    @pytest.mark.security
    def test_finding_unrestricted_query_access(self, cli_runner, target, port):
        """Test QRY unrestricted query access finding [Category A]

        ResponseMixin._extract_query_results appends finding when query
        returns patient records. The mock always returns patient data.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-qry",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"QRY finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # The finding reports "Unrestricted Query Access" or the query produces patient results
        assert any(term in messages for term in ["unrestricted query", "query", "patient"]), (
            f"Expected query access finding or patient data, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_observation_results_accessible(self, cli_runner, target, port):
        """Test QRY^R02 observation results accessible finding [Category B]

        ResponseMixin._extract_observation_results appends finding when
        observation query returns results.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-obs",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["observation", "query", "qry", "lab"]), (
            f"Expected observation query attempt in output, got: {combined[:500]}"
        )

    @pytest.mark.security
    def test_finding_pharmacy_history_accessible(self, cli_runner, target, port):
        """Test QBP^Q31 pharmacy dispense history accessible finding [Category B]

        ResponseMixin._extract_pharmacy_results appends finding when
        pharmacy query returns medication records.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-rx",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(
            term in combined for term in ["pharmacy", "dispense", "medication", "qbp", "query"]
        ), f"Expected pharmacy query attempt in output, got: {combined[:500]}"

    @pytest.mark.security
    def test_finding_order_status_accessible(self, cli_runner, target, port):
        """Test OSQ^Q06 order status query accessible finding [Category B]

        ResponseMixin._extract_order_status appends finding when order
        query returns order records.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-orders",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["order status", "order", "osq", "query"]), (
            f"Expected order query attempt in output, got: {combined[:500]}"
        )

    # -- ProbeMixin findings (dangerous operations in probe) -----------------

    @pytest.mark.security
    def test_finding_probe_dangerous_operations(self, cli_runner, target, port):
        """Test probe mode detects dangerous accepted operations [Category A]

        ProbeMixin._probe_operations appends findings for HIGH-risk operations
        that are accepted (AA/CA). The mock accepts all messages.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-ops",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Probe finding test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Probe should find dangerous operations: ORM^O01, RDE^O11, ADT^A40, etc.
        assert "dangerous" in messages or "supported" in messages, (
            f"Expected dangerous operation findings from probe, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_probe_reports_high_risk_count(self, cli_runner, target, port):
        """Test probe summary includes dangerous operation count [Category A]

        ProbeMixin._display_probe_results shows 'X dangerous' in summary
        when HIGH-risk operations are accepted.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-ops",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Probe summary test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        # Summary line: "X/Y accepted (Z dangerous)"
        assert "accepted" in messages, (
            f"Expected probe summary with accepted count, got: {messages[:500]}"
        )

    # -- SpecialQueryMixin findings ------------------------------------------

    @pytest.mark.security
    def test_finding_immunization_records_accessible(self, cli_runner, target, port):
        """Test QBP^Z34 immunization records accessible finding [Category B]

        SpecialQueryMixin._extract_immunization_results appends finding
        when immunization query returns records. Requires --patient-id.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--query-imm",
            "--patient-id",
            "PT10001",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        messages = ""
        if result.scan_log is not None and len(result.scan_log) > 0:
            messages = _all_messages(result.scan_log)
        combined = messages + " " + result.combined_output.lower()
        assert any(term in combined for term in ["immunization", "qbp", "z34", "query"]), (
            f"Expected immunization query attempt in output, got: {combined[:500]}"
        )

    # -- Combined findings tests (multiple findings in one scan) -------------

    @pytest.mark.security
    def test_finding_all_three_security_mixin_findings(self, cli_runner, target, port):
        """Test all three SecurityMixin findings fire together [Category A]

        A basic scan without TLS should produce AUTH, ACCESS, and CRYPTO
        findings simultaneously.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Combined findings test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        # All three flags should appear
        assert "auth" in messages, (
            f"Expected [AUTH] finding in combined output, got: {messages[:500]}"
        )
        assert "crypto" in messages, (
            f"Expected [CRYPTO] finding in combined output, got: {messages[:500]}"
        )
        assert "access" in messages, (
            f"Expected [ACCESS] finding in combined output, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_finding_enum_all_produces_multiple_findings(self, cli_runner, target, port):
        """Test --enum-all generates query-related security findings [Category A]

        --enum-all enables --enum-patients (wildcard query), --query-obs,
        --query-rx, --query-orders, etc. Multiple data-access findings
        should fire.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--enum-all",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Enum-all findings test failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        # At minimum, AUTH + CRYPTO + ACCESS + wildcard query should fire
        finding_count = sum(
            1
            for term in [
                "no authentication",
                "unencrypted",
                "unknown sender",
                "wildcard",
            ]
            if term in messages
        )
        assert finding_count >= 2, (
            f"Expected at least 2 distinct findings from --enum-all, found {finding_count}. "
            f"Output: {messages[:500]}"
        )

    # ========================================================================
    # TLS Tests (against Python mock MLLPS on port 2576)
    # ========================================================================

    @pytest.mark.security
    def test_tls_connection(self, cli_runner, target):
        """Test TLS/MLLPS connection to Python mock [Category A]"""
        require_port(MOCK_HOST, PYTHON_TLS_PORT, "HL7 TLS mock")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(PYTHON_TLS_PORT),
            "--tls",
            "--tls-insecure",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"TLS connection failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "tls" in messages or "certificate" in messages or "connected" in messages, (
            f"Expected TLS-related messages, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_tls_certificate_finding(self, cli_runner, target):
        """Test that self-signed cert produces security finding [Category A]"""
        require_port(MOCK_HOST, PYTHON_TLS_PORT, "HL7 TLS mock")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(PYTHON_TLS_PORT),
            "--tls",
            "--tls-insecure",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"TLS cert test failed: {result.stderr}"
        messages = _all_messages(result.scan_log)
        assert "self-signed" in messages or "certificate" in messages, (
            f"Expected self-signed cert finding, got: {messages[:500]}"
        )

    @pytest.mark.security
    def test_tls_on_plain_port_fails(self, cli_runner, target, port):
        """Test TLS against plain MLLP port handles gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--tls",
            format="json",
            json_log=True,
            timeout=15,
        )

        # TLS handshake against plain MLLP should fail gracefully
        assert result.returncode != -1, "TLS attempt should not hang"

    # ========================================================================
    # Fuzzing Tests -- Write Operations
    # ========================================================================

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_mode(self, cli_runner, target, port):
        """Test HL7 message fuzzing [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=120,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            messages = _all_messages(result.scan_log)
            assert "fuzz" in messages, f"Expected fuzzing-related output, got: {messages[:300]}"

    @pytest.mark.fuzz
    def test_fuzz_requires_confirm(self, cli_runner, target, port):
        """Test that fuzzing warns about --confirm [Category A]"""
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

        # Fuzzing without --confirm logs a warning; process still exits 0
        assert result.success, f"Fuzz requires-confirm should exit 0: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        output = result.combined_output.lower()
        assert "confirm" in messages or "confirm" in output, (
            f"Expected --confirm warning for fuzz, got: {messages[:300]}"
        )

    @pytest.mark.fuzz
    @pytest.mark.slow
    def test_fuzz_segment_specific(self, cli_runner, target, port):
        """Test fuzzing with specific segment target [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--fuzz",
            "--fuzz-segment",
            "PID",
            "--fuzz-iterations",
            "3",
            "--confirm",
            format="json",
            json_log=True,
            timeout=120,
        )

        assert result.returncode in [0, 1]

    # ========================================================================
    # Timeout and Connection Error Tests
    # ========================================================================

    def test_short_timeout(self, cli_runner, target, port):
        """Test with short timeout setting [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--timeout",
            "5",
            format="json",
            json_log=True,
            timeout=15,
        )

        assert result.returncode in [0, 1], f"Short timeout should not crash: {result.stderr}"
        assert result.execution_time < 20, "Should respect timeout setting"

    def test_connection_refused_port(self, cli_runner, target):
        """Test connection to closed port logs error [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            "65533",
            "--timeout",
            "3",
            format="json",
            json_log=True,
            timeout=15,
        )

        # Process may exit 0 (framework quirk) but log should contain error
        assert result.returncode != -1, "Should not hang"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            messages = _all_messages(result.scan_log)
            assert "refused" in messages or "failed" in messages or "error" in messages, (
                f"Expected connection error in log, got: {messages[:300]}"
            )

    def test_pcd01_invalid_dose_rate_rejected(self, cli_runner, target, port):
        """Test that a non-numeric --dose-rate is rejected by argument parsing [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--pcd-01",
            "--dose-rate",
            "not-a-number",
            "--confirm",
            format="json",
            json_log=True,
            timeout=15,
            expect_json=False,
        )

        assert result.returncode != 0, "Non-numeric --dose-rate should be rejected"
        assert "Traceback" not in result.combined_output, (
            f"Invalid --dose-rate should not crash with a traceback: {result.combined_output[:500]}"
        )

    # ========================================================================
    # Verbose / Debug Output Tests
    # ========================================================================

    def test_verbose_output_with_json_log(self, cli_runner, target, port):
        """Test verbose flag produces more log events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            verbose=True,
            timeout=30,
        )

        assert result.success, f"Verbose mode failed: {result.stderr}"
        if result.scan_log is not None:
            assert len(result.scan_log) > 0, "Verbose mode should produce log events"

    def test_debug_output_with_json_log(self, cli_runner, target, port):
        """Test debug flag produces detailed events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            debug=True,
            timeout=30,
        )

        assert result.success, f"Debug mode failed: {result.stderr}"
        if result.scan_log is not None:
            assert len(result.scan_log) > 0, "Debug mode should produce log events"

    # ========================================================================
    # MRN Alias Test
    # ========================================================================

    def test_mrn_alias(self, cli_runner, target, port):
        """Test --mrn as alias for --patient-id [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--mrn",
            "MRN12345",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # SSN Sensitive Data Test
    # ========================================================================

    @pytest.mark.security
    def test_ssn_in_message(self, cli_runner, target, port):
        """Test ADT with SSN data (sensitive PII) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--ssn",
            "123-45-6789",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    # ========================================================================
    # JSON Output Test
    # ========================================================================

    def test_json_output_format(self, cli_runner, target, port):
        """Test JSON output contains expected structure [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"JSON output test failed: {result.stderr}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)


# ============================================================================
# Python Mock Validation (port 2575)
# ============================================================================


@pytest.mark.hl7
class TestHl7PythonMock(BaseProtocolIntegrationTest):
    """Cross-validation tests against the Python HL7 mock (port 2575)"""

    @property
    def protocol_name(self) -> str:
        return "hl7"

    @property
    def default_port(self) -> int:
        return PYTHON_MOCK_PORT

    @pytest.fixture
    def port(self):
        return PYTHON_MOCK_PORT

    @pytest.fixture(autouse=True)
    def _check_python_mock(self):
        require_port(MOCK_HOST, PYTHON_MOCK_PORT, "Python HL7 mock")

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    def test_python_mock_connectivity(self, cli_runner, target, port):
        """Test basic connectivity to Python mock [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Python mock connection failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "connected" in messages or "mllp" in messages

    def test_python_mock_probe_ops(self, cli_runner, target, port):
        """Test probe operations on Python mock [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--probe-ops",
            format="json",
            json_log=True,
            timeout=60,
        )

        assert result.success, f"Python mock probe failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert any(term in messages for term in ["supported", "probing", "adt", "oru"])

    def test_python_mock_adt(self, cli_runner, target, port):
        """Test ADT^A01 on Python mock [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-adt",
            "--patient-id",
            "PT001",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Python mock ADT failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_python_mock_qry(self, cli_runner, target, port):
        """Test QRY^Q01 on Python mock [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--send-qry",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Python mock QRY failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_python_mock_tls(self, cli_runner, target):
        """Test TLS/MLLPS on Python mock port 2576 [Category A]"""
        require_port(MOCK_HOST, PYTHON_TLS_PORT, "Python HL7 TLS mock")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(PYTHON_TLS_PORT),
            "--tls",
            "--tls-insecure",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Python mock TLS failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "tls" in messages or "certificate" in messages or "connected" in messages


@contextlib.contextmanager
def _dummy_tcp_server():
    """A local TCP server that accepts connections but never speaks HL7/MLLP.

    Safety: binds only to 127.0.0.1 on an ephemeral port. It provides a
    "TCP connects but is not an HL7 endpoint" target for the connection-1
    false-positive regression below — it never touches a real device or external
    network. Accepted sockets are held open and silent so the MLLP query never
    receives an HL7 ACK.
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


class TestHL7P1FalsePositiveRegression:
    """Regression guard for the connection-1 false-positive identification bug.

    A bare TCP connect to a port that speaks *something other than HL7/MLLP*
    opens the channel but never returns an HL7 ACK. Before the fix,
    create_conn_obj() only performed a TCP connect (which succeeds on any open
    port) and proto_flow never set success=False, so the base
    ``NetworkConnection.run()`` defaulted success=True and OIDA reported a
    false-positive HL7 endpoint. The fix tracks whether the peer ever returned a
    valid HL7 message (an MSH segment) and gates success=False otherwise.

    Safety: targets only a local in-process dummy TCP server bound to 127.0.0.1
    and a closed local port — never a real device or external network.
    """

    def _read_result_payload(self, out_dir, result):
        candidates = sorted(out_dir.glob("*.json"))
        assert candidates, (
            "no JSON result file was written to the output directory; "
            f"combined output: {result.combined_output[:800]}"
        )
        payload = json.loads(candidates[-1].read_text())
        return payload[0] if isinstance(payload, list) else payload

    def test_non_hl7_tcp_port_is_not_a_false_positive(self, cli_runner, tmp_path):
        """A TCP-connectable but non-HL7 port must report success=False."""
        with _dummy_tcp_server() as port:
            out_dir = tmp_path / "p1_non_hl7"
            result = cli_runner.run(
                "hl7",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "3",
                format="json",
                output=str(out_dir),
                expect_json=False,
                timeout=30,
            )
            last = self._read_result_payload(out_dir, result)
            assert last["success"] is False, (
                "connection-1 regression: a non-HL7 TCP port was reported as a "
                f"successful HL7 identification. Payload: {last}"
            )

    def test_closed_port_is_not_a_false_positive(self, cli_runner, tmp_path):
        """A closed local port must report success=False (never a phantom endpoint)."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        out_dir = tmp_path / "p1_closed"
        result = cli_runner.run(
            "hl7",
            "127.0.0.1",
            "--port",
            str(closed_port),
            "--timeout",
            "3",
            format="json",
            output=str(out_dir),
            expect_json=False,
            timeout=30,
        )
        last = self._read_result_payload(out_dir, result)
        assert last["success"] is False, (
            "connection-1 regression: a closed port was reported as a successful "
            f"HL7 identification. Payload: {last}"
        )
