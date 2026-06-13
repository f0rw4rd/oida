#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR SearchMixin.

Tests resource search and display functionality for all FHIR resource types
using a mock host class that incorporates SearchMixin.
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.fhir.mixins.search import SearchMixin


class MockSearchHost(SearchMixin):
    """Mock host class that mixes in SearchMixin for testing."""

    def __init__(self, **arg_overrides):
        self.args = Mock()
        self.logger = Mock()
        self.logger.findings = []
        self.results = {"data": {}}
        self.smart_client = Mock()

        defaults = dict(
            max_results=100,
            patient_id=None,
            patient_name=None,
            patient_dob=None,
            patient_gender=None,
            wildcard=False,
            date_from=None,
            date_to=None,
            code=None,
            category=None,
            include=None,
            revinclude=None,
            elements=None,
            summary=None,
            save_response=None,
            practitioner_name=None,
            organization_name=None,
            location_name=None,
            device_type=None,
            # Auth attrs must be None so supplied_auth=False in security checks
            username=None,
            password=None,
            token=None,
        )
        defaults.update(arg_overrides)
        for k, v in defaults.items():
            setattr(self.args, k, v)

    def _get_base_url(self):
        return "https://fhir.example.com/r4"


class TestApplySearchModifiers(unittest.TestCase):
    """Test _apply_search_modifiers() method"""

    def test_include_applied(self):
        """Test _include is added to params when set"""
        host = MockSearchHost(include="Patient:organization")
        params = {}
        host._apply_search_modifiers(params)
        self.assertEqual(params["_include"], "Patient:organization")

    def test_revinclude_applied(self):
        """Test _revinclude is added to params when set"""
        host = MockSearchHost(revinclude="Observation:patient")
        params = {}
        host._apply_search_modifiers(params)
        self.assertEqual(params["_revinclude"], "Observation:patient")

    def test_elements_applied(self):
        """Test _elements is added to params when set"""
        host = MockSearchHost(elements="id,name")
        params = {}
        host._apply_search_modifiers(params)
        self.assertEqual(params["_elements"], "id,name")

    def test_summary_applied(self):
        """Test _summary is added to params when set"""
        host = MockSearchHost(summary="count")
        params = {}
        host._apply_search_modifiers(params)
        self.assertEqual(params["_summary"], "count")

    def test_none_values_skipped(self):
        """Test None args are not added to params"""
        host = MockSearchHost()
        params = {}
        host._apply_search_modifiers(params)
        self.assertEqual(len(params), 0)

    def test_all_modifiers_at_once(self):
        """Test all modifiers can be applied simultaneously"""
        host = MockSearchHost(
            include="Patient:org",
            revinclude="Obs:patient",
            elements="id,name",
            summary="true",
        )
        params = {}
        host._apply_search_modifiers(params)
        self.assertEqual(len(params), 4)


class TestSaveResponseIfRequested(unittest.TestCase):
    """Test _save_response_if_requested() method"""

    def test_no_save_response_skips(self):
        """Test no save_response arg means no file write"""
        host = MockSearchHost()
        host._save_response_if_requested({"test": True})
        # No exception, no calls to export

    @patch("oida.protocols.fhir.mixins.search.os.path.dirname", return_value=".")
    @patch("oida.protocols.fhir.mixins.search.os.path.basename", return_value="response.json")
    def test_with_save_response_path(self, mock_base, mock_dir):
        """Test data is saved when save_response is set"""
        host = MockSearchHost(save_response="/tmp/response.json")

        with (
            patch("oida.utils.export_utils.export_json") as mock_export,
            patch("oida.utils.common_types.safe_file_path", return_value="/tmp/response.json"),
        ):
            host._save_response_if_requested({"test": True})
            mock_export.assert_called_once()

    def test_exception_handling(self):
        """Test exception in save is caught and logged"""
        host = MockSearchHost(save_response="/tmp/response.json")

        with patch("oida.utils.common_types.safe_file_path", side_effect=ValueError("bad path")):
            host._save_response_if_requested({"test": True})
            host.logger.warning.assert_called()


class TestSearchPatients(unittest.TestCase):
    """Test _search_patients() method"""

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_success_with_results(self, mock_parser, mock_patient):
        """Test successful patient search returns parsed results"""
        host = MockSearchHost()

        mock_p = Mock()
        mock_p.id = "PT001"
        mock_search = Mock()
        mock_search.perform_resources.return_value = [mock_p]
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "PT001", "name": "John"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        self.assertIn("patients", host.results["data"])
        self.assertEqual(host.results["data"]["patients"]["count"], 1)

    @patch("oida.protocols.fhir.mixins.search.patient")
    def test_no_results(self, mock_patient):
        """Test patient search with no results"""
        host = MockSearchHost()

        mock_search = Mock()
        mock_search.perform_resources.return_value = []
        mock_patient.Patient.where.return_value = mock_search

        host._search_patients()
        host.logger.display.assert_any_call("  No patients found")

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_with_name_filter(self, mock_parser, mock_patient):
        """Test patient search with name filter"""
        host = MockSearchHost(patient_name="Smith")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock(id="1")]
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "1", "name": "Smith"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        call_args = mock_patient.Patient.where.call_args
        self.assertEqual(call_args[1]["struct"]["name"], "Smith")

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_with_id_filter(self, mock_parser, mock_patient):
        """Test patient search with ID filter"""
        host = MockSearchHost(patient_id="PT001")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock(id="PT001")]
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "PT001"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        call_args = mock_patient.Patient.where.call_args
        self.assertEqual(call_args[1]["struct"]["_id"], "PT001")

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_with_dob_filter(self, mock_parser, mock_patient):
        """Test patient search with DOB filter"""
        host = MockSearchHost(patient_dob="1990-01-01")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "1"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        call_args = mock_patient.Patient.where.call_args
        self.assertEqual(call_args[1]["struct"]["birthdate"], "1990-01-01")

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_with_gender_filter(self, mock_parser, mock_patient):
        """Test patient search with gender filter"""
        host = MockSearchHost(patient_gender="female")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "1"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        call_args = mock_patient.Patient.where.call_args
        self.assertEqual(call_args[1]["struct"]["gender"], "female")

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_wildcard_search(self, mock_parser, mock_patient):
        """Test wildcard enumeration iterates through letter prefixes"""
        host = MockSearchHost(wildcard=True)

        mock_p = Mock()
        mock_p.id = "PT001"
        mock_search = Mock()
        mock_search.perform_resources.return_value = [mock_p]
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "PT001", "name": "Test"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        # Should have called Patient.where multiple times (once per letter)
        self.assertTrue(mock_patient.Patient.where.call_count >= 1)

    @patch("oida.protocols.fhir.mixins.search.patient")
    def test_search_exception(self, mock_patient):
        """Test exception during patient search is caught"""
        host = MockSearchHost()
        mock_patient.Patient.where.side_effect = Exception("Connection failed")

        host._search_patients()

        self.assertIn("error", host.results["data"]["patients"])
        host.logger.warning.assert_called()

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_security_finding_over_10_patients(self, mock_parser, mock_patient):
        """Test security finding when > 10 patients returned"""
        host = MockSearchHost()

        patients = [Mock(id=str(i)) for i in range(15)]
        mock_search = Mock()
        mock_search.perform_resources.return_value = patients
        mock_patient.Patient.where.return_value = mock_search
        mock_parser.parse_patient.return_value = {"id": "1"}

        with patch.object(host, "_display_patient_results"):
            host._search_patients()

        findings = host.results["data"].get("security_findings", [])
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["issue"], "Unrestricted Patient Access")


class TestSearchObservations(unittest.TestCase):
    """Test _search_observations() method"""

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_success(self, mock_parser, mock_obs):
        """Test successful observation search"""
        host = MockSearchHost()

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_obs.Observation.where.return_value = mock_search
        mock_parser.parse_observation.return_value = {"id": "O1", "code": "8867-4"}

        with patch.object(host, "_display_observation_results"):
            host._search_observations()

        self.assertEqual(host.results["data"]["observations"]["count"], 1)

    @patch("oida.protocols.fhir.mixins.search.observation")
    def test_no_results(self, mock_obs):
        """Test observation search with no results"""
        host = MockSearchHost()
        mock_search = Mock()
        mock_search.perform_resources.return_value = []
        mock_obs.Observation.where.return_value = mock_search

        host._search_observations()
        host.logger.display.assert_any_call("  No observations found")

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_date_from_filter(self, mock_parser, mock_obs):
        """Test date_from filter builds ge prefix"""
        host = MockSearchHost(date_from="2024-01-01")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_obs.Observation.where.return_value = mock_search
        mock_parser.parse_observation.return_value = {"id": "1"}

        with patch.object(host, "_display_observation_results"):
            host._search_observations()

        params = mock_obs.Observation.where.call_args[1]["struct"]
        self.assertEqual(params["date"], "ge2024-01-01")

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_date_to_filter(self, mock_parser, mock_obs):
        """Test date_to filter builds le prefix"""
        host = MockSearchHost(date_to="2024-12-31")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_obs.Observation.where.return_value = mock_search
        mock_parser.parse_observation.return_value = {"id": "1"}

        with patch.object(host, "_display_observation_results"):
            host._search_observations()

        params = mock_obs.Observation.where.call_args[1]["struct"]
        self.assertEqual(params["date"], "le2024-12-31")

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_date_range_filter(self, mock_parser, mock_obs):
        """Test both date_from and date_to build list"""
        host = MockSearchHost(date_from="2024-01-01", date_to="2024-12-31")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_obs.Observation.where.return_value = mock_search
        mock_parser.parse_observation.return_value = {"id": "1"}

        with patch.object(host, "_display_observation_results"):
            host._search_observations()

        params = mock_obs.Observation.where.call_args[1]["struct"]
        # Both bounds use $and combinator (bare list raises TypeError in fhirclient)
        self.assertIsInstance(params["date"], dict)
        self.assertIn("$and", params["date"])
        self.assertIn("ge2024-01-01", params["date"]["$and"])
        self.assertIn("le2024-12-31", params["date"]["$and"])

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_code_filter(self, mock_parser, mock_obs):
        """Test code filter is applied"""
        host = MockSearchHost(code="8867-4")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_obs.Observation.where.return_value = mock_search
        mock_parser.parse_observation.return_value = {"id": "1"}

        with patch.object(host, "_display_observation_results"):
            host._search_observations()

        params = mock_obs.Observation.where.call_args[1]["struct"]
        self.assertEqual(params["code"], "8867-4")

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_category_filter(self, mock_parser, mock_obs):
        """Test category filter is applied"""
        host = MockSearchHost(category="vital-signs")

        mock_search = Mock()
        mock_search.perform_resources.return_value = [Mock()]
        mock_obs.Observation.where.return_value = mock_search
        mock_parser.parse_observation.return_value = {"id": "1"}

        with patch.object(host, "_display_observation_results"):
            host._search_observations()

        params = mock_obs.Observation.where.call_args[1]["struct"]
        self.assertEqual(params["category"], "vital-signs")

    @patch("oida.protocols.fhir.mixins.search.observation")
    def test_exception(self, mock_obs):
        """Test exception during observation search is handled"""
        host = MockSearchHost()
        mock_obs.Observation.where.side_effect = Exception("Timeout")

        host._search_observations()
        self.assertIn("error", host.results["data"]["observations"])


def _make_simple_search_test(method_name, resource_module_name, resource_class_name, results_key):
    """Factory to create test methods for simple resource searches."""

    class SearchTestCase(unittest.TestCase):
        @patch(f"oida.protocols.fhir.mixins.search.{resource_module_name}")
        @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
        def test_success(self, mock_parser, mock_module):
            host = MockSearchHost()
            resource_cls = getattr(mock_module, resource_class_name)
            mock_search = Mock()
            mock_search.perform_resources.return_value = [Mock()]
            resource_cls.where.return_value = mock_search
            # Set up the parser to return a minimal dict
            for attr in dir(mock_parser):
                if callable(getattr(mock_parser, attr)) and attr.startswith("parse_"):
                    getattr(mock_parser, attr).return_value = {"id": "1"}

            display_method = f"_display_{results_key}_results"
            if hasattr(host, display_method):
                with patch.object(host, display_method):
                    getattr(host, method_name)()
            else:
                getattr(host, method_name)()

            self.assertIn(results_key, host.results["data"])
            self.assertEqual(host.results["data"][results_key]["count"], 1)

        @patch(f"oida.protocols.fhir.mixins.search.{resource_module_name}")
        def test_no_results(self, mock_module):
            host = MockSearchHost()
            resource_cls = getattr(mock_module, resource_class_name)
            mock_search = Mock()
            mock_search.perform_resources.return_value = []
            resource_cls.where.return_value = mock_search

            getattr(host, method_name)()
            # Should log "No ... found"
            self.assertTrue(host.logger.display.called)

        @patch(f"oida.protocols.fhir.mixins.search.{resource_module_name}")
        def test_exception(self, mock_module):
            host = MockSearchHost()
            resource_cls = getattr(mock_module, resource_class_name)
            resource_cls.where.side_effect = Exception("Server error")

            getattr(host, method_name)()
            self.assertIn("error", host.results["data"][results_key])

    return SearchTestCase


# Generate test classes for simple resource searches
TestSearchMedications = _make_simple_search_test(
    "_search_medications", "medicationrequest", "MedicationRequest", "medications"
)
TestSearchMedications.__qualname__ = "TestSearchMedications"

TestSearchConditions = _make_simple_search_test(
    "_search_conditions", "condition", "Condition", "conditions"
)
TestSearchConditions.__qualname__ = "TestSearchConditions"

TestSearchEncounters = _make_simple_search_test(
    "_search_encounters", "encounter", "Encounter", "encounters"
)
TestSearchEncounters.__qualname__ = "TestSearchEncounters"

TestSearchProcedures = _make_simple_search_test(
    "_search_procedures", "procedure", "Procedure", "procedures"
)
TestSearchProcedures.__qualname__ = "TestSearchProcedures"

TestSearchAllergies = _make_simple_search_test(
    "_search_allergies", "allergyintolerance", "AllergyIntolerance", "allergies"
)
TestSearchAllergies.__qualname__ = "TestSearchAllergies"

TestSearchImmunizations = _make_simple_search_test(
    "_search_immunizations", "immunization", "Immunization", "immunizations"
)
TestSearchImmunizations.__qualname__ = "TestSearchImmunizations"

TestSearchDiagnosticReports = _make_simple_search_test(
    "_search_diagnostic_reports", "diagnosticreport", "DiagnosticReport", "diagnostic_reports"
)
TestSearchDiagnosticReports.__qualname__ = "TestSearchDiagnosticReports"

TestSearchDocuments = _make_simple_search_test(
    "_search_documents", "documentreference", "DocumentReference", "documents"
)
TestSearchDocuments.__qualname__ = "TestSearchDocuments"

TestSearchPractitioners = _make_simple_search_test(
    "_search_practitioners", "practitioner", "Practitioner", "practitioners"
)
TestSearchPractitioners.__qualname__ = "TestSearchPractitioners"

TestSearchOrganizations = _make_simple_search_test(
    "_search_organizations", "organization", "Organization", "organizations"
)
TestSearchOrganizations.__qualname__ = "TestSearchOrganizations"

TestSearchLocations = _make_simple_search_test(
    "_search_locations", "location", "Location", "locations"
)
TestSearchLocations.__qualname__ = "TestSearchLocations"

TestSearchDevices = _make_simple_search_test("_search_devices", "device", "Device", "devices")
TestSearchDevices.__qualname__ = "TestSearchDevices"

TestSearchOrders = _make_simple_search_test(
    "_search_orders", "servicerequest", "ServiceRequest", "orders"
)
TestSearchOrders.__qualname__ = "TestSearchOrders"


class TestReadResource(unittest.TestCase):
    """Test _read_resource() method"""

    @patch("oida.protocols.fhir.mixins.search.patient")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_read_patient_by_id(self, mock_parser, mock_patient):
        """Test reading a Patient by ID"""
        host = MockSearchHost()
        mock_resource = Mock()
        mock_patient.Patient.read.return_value = mock_resource
        mock_parser.parse_patient.return_value = {"id": "PT001", "name": "John"}

        host._read_resource("Patient", "PT001")

        mock_patient.Patient.read.assert_called_once_with("PT001", host.smart_client.server)
        self.assertIn("read_patient", host.results["data"])

    @patch("oida.protocols.fhir.mixins.search.observation")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_read_observation_by_id(self, mock_parser, mock_obs):
        """Test reading an Observation by ID"""
        host = MockSearchHost()
        mock_resource = Mock()
        mock_obs.Observation.read.return_value = mock_resource
        mock_parser.parse_observation.return_value = {"id": "O001"}

        host._read_resource("Observation", "O001")

        mock_obs.Observation.read.assert_called_once_with("O001", host.smart_client.server)
        self.assertIn("read_observation", host.results["data"])

    def test_unsupported_resource_type(self):
        """Test unsupported resource type logs warning"""
        host = MockSearchHost()
        host._read_resource("FakeResource", "123")
        host.logger.warning.assert_called()

    @patch("oida.protocols.fhir.mixins.search.patient")
    def test_resource_not_found(self, mock_patient):
        """Test resource not found logs warning"""
        host = MockSearchHost()
        mock_patient.Patient.read.return_value = None

        host._read_resource("Patient", "NONEXIST")
        host.logger.warning.assert_called()

    @patch("oida.protocols.fhir.mixins.search.patient")
    def test_read_exception(self, mock_patient):
        """Test exception during read is handled"""
        host = MockSearchHost()
        mock_patient.Patient.read.side_effect = Exception("Not found")

        host._read_resource("Patient", "BAD")
        host.logger.warning.assert_called()

    @patch("oida.protocols.fhir.mixins.search.condition")
    @patch("oida.protocols.fhir.mixins.search.FHIRResourceParser")
    def test_read_condition_by_id(self, mock_parser, mock_cond):
        """Test reading a Condition by ID uses condition parser"""
        host = MockSearchHost()
        mock_resource = Mock()
        mock_cond.Condition.read.return_value = mock_resource
        mock_parser.parse_condition.return_value = {"id": "C001"}

        host._read_resource("Condition", "C001")
        self.assertIn("read_condition", host.results["data"])

    @patch("oida.protocols.fhir.mixins.search.encounter")
    def test_read_encounter_fallback_parsing(self, mock_enc):
        """Test reading Encounter uses generic fallback parse"""
        host = MockSearchHost()
        mock_resource = Mock()
        mock_enc.Encounter.read.return_value = mock_resource

        host._read_resource("Encounter", "E001")
        # Encounter hits the else branch (generic dict)
        self.assertIn("read_encounter", host.results["data"])
        self.assertEqual(host.results["data"]["read_encounter"]["type"], "Encounter")


if __name__ == "__main__":
    unittest.main()
