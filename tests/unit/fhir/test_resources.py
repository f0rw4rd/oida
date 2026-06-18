#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR resource builder and parser functionality.

Tests the FHIRResourceBuilder and FHIRResourceParser classes for:
- Patient resource creation and parsing
- Observation resource creation and parsing
- MedicationRequest resource creation and parsing
- Condition resource creation and parsing
- Encounter resource creation and parsing
"""

import unittest
from unittest.mock import MagicMock


class TestFHIRResourceBuilder(unittest.TestCase):
    """Test FHIR resource builder functionality"""

    def test_builder_initialization(self):
        """Test FHIRResourceBuilder initialization"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        self.assertIsNotNone(builder)
        self.assertEqual(builder.version, "R4")

    def test_build_patient_minimal(self):
        """Test building a minimal Patient resource"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        patient = builder.build_patient(
            patient_id="PT001",
            family_name="Doe",
            given_name="John",
        )

        self.assertEqual(patient["resourceType"], "Patient")
        self.assertEqual(patient["id"], "PT001")
        self.assertEqual(patient["name"][0]["family"], "Doe")
        self.assertIn("John", patient["name"][0]["given"])

    def test_build_patient_complete(self):
        """Test building a complete Patient resource"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        patient = builder.build_patient(
            patient_id="PT001",
            family_name="Doe",
            given_name="John",
            gender="male",
            birth_date="1980-01-15",
            address_line="123 Main Street",
            city="Anytown",
            state="ST",
            postal_code="12345",
            country="USA",
            phone="(555) 123-4567",
            email="john.doe@example.com",
            identifier_value="MRN001",
        )

        self.assertEqual(patient["resourceType"], "Patient")
        self.assertEqual(patient["gender"], "male")
        self.assertEqual(patient["birthDate"], "1980-01-15")
        self.assertIn("address", patient)
        self.assertIn("telecom", patient)
        self.assertIn("identifier", patient)

    def test_build_observation_vital_signs(self):
        """Test building a vital signs Observation"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        obs = builder.build_observation(
            observation_id="OBS001",
            patient_reference="Patient/PT001",
            code="8867-4",
            code_display="Heart rate",
            value=72,
            value_unit="beats/minute",
            category_code="vital-signs",
        )

        self.assertEqual(obs["resourceType"], "Observation")
        self.assertEqual(obs["id"], "OBS001")
        self.assertEqual(obs["status"], "final")
        self.assertEqual(obs["subject"]["reference"], "Patient/PT001")
        self.assertEqual(obs["valueQuantity"]["value"], 72)

    def test_build_observation_laboratory(self):
        """Test building a laboratory Observation"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        obs = builder.build_observation(
            observation_id="OBS002",
            patient_reference="Patient/PT001",
            code="2339-0",
            code_display="Glucose [Mass/volume] in Blood",
            value=95,
            value_unit="mg/dL",
            category_code="laboratory",
        )

        self.assertEqual(obs["resourceType"], "Observation")
        self.assertEqual(obs["category"][0]["coding"][0]["code"], "laboratory")

    def test_build_medication_request(self):
        """Test building a MedicationRequest"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        med = builder.build_medication_request(
            medication_request_id="MED001",
            patient_reference="Patient/PT001",
            medication_code="197361",
            medication_display="Lisinopril 10 MG Oral Tablet",
            dosage_text="Take 1 tablet by mouth daily",
        )

        self.assertEqual(med["resourceType"], "MedicationRequest")
        self.assertEqual(med["id"], "MED001")
        self.assertEqual(med["status"], "active")
        self.assertEqual(med["intent"], "order")
        self.assertEqual(med["subject"]["reference"], "Patient/PT001")

    def test_build_condition(self):
        """Test building a Condition resource"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        condition = builder.build_condition(
            condition_id="CON001",
            patient_reference="Patient/PT001",
            code="73211009",
            code_system="http://snomed.info/sct",
            code_display="Diabetes mellitus",
            clinical_status="active",
            onset_datetime="2020-05-15",
        )

        self.assertEqual(condition["resourceType"], "Condition")
        self.assertEqual(condition["id"], "CON001")
        self.assertEqual(condition["clinicalStatus"]["coding"][0]["code"], "active")
        self.assertEqual(condition["onsetDateTime"], "2020-05-15")

    def test_build_encounter(self):
        """Test building an Encounter resource"""
        from oida.protocols.fhir.resources import FHIRResourceBuilder

        builder = FHIRResourceBuilder()
        encounter = builder.build_encounter(
            encounter_id="ENC001",
            patient_reference="Patient/PT001",
            class_code="AMB",
            status="finished",
            period_start="2024-01-15T09:00:00Z",
            period_end="2024-01-15T10:30:00Z",
        )

        self.assertEqual(encounter["resourceType"], "Encounter")
        self.assertEqual(encounter["id"], "ENC001")
        self.assertEqual(encounter["status"], "finished")
        self.assertEqual(encounter["class"]["code"], "AMB")


class TestFHIRResourceParser(unittest.TestCase):
    """Test FHIR resource parser functionality"""

    def _create_mock_resource(self, **attrs):
        """Create a mock FHIR resource with attributes"""
        mock = MagicMock()
        for key, value in attrs.items():
            setattr(mock, key, value)
        # Set defaults for missing attributes
        for attr in [
            "id",
            "name",
            "gender",
            "birthDate",
            "telecom",
            "address",
            "identifier",
            "subject",
            "code",
            "status",
            "valueQuantity",
            "effectiveDateTime",
            "effectivePeriod",
            "category",
        ]:
            if not hasattr(mock, attr):
                setattr(mock, attr, None)
        return mock

    def test_parser_class_methods(self):
        """Test FHIRResourceParser has classmethod parsers"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        # Parser methods are classmethods
        self.assertTrue(hasattr(FHIRResourceParser, "parse_patient"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_observation"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_medication_request"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_condition"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_encounter"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_procedure"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_allergy"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_immunization"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_diagnostic_report"))
        self.assertTrue(hasattr(FHIRResourceParser, "parse_document_reference"))

    def test_parse_patient(self):
        """Test parsing a Patient resource"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        # Create mock patient with proper structure
        mock_name = MagicMock()
        mock_name.given = ["John", "Michael"]
        mock_name.family = "Doe"

        mock_phone = MagicMock()
        mock_phone.system = "phone"
        mock_phone.value = "(555) 123-4567"

        mock_address = MagicMock()
        mock_address.line = ["123 Main St"]
        mock_address.city = "Anytown"
        mock_address.state = "ST"
        mock_address.postalCode = "12345"

        mock_ident = MagicMock()
        mock_ident.system = "http://hospital.local/mrn"
        mock_ident.value = "MRN001"

        mock_patient = MagicMock()
        mock_patient.id = "PT001"
        mock_patient.name = [mock_name]
        mock_patient.gender = "male"
        mock_patient.birthDate = MagicMock(isostring="1980-01-15")
        mock_patient.telecom = [mock_phone]
        mock_patient.address = [mock_address]
        mock_patient.identifier = [mock_ident]

        result = FHIRResourceParser.parse_patient(mock_patient)

        self.assertEqual(result["id"], "PT001")
        self.assertEqual(result["name"], "John Michael Doe")
        self.assertEqual(result["gender"], "male")
        self.assertEqual(result["birth_date"], "1980-01-15")

    def test_parse_observation(self):
        """Test parsing an Observation resource"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        mock_coding = MagicMock()
        mock_coding.code = "8867-4"
        mock_coding.display = "Heart rate"

        mock_code = MagicMock()
        mock_code.coding = [mock_coding]
        mock_code.text = None

        mock_value = MagicMock()
        mock_value.value = 72
        mock_value.unit = "beats/minute"

        mock_subject = MagicMock()
        mock_subject.reference = "Patient/PT001"

        mock_obs = MagicMock()
        mock_obs.id = "OBS001"
        mock_obs.status = "final"
        mock_obs.code = mock_code
        mock_obs.valueQuantity = mock_value
        mock_obs.valueString = None
        mock_obs.valueCodeableConcept = None
        mock_obs.subject = mock_subject
        mock_obs.effectiveDateTime = MagicMock(isostring="2024-01-15")
        mock_obs.effectivePeriod = None
        mock_obs.category = None

        result = FHIRResourceParser.parse_observation(mock_obs)

        self.assertEqual(result["id"], "OBS001")
        self.assertEqual(result["status"], "final")
        self.assertEqual(result["code"], "8867-4")
        self.assertEqual(result["value"], 72)
        self.assertEqual(result["unit"], "beats/minute")

    def test_parse_medication_request(self):
        """Test parsing a MedicationRequest resource"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        mock_med_code = MagicMock()
        mock_med_code.coding = [MagicMock(code="197361", display="Lisinopril 10 MG")]
        mock_med_code.text = "Lisinopril 10 MG"

        mock_subject = MagicMock()
        mock_subject.reference = "Patient/PT001"

        mock_dosage = MagicMock()
        mock_dosage.text = "Take 1 tablet daily"

        mock_requester = MagicMock()
        mock_requester.display = "Dr. Smith"
        mock_requester.reference = None

        mock_med = MagicMock()
        mock_med.id = "MED001"
        mock_med.status = "active"
        mock_med.intent = "order"
        mock_med.medicationCodeableConcept = mock_med_code
        mock_med.medicationReference = None
        mock_med.subject = mock_subject
        mock_med.authoredOn = MagicMock(isostring="2024-01-15")
        mock_med.requester = mock_requester
        mock_med.dosageInstruction = [mock_dosage]

        result = FHIRResourceParser.parse_medication_request(mock_med)

        self.assertEqual(result["id"], "MED001")
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["patient_id"], "PT001")

    def test_parse_condition(self):
        """Test parsing a Condition resource"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        mock_coding = MagicMock()
        mock_coding.code = "73211009"
        mock_coding.display = "Diabetes mellitus"

        mock_code = MagicMock()
        mock_code.coding = [mock_coding]
        mock_code.text = "Diabetes mellitus"

        mock_clinical_status = MagicMock()
        mock_clinical_status.coding = [MagicMock(code="active")]
        mock_clinical_status.text = None

        mock_subject = MagicMock()
        mock_subject.reference = "Patient/PT001"

        mock_condition = MagicMock()
        mock_condition.id = "CON001"
        mock_condition.code = mock_code
        mock_condition.clinicalStatus = mock_clinical_status
        mock_condition.subject = mock_subject
        mock_condition.onsetDateTime = MagicMock(isostring="2020-05-15")
        mock_condition.recordedDate = None
        mock_condition.category = None

        result = FHIRResourceParser.parse_condition(mock_condition)

        self.assertEqual(result["id"], "CON001")
        self.assertEqual(result["code"], "73211009")
        self.assertEqual(result["display"], "Diabetes mellitus")
        self.assertEqual(result["clinical_status"], "active")

    def test_parse_encounter(self):
        """Test parsing an Encounter resource"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        mock_class = MagicMock()
        mock_class.code = "AMB"

        mock_type_coding = MagicMock()
        mock_type_coding.display = "Office Visit"
        mock_type = MagicMock()
        mock_type.coding = [mock_type_coding]
        mock_type.text = None

        mock_subject = MagicMock()
        mock_subject.reference = "Patient/PT001"

        mock_period = MagicMock()
        mock_period.start = MagicMock(isostring="2024-01-15T09:00:00Z")
        mock_period.end = MagicMock(isostring="2024-01-15T10:30:00Z")

        mock_encounter = MagicMock()
        mock_encounter.id = "ENC001"
        mock_encounter.status = "finished"
        mock_encounter.class_fhir = mock_class
        mock_encounter.type = [mock_type]
        mock_encounter.subject = mock_subject
        mock_encounter.period = mock_period

        result = FHIRResourceParser.parse_encounter(mock_encounter)

        self.assertEqual(result["id"], "ENC001")
        self.assertEqual(result["status"], "finished")
        self.assertEqual(result["patient_id"], "PT001")

    def test_format_fhir_date_with_isostring(self):
        """Test _format_fhir_date with FHIRDate-like object"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        mock_date = MagicMock()
        mock_date.isostring = "2024-01-15"
        mock_date.date = None

        result = FHIRResourceParser._format_fhir_date(mock_date)
        self.assertEqual(result, "2024-01-15")

    def test_format_fhir_date_with_date(self):
        """Test _format_fhir_date with date property"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        mock_date = MagicMock()
        mock_date.isostring = None
        mock_date.date = "2024-01-15"

        result = FHIRResourceParser._format_fhir_date(mock_date)
        self.assertEqual(result, "2024-01-15")

    def test_format_fhir_date_empty(self):
        """Test _format_fhir_date with None"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        result = FHIRResourceParser._format_fhir_date(None)
        self.assertEqual(result, "")

    def test_get_reference_id(self):
        """Test _get_reference_id extracts ID from reference"""
        from oida.protocols.fhir.resources import FHIRResourceParser

        self.assertEqual(FHIRResourceParser._get_reference_id("Patient/123"), "123")
        self.assertEqual(FHIRResourceParser._get_reference_id("123"), "123")
        self.assertEqual(FHIRResourceParser._get_reference_id(""), "")
        self.assertEqual(FHIRResourceParser._get_reference_id(None), "")


if __name__ == "__main__":
    unittest.main()
