#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for FHIR CRUDMixin.

Tests create, update, and delete operations for FHIR resources.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock

from oida.protocols.fhir.mixins.crud import CRUDMixin
from oida.utils.confirm_gate import ConfirmGateMixin


class MockCRUDHost(CRUDMixin, ConfirmGateMixin):
    """Mock host class that mixes in CRUDMixin for testing."""

    def __init__(self, **arg_overrides):
        self.args = Mock()
        self.logger = Mock()
        self.logger.findings = []
        self.results = {"data": {}}
        self.smart_client = Mock()

        defaults = dict(
            confirm=False,
            patient_data=None,
            patient_given_name=None,
            patient_family_name=None,
            patient_dob=None,
            patient_gender=None,
            patient_id=None,
            update_patient=None,
            delete_patient=None,
            observation_data=None,
            observation_code=None,
            observation_value=None,
            observation_unit=None,
            create_patient=False,
            create_observation=False,
        )
        defaults.update(arg_overrides)
        for k, v in defaults.items():
            setattr(self.args, k, v)


class TestCreatePatient(unittest.TestCase):
    """Test _create_patient() method"""

    def test_no_confirm_flag(self):
        """Test create patient fails without --confirm"""
        host = MockCRUDHost(confirm=False)
        host._create_patient()
        host.logger.fail.assert_called_with("Write operations require --confirm flag")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_with_patient_data_json(self, mock_patient):
        """Test create patient from JSON string"""
        host = MockCRUDHost(
            confirm=True,
            patient_data='{"resourceType": "Patient", "name": [{"given": ["Test"]}]}',
        )

        mock_new = MagicMock()
        mock_new.id = "NEW-001"
        mock_new.create.return_value = True
        mock_patient.Patient.return_value = mock_new

        host._create_patient()

        host.logger.success.assert_called()
        self.assertIn("created_patient", host.results["data"])
        self.assertEqual(host.results["data"]["created_patient"]["id"], "NEW-001")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_default_patient_data(self, mock_builder, mock_patient):
        """Test create patient with default data when no JSON provided"""
        host = MockCRUDHost(confirm=True)

        mock_builder.build_patient.return_value = {
            "resourceType": "Patient",
            "name": [{"given": ["Test"], "family": "Patient"}],
        }

        mock_new = MagicMock()
        mock_new.id = "NEW-002"
        mock_new.create.return_value = True
        mock_patient.Patient.return_value = mock_new

        host._create_patient()

        mock_builder.build_patient.assert_called_once()
        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_custom_patient_args(self, mock_builder, mock_patient):
        """Test create patient uses CLI name/dob/gender args"""
        host = MockCRUDHost(
            confirm=True,
            patient_given_name="Jane",
            patient_family_name="Doe",
            patient_dob="1985-03-15",
            patient_gender="female",
        )

        mock_builder.build_patient.return_value = {"resourceType": "Patient"}
        mock_new = MagicMock()
        mock_new.id = "NEW-003"
        mock_new.create.return_value = True
        mock_patient.Patient.return_value = mock_new

        host._create_patient()

        call_kwargs = mock_builder.build_patient.call_args
        self.assertEqual(call_kwargs[1]["given_name"], "Jane")
        self.assertEqual(call_kwargs[1]["family_name"], "Doe")
        self.assertEqual(call_kwargs[1]["birth_date"], "1985-03-15")
        self.assertEqual(call_kwargs[1]["gender"], "female")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_create_success(self, mock_patient):
        """Test successful create logs success"""
        host = MockCRUDHost(
            confirm=True,
            patient_data='{"resourceType": "Patient"}',
        )

        mock_new = MagicMock()
        mock_new.id = "CREATED"
        mock_new.create.return_value = True
        mock_patient.Patient.return_value = mock_new

        host._create_patient()
        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_create_failure(self, mock_patient):
        """Test failed create logs failure"""
        host = MockCRUDHost(
            confirm=True,
            patient_data='{"resourceType": "Patient"}',
        )

        mock_new = MagicMock()
        mock_new.create.return_value = None
        mock_patient.Patient.return_value = mock_new

        host._create_patient()
        host.logger.fail.assert_called_with("Failed to create Patient")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_create_exception(self, mock_patient):
        """Test exception during create is handled"""
        host = MockCRUDHost(
            confirm=True,
            patient_data='{"resourceType": "Patient"}',
        )

        mock_patient.Patient.side_effect = Exception("Server error")

        host._create_patient()
        host.logger.fail.assert_called()
        self.assertIn("error", host.results["data"]["created_patient"])


class TestUpdatePatient(unittest.TestCase):
    """Test _update_patient() method"""

    def test_no_confirm_flag(self):
        """Test update fails without --confirm"""
        host = MockCRUDHost(confirm=False, update_patient="PT001")
        host._update_patient()
        host.logger.fail.assert_called_with("Write operations require --confirm flag")

    def test_no_patient_id(self):
        """Test update fails without patient ID"""
        host = MockCRUDHost(confirm=True, update_patient=None)
        host._update_patient()
        host.logger.fail.assert_called_with("No patient ID specified for update")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_patient_not_found(self, mock_patient):
        """Test update fails when patient not found"""
        host = MockCRUDHost(confirm=True, update_patient="PT999")
        mock_patient.Patient.read.return_value = None

        host._update_patient()
        host.logger.fail.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_with_json_data_allowed_field(self, mock_patient):
        """Test update with JSON data for allowed fields"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_data='{"gender": "male", "active": true}',
        )

        mock_existing = MagicMock()
        mock_existing.as_json.return_value = {"resourceType": "Patient", "id": "PT001"}
        mock_patient.Patient.read.return_value = mock_existing

        rebuilt = MagicMock()
        rebuilt.update.return_value = True
        mock_patient.Patient.return_value = rebuilt

        host._update_patient()

        # Allowed fields are merged into the resource JSON and the resource is
        # rebuilt via the model constructor (so fhirclient converts dicts to
        # typed sub-models), not set via raw setattr.
        mock_patient.Patient.assert_called_once_with(
            {"resourceType": "Patient", "id": "PT001", "gender": "male", "active": True}
        )
        rebuilt.update.assert_called_once()
        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_with_json_data_disallowed_field(self, mock_patient):
        """Test update skips disallowed fields with warning"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_data='{"id": "HACK", "gender": "female"}',
        )

        mock_existing = MagicMock()
        mock_existing.as_json.return_value = {"resourceType": "Patient", "id": "PT001"}
        mock_patient.Patient.read.return_value = mock_existing

        rebuilt = MagicMock()
        rebuilt.update.return_value = True
        mock_patient.Patient.return_value = rebuilt

        host._update_patient()

        # 'id' should be skipped with warning
        host.logger.warning.assert_called()
        # 'gender' should be merged into the rebuilt resource; 'id' excluded.
        mock_patient.Patient.assert_called_once_with(
            {"resourceType": "Patient", "id": "PT001", "gender": "female"}
        )

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_with_cli_given_name(self, mock_patient):
        """Test update using CLI args (given_name)"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_given_name="UpdatedFirst",
        )

        mock_existing = MagicMock()
        mock_existing.update.return_value = True
        mock_patient.Patient.read.return_value = mock_existing

        with patch("fhirclient.models.humanname.HumanName") as mock_hn:
            mock_name = MagicMock()
            mock_hn.return_value = mock_name
            host._update_patient()

        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_with_cli_family_name(self, mock_patient):
        """Test update using CLI args (family_name)"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_family_name="NewFamily",
        )

        mock_existing = MagicMock()
        mock_existing.update.return_value = True
        mock_patient.Patient.read.return_value = mock_existing

        with patch("fhirclient.models.humanname.HumanName") as mock_hn:
            mock_name = MagicMock()
            mock_hn.return_value = mock_name
            host._update_patient()

        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_with_dob(self, mock_patient):
        """Test update using CLI args (dob)"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_dob="2000-06-15",
        )

        mock_existing = MagicMock()
        mock_existing.update.return_value = True
        mock_patient.Patient.read.return_value = mock_existing

        with patch("fhirclient.models.fhirdate.FHIRDate") as mock_date:
            mock_date.return_value = "2000-06-15"
            host._update_patient()

        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_with_gender(self, mock_patient):
        """Test update using CLI args (gender)"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_gender="other",
        )

        mock_existing = MagicMock()
        mock_existing.update.return_value = True
        mock_patient.Patient.read.return_value = mock_existing

        host._update_patient()
        self.assertEqual(mock_existing.gender, "other")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_success(self, mock_patient):
        """Test successful update"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_data='{"gender": "male"}',
        )

        mock_existing = MagicMock()
        mock_existing.update.return_value = True
        mock_patient.Patient.read.return_value = mock_existing

        host._update_patient()

        self.assertIn("updated_patient", host.results["data"])
        self.assertTrue(host.results["data"]["updated_patient"]["success"])

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_failure(self, mock_patient):
        """Test update that returns falsy result"""
        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_data='{"gender": "male"}',
        )

        mock_existing = MagicMock()
        mock_existing.as_json.return_value = {"resourceType": "Patient", "id": "PT001"}
        mock_patient.Patient.read.return_value = mock_existing

        rebuilt = MagicMock()
        rebuilt.update.return_value = None
        mock_patient.Patient.return_value = rebuilt

        host._update_patient()
        host.logger.fail.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_update_exception(self, mock_patient):
        """Test exception during update"""
        host = MockCRUDHost(confirm=True, update_patient="PT001")
        mock_patient.Patient.read.side_effect = Exception("Server error")

        host._update_patient()
        host.logger.fail.assert_called()
        self.assertIn("error", host.results["data"]["updated_patient"])


class TestUpdatePatientRealModel(unittest.TestCase):
    """Regression tests against the real fhirclient Patient model.

    These do NOT mock the `patient` module, so they exercise fhirclient's
    dict -> typed sub-model conversion. The previous implementation did
    setattr(existing, "name", [{...}]) with a raw dict, which made
    existing.update() raise FHIRValidationError; that error was swallowed
    and surfaced only as a generic 'failed' message.
    """

    def test_structured_field_does_not_raise(self):
        """JSON with a structured `name` must update cleanly (was: swallowed error)."""
        from oida.protocols.fhir.mixins import crud

        host = MockCRUDHost(
            confirm=True,
            update_patient="PT001",
            patient_data=(
                '{"name": [{"use": "official", "family": "Doe", "given": ["Jane"]}],'
                ' "gender": "female"}'
            ),
        )

        existing = crud.patient.Patient({"resourceType": "Patient", "id": "PT001"})
        captured = {}

        def fake_update(self_resource, server):
            captured["json"] = self_resource.as_json()
            return {"resourceType": "Patient", "id": "PT001"}

        with patch.object(crud.patient.Patient, "read", return_value=existing):
            with patch.object(crud.patient.Patient, "update", fake_update, create=True):
                host._update_patient()

        # No swallowed FHIRValidationError -> success, not fail.
        host.logger.success.assert_called()
        host.logger.fail.assert_not_called()
        # The structured name survived the dict -> HumanName conversion.
        self.assertEqual(captured["json"]["name"][0]["family"], "Doe")
        self.assertEqual(captured["json"]["name"][0]["given"], ["Jane"])
        self.assertEqual(captured["json"]["gender"], "female")

    def test_old_setattr_path_would_raise(self):
        """Document the original defect: raw setattr makes as_json() raise."""
        from oida.protocols.fhir.mixins import crud
        from fhirclient.models.fhirabstractbase import FHIRValidationError

        existing = crud.patient.Patient({"resourceType": "Patient", "id": "PT001"})
        # This is exactly what the buggy code did.
        existing.name = [{"use": "official", "family": "Doe", "given": ["Jane"]}]
        with self.assertRaises(FHIRValidationError):
            existing.as_json()


class TestDeletePatient(unittest.TestCase):
    """Test _delete_patient() method"""

    def test_no_confirm_flag(self):
        """Test delete fails without --confirm"""
        host = MockCRUDHost(confirm=False, delete_patient="PT001")
        host._delete_patient()
        host.logger.fail.assert_called_with("Write operations require --confirm flag")

    def test_no_patient_id(self):
        """Test delete fails without patient ID"""
        host = MockCRUDHost(confirm=True, delete_patient=None)
        host._delete_patient()
        host.logger.fail.assert_called_with("No patient ID specified for delete")

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_patient_not_found(self, mock_patient):
        """Test delete fails when patient not found"""
        host = MockCRUDHost(confirm=True, delete_patient="PT999")
        mock_patient.Patient.read.return_value = None

        host._delete_patient()
        host.logger.fail.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_delete_success(self, mock_patient):
        """Test successful patient deletion"""
        host = MockCRUDHost(confirm=True, delete_patient="PT001")

        mock_existing = MagicMock()
        mock_patient.Patient.read.return_value = mock_existing

        host._delete_patient()

        mock_existing.delete.assert_called_once()
        host.logger.success.assert_called()
        self.assertIn("deleted_patient", host.results["data"])
        self.assertTrue(host.results["data"]["deleted_patient"]["success"])

    @patch("oida.protocols.fhir.mixins.crud.patient")
    def test_delete_exception(self, mock_patient):
        """Test exception during delete"""
        host = MockCRUDHost(confirm=True, delete_patient="PT001")

        mock_existing = MagicMock()
        mock_existing.delete.side_effect = Exception("Forbidden")
        mock_patient.Patient.read.return_value = mock_existing

        host._delete_patient()
        host.logger.fail.assert_called()
        self.assertIn("error", host.results["data"]["deleted_patient"])


class TestCreateObservation(unittest.TestCase):
    """Test _create_observation() method"""

    def test_no_confirm_flag(self):
        """Test create observation fails without --confirm"""
        host = MockCRUDHost(confirm=False)
        host._create_observation()
        host.logger.fail.assert_called_with("Write operations require --confirm flag")

    def test_no_patient_id_without_json(self):
        """Test create observation fails without patient_id when no JSON data"""
        host = MockCRUDHost(confirm=True, patient_id=None, observation_data=None)
        host._create_observation()
        host.logger.fail.assert_called_with("--patient-id required for observation creation")

    @patch("oida.protocols.fhir.mixins.crud.observation")
    def test_with_observation_data_json(self, mock_obs):
        """Test create observation from JSON string"""
        host = MockCRUDHost(
            confirm=True,
            observation_data='{"resourceType": "Observation", "status": "final"}',
        )

        mock_new = MagicMock()
        mock_new.id = "OBS-001"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        host.logger.success.assert_called()
        self.assertIn("created_observation", host.results["data"])

    @patch("oida.protocols.fhir.mixins.crud.observation")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_default_observation(self, mock_builder, mock_obs):
        """Test create observation with default data"""
        host = MockCRUDHost(
            confirm=True,
            patient_id="PT001",
            observation_data=None,
        )

        mock_builder.build_observation.return_value = {
            "resourceType": "Observation",
            "status": "final",
        }

        mock_new = MagicMock()
        mock_new.id = "OBS-002"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        mock_builder.build_observation.assert_called_once()
        host.logger.success.assert_called()

    @patch("oida.protocols.fhir.mixins.crud.observation")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_custom_observation_code(self, mock_builder, mock_obs):
        """Test create observation with custom code"""
        host = MockCRUDHost(
            confirm=True,
            patient_id="PT001",
            observation_code="29463-7",
            observation_value="80",
            observation_unit="kg",
        )

        mock_builder.build_observation.return_value = {"resourceType": "Observation"}
        mock_new = MagicMock()
        mock_new.id = "OBS-003"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        call_kwargs = mock_builder.build_observation.call_args[1]
        self.assertEqual(call_kwargs["code"], "29463-7")
        self.assertEqual(call_kwargs["value"], 80.0)
        self.assertEqual(call_kwargs["value_unit"], "kg")

    @patch("oida.protocols.fhir.mixins.crud.observation")
    def test_create_observation_success(self, mock_obs):
        """Test successful observation creation"""
        host = MockCRUDHost(
            confirm=True,
            observation_data='{"resourceType": "Observation", "status": "final"}',
        )

        mock_new = MagicMock()
        mock_new.id = "OBS-OK"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        self.assertEqual(host.results["data"]["created_observation"]["id"], "OBS-OK")

    @patch("oida.protocols.fhir.mixins.crud.observation")
    def test_create_observation_failure(self, mock_obs):
        """Test failed observation creation"""
        host = MockCRUDHost(
            confirm=True,
            observation_data='{"resourceType": "Observation"}',
        )

        mock_new = MagicMock()
        mock_new.create.return_value = None
        mock_obs.Observation.return_value = mock_new

        host._create_observation()
        host.logger.fail.assert_called_with("Failed to create Observation")

    @patch("oida.protocols.fhir.mixins.crud.observation")
    def test_create_observation_exception(self, mock_obs):
        """Test exception during observation creation"""
        host = MockCRUDHost(
            confirm=True,
            observation_data='{"resourceType": "Observation"}',
        )

        mock_obs.Observation.side_effect = Exception("Validation error")

        host._create_observation()
        host.logger.fail.assert_called()
        self.assertIn("error", host.results["data"]["created_observation"])

    @patch("oida.protocols.fhir.mixins.crud.observation")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_observation_value_non_numeric(self, mock_builder, mock_obs):
        """Test non-numeric observation value kept as string"""
        host = MockCRUDHost(
            confirm=True,
            patient_id="PT001",
            observation_value="positive",
        )

        mock_builder.build_observation.return_value = {"resourceType": "Observation"}
        mock_new = MagicMock()
        mock_new.id = "OBS-STR"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        call_kwargs = mock_builder.build_observation.call_args[1]
        # "positive" can't be float, so it stays as the original string
        self.assertEqual(call_kwargs["value"], "positive")

    @patch("oida.protocols.fhir.mixins.crud.observation")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_observation_value_numeric_conversion(self, mock_builder, mock_obs):
        """Test numeric observation value is converted to float"""
        host = MockCRUDHost(
            confirm=True,
            patient_id="PT001",
            observation_value="98.6",
        )

        mock_builder.build_observation.return_value = {"resourceType": "Observation"}
        mock_new = MagicMock()
        mock_new.id = "OBS-NUM"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        call_kwargs = mock_builder.build_observation.call_args[1]
        self.assertEqual(call_kwargs["value"], 98.6)

    @patch("oida.protocols.fhir.mixins.crud.observation")
    @patch("oida.protocols.fhir.mixins.crud.FHIRResourceBuilder")
    def test_observation_default_value_when_none(self, mock_builder, mock_obs):
        """Test default value of 72 when no observation_value provided"""
        host = MockCRUDHost(
            confirm=True,
            patient_id="PT001",
            observation_value=None,
        )

        mock_builder.build_observation.return_value = {"resourceType": "Observation"}
        mock_new = MagicMock()
        mock_new.id = "OBS-DEF"
        mock_new.create.return_value = True
        mock_obs.Observation.return_value = mock_new

        host._create_observation()

        call_kwargs = mock_builder.build_observation.call_args[1]
        self.assertEqual(call_kwargs["value"], 72)


if __name__ == "__main__":
    unittest.main()
