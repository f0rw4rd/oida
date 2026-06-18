"""
FHIR CRUD Mixin

Provides create, update, and delete operations for FHIR resources.
"""

import json

from ..helpers import observation, patient
from ..resources import FHIRResourceBuilder


class CRUDMixin:
    """Mixin providing FHIR create/update/delete operations."""

    def _create_patient(self):
        """Create a test Patient resource"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operations require --confirm flag")
            return

        self.logger.display("Creating Patient resource...")

        try:
            patient_json = getattr(self.args, "patient_data", None)

            if patient_json:
                patient_data = json.loads(patient_json)
            else:
                patient_data = FHIRResourceBuilder.build_patient(
                    given_name=getattr(self.args, "patient_given_name", "") or "Test",
                    family_name=getattr(self.args, "patient_family_name", "") or "Patient",
                    birth_date=getattr(self.args, "patient_dob", "") or "1990-01-01",
                    gender=getattr(self.args, "patient_gender", "") or "unknown",
                )

            new_patient = patient.Patient(patient_data)
            result = new_patient.create(self.smart_client.server)

            if result:
                self.logger.success(f"Created Patient: {new_patient.id}")
                self.results["data"]["created_patient"] = {
                    "id": new_patient.id,
                    "data": patient_data,
                }
            else:
                self.logger.fail("Failed to create Patient")

        except Exception as e:
            self.logger.debug("create patient failed: %s", e)
            self.logger.fail(f"Create Patient failed: {e}")
            self.results["data"]["created_patient"] = {"error": str(e)}

    def _update_patient(self):
        """Update an existing Patient resource"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operations require --confirm flag")
            return

        patient_id = getattr(self.args, "update_patient", None)
        if not patient_id:
            self.logger.fail("No patient ID specified for update")
            return

        self.logger.display(f"Updating Patient/{patient_id}...")

        try:
            existing = patient.Patient.read(patient_id, self.smart_client.server)

            if not existing:
                self.logger.fail(f"Patient/{patient_id} not found")
                return

            patient_json = getattr(self.args, "patient_data", None)

            ALLOWED_PATIENT_FIELDS = {
                "name",
                "gender",
                "birthDate",
                "address",
                "telecom",
                "identifier",
                "active",
                "maritalStatus",
                "communication",
            }

            if patient_json:
                updates = json.loads(patient_json)
                for key, value in updates.items():
                    if key in ALLOWED_PATIENT_FIELDS:
                        setattr(existing, key, value)
                    else:
                        self.logger.warning(f"Skipping unknown field: {key}")
            else:
                given = getattr(self.args, "patient_given_name", None)
                family = getattr(self.args, "patient_family_name", None)

                if given or family:
                    from fhirclient.models.humanname import HumanName

                    name = HumanName()
                    if given:
                        name.given = [given]
                    if family:
                        name.family = family
                    name.use = "official"
                    existing.name = [name]

                dob = getattr(self.args, "patient_dob", None)
                if dob:
                    from fhirclient.models.fhirdate import FHIRDate

                    existing.birthDate = FHIRDate(dob)

                gender = getattr(self.args, "patient_gender", None)
                if gender:
                    existing.gender = gender

            result = existing.update(self.smart_client.server)

            if result:
                self.logger.success(f"Updated Patient/{patient_id}")
                self.results["data"]["updated_patient"] = {
                    "id": patient_id,
                    "success": True,
                }
            else:
                self.logger.fail(f"Failed to update Patient/{patient_id}")

        except Exception as e:
            self.logger.debug("update patient failed: %s", e)
            self.logger.fail(f"Update Patient failed: {e}")
            self.results["data"]["updated_patient"] = {"error": str(e)}

    def _delete_patient(self):
        """Delete a Patient resource"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operations require --confirm flag")
            return

        patient_id = getattr(self.args, "delete_patient", None)
        if not patient_id:
            self.logger.fail("No patient ID specified for delete")
            return

        self.logger.display(f"Deleting Patient/{patient_id}...")

        try:
            existing = patient.Patient.read(patient_id, self.smart_client.server)

            if not existing:
                self.logger.fail(f"Patient/{patient_id} not found")
                return

            existing.delete(self.smart_client.server)

            self.logger.success(f"Deleted Patient/{patient_id}")
            self.results["data"]["deleted_patient"] = {
                "id": patient_id,
                "success": True,
            }

        except Exception as e:
            self.logger.debug("delete patient failed: %s", e)
            self.logger.fail(f"Delete Patient failed: {e}")
            self.results["data"]["deleted_patient"] = {"error": str(e)}

    def _create_observation(self):
        """Create a test Observation resource"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("Write operations require --confirm flag")
            return

        self.logger.display("Creating Observation resource...")

        try:
            obs_json = getattr(self.args, "observation_data", None)

            if obs_json:
                obs_data = json.loads(obs_json)
            else:
                patient_id = getattr(self.args, "patient_id", None)
                if not patient_id:
                    self.logger.fail("--patient-id required for observation creation")
                    return

                obs_code = getattr(self.args, "observation_code", None) or "8867-4"
                obs_value = getattr(self.args, "observation_value", None)
                obs_unit = getattr(self.args, "observation_unit", None) or ""

                if obs_value:
                    try:
                        obs_value = float(obs_value)
                    except ValueError as e:
                        self.logger.debug("create observation failed: %s", e)
                        pass  # Keep as string

                obs_data = FHIRResourceBuilder.build_observation(
                    patient_reference=patient_id,
                    code=obs_code,
                    code_display=f"Test Observation {obs_code}",
                    value=obs_value or 72,
                    value_unit=obs_unit,
                    status="final",
                )

            new_obs = observation.Observation(obs_data)
            result = new_obs.create(self.smart_client.server)

            if result:
                self.logger.success(f"Created Observation: {new_obs.id}")
                self.results["data"]["created_observation"] = {
                    "id": new_obs.id,
                    "data": obs_data,
                }
            else:
                self.logger.fail("Failed to create Observation")

        except Exception as e:
            self.logger.debug("create observation failed: %s", e)
            self.logger.fail(f"Create Observation failed: {e}")
            self.results["data"]["created_observation"] = {"error": str(e)}
