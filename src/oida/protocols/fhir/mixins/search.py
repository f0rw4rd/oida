"""
FHIR Search Mixin

Provides resource search and display functionality for all FHIR resource types.
"""

import os
from typing import Any, Dict, List

from ..helpers import (
    allergyintolerance,
    condition,
    device,
    diagnosticreport,
    documentreference,
    encounter,
    immunization,
    location,
    medicationrequest,
    observation,
    organization,
    patient,
    practitioner,
    procedure,
    servicerequest,
)
from ..resources import FHIRResourceParser

# Above this many patient records returned for an *unauthenticated* request we
# flag likely unrestricted access. Only meaningful when no credentials/token
# were supplied -- an authorized token routinely returns far more.
UNRESTRICTED_PATIENT_THRESHOLD = 10


class SearchMixin:
    """Mixin providing FHIR resource search operations."""

    def _apply_search_modifiers(self, search_params: Dict[str, Any]):
        """Apply common FHIR search modifiers from CLI args to search params.

        Handles --include, --revinclude, --elements, --summary.
        """
        include = getattr(self.args, "include", None)
        if include:
            search_params["_include"] = include

        revinclude = getattr(self.args, "revinclude", None)
        if revinclude:
            search_params["_revinclude"] = revinclude

        elements = getattr(self.args, "elements", None)
        if elements:
            search_params["_elements"] = elements

        summary = getattr(self.args, "summary", None)
        if summary:
            search_params["_summary"] = summary

    def _save_response_if_requested(self, data: Any):
        """Save raw response data to file if --save-response is set."""
        save_path = getattr(self.args, "save_response", None)
        if not save_path:
            return
        try:
            from oida.utils.common_types import safe_file_path
            from oida.utils.export_utils import export_json

            save_path = safe_file_path(save_path)
            output_dir = os.path.dirname(save_path) or "."
            filename = os.path.basename(save_path)
            export_json(data, output_dir, filename, logger=self.logger)
        except Exception as e:
            self.logger.warning(f"Failed to save response: {e}")

    def _search_patients(self):
        """Search for Patient resources"""
        self.logger.display("Searching for Patient resources...")

        try:
            search_params = {}
            max_results = getattr(self.args, "max_results", 100)

            # Add search filters if provided
            patient_name = getattr(self.args, "patient_name", None)
            if patient_name:
                search_params["name"] = patient_name

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["_id"] = patient_id

            patient_dob = getattr(self.args, "patient_dob", None)
            if patient_dob:
                search_params["birthdate"] = patient_dob

            patient_gender = getattr(self.args, "patient_gender", None)
            if patient_gender:
                search_params["gender"] = patient_gender

            # Apply common FHIR search modifiers
            self._apply_search_modifiers(search_params)

            # Use wildcard if --wildcard flag and no specific search params given
            has_specific_params = any(
                k not in ("_count", "_include", "_revinclude", "_elements", "_summary")
                for k in search_params
            )
            if getattr(self.args, "wildcard", False) and not has_specific_params:
                search_params["_count"] = str(max_results)
                # Wildcard enumeration: iterate through a-z name prefixes
                all_patients = []
                seen_ids = set()
                for letter in "abcdefghijklmnopqrstuvwxyz":
                    if len(all_patients) >= max_results:
                        break
                    prefix_params = dict(search_params)
                    prefix_params["name"] = letter
                    try:
                        search = patient.Patient.where(struct=prefix_params)
                        results = search.perform_resources(self.smart_client.server)
                        if results:
                            for p in results:
                                pid = getattr(p, "id", None)
                                if pid and pid not in seen_ids:
                                    seen_ids.add(pid)
                                    all_patients.append(p)
                    except Exception as e:
                        self.logger.debug(f"Wildcard search '{letter}' failed: {e}")

                if all_patients:
                    parsed = [
                        FHIRResourceParser.parse_patient(p) for p in all_patients[:max_results]
                    ]
                    self._display_patient_results(parsed)
                    self.results["data"]["patients"] = {
                        "count": len(parsed),
                        "records": parsed,
                    }
                else:
                    self.logger.display("  No patients found (wildcard)")
                return
            else:
                search_params["_count"] = str(max_results)

            # Perform search
            search = patient.Patient.where(struct=search_params)
            patients = search.perform_resources(self.smart_client.server)

            if patients:
                parsed = [FHIRResourceParser.parse_patient(p) for p in patients]
                self._display_patient_results(parsed)
                self.results["data"]["patients"] = {
                    "count": len(parsed),
                    "records": parsed,
                }

                # Security finding only when an *unauthenticated* search returns
                # a large result set. With supplied auth a big count is expected,
                # so gate on the absence of credentials/token to avoid false
                # positives on authorized access.
                supplied_auth = bool(
                    getattr(self.args, "username", None)
                    or getattr(self.args, "password", None)
                    or getattr(self.args, "token", None)
                )
                if not supplied_auth and len(parsed) > UNRESTRICTED_PATIENT_THRESHOLD:
                    self.results["data"].setdefault("security_findings", []).append(
                        {
                            "operation": "Patient Search",
                            "issue": "Unrestricted Patient Access",
                            "description": (
                                f"Unauthenticated search returned {len(parsed)} patient "
                                f"records (> {UNRESTRICTED_PATIENT_THRESHOLD})"
                            ),
                        }
                    )
            else:
                self.logger.display("  No patients found")

        except Exception as e:
            self.logger.warning(f"Patient search failed: {e}")
            self.results["data"]["patients"] = {"error": str(e)}

    def _display_patient_results(self, patients: List[Dict]):
        """Display patient search results in table format"""
        from ....utils.export_utils import print_table

        if not patients:
            self.logger.display("  No patients found")
            return

        column_defs = [
            ("id", "ID"),
            ("name", "Name"),
            ("birth_date", "DOB"),
            ("gender", "Gender"),
            ("phone", "Phone"),
            ("address", "Address"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(p.get(k) for p in patients)]
        rows = [[p.get(k, "") for k, _ in active_columns] for p in patients]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(patients)} patient(s) found")

    def _search_observations(self):
        """Search for Observation resources"""
        self.logger.display("Searching for Observation resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            date_from = getattr(self.args, "date_from", None)
            if date_from:
                search_params["date"] = f"ge{date_from}"

            date_to = getattr(self.args, "date_to", None)
            if date_to:
                if "date" in search_params:
                    # Both bounds: emit a repeated `date` param (date=ge..&date=le..).
                    # A bare two-element list value raises TypeError in
                    # fhirclient's as_parameter(); the $and combinator round-trips.
                    search_params["date"] = {"$and": [search_params["date"], f"le{date_to}"]}
                else:
                    search_params["date"] = f"le{date_to}"

            code_filter = getattr(self.args, "code", None)
            if code_filter:
                search_params["code"] = code_filter

            category_filter = getattr(self.args, "category", None)
            if category_filter:
                search_params["category"] = category_filter

            self._apply_search_modifiers(search_params)

            search = observation.Observation.where(struct=search_params)
            observations = search.perform_resources(self.smart_client.server)

            if observations:
                parsed = [FHIRResourceParser.parse_observation(o) for o in observations]
                self._display_observation_results(parsed)
                self.results["data"]["observations"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No observations found")

        except Exception as e:
            self.logger.warning(f"Observation search failed: {e}")
            self.results["data"]["observations"] = {"error": str(e)}

    def _display_observation_results(self, observations: List[Dict]):
        """Display observation search results"""
        from ....utils.export_utils import print_table

        if not observations:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("code", "Code"),
            ("display", "Name"),
            ("value", "Value"),
            ("unit", "Unit"),
            ("effective_date", "Date"),
            ("status", "Status"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(o.get(k) for o in observations)]
        rows = [[o.get(k, "") for k, _ in active_columns] for o in observations]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(observations)} observation(s) found")

    def _search_medications(self):
        """Search for MedicationRequest resources"""
        self.logger.display("Searching for MedicationRequest resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = medicationrequest.MedicationRequest.where(struct=search_params)
            medications = search.perform_resources(self.smart_client.server)

            if medications:
                parsed = [FHIRResourceParser.parse_medication_request(m) for m in medications]
                self._display_medication_results(parsed)
                self.results["data"]["medications"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No medication requests found")

        except Exception as e:
            self.logger.warning(f"MedicationRequest search failed: {e}")
            self.results["data"]["medications"] = {"error": str(e)}

    def _display_medication_results(self, medications: List[Dict]):
        """Display medication search results"""
        from ....utils.export_utils import print_table

        if not medications:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("medication", "Medication"),
            ("dosage", "Dosage"),
            ("status", "Status"),
            ("authored_on", "Date"),
            ("requester", "Requester"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(m.get(k) for m in medications)]
        rows = [[m.get(k, "") for k, _ in active_columns] for m in medications]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(medications)} medication(s) found")

    def _search_conditions(self):
        """Search for Condition resources"""
        self.logger.display("Searching for Condition resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = condition.Condition.where(struct=search_params)
            conditions = search.perform_resources(self.smart_client.server)

            if conditions:
                parsed = [FHIRResourceParser.parse_condition(c) for c in conditions]
                self._display_condition_results(parsed)
                self.results["data"]["conditions"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No conditions found")

        except Exception as e:
            self.logger.warning(f"Condition search failed: {e}")
            self.results["data"]["conditions"] = {"error": str(e)}

    def _display_condition_results(self, conditions: List[Dict]):
        """Display condition search results"""
        from ....utils.export_utils import print_table

        if not conditions:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("code", "Code"),
            ("display", "Condition"),
            ("clinical_status", "Status"),
            ("onset_date", "Onset"),
            ("recorded_date", "Recorded"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(c.get(k) for c in conditions)]
        rows = [[c.get(k, "") for k, _ in active_columns] for c in conditions]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(conditions)} condition(s) found")

    def _search_encounters(self):
        """Search for Encounter resources"""
        self.logger.display("Searching for Encounter resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = encounter.Encounter.where(struct=search_params)
            encounters = search.perform_resources(self.smart_client.server)

            if encounters:
                parsed = [FHIRResourceParser.parse_encounter(e) for e in encounters]
                self._display_encounter_results(parsed)
                self.results["data"]["encounters"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No encounters found")

        except Exception as e:
            self.logger.warning(f"Encounter search failed: {e}")
            self.results["data"]["encounters"] = {"error": str(e)}

    def _display_encounter_results(self, encounters: List[Dict]):
        """Display encounter search results"""
        from ....utils.export_utils import print_table

        if not encounters:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("class_code", "Class"),
            ("type_display", "Type"),
            ("status", "Status"),
            ("period_start", "Start"),
            ("period_end", "End"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(e.get(k) for e in encounters)]
        rows = [[e.get(k, "") for k, _ in active_columns] for e in encounters]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(encounters)} encounter(s) found")

    def _search_procedures(self):
        """Search for Procedure resources"""
        self.logger.display("Searching for Procedure resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = procedure.Procedure.where(struct=search_params)
            procedures = search.perform_resources(self.smart_client.server)

            if procedures:
                parsed = [FHIRResourceParser.parse_procedure(p) for p in procedures]
                self._display_procedure_results(parsed)
                self.results["data"]["procedures"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No procedures found")

        except Exception as e:
            self.logger.warning(f"Procedure search failed: {e}")
            self.results["data"]["procedures"] = {"error": str(e)}

    def _display_procedure_results(self, procedures: List[Dict]):
        """Display procedure search results"""
        from ....utils.export_utils import print_table

        if not procedures:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("code", "Code"),
            ("display", "Procedure"),
            ("status", "Status"),
            ("performed_date", "Date"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(p.get(k) for p in procedures)]
        rows = [[p.get(k, "") for k, _ in active_columns] for p in procedures]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(procedures)} procedure(s) found")

    def _search_allergies(self):
        """Search for AllergyIntolerance resources"""
        self.logger.display("Searching for AllergyIntolerance resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = allergyintolerance.AllergyIntolerance.where(struct=search_params)
            allergies = search.perform_resources(self.smart_client.server)

            if allergies:
                parsed = [FHIRResourceParser.parse_allergy(a) for a in allergies]
                self._display_allergy_results(parsed)
                self.results["data"]["allergies"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No allergies found")

        except Exception as e:
            self.logger.warning(f"AllergyIntolerance search failed: {e}")
            self.results["data"]["allergies"] = {"error": str(e)}

    def _display_allergy_results(self, allergies: List[Dict]):
        """Display allergy search results"""
        from ....utils.export_utils import print_table

        if not allergies:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("substance", "Substance"),
            ("clinical_status", "Status"),
            ("criticality", "Criticality"),
            ("category", "Category"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(a.get(k) for a in allergies)]
        rows = [[a.get(k, "") for k, _ in active_columns] for a in allergies]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(allergies)} allergy(s) found")

    def _search_immunizations(self):
        """Search for Immunization resources"""
        self.logger.display("Searching for Immunization resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = immunization.Immunization.where(struct=search_params)
            immunizations = search.perform_resources(self.smart_client.server)

            if immunizations:
                parsed = [FHIRResourceParser.parse_immunization(i) for i in immunizations]
                self._display_immunization_results(parsed)
                self.results["data"]["immunizations"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No immunizations found")

        except Exception as e:
            self.logger.warning(f"Immunization search failed: {e}")
            self.results["data"]["immunizations"] = {"error": str(e)}

    def _display_immunization_results(self, immunizations: List[Dict]):
        """Display immunization search results"""
        from ....utils.export_utils import print_table

        if not immunizations:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("vaccine_code", "Vaccine"),
            ("occurrence_date", "Date"),
            ("status", "Status"),
            ("lot_number", "Lot"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(i.get(k) for i in immunizations)]
        rows = [[i.get(k, "") for k, _ in active_columns] for i in immunizations]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(immunizations)} immunization(s) found")

    def _search_diagnostic_reports(self):
        """Search for DiagnosticReport resources"""
        self.logger.display("Searching for DiagnosticReport resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = diagnosticreport.DiagnosticReport.where(struct=search_params)
            reports = search.perform_resources(self.smart_client.server)

            if reports:
                parsed = [FHIRResourceParser.parse_diagnostic_report(r) for r in reports]
                self._display_diagnostic_results(parsed)
                self.results["data"]["diagnostic_reports"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No diagnostic reports found")

        except Exception as e:
            self.logger.warning(f"DiagnosticReport search failed: {e}")
            self.results["data"]["diagnostic_reports"] = {"error": str(e)}

    def _display_diagnostic_results(self, reports: List[Dict]):
        """Display diagnostic report search results"""
        from ....utils.export_utils import print_table

        if not reports:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("code", "Code"),
            ("display", "Report"),
            ("status", "Status"),
            ("issued", "Issued"),
            ("category", "Category"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(r.get(k) for r in reports)]
        rows = [[r.get(k, "") for k, _ in active_columns] for r in reports]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(reports)} diagnostic report(s) found")

    def _search_documents(self):
        """Search for DocumentReference resources"""
        self.logger.display("Searching for DocumentReference resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = documentreference.DocumentReference.where(struct=search_params)
            documents = search.perform_resources(self.smart_client.server)

            if documents:
                parsed = [FHIRResourceParser.parse_document_reference(d) for d in documents]
                self._display_document_results(parsed)
                self.results["data"]["documents"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No documents found")

        except Exception as e:
            self.logger.warning(f"DocumentReference search failed: {e}")
            self.results["data"]["documents"] = {"error": str(e)}

    def _display_document_results(self, documents: List[Dict]):
        """Display document search results"""
        from ....utils.export_utils import print_table

        if not documents:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("type_display", "Type"),
            ("status", "Status"),
            ("date", "Date"),
            ("content_type", "Content Type"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(doc.get(k) for doc in documents)]
        rows = [[doc.get(k, "") for k, _ in active_columns] for doc in documents]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(documents)} document(s) found")

    def _read_resource(self, resource_type: str, resource_id: str):
        """Read a specific resource by ID"""
        self.logger.display(f"Reading {resource_type}/{resource_id}...")

        try:
            # Only the five resource types reachable from --read-* CLI args.
            resource_models = {
                "Patient": patient.Patient,
                "Observation": observation.Observation,
                "MedicationRequest": medicationrequest.MedicationRequest,
                "Condition": condition.Condition,
                "Encounter": encounter.Encounter,
            }

            model = resource_models.get(resource_type)
            if not model:
                self.logger.warning(f"Unsupported resource type: {resource_type}")
                return

            resource = model.read(resource_id, self.smart_client.server)

            if resource:
                if resource_type == "Patient":
                    parsed = FHIRResourceParser.parse_patient(resource)
                elif resource_type == "Observation":
                    parsed = FHIRResourceParser.parse_observation(resource)
                elif resource_type == "MedicationRequest":
                    parsed = FHIRResourceParser.parse_medication_request(resource)
                elif resource_type == "Condition":
                    parsed = FHIRResourceParser.parse_condition(resource)
                else:
                    parsed = {"id": resource_id, "type": resource_type}

                self.logger.success(f"Found {resource_type}/{resource_id}")
                for key, value in parsed.items():
                    if value:
                        self.logger.display(f"  {key}: {value}")

                self.results["data"][f"read_{resource_type.lower()}"] = parsed
            else:
                self.logger.warning(f"{resource_type}/{resource_id} not found")

        except Exception as e:
            self.logger.warning(f"Failed to read {resource_type}/{resource_id}: {e}")

    # =========================================================================
    # Additional Resource Searches (Priority 1)
    # =========================================================================

    def _search_practitioners(self):
        """Search for Practitioner resources"""
        self.logger.display("Searching for Practitioner resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            name = getattr(self.args, "practitioner_name", None)
            if name:
                search_params["name"] = name

            self._apply_search_modifiers(search_params)

            search = practitioner.Practitioner.where(struct=search_params)
            practitioners = search.perform_resources(self.smart_client.server)

            if practitioners:
                parsed = [FHIRResourceParser.parse_practitioner(p) for p in practitioners]
                self._display_practitioner_results(parsed)
                self.results["data"]["practitioners"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No practitioners found")

        except Exception as e:
            self.logger.warning(f"Practitioner search failed: {e}")
            self.results["data"]["practitioners"] = {"error": str(e)}

    def _display_practitioner_results(self, practitioners: List[Dict]):
        """Display practitioner search results"""
        from ....utils.export_utils import print_table

        if not practitioners:
            return

        column_defs = [
            ("id", "ID"),
            ("name", "Name"),
            ("gender", "Gender"),
            ("phone", "Phone"),
            ("email", "Email"),
            ("qualifications", "Qualifications"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(p.get(k) for p in practitioners)]
        rows = []
        for p in practitioners:
            row = []
            for k, _ in active_columns:
                val = p.get(k, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                row.append(val)
            rows.append(row)
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(practitioners)} practitioner(s) found")

    def _search_organizations(self):
        """Search for Organization resources"""
        self.logger.display("Searching for Organization resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            name = getattr(self.args, "organization_name", None)
            if name:
                search_params["name"] = name

            self._apply_search_modifiers(search_params)

            search = organization.Organization.where(struct=search_params)
            organizations = search.perform_resources(self.smart_client.server)

            if organizations:
                parsed = [FHIRResourceParser.parse_organization(o) for o in organizations]
                self._display_organization_results(parsed)
                self.results["data"]["organizations"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No organizations found")

        except Exception as e:
            self.logger.warning(f"Organization search failed: {e}")
            self.results["data"]["organizations"] = {"error": str(e)}

    def _display_organization_results(self, organizations: List[Dict]):
        """Display organization search results"""
        from ....utils.export_utils import print_table

        if not organizations:
            return

        column_defs = [
            ("id", "ID"),
            ("name", "Name"),
            ("type_display", "Type"),
            ("phone", "Phone"),
            ("address", "Address"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(o.get(k) for o in organizations)]
        rows = [[o.get(k, "") for k, _ in active_columns] for o in organizations]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(organizations)} organization(s) found")

    def _search_locations(self):
        """Search for Location resources"""
        self.logger.display("Searching for Location resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            name = getattr(self.args, "location_name", None)
            if name:
                search_params["name"] = name

            self._apply_search_modifiers(search_params)

            search = location.Location.where(struct=search_params)
            locations = search.perform_resources(self.smart_client.server)

            if locations:
                parsed = [FHIRResourceParser.parse_location(loc) for loc in locations]
                self._display_location_results(parsed)
                self.results["data"]["locations"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No locations found")

        except Exception as e:
            self.logger.warning(f"Location search failed: {e}")
            self.results["data"]["locations"] = {"error": str(e)}

    def _display_location_results(self, locations: List[Dict]):
        """Display location search results"""
        from ....utils.export_utils import print_table

        if not locations:
            return

        column_defs = [
            ("id", "ID"),
            ("name", "Name"),
            ("status", "Status"),
            ("mode", "Mode"),
            ("type_display", "Type"),
            ("address", "Address"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(loc.get(k) for loc in locations)]
        rows = [[loc.get(k, "") for k, _ in active_columns] for loc in locations]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(locations)} location(s) found")

    def _search_devices(self):
        """Search for Device resources"""
        self.logger.display("Searching for Device resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            device_type = getattr(self.args, "device_type", None)
            if device_type:
                search_params["type"] = device_type

            self._apply_search_modifiers(search_params)

            search = device.Device.where(struct=search_params)
            devices = search.perform_resources(self.smart_client.server)

            if devices:
                parsed = [FHIRResourceParser.parse_device(d) for d in devices]
                self._display_device_results(parsed)
                self.results["data"]["devices"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No devices found")

        except Exception as e:
            self.logger.warning(f"Device search failed: {e}")
            self.results["data"]["devices"] = {"error": str(e)}

    def _display_device_results(self, devices: List[Dict]):
        """Display device search results"""
        from ....utils.export_utils import print_table

        if not devices:
            return

        column_defs = [
            ("id", "ID"),
            ("device_name", "Name"),
            ("type_display", "Type"),
            ("manufacturer", "Manufacturer"),
            ("model", "Model"),
            ("serial_number", "Serial"),
            ("status", "Status"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(dev.get(k) for dev in devices)]
        rows = [[dev.get(k, "") for k, _ in active_columns] for dev in devices]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(devices)} device(s) found")

    def _search_orders(self):
        """Search for ServiceRequest (order) resources"""
        self.logger.display("Searching for ServiceRequest resources...")

        try:
            search_params = {"_count": str(getattr(self.args, "max_results", 100))}

            patient_id = getattr(self.args, "patient_id", None)
            if patient_id:
                search_params["patient"] = patient_id

            self._apply_search_modifiers(search_params)

            search = servicerequest.ServiceRequest.where(struct=search_params)
            orders = search.perform_resources(self.smart_client.server)

            if orders:
                parsed = [FHIRResourceParser.parse_service_request(o) for o in orders]
                self._display_order_results(parsed)
                self.results["data"]["orders"] = {
                    "count": len(parsed),
                    "records": parsed,
                }
            else:
                self.logger.display("  No service requests found")

        except Exception as e:
            self.logger.warning(f"ServiceRequest search failed: {e}")
            self.results["data"]["orders"] = {"error": str(e)}

    def _display_order_results(self, orders: List[Dict]):
        """Display order search results"""
        from ....utils.export_utils import print_table

        if not orders:
            return

        column_defs = [
            ("id", "ID"),
            ("patient_id", "Patient"),
            ("code", "Code"),
            ("display", "Order"),
            ("status", "Status"),
            ("intent", "Intent"),
            ("authored_on", "Date"),
            ("requester", "Requester"),
        ]

        active_columns = [(k, d) for k, d in column_defs if any(o.get(k) for o in orders)]
        rows = [[o.get(k, "") for k, _ in active_columns] for o in orders]
        headers = [d for _, d in active_columns]

        print_table(rows, headers, logger=self.logger)
        self.logger.success(f"Total: {len(orders)} service request(s) found")
