"""
FHIR Resource Builder and Parser

Helper classes for building and parsing FHIR R4 resources.

FHIRResourceBuilder: Creates FHIR resources for testing
FHIRResourceParser: Parses FHIR responses into simplified dictionaries
"""

from datetime import datetime
from typing import Any, Dict


class FHIRResourceBuilder:
    """Build FHIR R4 resources for testing purposes"""

    @staticmethod
    def build_patient(
        patient_id: str = "",
        given_name: str = "",
        family_name: str = "",
        birth_date: str = "",
        gender: str = "",
        phone: str = "",
        email: str = "",
        address_line: str = "",
        city: str = "",
        state: str = "",
        postal_code: str = "",
        country: str = "",
        identifier_system: str = "http://hospital.example.org/mrn",
        identifier_value: str = "",
    ) -> Dict[str, Any]:
        """
        Build a Patient resource dictionary

        Args:
            patient_id: Logical resource ID
            given_name: Patient's given name (first name)
            family_name: Patient's family name (last name)
            birth_date: Date of birth (YYYY-MM-DD)
            gender: Administrative gender (male, female, other, unknown)
            phone: Phone number
            email: Email address
            address_line: Street address
            city: City
            state: State/Province
            postal_code: Postal/ZIP code
            country: Country
            identifier_system: System URI for identifier
            identifier_value: Identifier value (e.g., MRN)

        Returns:
            Dict representing FHIR Patient resource
        """
        patient: Dict[str, Any] = {
            "resourceType": "Patient",
            "id": patient_id,
        }

        # Identifier (MRN)
        if identifier_value:
            patient["identifier"] = [
                {
                    "system": identifier_system,
                    "value": identifier_value,
                }
            ]

        # Name
        if given_name or family_name:
            name: Dict[str, Any] = {"use": "official"}
            if family_name:
                name["family"] = family_name
            if given_name:
                name["given"] = [given_name]
            patient["name"] = [name]

        # Gender
        if gender:
            patient["gender"] = gender

        # Birth date
        if birth_date:
            patient["birthDate"] = birth_date

        # Telecom
        telecoms = []
        if phone:
            telecoms.append(
                {
                    "system": "phone",
                    "value": phone,
                    "use": "home",
                }
            )
        if email:
            telecoms.append(
                {
                    "system": "email",
                    "value": email,
                }
            )
        if telecoms:
            patient["telecom"] = telecoms

        # Address
        if address_line or city or state or postal_code:
            address: Dict[str, Any] = {"use": "home"}
            if address_line:
                address["line"] = [address_line]
            if city:
                address["city"] = city
            if state:
                address["state"] = state
            if postal_code:
                address["postalCode"] = postal_code
            if country:
                address["country"] = country
            patient["address"] = [address]

        return patient

    @staticmethod
    def build_observation(
        observation_id: str = "",
        patient_reference: str = "",
        code: str = "",
        code_display: str = "",
        code_system: str = "http://loinc.org",
        value: Any = None,
        value_unit: str = "",
        value_code: str = "",
        value_system: str = "http://unitsofmeasure.org",
        status: str = "final",
        effective_datetime: str = "",
        category_code: str = "laboratory",
        category_system: str = "http://terminology.hl7.org/CodeSystem/observation-category",
    ) -> Dict[str, Any]:
        """
        Build an Observation resource dictionary

        Args:
            observation_id: Logical resource ID
            patient_reference: Patient reference (e.g., "Patient/123")
            code: Observation code (e.g., LOINC code)
            code_display: Display name for the code
            code_system: Code system URI
            value: Observation value (numeric or string)
            value_unit: Unit display text
            value_code: Unit code
            value_system: Unit system URI
            status: Observation status
            effective_datetime: When observation was made (ISO datetime)
            category_code: Category code
            category_system: Category system URI

        Returns:
            Dict representing FHIR Observation resource
        """
        obs: Dict[str, Any] = {
            "resourceType": "Observation",
            "id": observation_id,
            "status": status,
        }

        # Category
        if category_code:
            obs["category"] = [
                {
                    "coding": [
                        {
                            "system": category_system,
                            "code": category_code,
                        }
                    ]
                }
            ]

        # Code
        if code:
            obs["code"] = {
                "coding": [
                    {
                        "system": code_system,
                        "code": code,
                        "display": code_display,
                    }
                ]
            }

        # Subject (patient reference)
        if patient_reference:
            if not patient_reference.startswith("Patient/"):
                patient_reference = f"Patient/{patient_reference}"
            obs["subject"] = {"reference": patient_reference}

        # Effective datetime
        if effective_datetime:
            obs["effectiveDateTime"] = effective_datetime
        else:
            obs["effectiveDateTime"] = datetime.now().isoformat()

        # Value
        if value is not None:
            if isinstance(value, (int, float)):
                obs["valueQuantity"] = {
                    "value": value,
                    "unit": value_unit,
                    "system": value_system,
                    "code": value_code or value_unit,
                }
            else:
                obs["valueString"] = str(value)

        return obs


class FHIRResourceParser:
    """Parse FHIR R4 resources into simplified dictionaries"""

    @staticmethod
    def _format_fhir_date(date_obj: Any) -> str:
        """
        Convert a FHIR date/datetime object to a YYYY-MM-DD string.

        Args:
            date_obj: FHIRDate, FHIRDateTime, or other date object

        Returns:
            Formatted date string (date-only) or empty string
        """
        if not date_obj:
            return ""
        # Try isostring property (FHIRDate/FHIRDateTime)
        if hasattr(date_obj, "isostring") and date_obj.isostring:
            result = date_obj.isostring
        # Try date property
        elif hasattr(date_obj, "date") and date_obj.date:
            result = str(date_obj.date)
        # Fall back to string conversion, but check for object representation
        else:
            result = str(date_obj)
            # Detect if we got a useless object repr instead of actual date
            if result.startswith("<") or "object at" in result:
                return ""
        # Return date-only portion (YYYY-MM-DD)
        if len(result) >= 10:
            return str(result[:10])
        return str(result)

    @staticmethod
    def _get_reference_id(reference: str) -> str:
        """Extract ID from FHIR reference (e.g., 'Patient/123' -> '123')"""
        if not reference:
            return ""
        if "/" in reference:
            return reference.split("/")[-1]
        return reference

    @staticmethod
    def _get_coding_display(codeable_concept: Any) -> str:
        """Extract display text from CodeableConcept"""
        if not codeable_concept:
            return ""
        if hasattr(codeable_concept, "text") and codeable_concept.text:
            return str(codeable_concept.text)
        if hasattr(codeable_concept, "coding") and codeable_concept.coding:
            for coding in codeable_concept.coding:
                if hasattr(coding, "display") and coding.display:
                    return str(coding.display)
        return ""

    @staticmethod
    def _get_coding_code(codeable_concept: Any) -> str:
        """Extract code from CodeableConcept"""
        if not codeable_concept:
            return ""
        if hasattr(codeable_concept, "coding") and codeable_concept.coding:
            for coding in codeable_concept.coding:
                if hasattr(coding, "code") and coding.code:
                    return str(coding.code)
        return ""

    @staticmethod
    def _format_name(name_list: Any) -> str:
        """Format HumanName list to string"""
        if not name_list:
            return ""
        for name in name_list:
            parts = []
            if hasattr(name, "given") and name.given:
                parts.extend(name.given)
            if hasattr(name, "family") and name.family:
                parts.append(name.family)
            if parts:
                return " ".join(parts)
        return ""

    @staticmethod
    def _format_address(address_list: Any) -> str:
        """Format Address list to string"""
        if not address_list:
            return ""
        for addr in address_list:
            parts = []
            if hasattr(addr, "line") and addr.line:
                parts.extend(addr.line)
            if hasattr(addr, "city") and addr.city:
                parts.append(addr.city)
            if hasattr(addr, "state") and addr.state:
                parts.append(addr.state)
            if hasattr(addr, "postalCode") and addr.postalCode:
                parts.append(addr.postalCode)
            if parts:
                return ", ".join(parts)
        return ""

    @staticmethod
    def _get_telecom(telecom_list: Any, system: str) -> str:
        """Get telecom value by system (phone, email, etc.)"""
        if not telecom_list:
            return ""
        for telecom in telecom_list:
            if hasattr(telecom, "system") and telecom.system == system:
                return getattr(telecom, "value", "")
        return ""

    @classmethod
    def parse_patient(cls, patient: Any) -> Dict[str, Any]:
        """
        Parse Patient resource to simplified dict

        Args:
            patient: FHIR Patient resource object

        Returns:
            Dict with patient information
        """
        # Get birth date - handle FHIRDate objects
        birth_date = getattr(patient, "birthDate", "")
        if birth_date and hasattr(birth_date, "isostring"):
            birth_date = birth_date.isostring
        elif birth_date and hasattr(birth_date, "date"):
            birth_date = str(birth_date.date)
        elif birth_date:
            birth_date = str(birth_date)

        result: Dict[str, Any] = {
            "id": getattr(patient, "id", ""),
            "name": cls._format_name(getattr(patient, "name", [])),
            "birth_date": birth_date,
            "gender": getattr(patient, "gender", ""),
            "phone": cls._get_telecom(getattr(patient, "telecom", []), "phone"),
            "email": cls._get_telecom(getattr(patient, "telecom", []), "email"),
            "address": cls._format_address(getattr(patient, "address", [])),
        }

        # Identifiers
        identifiers = []
        if hasattr(patient, "identifier") and patient.identifier:
            for ident in patient.identifier:
                system = getattr(ident, "system", "")
                value = getattr(ident, "value", "")
                if value:
                    identifiers.append(f"{system}|{value}" if system else value)
        result["identifiers"] = identifiers

        # MRN (common identifier)
        for ident in identifiers:
            if "mrn" in ident.lower() or "medical" in ident.lower():
                result["mrn"] = ident.split("|")[-1] if "|" in ident else ident
                break

        return result

    @classmethod
    def parse_observation(cls, observation: Any) -> Dict[str, Any]:
        """
        Parse Observation resource to simplified dict

        Args:
            observation: FHIR Observation resource object

        Returns:
            Dict with observation information
        """
        result: Dict[str, Any] = {
            "id": getattr(observation, "id", ""),
            "status": getattr(observation, "status", ""),
            "code": cls._get_coding_code(getattr(observation, "code", None)),
            "display": cls._get_coding_display(getattr(observation, "code", None)),
            "value": "",
            "unit": "",
            "effective_date": "",
            "patient_id": "",
            "category": "",
        }

        # Patient reference
        if hasattr(observation, "subject") and observation.subject:
            ref = getattr(observation.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Value
        if hasattr(observation, "valueQuantity") and observation.valueQuantity:
            vq = observation.valueQuantity
            result["value"] = getattr(vq, "value", "")
            result["unit"] = getattr(vq, "unit", "") or getattr(vq, "code", "")
        elif hasattr(observation, "valueString") and observation.valueString:
            result["value"] = observation.valueString
        elif hasattr(observation, "valueCodeableConcept") and observation.valueCodeableConcept:
            result["value"] = cls._get_coding_display(observation.valueCodeableConcept)

        # Effective datetime
        if hasattr(observation, "effectiveDateTime") and observation.effectiveDateTime:
            result["effective_date"] = cls._format_fhir_date(observation.effectiveDateTime)
        elif hasattr(observation, "effectivePeriod") and observation.effectivePeriod:
            result["effective_date"] = cls._format_fhir_date(
                getattr(observation.effectivePeriod, "start", None)
            )

        # Category
        if hasattr(observation, "category") and observation.category:
            for cat in observation.category:
                result["category"] = cls._get_coding_display(cat)
                break

        return result

    @classmethod
    def parse_medication_request(cls, med_request: Any) -> Dict[str, Any]:
        """
        Parse MedicationRequest resource to simplified dict

        Args:
            med_request: FHIR MedicationRequest resource object

        Returns:
            Dict with medication request information
        """
        result: Dict[str, Any] = {
            "id": getattr(med_request, "id", ""),
            "status": getattr(med_request, "status", ""),
            "intent": getattr(med_request, "intent", ""),
            "medication": "",
            "medication_code": "",
            "dosage": "",
            "authored_on": "",
            "patient_id": "",
            "requester": "",
        }

        # Medication
        med_cc = getattr(med_request, "medicationCodeableConcept", None)
        if med_cc:
            result["medication"] = cls._get_coding_display(med_cc)
            result["medication_code"] = cls._get_coding_code(med_cc)
        elif hasattr(med_request, "medicationReference") and med_request.medicationReference:
            result["medication"] = getattr(med_request.medicationReference, "display", "")

        # Patient
        if hasattr(med_request, "subject") and med_request.subject:
            ref = getattr(med_request.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Authored on
        if hasattr(med_request, "authoredOn") and med_request.authoredOn:
            result["authored_on"] = cls._format_fhir_date(med_request.authoredOn)

        # Requester
        if hasattr(med_request, "requester") and med_request.requester:
            requester = med_request.requester
            display = getattr(requester, "display", "")
            ref = cls._get_reference_id(getattr(requester, "reference", ""))
            result["requester"] = display or ref

        # Dosage
        if hasattr(med_request, "dosageInstruction") and med_request.dosageInstruction:
            dosages = []
            for dosage in med_request.dosageInstruction:
                if hasattr(dosage, "text") and dosage.text:
                    dosages.append(dosage.text)
            result["dosage"] = "; ".join(dosages)

        return result

    @classmethod
    def parse_condition(cls, condition: Any) -> Dict[str, Any]:
        """
        Parse Condition resource to simplified dict

        Args:
            condition: FHIR Condition resource object

        Returns:
            Dict with condition information
        """
        result: Dict[str, Any] = {
            "id": getattr(condition, "id", ""),
            "code": cls._get_coding_code(getattr(condition, "code", None)),
            "display": cls._get_coding_display(getattr(condition, "code", None)),
            "clinical_status": "",
            "verification_status": "",
            "onset_date": "",
            "recorded_date": "",
            "patient_id": "",
            "category": "",
        }

        # Clinical status
        if hasattr(condition, "clinicalStatus") and condition.clinicalStatus:
            result["clinical_status"] = cls._get_coding_code(condition.clinicalStatus)

        # Verification status
        if hasattr(condition, "verificationStatus") and condition.verificationStatus:
            result["verification_status"] = cls._get_coding_code(condition.verificationStatus)

        # Patient
        if hasattr(condition, "subject") and condition.subject:
            ref = getattr(condition.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Onset
        if hasattr(condition, "onsetDateTime") and condition.onsetDateTime:
            result["onset_date"] = cls._format_fhir_date(condition.onsetDateTime)

        # Recorded date
        if hasattr(condition, "recordedDate") and condition.recordedDate:
            result["recorded_date"] = cls._format_fhir_date(condition.recordedDate)

        # Category
        if hasattr(condition, "category") and condition.category:
            for cat in condition.category:
                result["category"] = cls._get_coding_display(cat)
                break

        return result

    @classmethod
    def parse_encounter(cls, encounter: Any) -> Dict[str, Any]:
        """
        Parse Encounter resource to simplified dict

        Args:
            encounter: FHIR Encounter resource object

        Returns:
            Dict with encounter information
        """
        result: Dict[str, Any] = {
            "id": getattr(encounter, "id", ""),
            "status": getattr(encounter, "status", ""),
            "class_code": "",
            "class_display": "",
            "type_code": "",
            "type_display": "",
            "period_start": "",
            "period_end": "",
            "patient_id": "",
        }

        # Class
        if hasattr(encounter, "class_fhir") and encounter.class_fhir:
            cls_obj = encounter.class_fhir
            result["class_code"] = getattr(cls_obj, "code", "")
            result["class_display"] = getattr(cls_obj, "display", "")

        # Type
        if hasattr(encounter, "type") and encounter.type:
            for t in encounter.type:
                result["type_code"] = cls._get_coding_code(t)
                result["type_display"] = cls._get_coding_display(t)
                break

        # Patient
        if hasattr(encounter, "subject") and encounter.subject:
            ref = getattr(encounter.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Period
        if hasattr(encounter, "period") and encounter.period:
            period = encounter.period
            if hasattr(period, "start") and period.start:
                result["period_start"] = cls._format_fhir_date(period.start)
            if hasattr(period, "end") and period.end:
                result["period_end"] = cls._format_fhir_date(period.end)

        return result

    @classmethod
    def parse_procedure(cls, procedure: Any) -> Dict[str, Any]:
        """
        Parse Procedure resource to simplified dict

        Args:
            procedure: FHIR Procedure resource object

        Returns:
            Dict with procedure information
        """
        result: Dict[str, Any] = {
            "id": getattr(procedure, "id", ""),
            "status": getattr(procedure, "status", ""),
            "code": cls._get_coding_code(getattr(procedure, "code", None)),
            "display": cls._get_coding_display(getattr(procedure, "code", None)),
            "performed_date": "",
            "patient_id": "",
            "performer": "",
        }

        # Patient
        if hasattr(procedure, "subject") and procedure.subject:
            ref = getattr(procedure.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Performed datetime
        if hasattr(procedure, "performedDateTime") and procedure.performedDateTime:
            result["performed_date"] = cls._format_fhir_date(procedure.performedDateTime)
        elif hasattr(procedure, "performedPeriod") and procedure.performedPeriod:
            result["performed_date"] = cls._format_fhir_date(
                getattr(procedure.performedPeriod, "start", None)
            )

        # Performer
        if hasattr(procedure, "performer") and procedure.performer:
            for perf in procedure.performer:
                if hasattr(perf, "actor") and perf.actor:
                    actor = perf.actor
                    display = getattr(actor, "display", "")
                    ref = cls._get_reference_id(getattr(actor, "reference", ""))
                    result["performer"] = display or ref
                    break

        return result

    @classmethod
    def parse_allergy(cls, allergy: Any) -> Dict[str, Any]:
        """
        Parse AllergyIntolerance resource to simplified dict

        Args:
            allergy: FHIR AllergyIntolerance resource object

        Returns:
            Dict with allergy information
        """
        result: Dict[str, Any] = {
            "id": getattr(allergy, "id", ""),
            "substance": cls._get_coding_display(getattr(allergy, "code", None)),
            "substance_code": cls._get_coding_code(getattr(allergy, "code", None)),
            "clinical_status": "",
            "verification_status": "",
            "criticality": getattr(allergy, "criticality", ""),
            "category": "",
            "patient_id": "",
        }

        # Clinical status
        if hasattr(allergy, "clinicalStatus") and allergy.clinicalStatus:
            result["clinical_status"] = cls._get_coding_code(allergy.clinicalStatus)

        # Verification status
        if hasattr(allergy, "verificationStatus") and allergy.verificationStatus:
            result["verification_status"] = cls._get_coding_code(allergy.verificationStatus)

        # Category
        if hasattr(allergy, "category") and allergy.category:
            result["category"] = ", ".join(allergy.category)

        # Patient
        if hasattr(allergy, "patient") and allergy.patient:
            ref = getattr(allergy.patient, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        return result

    @classmethod
    def parse_immunization(cls, immunization: Any) -> Dict[str, Any]:
        """
        Parse Immunization resource to simplified dict

        Args:
            immunization: FHIR Immunization resource object

        Returns:
            Dict with immunization information
        """
        result: Dict[str, Any] = {
            "id": getattr(immunization, "id", ""),
            "status": getattr(immunization, "status", ""),
            "vaccine_code": cls._get_coding_display(getattr(immunization, "vaccineCode", None)),
            "vaccine_code_value": cls._get_coding_code(getattr(immunization, "vaccineCode", None)),
            "occurrence_date": "",
            "lot_number": getattr(immunization, "lotNumber", ""),
            "patient_id": "",
            "performer": "",
        }

        # Patient
        if hasattr(immunization, "patient") and immunization.patient:
            ref = getattr(immunization.patient, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Occurrence
        if hasattr(immunization, "occurrenceDateTime") and immunization.occurrenceDateTime:
            result["occurrence_date"] = cls._format_fhir_date(immunization.occurrenceDateTime)
        elif hasattr(immunization, "occurrenceString") and immunization.occurrenceString:
            result["occurrence_date"] = immunization.occurrenceString

        # Performer
        if hasattr(immunization, "performer") and immunization.performer:
            for perf in immunization.performer:
                if hasattr(perf, "actor") and perf.actor:
                    actor = perf.actor
                    display = getattr(actor, "display", "")
                    ref = cls._get_reference_id(getattr(actor, "reference", ""))
                    result["performer"] = display or ref
                    break

        return result

    @classmethod
    def parse_diagnostic_report(cls, report: Any) -> Dict[str, Any]:
        """
        Parse DiagnosticReport resource to simplified dict

        Args:
            report: FHIR DiagnosticReport resource object

        Returns:
            Dict with diagnostic report information
        """
        result: Dict[str, Any] = {
            "id": getattr(report, "id", ""),
            "status": getattr(report, "status", ""),
            "code": cls._get_coding_code(getattr(report, "code", None)),
            "display": cls._get_coding_display(getattr(report, "code", None)),
            "category": "",
            "issued": "",
            "effective_date": "",
            "patient_id": "",
            "conclusion": getattr(report, "conclusion", ""),
        }

        # Category
        if hasattr(report, "category") and report.category:
            for cat in report.category:
                result["category"] = cls._get_coding_display(cat)
                break

        # Patient
        if hasattr(report, "subject") and report.subject:
            ref = getattr(report.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Issued
        if hasattr(report, "issued") and report.issued:
            result["issued"] = cls._format_fhir_date(report.issued)

        # Effective datetime
        if hasattr(report, "effectiveDateTime") and report.effectiveDateTime:
            result["effective_date"] = cls._format_fhir_date(report.effectiveDateTime)

        return result

    @classmethod
    def parse_document_reference(cls, document: Any) -> Dict[str, Any]:
        """
        Parse DocumentReference resource to simplified dict

        Args:
            document: FHIR DocumentReference resource object

        Returns:
            Dict with document reference information
        """
        result: Dict[str, Any] = {
            "id": getattr(document, "id", ""),
            "status": getattr(document, "status", ""),
            "type_code": cls._get_coding_code(getattr(document, "type", None)),
            "type_display": cls._get_coding_display(getattr(document, "type", None)),
            "category": "",
            "date": "",
            "description": getattr(document, "description", ""),
            "patient_id": "",
            "content_type": "",
            "content_url": "",
        }

        # Category
        if hasattr(document, "category") and document.category:
            for cat in document.category:
                result["category"] = cls._get_coding_display(cat)
                break

        # Patient
        if hasattr(document, "subject") and document.subject:
            ref = getattr(document.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Date
        if hasattr(document, "date") and document.date:
            result["date"] = cls._format_fhir_date(document.date)

        # Content
        if hasattr(document, "content") and document.content:
            for content in document.content:
                if hasattr(content, "attachment") and content.attachment:
                    att = content.attachment
                    result["content_type"] = getattr(att, "contentType", "")
                    result["content_url"] = getattr(att, "url", "")
                    break

        return result

    @classmethod
    def parse_practitioner(cls, practitioner: Any) -> Dict[str, Any]:
        """
        Parse Practitioner resource to simplified dict

        Args:
            practitioner: FHIR Practitioner resource object

        Returns:
            Dict with practitioner information
        """
        result: Dict[str, Any] = {
            "id": getattr(practitioner, "id", ""),
            "active": getattr(practitioner, "active", True),
            "name": cls._format_name(getattr(practitioner, "name", [])),
            "gender": getattr(practitioner, "gender", ""),
            "birth_date": "",
            "phone": cls._get_telecom(getattr(practitioner, "telecom", []), "phone"),
            "email": cls._get_telecom(getattr(practitioner, "telecom", []), "email"),
            "address": cls._format_address(getattr(practitioner, "address", [])),
            "qualifications": [],
        }

        # Birth date
        if hasattr(practitioner, "birthDate") and practitioner.birthDate:
            result["birth_date"] = cls._format_fhir_date(practitioner.birthDate)

        # Qualifications
        if hasattr(practitioner, "qualification") and practitioner.qualification:
            for qual in practitioner.qualification:
                if hasattr(qual, "code") and qual.code:
                    result["qualifications"].append(cls._get_coding_display(qual.code))

        # Identifiers (NPI, etc.)
        identifiers = []
        if hasattr(practitioner, "identifier") and practitioner.identifier:
            for ident in practitioner.identifier:
                system = getattr(ident, "system", "")
                value = getattr(ident, "value", "")
                if value:
                    identifiers.append(f"{system}|{value}" if system else value)
        result["identifiers"] = identifiers

        return result

    @classmethod
    def parse_organization(cls, organization: Any) -> Dict[str, Any]:
        """
        Parse Organization resource to simplified dict

        Args:
            organization: FHIR Organization resource object

        Returns:
            Dict with organization information
        """
        result: Dict[str, Any] = {
            "id": getattr(organization, "id", ""),
            "active": getattr(organization, "active", True),
            "name": getattr(organization, "name", ""),
            "type": "",
            "phone": cls._get_telecom(getattr(organization, "telecom", []), "phone"),
            "email": cls._get_telecom(getattr(organization, "telecom", []), "email"),
            "address": cls._format_address(getattr(organization, "address", [])),
            "part_of": "",
        }

        # Type
        if hasattr(organization, "type") and organization.type:
            for t in organization.type:
                result["type"] = cls._get_coding_display(t)
                break

        # Part of (parent organization)
        if hasattr(organization, "partOf") and organization.partOf:
            ref = getattr(organization.partOf, "reference", "")
            display = getattr(organization.partOf, "display", "")
            result["part_of"] = display or cls._get_reference_id(ref)

        # Identifiers
        identifiers = []
        if hasattr(organization, "identifier") and organization.identifier:
            for ident in organization.identifier:
                system = getattr(ident, "system", "")
                value = getattr(ident, "value", "")
                if value:
                    identifiers.append(f"{system}|{value}" if system else value)
        result["identifiers"] = identifiers

        return result

    @classmethod
    def parse_location(cls, location: Any) -> Dict[str, Any]:
        """
        Parse Location resource to simplified dict

        Args:
            location: FHIR Location resource object

        Returns:
            Dict with location information
        """
        result: Dict[str, Any] = {
            "id": getattr(location, "id", ""),
            "status": getattr(location, "status", ""),
            "name": getattr(location, "name", ""),
            "description": getattr(location, "description", ""),
            "mode": getattr(location, "mode", ""),
            "type": "",
            "phone": cls._get_telecom(getattr(location, "telecom", []), "phone"),
            "address": "",
            "managing_organization": "",
            "physical_type": "",
        }

        # Type
        if hasattr(location, "type") and location.type:
            for t in location.type:
                result["type"] = cls._get_coding_display(t)
                break

        # Physical type
        if hasattr(location, "physicalType") and location.physicalType:
            result["physical_type"] = cls._get_coding_display(location.physicalType)

        # Address
        if hasattr(location, "address") and location.address:
            addr = location.address
            parts = []
            if hasattr(addr, "line") and addr.line:
                parts.extend(addr.line)
            if hasattr(addr, "city") and addr.city:
                parts.append(addr.city)
            if hasattr(addr, "state") and addr.state:
                parts.append(addr.state)
            if parts:
                result["address"] = ", ".join(parts)

        # Managing organization
        if hasattr(location, "managingOrganization") and location.managingOrganization:
            ref = getattr(location.managingOrganization, "reference", "")
            display = getattr(location.managingOrganization, "display", "")
            result["managing_organization"] = display or cls._get_reference_id(ref)

        return result

    @classmethod
    def parse_device(cls, device: Any) -> Dict[str, Any]:
        """
        Parse Device resource to simplified dict

        Args:
            device: FHIR Device resource object

        Returns:
            Dict with device information
        """
        result: Dict[str, Any] = {
            "id": getattr(device, "id", ""),
            "status": getattr(device, "status", ""),
            "device_name": "",
            "type": "",
            "manufacturer": getattr(device, "manufacturer", ""),
            "model_number": getattr(device, "modelNumber", ""),
            "serial_number": getattr(device, "serialNumber", ""),
            "lot_number": getattr(device, "lotNumber", ""),
            "owner": "",
            "location": "",
            "patient": "",
        }

        # Device name
        if hasattr(device, "deviceName") and device.deviceName:
            for dn in device.deviceName:
                result["device_name"] = getattr(dn, "name", "")
                break

        # Type
        if hasattr(device, "type") and device.type:
            result["type"] = cls._get_coding_display(device.type)

        # Owner
        if hasattr(device, "owner") and device.owner:
            ref = getattr(device.owner, "reference", "")
            display = getattr(device.owner, "display", "")
            result["owner"] = display or cls._get_reference_id(ref)

        # Location
        if hasattr(device, "location") and device.location:
            ref = getattr(device.location, "reference", "")
            display = getattr(device.location, "display", "")
            result["location"] = display or cls._get_reference_id(ref)

        # Patient
        if hasattr(device, "patient") and device.patient:
            ref = getattr(device.patient, "reference", "")
            result["patient"] = cls._get_reference_id(ref)

        # Identifiers (UDI, etc.)
        identifiers = []
        if hasattr(device, "identifier") and device.identifier:
            for ident in device.identifier:
                system = getattr(ident, "system", "")
                value = getattr(ident, "value", "")
                if value:
                    identifiers.append(f"{system}|{value}" if system else value)
        result["identifiers"] = identifiers

        return result

    @classmethod
    def parse_service_request(cls, service_request: Any) -> Dict[str, Any]:
        """
        Parse ServiceRequest resource to simplified dict

        Args:
            service_request: FHIR ServiceRequest resource object

        Returns:
            Dict with service request (order) information
        """
        result: Dict[str, Any] = {
            "id": getattr(service_request, "id", ""),
            "status": getattr(service_request, "status", ""),
            "intent": getattr(service_request, "intent", ""),
            "priority": getattr(service_request, "priority", ""),
            "code": cls._get_coding_code(getattr(service_request, "code", None)),
            "display": cls._get_coding_display(getattr(service_request, "code", None)),
            "category": "",
            "patient_id": "",
            "requester": "",
            "performer": "",
            "authored_on": "",
            "occurrence_date": "",
            "reason": "",
        }

        # Category
        if hasattr(service_request, "category") and service_request.category:
            for cat in service_request.category:
                result["category"] = cls._get_coding_display(cat)
                break

        # Patient
        if hasattr(service_request, "subject") and service_request.subject:
            ref = getattr(service_request.subject, "reference", "")
            result["patient_id"] = cls._get_reference_id(ref)

        # Requester
        if hasattr(service_request, "requester") and service_request.requester:
            ref = getattr(service_request.requester, "reference", "")
            display = getattr(service_request.requester, "display", "")
            result["requester"] = display or cls._get_reference_id(ref)

        # Performer
        if hasattr(service_request, "performer") and service_request.performer:
            for perf in service_request.performer:
                ref = getattr(perf, "reference", "")
                display = getattr(perf, "display", "")
                result["performer"] = display or cls._get_reference_id(ref)
                break

        # Authored on
        if hasattr(service_request, "authoredOn") and service_request.authoredOn:
            result["authored_on"] = cls._format_fhir_date(service_request.authoredOn)

        # Occurrence (when to perform)
        if hasattr(service_request, "occurrenceDateTime") and service_request.occurrenceDateTime:
            result["occurrence_date"] = cls._format_fhir_date(service_request.occurrenceDateTime)
        elif hasattr(service_request, "occurrencePeriod") and service_request.occurrencePeriod:
            result["occurrence_date"] = cls._format_fhir_date(
                getattr(service_request.occurrencePeriod, "start", None)
            )

        # Reason
        if hasattr(service_request, "reasonCode") and service_request.reasonCode:
            for reason in service_request.reasonCode:
                result["reason"] = cls._get_coding_display(reason)
                break

        return result


# Module exports
__all__ = ["FHIRResourceBuilder", "FHIRResourceParser"]
