"""
Extended unit tests for the FHIR resource builder and parser
(oida.protocols.fhir.resources).

These tests exercise the parsing/building logic directly against plain
value objects (SimpleNamespace) that mimic the duck-typed FHIR resource
shapes the parser reads via ``getattr``/``hasattr``. Nothing external is
mocked because nothing external is touched: ``resources.py`` is pure data
transformation with no I/O. No monkey-patching of the code under test.

The existing ``test_resources.py`` covers Patient/Observation/Condition/
Encounter plus a couple of helpers; this file covers the remaining
resource parsers and the builder/helper branches that were uncovered.
"""

from types import SimpleNamespace

from oida.protocols.fhir.resources import FHIRResourceBuilder, FHIRResourceParser


# ---------------------------------------------------------------------------
# Small value-object helpers (no MagicMock -- precise hasattr/getattr)
# ---------------------------------------------------------------------------


def _coding(code="", display=""):
    return SimpleNamespace(code=code, display=display)


def _cc(code="", display="", text=None):
    """A CodeableConcept-like object."""
    return SimpleNamespace(coding=[_coding(code, display)], text=text)


def _ref(reference="", display=""):
    return SimpleNamespace(reference=reference, display=display)


# ===========================================================================
# Builder branches not covered by the base test file
# ===========================================================================


class TestBuilderObservationBranches:
    def test_observation_string_value(self):
        obs = FHIRResourceBuilder.build_observation(
            observation_id="O1",
            patient_reference="PT9",  # bare id -> prefixed with Patient/
            code="1234-5",
            value="positive",
        )
        # non-numeric value lands in valueString, not valueQuantity
        assert obs["valueString"] == "positive"
        assert "valueQuantity" not in obs
        # bare patient reference normalised
        assert obs["subject"]["reference"] == "Patient/PT9"

    def test_observation_numeric_value_quantity(self):
        obs = FHIRResourceBuilder.build_observation(
            observation_id="O2",
            code="8867-4",
            value=72.5,
            value_unit="beats/minute",
        )
        vq = obs["valueQuantity"]
        assert vq["value"] == 72.5
        assert vq["unit"] == "beats/minute"
        # code falls back to unit when value_code omitted
        assert vq["code"] == "beats/minute"

    def test_observation_default_effective_datetime(self):
        obs = FHIRResourceBuilder.build_observation(observation_id="O3", code="X")
        # No effective_datetime supplied -> now() is filled in (ISO 8601)
        assert "T" in obs["effectiveDateTime"]

    def test_observation_no_code_no_value(self):
        obs = FHIRResourceBuilder.build_observation(observation_id="O4")
        assert "code" not in obs
        assert "valueQuantity" not in obs
        assert "valueString" not in obs


class TestBuilderPatientBranches:
    def test_patient_email_only_telecom(self):
        p = FHIRResourceBuilder.build_patient(patient_id="P1", email="a@b.c")
        systems = {t["system"] for t in p["telecom"]}
        assert systems == {"email"}

    def test_patient_address_country_included(self):
        p = FHIRResourceBuilder.build_patient(patient_id="P2", city="Town", country="USA")
        assert p["address"][0]["country"] == "USA"
        assert p["address"][0]["city"] == "Town"

    def test_patient_no_optional_fields(self):
        p = FHIRResourceBuilder.build_patient(patient_id="P3")
        assert p["resourceType"] == "Patient"
        assert "name" not in p
        assert "telecom" not in p
        assert "address" not in p
        assert "identifier" not in p


# ===========================================================================
# Parser helper edge cases
# ===========================================================================


class TestParserHelpers:
    def test_format_fhir_date_object_repr_returns_empty(self):
        # An object whose str() is a <... object at 0x...> repr -> empty string
        class Opaque:
            pass

        assert FHIRResourceParser._format_fhir_date(Opaque()) == ""

    def test_format_fhir_date_short_string(self):
        # Shorter than 10 chars -> returned as-is
        assert FHIRResourceParser._format_fhir_date("2024") == "2024"

    def test_format_fhir_date_truncates_to_date(self):
        d = SimpleNamespace(isostring="2024-01-15T09:00:00Z", date=None)
        assert FHIRResourceParser._format_fhir_date(d) == "2024-01-15"

    def test_get_coding_display_prefers_text(self):
        assert FHIRResourceParser._get_coding_display(_cc(display="D", text="T")) == "T"

    def test_get_coding_display_falls_back_to_coding(self):
        assert FHIRResourceParser._get_coding_display(_cc(display="D")) == "D"

    def test_get_coding_display_empty(self):
        assert FHIRResourceParser._get_coding_display(None) == ""

    def test_get_coding_code(self):
        assert FHIRResourceParser._get_coding_code(_cc(code="C1")) == "C1"

    def test_get_coding_code_none(self):
        assert FHIRResourceParser._get_coding_code(None) == ""

    def test_format_name_given_and_family(self):
        n = SimpleNamespace(given=["Jane", "Q"], family="Public")
        assert FHIRResourceParser._format_name([n]) == "Jane Q Public"

    def test_format_name_empty(self):
        assert FHIRResourceParser._format_name([]) == ""

    def test_format_address_full(self):
        a = SimpleNamespace(line=["1 St"], city="Town", state="ST", postalCode="00000")
        assert FHIRResourceParser._format_address([a]) == "1 St, Town, ST, 00000"

    def test_get_telecom_match_and_miss(self):
        phone = SimpleNamespace(system="phone", value="555")
        email = SimpleNamespace(system="email", value="x@y.z")
        assert FHIRResourceParser._get_telecom([phone, email], "email") == "x@y.z"
        assert FHIRResourceParser._get_telecom([phone], "fax") == ""

    def test_get_reference_id_variants(self):
        assert FHIRResourceParser._get_reference_id("Practitioner/77") == "77"
        assert FHIRResourceParser._get_reference_id("77") == "77"
        assert FHIRResourceParser._get_reference_id(None) == ""


# ===========================================================================
# Observation parser extra branches
# ===========================================================================


class TestParseObservationBranches:
    def test_value_string_branch(self):
        obs = SimpleNamespace(
            id="O",
            status="final",
            code=_cc(code="c"),
            subject=_ref("Patient/1"),
            valueQuantity=None,
            valueString="reactive",
            valueCodeableConcept=None,
            effectiveDateTime=None,
            effectivePeriod=None,
            category=None,
        )
        result = FHIRResourceParser.parse_observation(obs)
        assert result["value"] == "reactive"
        assert result["patient_id"] == "1"

    def test_value_codeable_concept_branch(self):
        obs = SimpleNamespace(
            id="O",
            status="final",
            code=_cc(code="c"),
            subject=None,
            valueQuantity=None,
            valueString=None,
            valueCodeableConcept=_cc(display="Negative"),
            effectiveDateTime=None,
            effectivePeriod=None,
            category=None,
        )
        result = FHIRResourceParser.parse_observation(obs)
        assert result["value"] == "Negative"

    def test_effective_period_branch_and_category(self):
        obs = SimpleNamespace(
            id="O",
            status="final",
            code=_cc(code="c"),
            subject=None,
            valueQuantity=None,
            valueString=None,
            valueCodeableConcept=None,
            effectiveDateTime=None,
            effectivePeriod=SimpleNamespace(
                start=SimpleNamespace(isostring="2024-02-02", date=None)
            ),
            category=[_cc(display="laboratory")],
        )
        result = FHIRResourceParser.parse_observation(obs)
        assert result["effective_date"] == "2024-02-02"
        assert result["category"] == "laboratory"

    def test_value_quantity_unit_falls_back_to_code(self):
        obs = SimpleNamespace(
            id="O",
            status="final",
            code=_cc(code="c"),
            subject=None,
            valueQuantity=SimpleNamespace(value=5, unit="", code="mg/dL"),
            valueString=None,
            valueCodeableConcept=None,
            effectiveDateTime=None,
            effectivePeriod=None,
            category=None,
        )
        result = FHIRResourceParser.parse_observation(obs)
        assert result["unit"] == "mg/dL"


# ===========================================================================
# MedicationRequest extra branches
# ===========================================================================


class TestParseMedicationRequest:
    def test_medication_reference_branch(self):
        med = SimpleNamespace(
            id="M",
            status="active",
            intent="order",
            medicationCodeableConcept=None,
            medicationReference=SimpleNamespace(display="Aspirin 81mg"),
            subject=_ref("Patient/5"),
            authoredOn=SimpleNamespace(isostring="2024-01-01", date=None),
            requester=_ref(reference="Practitioner/9", display=""),
            dosageInstruction=[SimpleNamespace(text="1 tab")],
        )
        result = FHIRResourceParser.parse_medication_request(med)
        assert result["medication"] == "Aspirin 81mg"
        assert result["patient_id"] == "5"
        assert result["authored_on"] == "2024-01-01"
        # requester display empty -> falls back to reference id
        assert result["requester"] == "9"
        assert result["dosage"] == "1 tab"

    def test_multiple_dosage_lines_joined(self):
        med = SimpleNamespace(
            id="M2",
            status="active",
            intent="order",
            medicationCodeableConcept=_cc(code="x", display="Drug"),
            medicationReference=None,
            subject=None,
            authoredOn=None,
            requester=None,
            dosageInstruction=[
                SimpleNamespace(text="morning"),
                SimpleNamespace(text="evening"),
            ],
        )
        result = FHIRResourceParser.parse_medication_request(med)
        assert result["dosage"] == "morning; evening"
        assert result["medication_code"] == "x"


# ===========================================================================
# Condition extra branches
# ===========================================================================


class TestParseConditionBranches:
    def test_verification_status_recorded_date_category(self):
        cond = SimpleNamespace(
            id="C",
            code=_cc(code="73211009", display="Diabetes"),
            clinicalStatus=_cc(code="active"),
            verificationStatus=_cc(code="confirmed"),
            subject=_ref("Patient/3"),
            onsetDateTime=None,
            recordedDate=SimpleNamespace(isostring="2023-09-09", date=None),
            category=[_cc(display="encounter-diagnosis")],
        )
        result = FHIRResourceParser.parse_condition(cond)
        assert result["verification_status"] == "confirmed"
        assert result["recorded_date"] == "2023-09-09"
        assert result["category"] == "encounter-diagnosis"
        assert result["patient_id"] == "3"


# ===========================================================================
# Procedure
# ===========================================================================


class TestParseProcedure:
    def test_performed_datetime_and_performer(self):
        proc = SimpleNamespace(
            id="PR",
            status="completed",
            code=_cc(code="80146002", display="Appendectomy"),
            subject=_ref("Patient/8"),
            performedDateTime=SimpleNamespace(isostring="2024-03-03", date=None),
            performedPeriod=None,
            performer=[SimpleNamespace(actor=_ref(reference="Practitioner/2", display="Dr. Who"))],
        )
        result = FHIRResourceParser.parse_procedure(proc)
        assert result["display"] == "Appendectomy"
        assert result["performed_date"] == "2024-03-03"
        assert result["patient_id"] == "8"
        # display preferred over reference id
        assert result["performer"] == "Dr. Who"

    def test_performed_period_branch(self):
        proc = SimpleNamespace(
            id="PR2",
            status="in-progress",
            code=_cc(code="x"),
            subject=None,
            performedDateTime=None,
            performedPeriod=SimpleNamespace(
                start=SimpleNamespace(isostring="2024-04-04", date=None)
            ),
            performer=[],
        )
        result = FHIRResourceParser.parse_procedure(proc)
        assert result["performed_date"] == "2024-04-04"
        assert result["performer"] == ""


# ===========================================================================
# AllergyIntolerance
# ===========================================================================


class TestParseAllergy:
    def test_full_allergy(self):
        allergy = SimpleNamespace(
            id="AL",
            code=_cc(code="227493005", display="Cashew nuts"),
            clinicalStatus=_cc(code="active"),
            verificationStatus=_cc(code="confirmed"),
            criticality="high",
            category=["food", "environment"],
            patient=_ref("Patient/4"),
        )
        result = FHIRResourceParser.parse_allergy(allergy)
        assert result["substance"] == "Cashew nuts"
        assert result["substance_code"] == "227493005"
        assert result["clinical_status"] == "active"
        assert result["verification_status"] == "confirmed"
        assert result["criticality"] == "high"
        assert result["category"] == "food, environment"
        assert result["patient_id"] == "4"


# ===========================================================================
# Immunization
# ===========================================================================


class TestParseImmunization:
    def test_occurrence_datetime_and_performer(self):
        imm = SimpleNamespace(
            id="IM",
            status="completed",
            vaccineCode=_cc(code="208", display="COVID-19"),
            patient=_ref("Patient/6"),
            occurrenceDateTime=SimpleNamespace(isostring="2021-05-05", date=None),
            occurrenceString=None,
            lotNumber="LOT123",
            performer=[SimpleNamespace(actor=_ref(reference="Practitioner/1", display=""))],
        )
        result = FHIRResourceParser.parse_immunization(imm)
        assert result["vaccine_code"] == "COVID-19"
        assert result["vaccine_code_value"] == "208"
        assert result["occurrence_date"] == "2021-05-05"
        assert result["lot_number"] == "LOT123"
        assert result["patient_id"] == "6"
        # display empty -> reference id
        assert result["performer"] == "1"

    def test_occurrence_string_branch(self):
        imm = SimpleNamespace(
            id="IM2",
            status="completed",
            vaccineCode=_cc(code="x"),
            patient=None,
            occurrenceDateTime=None,
            occurrenceString="2021",
            lotNumber="",
            performer=[],
        )
        result = FHIRResourceParser.parse_immunization(imm)
        assert result["occurrence_date"] == "2021"


# ===========================================================================
# DiagnosticReport
# ===========================================================================


class TestParseDiagnosticReport:
    def test_full_report(self):
        rep = SimpleNamespace(
            id="DR",
            status="final",
            code=_cc(code="58410-2", display="CBC panel"),
            category=[_cc(display="Hematology")],
            subject=_ref("Patient/2"),
            issued=SimpleNamespace(isostring="2024-06-06", date=None),
            effectiveDateTime=SimpleNamespace(isostring="2024-06-05", date=None),
            conclusion="Within normal limits",
        )
        result = FHIRResourceParser.parse_diagnostic_report(rep)
        assert result["display"] == "CBC panel"
        assert result["category"] == "Hematology"
        assert result["issued"] == "2024-06-06"
        assert result["effective_date"] == "2024-06-05"
        assert result["conclusion"] == "Within normal limits"
        assert result["patient_id"] == "2"


# ===========================================================================
# DocumentReference
# ===========================================================================


class TestParseDocumentReference:
    def test_full_document(self):
        att = SimpleNamespace(contentType="application/pdf", url="http://x/doc.pdf")
        doc = SimpleNamespace(
            id="DOC",
            status="current",
            type=_cc(code="34133-9", display="Summary"),
            category=[_cc(display="Clinical Note")],
            subject=_ref("Patient/7"),
            date=SimpleNamespace(isostring="2024-07-07", date=None),
            description="Discharge summary",
            content=[SimpleNamespace(attachment=att)],
        )
        result = FHIRResourceParser.parse_document_reference(doc)
        assert result["type_display"] == "Summary"
        assert result["category"] == "Clinical Note"
        assert result["date"] == "2024-07-07"
        assert result["description"] == "Discharge summary"
        assert result["content_type"] == "application/pdf"
        assert result["content_url"] == "http://x/doc.pdf"
        assert result["patient_id"] == "7"


# ===========================================================================
# Practitioner
# ===========================================================================


class TestParsePractitioner:
    def test_full_practitioner(self):
        name = SimpleNamespace(given=["Greg"], family="House")
        qual = SimpleNamespace(code=_cc(display="MD"))
        ident = SimpleNamespace(system="http://hl7.org/fhir/sid/us-npi", value="1234567890")
        prac = SimpleNamespace(
            id="PRAC",
            active=True,
            name=[name],
            gender="male",
            birthDate=SimpleNamespace(isostring="1970-01-01", date=None),
            telecom=[SimpleNamespace(system="phone", value="555")],
            address=[SimpleNamespace(line=["1 St"], city="Town", state="ST", postalCode="0")],
            qualification=[qual],
            identifier=[ident],
        )
        result = FHIRResourceParser.parse_practitioner(prac)
        assert result["name"] == "Greg House"
        assert result["gender"] == "male"
        assert result["birth_date"] == "1970-01-01"
        assert result["phone"] == "555"
        assert result["qualifications"] == ["MD"]
        assert result["identifiers"] == ["http://hl7.org/fhir/sid/us-npi|1234567890"]


# ===========================================================================
# Organization
# ===========================================================================


class TestParseOrganization:
    def test_full_organization(self):
        ident = SimpleNamespace(system="", value="ORG-1")  # no system -> bare value
        org = SimpleNamespace(
            id="ORG",
            active=True,
            name="General Hospital",
            type=[_cc(display="Healthcare Provider")],
            telecom=[SimpleNamespace(system="email", value="info@gh.org")],
            address=[
                SimpleNamespace(line=["10 Ave"], city="Metro", state="NY", postalCode="10001")
            ],
            partOf=SimpleNamespace(reference="Organization/parent", display="Parent Health"),
            identifier=[ident],
        )
        result = FHIRResourceParser.parse_organization(org)
        assert result["name"] == "General Hospital"
        assert result["type"] == "Healthcare Provider"
        assert result["email"] == "info@gh.org"
        # display preferred over reference id
        assert result["part_of"] == "Parent Health"
        assert result["identifiers"] == ["ORG-1"]

    def test_partof_reference_fallback(self):
        org = SimpleNamespace(
            id="ORG2",
            active=False,
            name="Clinic",
            type=None,
            telecom=None,
            address=None,
            partOf=SimpleNamespace(reference="Organization/99", display=""),
            identifier=None,
        )
        result = FHIRResourceParser.parse_organization(org)
        assert result["part_of"] == "99"


# ===========================================================================
# Location
# ===========================================================================


class TestParseLocation:
    def test_full_location(self):
        loc = SimpleNamespace(
            id="LOC",
            status="active",
            name="ICU Bed 3",
            description="Critical care",
            mode="instance",
            type=[_cc(display="Intensive Care")],
            physicalType=_cc(display="Bed"),
            telecom=[SimpleNamespace(system="phone", value="555")],
            address=SimpleNamespace(line=["Ward 1"], city="Metro", state="NY"),
            managingOrganization=SimpleNamespace(reference="Organization/5", display="Ops"),
        )
        result = FHIRResourceParser.parse_location(loc)
        assert result["name"] == "ICU Bed 3"
        assert result["type"] == "Intensive Care"
        assert result["physical_type"] == "Bed"
        assert result["address"] == "Ward 1, Metro, NY"
        assert result["managing_organization"] == "Ops"


# ===========================================================================
# Device
# ===========================================================================


class TestParseDevice:
    def test_full_device(self):
        ident = SimpleNamespace(system="udi", value="UDI-1")
        dev = SimpleNamespace(
            id="DEV",
            status="active",
            deviceName=[SimpleNamespace(name="Infusion Pump")],
            type=_cc(display="Pump"),
            manufacturer="Acme Medical",
            modelNumber="X100",
            serialNumber="SN-9",
            lotNumber="L-2",
            owner=SimpleNamespace(reference="Organization/3", display="Biomed"),
            location=SimpleNamespace(reference="Location/7", display="Ward A"),
            patient=_ref("Patient/11"),
            identifier=[ident],
        )
        result = FHIRResourceParser.parse_device(dev)
        assert result["device_name"] == "Infusion Pump"
        assert result["type"] == "Pump"
        assert result["manufacturer"] == "Acme Medical"
        assert result["serial_number"] == "SN-9"
        assert result["owner"] == "Biomed"
        assert result["location"] == "Ward A"
        assert result["patient"] == "11"
        assert result["identifiers"] == ["udi|UDI-1"]


# ===========================================================================
# ServiceRequest
# ===========================================================================


class TestParseServiceRequest:
    def test_full_service_request(self):
        sr = SimpleNamespace(
            id="SR",
            status="active",
            intent="order",
            priority="urgent",
            code=_cc(code="306181000000106", display="MRI Brain"),
            category=[_cc(display="Imaging")],
            subject=_ref("Patient/13"),
            requester=SimpleNamespace(reference="Practitioner/4", display="Dr. Strange"),
            performer=[SimpleNamespace(reference="Organization/2", display="Radiology")],
            authoredOn=SimpleNamespace(isostring="2024-08-08", date=None),
            occurrenceDateTime=SimpleNamespace(isostring="2024-08-10", date=None),
            occurrencePeriod=None,
            reasonCode=[_cc(display="Headache")],
        )
        result = FHIRResourceParser.parse_service_request(sr)
        assert result["priority"] == "urgent"
        assert result["display"] == "MRI Brain"
        assert result["category"] == "Imaging"
        assert result["patient_id"] == "13"
        assert result["requester"] == "Dr. Strange"
        assert result["performer"] == "Radiology"
        assert result["authored_on"] == "2024-08-08"
        assert result["occurrence_date"] == "2024-08-10"
        assert result["reason"] == "Headache"

    def test_occurrence_period_branch(self):
        sr = SimpleNamespace(
            id="SR2",
            status="draft",
            intent="plan",
            priority="",
            code=_cc(code="x"),
            category=None,
            subject=None,
            requester=SimpleNamespace(reference="Practitioner/7", display=""),
            performer=None,
            authoredOn=None,
            occurrenceDateTime=None,
            occurrencePeriod=SimpleNamespace(
                start=SimpleNamespace(isostring="2024-09-09", date=None)
            ),
            reasonCode=None,
        )
        result = FHIRResourceParser.parse_service_request(sr)
        assert result["occurrence_date"] == "2024-09-09"
        # requester display empty -> reference id
        assert result["requester"] == "7"


# ===========================================================================
# Patient parser MRN / birthdate branches
# ===========================================================================


class TestParsePatientBranches:
    def test_mrn_detected_from_identifier(self):
        ident = SimpleNamespace(system="http://hospital/mrn", value="000123")
        # parse_patient checks hasattr(birthDate, "isostring") first; to reach
        # the .date branch the object must NOT carry an isostring attribute.
        bd = SimpleNamespace(date="1990-12-12")
        patient = SimpleNamespace(
            id="P",
            name=[],
            gender="female",
            birthDate=bd,
            telecom=[],
            address=[],
            identifier=[ident],
        )
        result = FHIRResourceParser.parse_patient(patient)
        # birthDate via .date attribute branch
        assert result["birth_date"] == "1990-12-12"
        # MRN extraction splits on the pipe
        assert result["mrn"] == "000123"

    def test_birthdate_plain_string(self):
        patient = SimpleNamespace(
            id="P2",
            name=[],
            gender="",
            birthDate="1985-06-06",
            telecom=[],
            address=[],
            identifier=[],
        )
        result = FHIRResourceParser.parse_patient(patient)
        assert result["birth_date"] == "1985-06-06"
        assert result["identifiers"] == []
