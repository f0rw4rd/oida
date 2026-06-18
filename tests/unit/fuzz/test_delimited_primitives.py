"""
Comprehensive tests for delimited block primitives.

Tests the generic delimited primitives used for HL7, ASTM, CSV-like protocols.
"""

import pytest

# Import the delimited primitives module
from oida.fuzz.primitives.delimited import (
    DelimitedField,
    DelimitedSegment,
    FramedMessage,
    HL7Delimiters,
    HL7Segment,
    HL7Message,
    build_delimiter_injection_values,
    build_oversized_field_values,
    build_mllp_corruption_values,
    build_encoding_char_values,
    build_segment_fuzzing_values,
)

# Import boofuzz primitives for type checking
from boofuzz import Block, Request, Static


# =============================================================================
# Test HL7Delimiters Constants
# =============================================================================


class TestHL7Delimiters:
    """Tests for HL7Delimiters constant values."""

    def test_field_separator(self):
        """HL7 field separator is pipe."""
        assert HL7Delimiters.FIELD_SEP == "|"

    def test_component_separator(self):
        """HL7 component separator is caret."""
        assert HL7Delimiters.COMPONENT_SEP == "^"

    def test_subcomponent_separator(self):
        """HL7 subcomponent separator is ampersand."""
        assert HL7Delimiters.SUBCOMPONENT_SEP == "&"

    def test_repetition_separator(self):
        """HL7 repetition separator is tilde."""
        assert HL7Delimiters.REPETITION_SEP == "~"

    def test_escape_char(self):
        """HL7 escape character is backslash."""
        assert HL7Delimiters.ESCAPE_CHAR == "\\"

    def test_segment_terminator(self):
        """HL7 segment terminator is carriage return."""
        assert HL7Delimiters.SEGMENT_TERM == "\r"

    def test_encoding_chars(self):
        """HL7 encoding characters in standard order."""
        assert HL7Delimiters.ENCODING_CHARS == "^~\\&"

    def test_mllp_start(self):
        """MLLP start marker is VT (0x0B)."""
        assert HL7Delimiters.MLLP_START == b"\x0b"

    def test_mllp_end(self):
        """MLLP end marker is FS+CR (0x1C 0x0D)."""
        assert HL7Delimiters.MLLP_END == b"\x1c\x0d"


# =============================================================================
# Test DelimitedField
# =============================================================================


class TestDelimitedField:
    """Tests for DelimitedField class."""

    def test_simple_field_creation(self):
        """Create a simple non-fuzzable field."""
        field = DelimitedField(name="Test_Field", value="test_value")
        assert field.name == "Test_Field"
        assert field.value == "test_value"
        assert field.fuzzable is False
        assert field.max_len == 200

    def test_fuzzable_field_creation(self):
        """Create a fuzzable field."""
        field = DelimitedField(
            name="Fuzz_Field",
            value="fuzz_me",
            fuzzable=True,
            max_len=500,
        )
        assert field.fuzzable is True
        assert field.max_len == 500

    def test_field_with_components(self):
        """Create a field with component list."""
        field = DelimitedField(
            name="Component_Field",
            components=["LAST", "FIRST", "MIDDLE"],
        )
        assert field.components == ["LAST", "FIRST", "MIDDLE"]

    def test_to_primitive_static(self):
        """Non-fuzzable field converts to Static primitive."""
        field = DelimitedField(name="Static_Field", value="static_value")
        primitive = field.to_primitive()
        assert isinstance(primitive, Static)

    def test_to_primitive_fuzzable(self):
        """Fuzzable field converts to SmartString primitive."""
        field = DelimitedField(
            name="Smart_Field",
            value="fuzz_value",
            fuzzable=True,
        )
        primitive = field.to_primitive()
        # SmartString returns either BoofuzzString or RadamsaString
        assert hasattr(primitive, "render")

    def test_to_primitive_with_components(self):
        """Field with components joins them correctly."""
        field = DelimitedField(
            name="Name_Field",
            components=["DOE", "JOHN", "A"],
        )
        primitive = field.to_primitive(component_sep="^")
        # The value should be joined with component separator
        assert isinstance(primitive, Static)


# =============================================================================
# Test DelimitedSegment
# =============================================================================


class TestDelimitedSegment:
    """Tests for DelimitedSegment class."""

    def test_simple_segment_creation(self):
        """Create a basic delimited segment."""
        segment = DelimitedSegment(
            name="Test_Segment",
            segment_id="TST",
            fields=["field1", "field2", "field3"],
        )
        assert segment.name == "Test_Segment"
        assert segment.segment_id == "TST"
        assert len(segment.fields) == 3

    def test_segment_default_delimiters(self):
        """Segment uses HL7-compatible defaults."""
        segment = DelimitedSegment(
            name="Default_Segment",
            segment_id="DEF",
            fields=["a", "b"],
        )
        assert segment.field_sep == "|"
        assert segment.component_sep == "^"
        assert segment.subcomponent_sep == "&"
        assert segment.repetition_sep == "~"
        assert segment.escape_char == "\\"
        assert segment.terminator == "\r"

    def test_segment_custom_delimiters(self):
        """Segment accepts custom delimiters."""
        segment = DelimitedSegment(
            name="Custom_Segment",
            segment_id="CUS",
            fields=["a", "b"],
            field_sep=",",
            component_sep=":",
            terminator="\n",
        )
        assert segment.field_sep == ","
        assert segment.component_sep == ":"
        assert segment.terminator == "\n"

    def test_segment_fuzzable_fields(self):
        """Segment tracks which fields should be fuzzed."""
        segment = DelimitedSegment(
            name="Fuzz_Segment",
            segment_id="FUZ",
            fields=["a", "b", "c", "d"],
            fuzzable_fields=[1, 3],
        )
        assert 1 in segment.fuzzable_fields
        assert 3 in segment.fuzzable_fields
        assert 0 not in segment.fuzzable_fields

    def test_segment_to_block(self):
        """Segment converts to boofuzz Block."""
        segment = DelimitedSegment(
            name="Block_Test",
            segment_id="BLK",
            fields=["val1", "val2"],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_segment_to_block_structure(self):
        """Segment block has correct child structure."""
        segment = DelimitedSegment(
            name="PID_Segment",
            segment_id="PID",
            fields=["1", "12345", "DOE^JOHN"],
        )
        block = segment.to_block()
        # Block should have: segment_id + (sep + field) * N + terminator
        # That's 1 + 3*2 + 1 = 8 children
        assert len(block.stack) >= 5  # At minimum: ID, sep, f1, sep, f2, sep, f3, term

    def test_segment_with_tuple_fields(self):
        """Segment handles (value, options) tuple fields."""
        segment = DelimitedSegment(
            name="Tuple_Test",
            segment_id="TUP",
            fields=[
                ("value1", {"fuzzable": True, "max_len": 100}),
                ("value2", {"name": "Custom_Name"}),
                "simple_value",
            ],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_segment_empty_fields(self):
        """Segment handles empty field values."""
        segment = DelimitedSegment(
            name="Empty_Test",
            segment_id="EMP",
            fields=["", "value", "", ""],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_segment_max_field_len(self):
        """Segment respects max_field_len setting."""
        segment = DelimitedSegment(
            name="MaxLen_Test",
            segment_id="MAX",
            fields=["test"],
            fuzzable_fields=[0],
            max_field_len=1000,
        )
        assert segment.max_field_len == 1000


# =============================================================================
# Test HL7Segment
# =============================================================================


class TestHL7Segment:
    """Tests for HL7Segment convenience class."""

    def test_hl7_segment_uses_hl7_delimiters(self):
        """HL7Segment automatically uses HL7 delimiters."""
        segment = HL7Segment(
            name="PID_Segment",
            segment_id="PID",
            fields=["1", "12345"],
        )
        assert segment.field_sep == "|"
        assert segment.component_sep == "^"
        assert segment.terminator == "\r"

    def test_hl7_segment_fuzzable_fields(self):
        """HL7Segment accepts fuzzable_fields parameter."""
        segment = HL7Segment(
            name="PID_Segment",
            segment_id="PID",
            fields=["1", "12345", "DOE^JOHN"],
            fuzzable_fields=[1, 2],
        )
        assert 1 in segment.fuzzable_fields
        assert 2 in segment.fuzzable_fields

    def test_hl7_segment_to_block(self):
        """HL7Segment converts to boofuzz Block."""
        segment = HL7Segment(
            name="EVN_Segment",
            segment_id="EVN",
            fields=["A01", "20240101120000"],
        )
        block = segment.to_block()
        assert isinstance(block, Block)


# =============================================================================
# Test FramedMessage
# =============================================================================


class TestFramedMessage:
    """Tests for FramedMessage class."""

    def test_framed_message_creation(self):
        """Create a basic framed message."""
        msg = FramedMessage(name="Test_Message")
        assert msg.name == "Test_Message"
        assert msg.segments == []

    def test_framed_message_default_markers(self):
        """FramedMessage uses MLLP markers by default."""
        msg = FramedMessage(name="MLLP_Message")
        assert msg.start_marker == b"\x0b"
        assert msg.end_marker == b"\x1c\x0d"

    def test_framed_message_custom_markers(self):
        """FramedMessage accepts custom frame markers."""
        msg = FramedMessage(
            name="Custom_Frame",
            start_marker=b"\x02",  # STX
            end_marker=b"\x03",  # ETX
        )
        assert msg.start_marker == b"\x02"
        assert msg.end_marker == b"\x03"

    def test_framed_message_add_segment(self):
        """Add segment to framed message."""
        msg = FramedMessage(name="Add_Test")
        segment = DelimitedSegment("SEG", "SEG", ["a", "b"])
        msg.add_segment(segment)
        assert len(msg.segments) == 1

    def test_framed_message_to_request(self):
        """FramedMessage converts to boofuzz Request."""
        msg = FramedMessage(name="Request_Test")
        segment = DelimitedSegment("SEG", "SEG", ["value"])
        msg.add_segment(segment)
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_framed_message_fuzz_framing(self):
        """FramedMessage can fuzz frame markers."""
        msg = FramedMessage(name="Fuzz_Frame", fuzz_framing=True)
        assert msg.fuzz_framing is True


# =============================================================================
# Test HL7Message
# =============================================================================


class TestHL7Message:
    """Tests for HL7Message class."""

    def test_hl7_message_creation(self):
        """Create an HL7 message."""
        msg = HL7Message(name="ADT_Test", message_type="ADT^A01")
        assert msg.name == "ADT_Test"
        assert msg.message_type == "ADT^A01"
        assert msg.version == "2.5"

    def test_hl7_message_custom_version(self):
        """HL7Message accepts custom version."""
        msg = HL7Message(
            name="Custom_Version",
            message_type="ORU^R01",
            version="2.3.1",
        )
        assert msg.version == "2.3.1"

    def test_hl7_message_uses_mllp_framing(self):
        """HL7Message uses MLLP framing."""
        msg = HL7Message(name="MLLP_Test", message_type="ACK")
        assert msg.start_marker == HL7Delimiters.MLLP_START
        assert msg.end_marker == HL7Delimiters.MLLP_END

    def test_hl7_message_application_settings(self):
        """HL7Message stores application settings."""
        msg = HL7Message(
            name="App_Test",
            message_type="ADT^A01",
            sending_app="LAB_SYSTEM",
            sending_facility="HOSPITAL_A",
            receiving_app="HIS_SYSTEM",
            receiving_facility="HOSPITAL_B",
            processing_id="P",
        )
        assert msg.sending_app == "LAB_SYSTEM"
        assert msg.sending_facility == "HOSPITAL_A"
        assert msg.receiving_app == "HIS_SYSTEM"
        assert msg.receiving_facility == "HOSPITAL_B"
        assert msg.processing_id == "P"

    def test_hl7_message_timestamp_format(self):
        """HL7Message generates valid timestamp format."""
        msg = HL7Message(name="TS_Test", message_type="ACK")
        ts = msg._get_timestamp()
        # Should be YYYYMMDDHHMMSS format (14 chars)
        assert len(ts) == 14
        assert ts.isdigit()

    def test_hl7_message_control_id_format(self):
        """HL7Message generates unique control IDs."""
        msg = HL7Message(name="ID_Test", message_type="ACK")
        id1 = msg._get_message_control_id()
        assert id1.startswith("MSG")
        # Control ID should be cached
        id2 = msg._get_message_control_id()
        assert id1 == id2

    def test_hl7_message_add_msh(self):
        """Add MSH segment to HL7 message."""
        msg = HL7Message(name="MSH_Test", message_type="ADT^A01")
        msg.add_msh()
        assert len(msg.segments) == 1

    def test_hl7_message_add_msh_with_fuzzable(self):
        """Add MSH segment with fuzzable fields."""
        msg = HL7Message(name="MSH_Fuzz", message_type="ADT^A01")
        msg.add_msh(fuzzable=["sending_app", "timestamp"])
        assert len(msg.segments) == 1

    def test_hl7_message_add_evn(self):
        """Add EVN segment to HL7 message."""
        msg = HL7Message(name="EVN_Test", message_type="ADT^A01")
        msg.add_evn(event_type="A01")
        assert len(msg.segments) == 1

    def test_hl7_message_add_pid(self):
        """Add PID segment to HL7 message."""
        msg = HL7Message(name="PID_Test", message_type="ADT^A01")
        msg.add_pid(
            patient_id_list="12345^^^MRN",
            name="DOE^JOHN^A",
            dob="19800101",
            gender="M",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_pid_with_fuzzable(self):
        """Add PID segment with fuzzable fields."""
        msg = HL7Message(name="PID_Fuzz", message_type="ADT^A01")
        msg.add_pid(
            patient_id_list="12345",
            name="DOE^JOHN",
            fuzzable=["patient_id_list", "name", "address"],
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_pv1(self):
        """Add PV1 segment to HL7 message."""
        msg = HL7Message(name="PV1_Test", message_type="ADT^A01")
        msg.add_pv1(
            patient_class="I",
            location="WEST^101^A",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_orc(self):
        """Add ORC segment to HL7 message."""
        msg = HL7Message(name="ORC_Test", message_type="ORM^O01")
        msg.add_orc(
            order_control="NW",
            placer_order="ORD001",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_obr(self):
        """Add OBR segment to HL7 message."""
        msg = HL7Message(name="OBR_Test", message_type="ORU^R01")
        msg.add_obr(
            placer_order="ORD001",
            filler_order="FIL001",
            universal_service_id="85025^CBC^L",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_obx(self):
        """Add OBX segment to HL7 message."""
        msg = HL7Message(name="OBX_Test", message_type="ORU^R01")
        msg.add_obx(
            value_type="NM",
            observation_id="1234-5^WBC^LN",
            value="7.5",
            units="K/uL",
            reference_range="4.5-11.0",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_msa(self):
        """Add MSA segment to HL7 message."""
        msg = HL7Message(name="MSA_Test", message_type="ACK")
        msg.add_msa(acknowledgment_code="AA")
        assert len(msg.segments) == 1

    def test_hl7_message_add_qrd(self):
        """Add QRD segment to HL7 message."""
        msg = HL7Message(name="QRD_Test", message_type="QRY^A19")
        msg.add_qrd(
            query_id="QRY001",
            who_subject="12345^^^MRN",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_custom_segment(self):
        """Add custom segment to HL7 message."""
        msg = HL7Message(name="Custom_Test", message_type="ADT^A01")
        msg.add_segment(
            segment_id="ZZZ",
            fields=["custom1", "custom2", "custom3"],
            fuzzable_fields=[1],
        )
        assert len(msg.segments) == 1

    def test_hl7_message_complete_adt_a01(self):
        """Build complete ADT^A01 message."""
        msg = HL7Message(name="Complete_ADT", message_type="ADT^A01")
        msg.add_msh()
        msg.add_evn(event_type="A01")
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_pv1(location="WEST^101")

        assert len(msg.segments) == 4
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_hl7_message_complete_oru_r01(self):
        """Build complete ORU^R01 message."""
        msg = HL7Message(name="Complete_ORU", message_type="ORU^R01")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_orc(order_control="RE")
        msg.add_obr(universal_service_id="85025^CBC^L")
        msg.add_obx(value_type="NM", observation_id="WBC", value="7.5")
        msg.add_obx(set_id="2", value_type="NM", observation_id="RBC", value="4.8")

        assert len(msg.segments) == 6
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_hl7_message_to_request_with_fuzz_framing(self):
        """HL7Message with fuzz_framing enabled."""
        msg = HL7Message(
            name="Fuzz_Frame_Test",
            message_type="ACK",
            fuzz_framing=True,
        )
        msg.add_msh()
        msg.add_msa()

        request = msg.to_request()
        assert isinstance(request, Request)

    # Tests for additional segment builders (matching protocol analyzer)

    def test_hl7_message_add_sch(self):
        """Add SCH segment to HL7 message."""
        msg = HL7Message(name="SCH_Test", message_type="SIU^S12")
        msg.add_sch(
            placer_appointment_id="APPT001",
            appointment_type="ROUTINE",
            duration="60",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_txa(self):
        """Add TXA segment to HL7 message."""
        msg = HL7Message(name="TXA_Test", message_type="MDM^T02")
        msg.add_txa(
            document_type="DS",
            unique_document_number="DOC001",
            completion_status="AU",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_rxo(self):
        """Add RXO segment to HL7 message."""
        msg = HL7Message(name="RXO_Test", message_type="RDE^O11")
        msg.add_rxo(
            drug_code="00069-0150-01",
            drug_name="AMOXICILLIN",
            requested_dose="500",
            requested_units="MG",
            refills="2",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_rxe(self):
        """Add RXE segment to HL7 message."""
        msg = HL7Message(name="RXE_Test", message_type="RDE^O11")
        msg.add_rxe(
            drug_code="00069-0150-01",
            drug_name="AMOXICILLIN",
            give_amount="500",
            give_units="MG",
            prescription_number="RX123456",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_rxa(self):
        """Add RXA segment to HL7 message."""
        msg = HL7Message(name="RXA_Test", message_type="VXU^V04")
        msg.add_rxa(
            admin_code="90734",
            admin_name="INFLUENZA VACCINE",
            admin_amount="0.5",
            admin_units="ML",
            lot_number="LOT123",
            manufacturer="SANOFI",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_rxd(self):
        """Add RXD segment to HL7 message."""
        msg = HL7Message(name="RXD_Test", message_type="RDS^O13")
        msg.add_rxd(
            drug_code="00069-0150-01",
            drug_name="AMOXICILLIN",
            actual_dispense_amount="30",
            actual_dispense_units="TAB",
            prescription_number="RX123456",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_rxg(self):
        """Add RXG segment to HL7 message."""
        msg = HL7Message(name="RXG_Test", message_type="RGV^O15")
        msg.add_rxg(
            drug_code="00069-0150-01",
            drug_name="AMOXICILLIN",
            give_amount="500",
            give_units="MG",
            give_dosage_form="TAB",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_dg1(self):
        """Add DG1 segment to HL7 message."""
        msg = HL7Message(name="DG1_Test", message_type="ADT^A01")
        msg.add_dg1(
            diagnosis_code="J06.9",
            diagnosis_description="ACUTE UPPER RESPIRATORY INFECTION",
            diagnosis_type="A",
            coding_method="ICD10",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_pr1(self):
        """Add PR1 segment to HL7 message."""
        msg = HL7Message(name="PR1_Test", message_type="ADT^A01")
        msg.add_pr1(
            procedure_code="99213",
            procedure_description="OFFICE VISIT",
            procedure_type="S",
            coding_method="CPT",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_mrg(self):
        """Add MRG segment to HL7 message."""
        msg = HL7Message(name="MRG_Test", message_type="ADT^A40")
        msg.add_mrg(
            prior_patient_id="OLD123",
            prior_patient_name="DOE^JOHN^OLD",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_ft1(self):
        """Add FT1 segment to HL7 message."""
        msg = HL7Message(name="FT1_Test", message_type="DFT^P03")
        msg.add_ft1(
            transaction_id="TRANS001",
            transaction_type="CG",
            transaction_code="99213",
            transaction_description="OFFICE VISIT",
            transaction_amount="150.00",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_gt1(self):
        """Add GT1 segment to HL7 message."""
        msg = HL7Message(name="GT1_Test", message_type="ADT^A01")
        msg.add_gt1(
            guarantor_number="GT001",
            guarantor_name="DOE^JANE",
            guarantor_relationship="SPO",
            guarantor_phone="555-1234",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_in1(self):
        """Add IN1 segment to HL7 message."""
        msg = HL7Message(name="IN1_Test", message_type="ADT^A01")
        msg.add_in1(
            insurance_plan_id="BCBS001",
            insurance_company_name="BLUE CROSS",
            group_number="GRP123",
            _policy_number="POL456",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_add_nk1(self):
        """Add NK1 segment to HL7 message."""
        msg = HL7Message(name="NK1_Test", message_type="ADT^A01")
        msg.add_nk1(
            name="DOE^JANE",
            relationship="SPO",
            phone="555-1234",
            contact_role="EC",
        )
        assert len(msg.segments) == 1

    def test_hl7_message_complete_pharmacy_order(self):
        """Build complete pharmacy order message."""
        msg = HL7Message(name="RDE_O11", message_type="RDE^O11")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_orc(order_control="NW", placer_order="ORD001")
        msg.add_rxo(
            drug_code="00069-0150-01",
            drug_name="AMOXICILLIN",
            requested_dose="500",
            requested_units="MG",
        )
        msg.add_rxe(
            drug_code="00069-0150-01",
            drug_name="AMOXICILLIN",
            give_amount="500",
            give_units="MG",
        )

        assert len(msg.segments) == 5
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_hl7_message_complete_immunization(self):
        """Build complete immunization message."""
        msg = HL7Message(name="VXU_V04", message_type="VXU^V04")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN", dob="19800101")
        msg.add_orc(order_control="RE")
        msg.add_rxa(
            admin_code="90734",
            admin_name="INFLUENZA VACCINE",
            admin_amount="0.5",
            admin_units="ML",
            lot_number="LOT123",
            manufacturer="SANOFI",
        )

        assert len(msg.segments) == 4
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_hl7_message_complete_financial(self):
        """Build complete financial transaction message."""
        msg = HL7Message(name="DFT_P03", message_type="DFT^P03")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_pv1()
        msg.add_ft1(
            transaction_code="99213",
            transaction_description="OFFICE VISIT",
            transaction_amount="150.00",
        )
        msg.add_dg1(
            diagnosis_code="J06.9",
            diagnosis_description="URI",
        )
        msg.add_pr1(
            procedure_code="99213",
            procedure_description="OFFICE VISIT",
        )
        msg.add_gt1(guarantor_name="DOE^JANE")
        msg.add_in1(insurance_company_name="BCBS", _policy_number="POL123")

        assert len(msg.segments) == 8
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_hl7_message_patient_merge(self):
        """Build patient merge message."""
        msg = HL7Message(name="ADT_A40", message_type="ADT^A40")
        msg.add_msh()
        msg.add_evn()
        msg.add_pid(patient_id_list="NEW123", name="DOE^JOHN^NEW")
        msg.add_mrg(
            prior_patient_id="OLD123",
            prior_patient_name="DOE^JOHN^OLD",
        )

        assert len(msg.segments) == 4
        request = msg.to_request()
        assert isinstance(request, Request)


# =============================================================================
# Test Attack Helpers
# =============================================================================


class TestDelimiterInjectionValues:
    """Tests for build_delimiter_injection_values helper."""

    def test_returns_list_of_bytes(self):
        """Function returns list of bytes objects."""
        values = build_delimiter_injection_values()
        assert isinstance(values, list)
        assert all(isinstance(v, bytes) for v in values)

    def test_includes_pipe_injection(self):
        """Includes field separator injection."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"|" in v for v in values)

    def test_includes_caret_injection(self):
        """Includes component separator injection."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"^" in v for v in values)

    def test_includes_tilde_injection(self):
        """Includes repetition separator injection."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"~" in v for v in values)

    def test_includes_escape_injection(self):
        """Includes escape character injection."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"\\" in v for v in values)

    def test_includes_segment_terminator_injection(self):
        """Includes segment terminator injection."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"\r" in v for v in values)

    def test_includes_sql_injection(self):
        """Includes SQL injection patterns."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"DROP" in v for v in values)

    def test_includes_xss_attempt(self):
        """Includes XSS attempt patterns."""
        values = build_delimiter_injection_values("TEST")
        assert any(b"<SCRIPT>" in v for v in values)

    def test_custom_base_value(self):
        """Respects custom base value."""
        values = build_delimiter_injection_values("CUSTOM")
        assert any(v.startswith(b"CUSTOM") for v in values)

    def test_sufficient_test_cases(self):
        """Generates sufficient test cases."""
        values = build_delimiter_injection_values()
        assert len(values) >= 15


class TestOversizedFieldValues:
    """Tests for build_oversized_field_values helper."""

    def test_returns_list_of_bytes(self):
        """Function returns list of bytes objects."""
        values = build_oversized_field_values()
        assert isinstance(values, list)
        assert all(isinstance(v, bytes) for v in values)

    def test_default_sizes(self):
        """Uses default sizes when none provided."""
        values = build_oversized_field_values()
        sizes = [len(v) for v in values]
        assert 1000 in sizes
        assert 5000 in sizes
        assert 10000 in sizes
        assert 50000 in sizes

    def test_custom_sizes(self):
        """Respects custom size list."""
        values = build_oversized_field_values(sizes=[100, 200, 300])
        assert len(values) == 3
        assert len(values[0]) == 100
        assert len(values[1]) == 200
        assert len(values[2]) == 300

    def test_custom_char(self):
        """Respects custom padding character."""
        values = build_oversized_field_values(sizes=[10], char="X")
        assert values[0] == b"XXXXXXXXXX"

    def test_default_char_is_A(self):
        """Default padding character is 'A'."""
        values = build_oversized_field_values(sizes=[5])
        assert values[0] == b"AAAAA"


class TestMLLPCorruptionValues:
    """Tests for build_mllp_corruption_values helper."""

    def test_returns_tuple_of_lists(self):
        """Function returns tuple of two lists."""
        start_values, end_values = build_mllp_corruption_values()
        assert isinstance(start_values, list)
        assert isinstance(end_values, list)

    def test_start_values_are_bytes(self):
        """Start marker values are bytes."""
        start_values, _ = build_mllp_corruption_values()
        assert all(isinstance(v, bytes) for v in start_values)

    def test_end_values_are_bytes(self):
        """End marker values are bytes."""
        _, end_values = build_mllp_corruption_values()
        assert all(isinstance(v, bytes) for v in end_values)

    def test_includes_valid_start(self):
        """Includes valid MLLP start marker."""
        start_values, _ = build_mllp_corruption_values()
        assert b"\x0b" in start_values

    def test_includes_valid_end(self):
        """Includes valid MLLP end marker."""
        _, end_values = build_mllp_corruption_values()
        assert b"\x1c\x0d" in end_values

    def test_includes_missing_start(self):
        """Includes empty start marker."""
        start_values, _ = build_mllp_corruption_values()
        assert b"" in start_values

    def test_includes_missing_end(self):
        """Includes empty end marker."""
        _, end_values = build_mllp_corruption_values()
        assert b"" in end_values

    def test_includes_double_start(self):
        """Includes doubled start marker."""
        start_values, _ = build_mllp_corruption_values()
        assert b"\x0b\x0b" in start_values

    def test_includes_reversed_end(self):
        """Includes reversed end marker."""
        _, end_values = build_mllp_corruption_values()
        assert b"\x0d\x1c" in end_values

    def test_sufficient_test_cases(self):
        """Generates sufficient test cases."""
        start_values, end_values = build_mllp_corruption_values()
        assert len(start_values) >= 8
        assert len(end_values) >= 8


class TestEncodingCharValues:
    """Tests for build_encoding_char_values helper."""

    def test_returns_list_of_bytes(self):
        """Function returns list of bytes."""
        values = build_encoding_char_values()
        assert isinstance(values, list)
        assert all(isinstance(v, bytes) for v in values)

    def test_includes_standard_encoding(self):
        """Includes standard HL7 encoding chars."""
        values = build_encoding_char_values()
        assert b"^~\\&" in values

    def test_includes_empty_encoding(self):
        """Includes empty encoding chars."""
        values = build_encoding_char_values()
        assert b"" in values

    def test_includes_partial_encoding(self):
        """Includes partial encoding chars."""
        values = build_encoding_char_values()
        assert b"^" in values or b"^~" in values

    def test_includes_null_bytes(self):
        """Includes null byte encoding."""
        values = build_encoding_char_values()
        assert any(b"\x00" in v for v in values)

    def test_includes_high_bytes(self):
        """Includes high byte encoding."""
        values = build_encoding_char_values()
        assert any(b"\xff" in v for v in values)

    def test_sufficient_test_cases(self):
        """Generates sufficient test cases."""
        values = build_encoding_char_values()
        assert len(values) >= 12


class TestSegmentFuzzingValues:
    """Tests for build_segment_fuzzing_values helper."""

    def test_returns_list_of_bytes(self):
        """Function returns list of bytes."""
        values = build_segment_fuzzing_values()
        assert isinstance(values, list)
        assert all(isinstance(v, bytes) for v in values)

    def test_includes_z_segments(self):
        """Includes Z-segment (custom) types."""
        values = build_segment_fuzzing_values()
        assert any(v.startswith(b"ZZZ") for v in values)

    def test_includes_invalid_segment_ids(self):
        """Includes invalid segment ID formats."""
        values = build_segment_fuzzing_values()
        assert any(v.startswith(b"XXX") for v in values)
        assert any(v.startswith(b"123") for v in values)

    def test_includes_empty_segment(self):
        """Includes empty segment."""
        values = build_segment_fuzzing_values()
        assert b"\r" in values

    def test_includes_binary_data(self):
        """Includes binary data in segment."""
        values = build_segment_fuzzing_values()
        assert any(b"\x00" in v for v in values)

    def test_includes_excessive_fields(self):
        """Includes segment with excessive fields."""
        values = build_segment_fuzzing_values()
        # Look for segment with many pipes (field separators)
        assert any(v.count(b"|") > 50 for v in values)

    def test_sufficient_test_cases(self):
        """Generates sufficient test cases."""
        values = build_segment_fuzzing_values()
        assert len(values) >= 10


# =============================================================================
# Test Integration - Complete Message Building
# =============================================================================


class TestHL7MessageIntegration:
    """Integration tests for complete HL7 message building."""

    def test_adt_a01_message_structure(self):
        """ADT^A01 message has correct structure."""
        msg = HL7Message(name="ADT_A01", message_type="ADT^A01")
        msg.add_msh()
        msg.add_evn()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_pv1()

        request = msg.to_request()

        # Verify request structure
        assert request.name == "ADT_A01"
        # Request should have start marker, content block, end marker
        assert len(request.stack) == 3

    def test_oru_r01_message_structure(self):
        """ORU^R01 message has correct structure."""
        msg = HL7Message(name="ORU_R01", message_type="ORU^R01")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_obr(universal_service_id="CBC")
        msg.add_obx(value_type="NM", observation_id="WBC", value="7.5")

        request = msg.to_request()
        assert request.name == "ORU_R01"

    def test_ack_message_structure(self):
        """ACK message has correct structure."""
        msg = HL7Message(name="ACK", message_type="ACK")
        msg.add_msh()
        msg.add_msa(acknowledgment_code="AA")

        request = msg.to_request()
        assert request.name == "ACK"
        assert len(msg.segments) == 2

    def test_qry_a19_message_structure(self):
        """QRY^A19 message has correct structure."""
        msg = HL7Message(name="QRY_A19", message_type="QRY^A19")
        msg.add_msh()
        msg.add_qrd(query_id="Q001", who_subject="12345^^^MRN")

        request = msg.to_request()
        assert request.name == "QRY_A19"
        assert len(msg.segments) == 2

    def test_orm_o01_message_structure(self):
        """ORM^O01 message has correct structure."""
        msg = HL7Message(name="ORM_O01", message_type="ORM^O01")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_orc(order_control="NW", placer_order="ORD001")
        msg.add_obr(placer_order="ORD001", universal_service_id="CBC")

        request = msg.to_request()
        assert request.name == "ORM_O01"
        assert len(msg.segments) == 4

    def test_message_with_all_fuzzable_fields(self):
        """Message with all fields marked fuzzable."""
        msg = HL7Message(
            name="Full_Fuzz",
            message_type="ADT^A01",
            fuzz_framing=True,
        )
        msg.add_msh(fuzzable=["encoding_chars", "sending_app", "receiving_app", "timestamp"])
        msg.add_pid(
            patient_id_list="12345",
            name="DOE^JOHN",
            fuzzable=["patient_id_list", "name", "dob", "address"],
        )

        request = msg.to_request()
        assert isinstance(request, Request)

    def test_message_with_multiple_obx_segments(self):
        """Message with multiple OBX result segments."""
        msg = HL7Message(name="Multi_OBX", message_type="ORU^R01")
        msg.add_msh()
        msg.add_pid(patient_id_list="12345", name="DOE^JOHN")
        msg.add_obr(universal_service_id="CBC")

        # Add multiple OBX segments
        for i in range(5):
            msg.add_obx(
                set_id=str(i + 1),
                value_type="NM",
                observation_id=f"TEST{i}",
                value=str(i * 10),
            )

        assert len(msg.segments) == 8  # MSH + PID + OBR + 5 OBX


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for delimited primitives."""

    def test_empty_segment_fields(self):
        """Handle segment with all empty fields."""
        segment = HL7Segment(
            name="Empty_Fields",
            segment_id="TST",
            fields=["", "", "", ""],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_unicode_in_fields(self):
        """Handle unicode characters in fields."""
        segment = HL7Segment(
            name="Unicode_Test",
            segment_id="PID",
            fields=["1", "12345", "Müller^Jürgen"],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_special_chars_in_fields(self):
        """Handle special characters in fields."""
        segment = HL7Segment(
            name="Special_Test",
            segment_id="PID",
            fields=["1", "12345", "O'Brien^John"],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_very_long_field_value(self):
        """Handle very long field value."""
        long_value = "A" * 10000
        segment = HL7Segment(
            name="Long_Test",
            segment_id="OBX",
            fields=[long_value],
            fuzzable_fields=[0],
            max_field_len=50000,
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    def test_message_with_no_segments(self):
        """Handle message with no segments."""
        msg = HL7Message(name="Empty_Message", message_type="ACK")
        request = msg.to_request()
        assert isinstance(request, Request)

    def test_custom_delimiters_for_astm(self):
        """Test ASTM-like delimiters."""
        segment = DelimitedSegment(
            name="ASTM_Segment",
            segment_id="H",
            fields=["field1", "field2"],
            field_sep="|",
            component_sep="^",
            terminator="\r\n",  # ASTM uses CRLF
        )
        assert segment.terminator == "\r\n"

    def test_csv_like_delimiters(self):
        """Test CSV-like delimiters."""
        segment = DelimitedSegment(
            name="CSV_Segment",
            segment_id="",  # CSV has no segment ID
            fields=["col1", "col2", "col3"],
            field_sep=",",
            terminator="\n",
        )
        assert segment.field_sep == ","

    def test_timestamp_consistency(self):
        """Timestamp is consistent within message."""
        msg = HL7Message(name="TS_Test", message_type="ADT^A01")
        ts1 = msg._get_timestamp()
        ts2 = msg._get_timestamp()
        assert ts1 == ts2

    def test_control_id_consistency(self):
        """Control ID is consistent within message."""
        msg = HL7Message(name="ID_Test", message_type="ADT^A01")
        id1 = msg._get_message_control_id()
        id2 = msg._get_message_control_id()
        assert id1 == id2


# =============================================================================
# Test Parametrized Segment Types
# =============================================================================


class TestParametrizedSegments:
    """Parametrized tests for various segment types."""

    @pytest.mark.parametrize(
        "segment_id", ["MSH", "PID", "PV1", "OBR", "OBX", "EVN", "MSA", "ORC", "QRD"]
    )
    def test_standard_segment_ids(self, segment_id):
        """Test standard HL7 segment IDs."""
        segment = HL7Segment(
            name=f"{segment_id}_Test",
            segment_id=segment_id,
            fields=["test_value"],
        )
        block = segment.to_block()
        assert isinstance(block, Block)

    @pytest.mark.parametrize(
        "message_type",
        [
            "ADT^A01",
            "ADT^A02",
            "ADT^A03",
            "ADT^A04",
            "ADT^A08",
            "ORU^R01",
            "ORM^O01",
            "QRY^A19",
            "ACK",
            "MDM^T01",
        ],
    )
    def test_standard_message_types(self, message_type):
        """Test standard HL7 message types."""
        msg = HL7Message(name=f"Test_{message_type}", message_type=message_type)
        msg.add_msh()
        request = msg.to_request()
        assert isinstance(request, Request)

    @pytest.mark.parametrize(
        "version", ["2.1", "2.2", "2.3", "2.3.1", "2.4", "2.5", "2.5.1", "2.6", "2.7"]
    )
    def test_hl7_versions(self, version):
        """Test various HL7 versions."""
        msg = HL7Message(
            name=f"Version_{version}",
            message_type="ADT^A01",
            version=version,
        )
        assert msg.version == version

    @pytest.mark.parametrize("processing_id", ["P", "D", "T"])
    def test_processing_ids(self, processing_id):
        """Test processing ID values."""
        msg = HL7Message(
            name=f"PI_{processing_id}",
            message_type="ADT^A01",
            processing_id=processing_id,
        )
        assert msg.processing_id == processing_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
