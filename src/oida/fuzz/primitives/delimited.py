r"""
Generic Delimited Block Primitives

Reusable primitives for delimited protocols like HL7, ASTM E1381, CSV, etc.

These primitives reduce boilerplate when building fuzzers for protocols that use
hierarchical delimiter structures:
    - HL7: |^~\& delimiters, \r segment terminator, MLLP framing
    - ASTM E1381: Similar to HL7 with |^& delimiters
    - CSV/TSV: Field delimiters with optional quoting
    - Syslog structured data: [key="value" ...]

Usage:
    # Simple approach - use HL7Message directly
    msg = HL7Message("ADT_A01", "ADT^A01")
    msg.add_msh(sending_app="LAB", receiving_app="HIS")
    msg.add_pid(patient_id="12345", name="DOE^JOHN")
    request = msg.to_request()

    # Low-level approach - build segments manually
    seg = DelimitedSegment("PID", "PID", [
        "1", "", "12345^^^MRN", "", "DOE^JOHN^A", "", "19800101", "M"
    ], fuzzable_fields=[2, 4])
    block = seg.to_block()
"""

from datetime import datetime
from typing import List, Optional, Tuple, Union

from boofuzz import Block, Bytes, Request, Static

from .dynamic import SmartString


# Type aliases
FieldValue = Union[str, bytes, Tuple[str, dict]]


class DelimitedField:
    """Single field with optional components in a delimited segment

    A field can contain:
    - Simple value: "DOE"
    - Components: "DOE^JOHN^A" (separated by component_sep)
    - Subcomponents: "DOE&JR^JOHN" (separated by subcomponent_sep)
    - Repetitions: "DOE~SMITH" (separated by repetition_sep)

    Args:
        name: Field identifier for fuzzing
        value: Field value (string or bytes)
        fuzzable: Whether to fuzz this field
        max_len: Maximum length for fuzzing
        components: List of component values (alternative to value)
    """

    def __init__(
        self,
        name: str,
        value: str = "",
        fuzzable: bool = False,
        max_len: int = 200,
        components: Optional[List[str]] = None,
    ):
        self.name = name
        self.value = value
        self.fuzzable = fuzzable
        self.max_len = max_len
        self.components = components

    def to_primitive(self, component_sep: str = "^"):
        """Convert to boofuzz primitive

        Args:
            component_sep: Separator for components

        Returns:
            boofuzz primitive (Static or SmartString)
        """
        if self.components:
            value = component_sep.join(self.components)
        else:
            value = self.value

        if self.fuzzable:
            return SmartString(self.name, value, max_len=self.max_len, fuzzable=True)
        return Static(self.name, value)


class DelimitedSegment:
    """Generic delimited segment builder for HL7, ASTM, CSV-like protocols

    A segment consists of:
    - Segment ID (e.g., "MSH", "PID", "OBX")
    - Fields separated by field_sep (e.g., "|")
    - Components within fields separated by component_sep (e.g., "^")
    - Terminated by terminator (e.g., "\r")

    Args:
        name: Segment name for fuzzing framework
        segment_id: 3-letter segment identifier (e.g., "MSH", "PID")
        fields: List of field values or (value, options) tuples
        field_sep: Field separator character
        component_sep: Component separator character
        subcomponent_sep: Subcomponent separator character
        repetition_sep: Repetition separator character
        escape_char: Escape character
        terminator: Segment terminator string
        fuzzable_fields: List of field indices to fuzz (0-based, after segment_id)
        max_field_len: Default max length for fuzzed fields

    Example:
        # Create PID segment with fuzzable patient_id (field 3) and name (field 5)
        pid = DelimitedSegment(
            name="PID_Segment",
            segment_id="PID",
            fields=["1", "", "12345^^^MRN", "", "DOE^JOHN^A", "", "19800101", "M"],
            fuzzable_fields=[2, 4],  # 0-indexed: patient_id and name
            max_field_len=500,
        )
    """

    def __init__(
        self,
        name: str,
        segment_id: str,
        fields: List[FieldValue],
        field_sep: str = "|",
        component_sep: str = "^",
        subcomponent_sep: str = "&",
        repetition_sep: str = "~",
        escape_char: str = "\\",
        terminator: str = "\r",
        fuzzable_fields: Optional[List[int]] = None,
        max_field_len: int = 200,
    ):
        self.name = name
        self.segment_id = segment_id
        self.fields = fields
        self.field_sep = field_sep
        self.component_sep = component_sep
        self.subcomponent_sep = subcomponent_sep
        self.repetition_sep = repetition_sep
        self.escape_char = escape_char
        self.terminator = terminator
        self.fuzzable_fields = set(fuzzable_fields or [])
        self.max_field_len = max_field_len

    def to_block(self) -> Block:
        """Convert to boofuzz Block with proper fuzzing

        Returns:
            boofuzz Block containing the segment
        """
        children = []

        # Segment ID
        children.append(Static(f"{self.name}_ID", self.segment_id))

        # Fields
        for i, field in enumerate(self.fields):
            # Add field separator before each field
            children.append(Static(f"{self.name}_Sep{i}", self.field_sep))

            # Parse field value and options
            if isinstance(field, tuple):
                value, options = field
                fuzzable = options.get("fuzzable", i in self.fuzzable_fields)
                max_len = options.get("max_len", self.max_field_len)
                field_name = options.get("name", f"{self.name}_F{i}")
            else:
                value = field
                fuzzable = i in self.fuzzable_fields
                max_len = self.max_field_len
                field_name = f"{self.name}_F{i}"

            # Create appropriate primitive
            if fuzzable:
                children.append(SmartString(field_name, str(value), max_len=max_len, fuzzable=True))
            elif value:
                children.append(Static(field_name, str(value)))
            # Empty fields are just separators, no content primitive needed

        # Terminator
        children.append(Static(f"{self.name}_Term", self.terminator))

        return Block(self.name, children=tuple(children))


class FramedMessage:
    """Generic framed message (MLLP, STX/ETX, etc.)

    A framed message consists of:
    - Start marker (e.g., 0x0B for MLLP)
    - Message content (segments)
    - End marker (e.g., 0x1C 0x0D for MLLP)

    Args:
        name: Message name for fuzzing framework
        start_marker: Start framing bytes
        end_marker: End framing bytes
        segments: List of DelimitedSegment objects
        fuzz_framing: Whether to fuzz the start/end markers
    """

    def __init__(
        self,
        name: str,
        start_marker: bytes = b"\x0b",
        end_marker: bytes = b"\x1c\x0d",
        segments: Optional[List[DelimitedSegment]] = None,
        fuzz_framing: bool = False,
    ):
        self.name = name
        self.start_marker = start_marker
        self.end_marker = end_marker
        self.segments = segments or []
        self.fuzz_framing = fuzz_framing

    def add_segment(self, segment: DelimitedSegment):
        """Add a segment to the message

        Args:
            segment: DelimitedSegment to add
        """
        self.segments.append(segment)

    def to_request(self) -> Request:
        """Convert to boofuzz Request

        Returns:
            boofuzz Request containing the complete message
        """
        children = []

        # Start marker
        children.append(Bytes("MLLP_Start", self.start_marker, fuzzable=self.fuzz_framing))

        # Message content block
        segment_children = []
        for segment in self.segments:
            segment_children.append(segment.to_block())

        children.append(Block("Message_Content", children=tuple(segment_children)))

        # End marker
        children.append(Bytes("MLLP_End", self.end_marker, fuzzable=self.fuzz_framing))

        return Request(self.name, children=tuple(children))


# =============================================================================
# HL7-Specific Classes
# =============================================================================


class HL7Delimiters:
    """HL7 v2.x delimiter constants"""

    FIELD_SEP = "|"
    COMPONENT_SEP = "^"
    SUBCOMPONENT_SEP = "&"
    REPETITION_SEP = "~"
    ESCAPE_CHAR = "\\"
    SEGMENT_TERM = "\r"
    ENCODING_CHARS = "^~\\&"

    # MLLP framing
    MLLP_START = b"\x0b"
    MLLP_END = b"\x1c\x0d"


class HL7Segment(DelimitedSegment):
    """HL7-specific segment with standard delimiters

    Convenience wrapper that pre-configures HL7 delimiters.
    """

    def __init__(
        self,
        name: str,
        segment_id: str,
        fields: List[FieldValue],
        fuzzable_fields: Optional[List[int]] = None,
        max_field_len: int = 200,
    ):
        super().__init__(
            name=name,
            segment_id=segment_id,
            fields=fields,
            field_sep=HL7Delimiters.FIELD_SEP,
            component_sep=HL7Delimiters.COMPONENT_SEP,
            subcomponent_sep=HL7Delimiters.SUBCOMPONENT_SEP,
            repetition_sep=HL7Delimiters.REPETITION_SEP,
            escape_char=HL7Delimiters.ESCAPE_CHAR,
            terminator=HL7Delimiters.SEGMENT_TERM,
            fuzzable_fields=fuzzable_fields,
            max_field_len=max_field_len,
        )


class HL7Message(FramedMessage):
    """HL7 v2.x message with MLLP framing

    High-level builder for HL7 messages with convenience methods for common
    segments (MSH, PID, PV1, OBX, etc.).

    Args:
        name: Message name for fuzzing framework
        message_type: HL7 message type (e.g., "ADT^A01", "ORU^R01")
        version: HL7 version (default "2.5")
        fuzz_framing: Whether to fuzz MLLP start/end markers

    Example:
        msg = HL7Message("ADT_Admit", "ADT^A01")
        msg.add_msh(sending_app="LAB", receiving_app="HIS")
        msg.add_pid(patient_id="12345", name="DOE^JOHN")
        msg.add_pv1(location="WEST^101^A")
        request = msg.to_request()
    """

    def __init__(
        self,
        name: str,
        message_type: str,
        version: str = "2.5",
        fuzz_framing: bool = False,
        sending_app: str = "FUZZ_APP",
        sending_facility: str = "FUZZ_FAC",
        receiving_app: str = "RECV_APP",
        receiving_facility: str = "RECV_FAC",
        processing_id: str = "P",
    ):
        super().__init__(
            name=name,
            start_marker=HL7Delimiters.MLLP_START,
            end_marker=HL7Delimiters.MLLP_END,
            fuzz_framing=fuzz_framing,
        )
        self.message_type = message_type
        self.version = version
        self.sending_app = sending_app
        self.sending_facility = sending_facility
        self.receiving_app = receiving_app
        self.receiving_facility = receiving_facility
        self.processing_id = processing_id
        self._msg_control_id = None
        self._timestamp = None

    def _get_timestamp(self) -> str:
        """Generate HL7 timestamp format: YYYYMMDDHHMMSS"""
        if self._timestamp is None:
            self._timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return self._timestamp

    def _get_message_control_id(self) -> str:
        """Generate unique message control ID"""
        if self._msg_control_id is None:
            self._msg_control_id = f"MSG{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}"
        return self._msg_control_id

    def add_msh(
        self,
        sending_app: Optional[str] = None,
        sending_facility: Optional[str] = None,
        receiving_app: Optional[str] = None,
        receiving_facility: Optional[str] = None,
        timestamp: Optional[str] = None,
        message_type: Optional[str] = None,
        message_control_id: Optional[str] = None,
        processing_id: Optional[str] = None,
        version: Optional[str] = None,
        fuzzable: Optional[List[str]] = None,
    ):
        """Add MSH (Message Header) segment

        Args:
            sending_app: Sending application (MSH-3)
            sending_facility: Sending facility (MSH-4)
            receiving_app: Receiving application (MSH-5)
            receiving_facility: Receiving facility (MSH-6)
            timestamp: Message timestamp (MSH-7)
            message_type: Message type (MSH-9), defaults to class message_type
            message_control_id: Unique message ID (MSH-10)
            processing_id: Processing ID P/D/T (MSH-11)
            version: HL7 version (MSH-12)
            fuzzable: List of field names to fuzz:
                      ["encoding_chars", "sending_app", "sending_facility",
                       "receiving_app", "receiving_facility", "timestamp",
                       "message_type", "message_control_id", "processing_id", "version"]
        """
        fuzzable = set(fuzzable or [])

        # MSH is special - field separator is MSH-1 and encoding chars are MSH-2
        # We build it manually since the segment ID includes the field separator
        fields = [
            # MSH-2: Encoding characters (^~\&)
            (
                HL7Delimiters.ENCODING_CHARS,
                {
                    "fuzzable": "encoding_chars" in fuzzable,
                    "max_len": 10,
                    "name": "MSH_Encoding_Chars",
                },
            ),
            # MSH-3: Sending Application
            (
                sending_app or self.sending_app,
                {
                    "fuzzable": "sending_app" in fuzzable,
                    "max_len": 100,
                    "name": "MSH_Sending_App",
                },
            ),
            # MSH-4: Sending Facility
            (
                sending_facility or self.sending_facility,
                {
                    "fuzzable": "sending_facility" in fuzzable,
                    "max_len": 100,
                    "name": "MSH_Sending_Fac",
                },
            ),
            # MSH-5: Receiving Application
            (
                receiving_app or self.receiving_app,
                {
                    "fuzzable": "receiving_app" in fuzzable,
                    "max_len": 100,
                    "name": "MSH_Receiving_App",
                },
            ),
            # MSH-6: Receiving Facility
            (
                receiving_facility or self.receiving_facility,
                {
                    "fuzzable": "receiving_facility" in fuzzable,
                    "max_len": 100,
                    "name": "MSH_Receiving_Fac",
                },
            ),
            # MSH-7: Date/Time of Message
            (
                timestamp or self._get_timestamp(),
                {
                    "fuzzable": "timestamp" in fuzzable,
                    "max_len": 26,
                    "name": "MSH_Timestamp",
                },
            ),
            # MSH-8: Security (usually empty)
            ("", {}),
            # MSH-9: Message Type
            (
                message_type or self.message_type,
                {
                    "fuzzable": "message_type" in fuzzable,
                    "max_len": 50,
                    "name": "MSH_Message_Type",
                },
            ),
            # MSH-10: Message Control ID
            (
                message_control_id or self._get_message_control_id(),
                {
                    "fuzzable": "message_control_id" in fuzzable,
                    "max_len": 50,
                    "name": "MSH_Control_ID",
                },
            ),
            # MSH-11: Processing ID
            (
                processing_id or self.processing_id,
                {
                    "fuzzable": "processing_id" in fuzzable,
                    "max_len": 3,
                    "name": "MSH_Processing_ID",
                },
            ),
            # MSH-12: Version ID
            (
                version or self.version,
                {
                    "fuzzable": "version" in fuzzable,
                    "max_len": 10,
                    "name": "MSH_Version",
                },
            ),
        ]

        segment = HL7Segment("MSH_Segment", "MSH", fields)
        self.segments.append(segment)

    def add_evn(
        self,
        event_type: str = "A01",
        timestamp: Optional[str] = None,
        fuzzable: Optional[List[str]] = None,
    ):
        """Add EVN (Event Type) segment

        Args:
            event_type: Event type code (EVN-1)
            timestamp: Event timestamp (EVN-2)
            fuzzable: List of field names to fuzz: ["event_type", "timestamp"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # EVN-1: Event Type Code
            (
                event_type,
                {
                    "fuzzable": "event_type" in fuzzable,
                    "max_len": 10,
                    "name": "EVN_Event_Type",
                },
            ),
            # EVN-2: Recorded Date/Time
            (
                timestamp or self._get_timestamp(),
                {
                    "fuzzable": "timestamp" in fuzzable,
                    "max_len": 26,
                    "name": "EVN_Timestamp",
                },
            ),
            # EVN-3 through EVN-6 (usually empty)
            ("", {}),
            ("", {}),
            ("", {}),
        ]

        segment = HL7Segment("EVN_Segment", "EVN", fields)
        self.segments.append(segment)

    def add_pid(
        self,
        set_id: str = "1",
        patient_id: str = "",
        patient_id_list: str = "12345^^^MRN",
        alt_patient_id: str = "",
        name: str = "DOE^JOHN^A",
        mothers_maiden: str = "",
        dob: str = "19800101",
        gender: str = "M",
        alias: str = "",
        race: str = "",
        address: str = "",
        county: str = "",
        phone_home: str = "",
        phone_business: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add PID (Patient Identification) segment

        Args:
            set_id: Set ID (PID-1)
            patient_id: Patient ID (PID-2, deprecated)
            patient_id_list: Patient ID list (PID-3)
            alt_patient_id: Alternate patient ID (PID-4)
            name: Patient name (PID-5)
            mothers_maiden: Mother's maiden name (PID-6)
            dob: Date of birth (PID-7)
            gender: Administrative sex (PID-8)
            alias: Patient alias (PID-9)
            race: Race (PID-10)
            address: Patient address (PID-11)
            county: County code (PID-12)
            phone_home: Home phone (PID-13)
            phone_business: Business phone (PID-14)
            fuzzable: List of field names to fuzz:
                      ["patient_id", "patient_id_list", "name", "dob", "gender",
                       "race", "address", "phone_home", "phone_business"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # PID-1: Set ID
            (set_id, {"name": "PID_Set_ID"}),
            # PID-2: Patient ID (deprecated)
            (
                patient_id,
                {
                    "fuzzable": "patient_id" in fuzzable,
                    "max_len": 200,
                    "name": "PID_Patient_ID",
                },
            ),
            # PID-3: Patient Identifier List
            (
                patient_id_list,
                {
                    "fuzzable": "patient_id_list" in fuzzable,
                    "max_len": 200,
                    "name": "PID_Patient_ID_List",
                },
            ),
            # PID-4: Alternate Patient ID
            (alt_patient_id, {"name": "PID_Alt_Patient_ID"}),
            # PID-5: Patient Name
            (
                name,
                {"fuzzable": "name" in fuzzable, "max_len": 200, "name": "PID_Name"},
            ),
            # PID-6: Mother's Maiden Name
            (mothers_maiden, {"name": "PID_Mothers_Maiden"}),
            # PID-7: Date/Time of Birth
            (
                dob,
                {"fuzzable": "dob" in fuzzable, "max_len": 26, "name": "PID_DOB"},
            ),
            # PID-8: Administrative Sex
            (
                gender,
                {
                    "fuzzable": "gender" in fuzzable,
                    "max_len": 10,
                    "name": "PID_Gender",
                },
            ),
            # PID-9: Patient Alias
            (alias, {"name": "PID_Alias"}),
            # PID-10: Race
            (
                race,
                {"fuzzable": "race" in fuzzable, "max_len": 50, "name": "PID_Race"},
            ),
            # PID-11: Patient Address
            (
                address,
                {
                    "fuzzable": "address" in fuzzable,
                    "max_len": 500,
                    "name": "PID_Address",
                },
            ),
            # PID-12: County Code
            (county, {"name": "PID_County"}),
            # PID-13: Phone Number - Home
            (
                phone_home,
                {
                    "fuzzable": "phone_home" in fuzzable,
                    "max_len": 50,
                    "name": "PID_Phone_Home",
                },
            ),
            # PID-14: Phone Number - Business
            (
                phone_business,
                {
                    "fuzzable": "phone_business" in fuzzable,
                    "max_len": 50,
                    "name": "PID_Phone_Business",
                },
            ),
        ]

        segment = HL7Segment("PID_Segment", "PID", fields)
        self.segments.append(segment)

    def add_pv1(
        self,
        set_id: str = "1",
        patient_class: str = "I",
        location: str = "WEST^101^A",
        admission_type: str = "",
        preadmit_number: str = "",
        prior_location: str = "",
        attending_doctor: str = "",
        referring_doctor: str = "",
        consulting_doctor: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add PV1 (Patient Visit) segment

        Args:
            set_id: Set ID (PV1-1)
            patient_class: Patient class I/O/E/P (PV1-2)
            location: Assigned patient location (PV1-3)
            admission_type: Admission type (PV1-4)
            preadmit_number: Preadmit number (PV1-5)
            prior_location: Prior patient location (PV1-6)
            attending_doctor: Attending doctor (PV1-7)
            referring_doctor: Referring doctor (PV1-8)
            consulting_doctor: Consulting doctor (PV1-9)
            fuzzable: List of field names to fuzz:
                      ["patient_class", "location", "admission_type",
                       "attending_doctor", "referring_doctor"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # PV1-1: Set ID
            (set_id, {"name": "PV1_Set_ID"}),
            # PV1-2: Patient Class
            (
                patient_class,
                {
                    "fuzzable": "patient_class" in fuzzable,
                    "max_len": 10,
                    "name": "PV1_Patient_Class",
                },
            ),
            # PV1-3: Assigned Patient Location
            (
                location,
                {
                    "fuzzable": "location" in fuzzable,
                    "max_len": 200,
                    "name": "PV1_Location",
                },
            ),
            # PV1-4: Admission Type
            (
                admission_type,
                {
                    "fuzzable": "admission_type" in fuzzable,
                    "max_len": 10,
                    "name": "PV1_Admission_Type",
                },
            ),
            # PV1-5: Preadmit Number
            (preadmit_number, {"name": "PV1_Preadmit"}),
            # PV1-6: Prior Patient Location
            (prior_location, {"name": "PV1_Prior_Location"}),
            # PV1-7: Attending Doctor
            (
                attending_doctor,
                {
                    "fuzzable": "attending_doctor" in fuzzable,
                    "max_len": 200,
                    "name": "PV1_Attending",
                },
            ),
            # PV1-8: Referring Doctor
            (
                referring_doctor,
                {
                    "fuzzable": "referring_doctor" in fuzzable,
                    "max_len": 200,
                    "name": "PV1_Referring",
                },
            ),
            # PV1-9: Consulting Doctor
            (consulting_doctor, {"name": "PV1_Consulting"}),
        ]

        segment = HL7Segment("PV1_Segment", "PV1", fields)
        self.segments.append(segment)

    def add_orc(
        self,
        order_control: str = "NW",
        placer_order: str = "",
        filler_order: str = "",
        placer_group: str = "",
        order_status: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add ORC (Common Order) segment

        Args:
            order_control: Order control code (ORC-1)
            placer_order: Placer order number (ORC-2)
            filler_order: Filler order number (ORC-3)
            placer_group: Placer group number (ORC-4)
            order_status: Order status (ORC-5)
            fuzzable: List of field names to fuzz:
                      ["order_control", "placer_order", "filler_order", "order_status"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # ORC-1: Order Control
            (
                order_control,
                {
                    "fuzzable": "order_control" in fuzzable,
                    "max_len": 10,
                    "name": "ORC_Order_Control",
                },
            ),
            # ORC-2: Placer Order Number
            (
                placer_order,
                {
                    "fuzzable": "placer_order" in fuzzable,
                    "max_len": 100,
                    "name": "ORC_Placer_Order",
                },
            ),
            # ORC-3: Filler Order Number
            (
                filler_order,
                {
                    "fuzzable": "filler_order" in fuzzable,
                    "max_len": 100,
                    "name": "ORC_Filler_Order",
                },
            ),
            # ORC-4: Placer Group Number
            (placer_group, {"name": "ORC_Placer_Group"}),
            # ORC-5: Order Status
            (
                order_status,
                {
                    "fuzzable": "order_status" in fuzzable,
                    "max_len": 10,
                    "name": "ORC_Order_Status",
                },
            ),
        ]

        segment = HL7Segment("ORC_Segment", "ORC", fields)
        self.segments.append(segment)

    def add_obr(
        self,
        set_id: str = "1",
        placer_order: str = "",
        filler_order: str = "",
        universal_service_id: str = "",
        priority: str = "",
        requested_datetime: str = "",
        observation_datetime: Optional[str] = None,
        fuzzable: Optional[List[str]] = None,
    ):
        """Add OBR (Observation Request) segment

        Args:
            set_id: Set ID (OBR-1)
            placer_order: Placer order number (OBR-2)
            filler_order: Filler order number (OBR-3)
            universal_service_id: Universal service ID (OBR-4)
            priority: Priority (OBR-5)
            requested_datetime: Requested date/time (OBR-6)
            observation_datetime: Observation date/time (OBR-7)
            fuzzable: List of field names to fuzz:
                      ["placer_order", "filler_order", "universal_service_id",
                       "priority", "requested_datetime"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # OBR-1: Set ID
            (set_id, {"name": "OBR_Set_ID"}),
            # OBR-2: Placer Order Number
            (
                placer_order,
                {
                    "fuzzable": "placer_order" in fuzzable,
                    "max_len": 100,
                    "name": "OBR_Placer_Order",
                },
            ),
            # OBR-3: Filler Order Number
            (
                filler_order,
                {
                    "fuzzable": "filler_order" in fuzzable,
                    "max_len": 100,
                    "name": "OBR_Filler_Order",
                },
            ),
            # OBR-4: Universal Service ID
            (
                universal_service_id,
                {
                    "fuzzable": "universal_service_id" in fuzzable,
                    "max_len": 200,
                    "name": "OBR_Service_ID",
                },
            ),
            # OBR-5: Priority
            (
                priority,
                {
                    "fuzzable": "priority" in fuzzable,
                    "max_len": 10,
                    "name": "OBR_Priority",
                },
            ),
            # OBR-6: Requested Date/Time
            (
                requested_datetime,
                {
                    "fuzzable": "requested_datetime" in fuzzable,
                    "max_len": 26,
                    "name": "OBR_Requested_DT",
                },
            ),
            # OBR-7: Observation Date/Time
            (
                observation_datetime or self._get_timestamp(),
                {"name": "OBR_Observation_DT"},
            ),
        ]

        segment = HL7Segment("OBR_Segment", "OBR", fields)
        self.segments.append(segment)

    def add_obx(
        self,
        set_id: str = "1",
        value_type: str = "NM",
        observation_id: str = "",
        observation_sub_id: str = "",
        value: str = "",
        units: str = "",
        reference_range: str = "",
        abnormal_flags: str = "",
        observation_status: str = "F",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add OBX (Observation/Result) segment

        Args:
            set_id: Set ID (OBX-1)
            value_type: Value type ST/NM/TX/etc (OBX-2)
            observation_id: Observation identifier (OBX-3)
            observation_sub_id: Observation sub-ID (OBX-4)
            value: Observation value (OBX-5)
            units: Units (OBX-6)
            reference_range: Reference range (OBX-7)
            abnormal_flags: Abnormal flags (OBX-8)
            observation_status: Observation status F/P/C (OBX-11)
            fuzzable: List of field names to fuzz:
                      ["value_type", "observation_id", "value", "units",
                       "reference_range", "abnormal_flags"]
        """
        fuzzable = set(fuzzable or [])

        # Use set_id to create unique names for multiple OBX segments
        seg_suffix = f"_{set_id}" if set_id != "1" else ""

        fields = [
            # OBX-1: Set ID
            (set_id, {"name": f"OBX_Set_ID{seg_suffix}"}),
            # OBX-2: Value Type
            (
                value_type,
                {
                    "fuzzable": "value_type" in fuzzable,
                    "max_len": 10,
                    "name": f"OBX_Value_Type{seg_suffix}",
                },
            ),
            # OBX-3: Observation Identifier
            (
                observation_id,
                {
                    "fuzzable": "observation_id" in fuzzable,
                    "max_len": 200,
                    "name": f"OBX_Observation_ID{seg_suffix}",
                },
            ),
            # OBX-4: Observation Sub-ID
            (observation_sub_id, {"name": f"OBX_Sub_ID{seg_suffix}"}),
            # OBX-5: Observation Value
            (
                value,
                {
                    "fuzzable": "value" in fuzzable,
                    "max_len": 100,
                    "name": f"OBX_Value{seg_suffix}",
                },
            ),
            # OBX-6: Units
            (
                units,
                {"fuzzable": "units" in fuzzable, "max_len": 50, "name": f"OBX_Units{seg_suffix}"},
            ),
            # OBX-7: Reference Range
            (
                reference_range,
                {
                    "fuzzable": "reference_range" in fuzzable,
                    "max_len": 100,
                    "name": f"OBX_Ref_Range{seg_suffix}",
                },
            ),
            # OBX-8: Abnormal Flags
            (
                abnormal_flags,
                {
                    "fuzzable": "abnormal_flags" in fuzzable,
                    "max_len": 10,
                    "name": f"OBX_Abnormal{seg_suffix}",
                },
            ),
            # OBX-9, OBX-10 (usually empty)
            ("", {}),
            ("", {}),
            # OBX-11: Observation Result Status
            (observation_status, {"name": f"OBX_Status{seg_suffix}"}),
        ]

        segment = HL7Segment(f"OBX_Segment{seg_suffix}", "OBX", fields)
        self.segments.append(segment)

    def add_msa(
        self,
        acknowledgment_code: str = "AA",
        message_control_id: Optional[str] = None,
        text_message: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add MSA (Message Acknowledgment) segment

        Args:
            acknowledgment_code: Acknowledgment code AA/AE/AR (MSA-1)
            message_control_id: Message control ID being acknowledged (MSA-2)
            text_message: Text message (MSA-3)
            fuzzable: List of field names to fuzz:
                      ["acknowledgment_code", "message_control_id", "text_message"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # MSA-1: Acknowledgment Code
            (
                acknowledgment_code,
                {
                    "fuzzable": "acknowledgment_code" in fuzzable,
                    "max_len": 10,
                    "name": "MSA_Ack_Code",
                },
            ),
            # MSA-2: Message Control ID
            (
                message_control_id or self._get_message_control_id(),
                {
                    "fuzzable": "message_control_id" in fuzzable,
                    "max_len": 50,
                    "name": "MSA_Control_ID",
                },
            ),
            # MSA-3: Text Message
            (
                text_message,
                {
                    "fuzzable": "text_message" in fuzzable,
                    "max_len": 200,
                    "name": "MSA_Text",
                },
            ),
        ]

        segment = HL7Segment("MSA_Segment", "MSA", fields)
        self.segments.append(segment)

    def add_qrd(
        self,
        query_datetime: Optional[str] = None,
        query_format: str = "R",
        query_priority: str = "I",
        query_id: str = "QRY001",
        deferred_response_type: str = "",
        deferred_response_datetime: str = "",
        quantity_limited: str = "RD",
        who_subject: str = "",
        what_subject: str = "DEM",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add QRD (Query Definition) segment

        Args:
            query_datetime: Query date/time (QRD-1)
            query_format: Query format code R/D/T (QRD-2)
            query_priority: Query priority I/D (QRD-3)
            query_id: Query ID (QRD-4)
            deferred_response_type: Deferred response type (QRD-5)
            deferred_response_datetime: Deferred response date/time (QRD-6)
            quantity_limited: Quantity limited request (QRD-7)
            who_subject: Who subject filter (QRD-8)
            what_subject: What subject filter (QRD-9)
            fuzzable: List of field names to fuzz:
                      ["query_format", "query_priority", "query_id",
                       "who_subject", "what_subject"]
        """
        fuzzable = set(fuzzable or [])

        fields = [
            # QRD-1: Query Date/Time
            (query_datetime or self._get_timestamp(), {"name": "QRD_DateTime"}),
            # QRD-2: Query Format Code
            (
                query_format,
                {
                    "fuzzable": "query_format" in fuzzable,
                    "max_len": 10,
                    "name": "QRD_Format",
                },
            ),
            # QRD-3: Query Priority
            (
                query_priority,
                {
                    "fuzzable": "query_priority" in fuzzable,
                    "max_len": 10,
                    "name": "QRD_Priority",
                },
            ),
            # QRD-4: Query ID
            (
                query_id,
                {
                    "fuzzable": "query_id" in fuzzable,
                    "max_len": 50,
                    "name": "QRD_ID",
                },
            ),
            # QRD-5: Deferred Response Type
            (deferred_response_type, {"name": "QRD_Deferred_Type"}),
            # QRD-6: Deferred Response Date/Time
            (deferred_response_datetime, {"name": "QRD_Deferred_DT"}),
            # QRD-7: Quantity Limited Request
            (quantity_limited, {"name": "QRD_Quantity"}),
            # QRD-8: Who Subject Filter
            (
                who_subject,
                {
                    "fuzzable": "who_subject" in fuzzable,
                    "max_len": 200,
                    "name": "QRD_Who",
                },
            ),
            # QRD-9: What Subject Filter
            (
                what_subject,
                {
                    "fuzzable": "what_subject" in fuzzable,
                    "max_len": 100,
                    "name": "QRD_What",
                },
            ),
        ]

        segment = HL7Segment("QRD_Segment", "QRD", fields)
        self.segments.append(segment)

    def add_segment(
        self,
        segment_id: str,
        fields: List[FieldValue],
        fuzzable_fields: Optional[List[int]] = None,
        name: Optional[str] = None,
    ):
        """Add arbitrary segment with custom fields

        Args:
            segment_id: 3-letter segment identifier
            fields: List of field values or (value, options) tuples
            fuzzable_fields: List of field indices to fuzz (0-based)
            name: Segment name for fuzzing (defaults to segment_id + "_Segment")
        """
        segment = HL7Segment(
            name=name or f"{segment_id}_Segment",
            segment_id=segment_id,
            fields=fields,
            fuzzable_fields=fuzzable_fields,
        )
        self.segments.append(segment)

    # =========================================================================
    # Additional Segment Builders (matching protocol analyzer)
    # =========================================================================

    def add_sch(
        self,
        placer_appointment_id: str = "",
        filler_appointment_id: str = "",
        event_reason: str = "",
        appointment_type: str = "",
        start_datetime: Optional[str] = None,
        duration: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add SCH (Scheduling Activity Information) segment

        Args:
            placer_appointment_id: Placer appointment ID (SCH-1)
            filler_appointment_id: Filler appointment ID (SCH-2)
            event_reason: Event reason (SCH-6)
            appointment_type: Appointment type (SCH-8)
            start_datetime: Start date/time (SCH-11)
            duration: Duration (SCH-9)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        fields = [
            (
                placer_appointment_id,
                {
                    "fuzzable": "placer_appointment_id" in fuzzable,
                    "max_len": 100,
                    "name": "SCH_Placer_ID",
                },
            ),
            (
                filler_appointment_id,
                {
                    "fuzzable": "filler_appointment_id" in fuzzable,
                    "max_len": 100,
                    "name": "SCH_Filler_ID",
                },
            ),
            ("", {}),  # SCH-3
            ("", {}),  # SCH-4
            ("", {}),  # SCH-5
            (
                event_reason,
                {
                    "fuzzable": "event_reason" in fuzzable,
                    "max_len": 200,
                    "name": "SCH_Event_Reason",
                },
            ),
            ("", {}),  # SCH-7
            (
                appointment_type,
                {
                    "fuzzable": "appointment_type" in fuzzable,
                    "max_len": 100,
                    "name": "SCH_Appt_Type",
                },
            ),
            (
                duration,
                {"fuzzable": "duration" in fuzzable, "max_len": 20, "name": "SCH_Duration"},
            ),
            ("", {}),  # SCH-10
            (
                start_datetime or self._get_timestamp(),
                {"fuzzable": "start_datetime" in fuzzable, "max_len": 26, "name": "SCH_Start_DT"},
            ),
        ]

        segment = HL7Segment("SCH_Segment", "SCH", fields)
        self.segments.append(segment)

    def add_txa(
        self,
        document_type: str = "",
        content_presentation: str = "TX",
        activity_datetime: Optional[str] = None,
        primary_provider: str = "",
        unique_document_number: str = "",
        completion_status: str = "AU",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add TXA (Transcription Document Header) segment

        Args:
            document_type: Document type (TXA-2)
            content_presentation: Content presentation TX/FT/RP (TXA-3)
            activity_datetime: Activity date/time (TXA-4)
            primary_provider: Primary provider (TXA-5)
            unique_document_number: Unique document number (TXA-12)
            completion_status: Completion status AU/DI (TXA-17)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        fields = [
            ("1", {"name": "TXA_Set_ID"}),
            (
                document_type,
                {"fuzzable": "document_type" in fuzzable, "max_len": 100, "name": "TXA_Doc_Type"},
            ),
            (
                content_presentation,
                {
                    "fuzzable": "content_presentation" in fuzzable,
                    "max_len": 10,
                    "name": "TXA_Content",
                },
            ),
            (
                activity_datetime or self._get_timestamp(),
                {
                    "fuzzable": "activity_datetime" in fuzzable,
                    "max_len": 26,
                    "name": "TXA_Activity_DT",
                },
            ),
            (
                primary_provider,
                {
                    "fuzzable": "primary_provider" in fuzzable,
                    "max_len": 200,
                    "name": "TXA_Provider",
                },
            ),
            ("", {}),  # TXA-6 through TXA-11
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            (
                unique_document_number,
                {
                    "fuzzable": "unique_document_number" in fuzzable,
                    "max_len": 100,
                    "name": "TXA_Doc_Number",
                },
            ),
            ("", {}),  # TXA-13 through TXA-16
            ("", {}),
            ("", {}),
            ("", {}),
            (
                completion_status,
                {"fuzzable": "completion_status" in fuzzable, "max_len": 10, "name": "TXA_Status"},
            ),
        ]

        segment = HL7Segment("TXA_Segment", "TXA", fields)
        self.segments.append(segment)

    def add_rxo(
        self,
        drug_code: str = "",
        drug_name: str = "",
        requested_dose: str = "",
        requested_units: str = "",
        requested_route: str = "",
        admin_instructions: str = "",
        dispense_amount: str = "",
        dispense_units: str = "",
        refills: str = "",
        ordering_provider: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add RXO (Pharmacy/Treatment Order) segment

        Args:
            drug_code: Drug identifier code (RXO-1)
            drug_name: Drug name (RXO-1 component 2)
            requested_dose: Requested give amount (RXO-2)
            requested_units: Requested give units (RXO-4)
            requested_route: Requested route (RXO-5)
            admin_instructions: Administration instructions (RXO-6)
            dispense_amount: Requested dispense amount (RXO-10)
            dispense_units: Requested dispense units (RXO-11)
            refills: Number of refills (RXO-12)
            ordering_provider: Ordering provider (RXO-14)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        drug_value = f"{drug_code}^{drug_name}^NDC" if drug_code or drug_name else ""

        fields = [
            (
                drug_value,
                {
                    "fuzzable": "drug_code" in fuzzable or "drug_name" in fuzzable,
                    "max_len": 200,
                    "name": "RXO_Drug",
                },
            ),
            (
                requested_dose,
                {"fuzzable": "requested_dose" in fuzzable, "max_len": 50, "name": "RXO_Dose"},
            ),
            ("", {}),  # RXO-3
            (
                requested_units,
                {"fuzzable": "requested_units" in fuzzable, "max_len": 50, "name": "RXO_Units"},
            ),
            (
                requested_route,
                {"fuzzable": "requested_route" in fuzzable, "max_len": 50, "name": "RXO_Route"},
            ),
            (
                admin_instructions,
                {
                    "fuzzable": "admin_instructions" in fuzzable,
                    "max_len": 500,
                    "name": "RXO_Instructions",
                },
            ),
            ("", {}),  # RXO-7 through RXO-9
            ("", {}),
            ("", {}),
            (
                dispense_amount,
                {
                    "fuzzable": "dispense_amount" in fuzzable,
                    "max_len": 50,
                    "name": "RXO_Dispense_Amt",
                },
            ),
            (
                dispense_units,
                {
                    "fuzzable": "dispense_units" in fuzzable,
                    "max_len": 50,
                    "name": "RXO_Dispense_Units",
                },
            ),
            (
                refills,
                {"fuzzable": "refills" in fuzzable, "max_len": 10, "name": "RXO_Refills"},
            ),
            ("", {}),  # RXO-13
            (
                ordering_provider,
                {
                    "fuzzable": "ordering_provider" in fuzzable,
                    "max_len": 200,
                    "name": "RXO_Provider",
                },
            ),
        ]

        segment = HL7Segment("RXO_Segment", "RXO", fields)
        self.segments.append(segment)

    def add_rxe(
        self,
        drug_code: str = "",
        drug_name: str = "",
        give_amount: str = "",
        give_units: str = "",
        give_dosage_form: str = "",
        dispense_amount: str = "",
        dispense_units: str = "",
        refills_remaining: str = "",
        prescription_number: str = "",
        _pharmacy: str = "",  # TODO: implement RXE-40 field
        fuzzable: Optional[List[str]] = None,
    ):
        """Add RXE (Pharmacy/Treatment Encoded Order) segment

        Args:
            drug_code: Drug code (RXE-2)
            drug_name: Drug name (RXE-2 component 2)
            give_amount: Give amount (RXE-3)
            give_units: Give units (RXE-5)
            give_dosage_form: Dosage form (RXE-6)
            dispense_amount: Dispense amount (RXE-10)
            dispense_units: Dispense units (RXE-11)
            refills_remaining: Refills remaining (RXE-16)
            prescription_number: Prescription number (RXE-15)
            _pharmacy: Dispensing pharmacy (RXE-40) - not yet implemented
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        drug_value = f"{drug_code}^{drug_name}^NDC" if drug_code or drug_name else ""

        fields = [
            ("1", {"name": "RXE_Quantity"}),  # RXE-1
            (
                drug_value,
                {
                    "fuzzable": "drug_code" in fuzzable or "drug_name" in fuzzable,
                    "max_len": 200,
                    "name": "RXE_Drug",
                },
            ),
            (
                give_amount,
                {"fuzzable": "give_amount" in fuzzable, "max_len": 50, "name": "RXE_Give_Amt"},
            ),
            ("", {}),  # RXE-4
            (
                give_units,
                {"fuzzable": "give_units" in fuzzable, "max_len": 50, "name": "RXE_Give_Units"},
            ),
            (
                give_dosage_form,
                {
                    "fuzzable": "give_dosage_form" in fuzzable,
                    "max_len": 50,
                    "name": "RXE_Dosage_Form",
                },
            ),
            ("", {}),  # RXE-7 through RXE-9
            ("", {}),
            ("", {}),
            (
                dispense_amount,
                {
                    "fuzzable": "dispense_amount" in fuzzable,
                    "max_len": 50,
                    "name": "RXE_Dispense_Amt",
                },
            ),
            (
                dispense_units,
                {
                    "fuzzable": "dispense_units" in fuzzable,
                    "max_len": 50,
                    "name": "RXE_Dispense_Units",
                },
            ),
            ("", {}),  # RXE-12 through RXE-14
            ("", {}),
            ("", {}),
            (
                prescription_number,
                {
                    "fuzzable": "prescription_number" in fuzzable,
                    "max_len": 100,
                    "name": "RXE_Rx_Number",
                },
            ),
            (
                refills_remaining,
                {"fuzzable": "refills_remaining" in fuzzable, "max_len": 10, "name": "RXE_Refills"},
            ),
        ]

        segment = HL7Segment("RXE_Segment", "RXE", fields)
        self.segments.append(segment)

    def add_rxa(
        self,
        admin_sub_id: str = "0",
        admin_code: str = "",
        admin_name: str = "",
        admin_start_datetime: Optional[str] = None,
        admin_end_datetime: str = "",
        admin_amount: str = "",
        admin_units: str = "",
        admin_route: str = "",
        admin_site: str = "",
        lot_number: str = "",
        expiration_date: str = "",
        manufacturer: str = "",
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add RXA (Pharmacy/Treatment Administration) segment

        Args:
            admin_sub_id: Administration sub-ID counter (RXA-1)
            admin_code: Administered code (RXA-5)
            admin_name: Administered drug name (RXA-5 component 2)
            admin_start_datetime: Admin start date/time (RXA-3)
            admin_end_datetime: Admin end date/time (RXA-4)
            admin_amount: Administered amount (RXA-6)
            admin_units: Administered units (RXA-7)
            admin_route: Administration route (RXA-9)
            admin_site: Administration site (RXA-10)
            lot_number: Substance lot number (RXA-15)
            expiration_date: Substance expiration date (RXA-16)
            manufacturer: Substance manufacturer (RXA-17)
            set_id: Give sub-ID counter (RXA-2)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        drug_value = f"{admin_code}^{admin_name}^NDC" if admin_code or admin_name else ""

        fields = [
            (admin_sub_id, {"name": "RXA_Sub_ID"}),
            (set_id, {"name": "RXA_Set_ID"}),
            (
                admin_start_datetime or self._get_timestamp(),
                {
                    "fuzzable": "admin_start_datetime" in fuzzable,
                    "max_len": 26,
                    "name": "RXA_Start_DT",
                },
            ),
            (
                admin_end_datetime,
                {"fuzzable": "admin_end_datetime" in fuzzable, "max_len": 26, "name": "RXA_End_DT"},
            ),
            (
                drug_value,
                {
                    "fuzzable": "admin_code" in fuzzable or "admin_name" in fuzzable,
                    "max_len": 200,
                    "name": "RXA_Drug",
                },
            ),
            (
                admin_amount,
                {"fuzzable": "admin_amount" in fuzzable, "max_len": 50, "name": "RXA_Amount"},
            ),
            (
                admin_units,
                {"fuzzable": "admin_units" in fuzzable, "max_len": 50, "name": "RXA_Units"},
            ),
            ("", {}),  # RXA-8
            (
                admin_route,
                {"fuzzable": "admin_route" in fuzzable, "max_len": 50, "name": "RXA_Route"},
            ),
            (
                admin_site,
                {"fuzzable": "admin_site" in fuzzable, "max_len": 100, "name": "RXA_Site"},
            ),
            ("", {}),  # RXA-11 through RXA-14
            ("", {}),
            ("", {}),
            ("", {}),
            (
                lot_number,
                {"fuzzable": "lot_number" in fuzzable, "max_len": 50, "name": "RXA_Lot"},
            ),
            (
                expiration_date,
                {
                    "fuzzable": "expiration_date" in fuzzable,
                    "max_len": 26,
                    "name": "RXA_Expiration",
                },
            ),
            (
                manufacturer,
                {
                    "fuzzable": "manufacturer" in fuzzable,
                    "max_len": 100,
                    "name": "RXA_Manufacturer",
                },
            ),
            ("", {}),  # RXA-18, RXA-19
            ("", {}),
            ("CP", {"name": "RXA_Completion"}),  # RXA-20: Completion Status
        ]

        segment = HL7Segment("RXA_Segment", "RXA", fields)
        self.segments.append(segment)

    def add_rxd(
        self,
        dispense_sub_id: str = "1",
        drug_code: str = "",
        drug_name: str = "",
        dispense_datetime: Optional[str] = None,
        actual_dispense_amount: str = "",
        actual_dispense_units: str = "",
        prescription_number: str = "",
        dispense_notes: str = "",
        dispensing_provider: str = "",
        lot_number: str = "",
        expiration_date: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add RXD (Pharmacy/Treatment Dispense) segment

        Args:
            dispense_sub_id: Dispense sub-ID counter (RXD-1)
            drug_code: Dispense/give code (RXD-2)
            drug_name: Drug name (RXD-2 component 2)
            dispense_datetime: Date/time dispensed (RXD-3)
            actual_dispense_amount: Actual dispense amount (RXD-4)
            actual_dispense_units: Actual dispense units (RXD-5)
            prescription_number: Prescription number (RXD-7)
            dispense_notes: Dispense notes (RXD-9)
            dispensing_provider: Dispensing provider (RXD-10)
            lot_number: Substance lot number (RXD-18)
            expiration_date: Substance expiration date (RXD-19)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        drug_value = f"{drug_code}^{drug_name}^NDC" if drug_code or drug_name else ""

        fields = [
            (dispense_sub_id, {"name": "RXD_Sub_ID"}),
            (
                drug_value,
                {
                    "fuzzable": "drug_code" in fuzzable or "drug_name" in fuzzable,
                    "max_len": 200,
                    "name": "RXD_Drug",
                },
            ),
            (
                dispense_datetime or self._get_timestamp(),
                {"fuzzable": "dispense_datetime" in fuzzable, "max_len": 26, "name": "RXD_DT"},
            ),
            (
                actual_dispense_amount,
                {
                    "fuzzable": "actual_dispense_amount" in fuzzable,
                    "max_len": 50,
                    "name": "RXD_Amount",
                },
            ),
            (
                actual_dispense_units,
                {
                    "fuzzable": "actual_dispense_units" in fuzzable,
                    "max_len": 50,
                    "name": "RXD_Units",
                },
            ),
            ("", {}),  # RXD-6
            (
                prescription_number,
                {
                    "fuzzable": "prescription_number" in fuzzable,
                    "max_len": 100,
                    "name": "RXD_Rx_Number",
                },
            ),
            ("", {}),  # RXD-8
            (
                dispense_notes,
                {"fuzzable": "dispense_notes" in fuzzable, "max_len": 500, "name": "RXD_Notes"},
            ),
            (
                dispensing_provider,
                {
                    "fuzzable": "dispensing_provider" in fuzzable,
                    "max_len": 200,
                    "name": "RXD_Provider",
                },
            ),
            ("", {}),  # RXD-11 through RXD-17
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            (
                lot_number,
                {"fuzzable": "lot_number" in fuzzable, "max_len": 50, "name": "RXD_Lot"},
            ),
            (
                expiration_date,
                {
                    "fuzzable": "expiration_date" in fuzzable,
                    "max_len": 26,
                    "name": "RXD_Expiration",
                },
            ),
        ]

        segment = HL7Segment("RXD_Segment", "RXD", fields)
        self.segments.append(segment)

    def add_rxg(
        self,
        give_sub_id: str = "1",
        drug_code: str = "",
        drug_name: str = "",
        give_amount: str = "",
        give_units: str = "",
        give_dosage_form: str = "",
        give_rate_amount: str = "",
        give_rate_units: str = "",
        give_strength: str = "",
        give_strength_units: str = "",
        dispense_sub_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add RXG (Pharmacy/Treatment Give) segment

        Args:
            give_sub_id: Give sub-ID counter (RXG-1)
            drug_code: Give code (RXG-4)
            drug_name: Drug name (RXG-4 component 2)
            give_amount: Give amount - minimum (RXG-5)
            give_units: Give units (RXG-7)
            give_dosage_form: Give dosage form (RXG-8)
            give_rate_amount: Give rate amount (RXG-15)
            give_rate_units: Give rate units (RXG-16)
            give_strength: Give strength (RXG-17)
            give_strength_units: Give strength units (RXG-18)
            dispense_sub_id: Dispense sub-ID counter (RXG-2)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        drug_value = f"{drug_code}^{drug_name}^NDC" if drug_code or drug_name else ""

        fields = [
            (give_sub_id, {"name": "RXG_Give_Sub_ID"}),
            (dispense_sub_id, {"name": "RXG_Dispense_Sub_ID"}),
            ("", {"name": "RXG_Quantity"}),  # RXG-3 (deprecated)
            (
                drug_value,
                {
                    "fuzzable": "drug_code" in fuzzable or "drug_name" in fuzzable,
                    "max_len": 200,
                    "name": "RXG_Drug",
                },
            ),
            (
                give_amount,
                {"fuzzable": "give_amount" in fuzzable, "max_len": 50, "name": "RXG_Amount"},
            ),
            ("", {}),  # RXG-6
            (
                give_units,
                {"fuzzable": "give_units" in fuzzable, "max_len": 50, "name": "RXG_Units"},
            ),
            (
                give_dosage_form,
                {
                    "fuzzable": "give_dosage_form" in fuzzable,
                    "max_len": 50,
                    "name": "RXG_Dosage_Form",
                },
            ),
            ("", {}),  # RXG-9 through RXG-14
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            (
                give_rate_amount,
                {"fuzzable": "give_rate_amount" in fuzzable, "max_len": 50, "name": "RXG_Rate_Amt"},
            ),
            (
                give_rate_units,
                {
                    "fuzzable": "give_rate_units" in fuzzable,
                    "max_len": 50,
                    "name": "RXG_Rate_Units",
                },
            ),
            (
                give_strength,
                {"fuzzable": "give_strength" in fuzzable, "max_len": 50, "name": "RXG_Strength"},
            ),
            (
                give_strength_units,
                {
                    "fuzzable": "give_strength_units" in fuzzable,
                    "max_len": 50,
                    "name": "RXG_Strength_Units",
                },
            ),
        ]

        segment = HL7Segment("RXG_Segment", "RXG", fields)
        self.segments.append(segment)

    def add_dg1(
        self,
        diagnosis_code: str = "",
        diagnosis_description: str = "",
        diagnosis_type: str = "A",
        diagnosis_datetime: Optional[str] = None,
        diagnosing_clinician: str = "",
        coding_method: str = "ICD10",
        diagnosis_priority: str = "",
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add DG1 (Diagnosis) segment

        Args:
            diagnosis_code: Diagnosis code ICD-10/ICD-9 (DG1-3)
            diagnosis_description: Diagnosis description (DG1-4)
            diagnosis_type: Diagnosis type A=Admitting, W=Working, F=Final (DG1-6)
            diagnosis_datetime: Diagnosis date/time (DG1-5)
            diagnosing_clinician: Diagnosing clinician (DG1-16)
            coding_method: Coding method ICD10/ICD9 (DG1-2)
            diagnosis_priority: Diagnosis priority 1=Primary, 2+=Secondary (DG1-15)
            set_id: Set ID (DG1-1)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        diag_value = (
            f"{diagnosis_code}^{diagnosis_description}^{coding_method}"
            if diagnosis_code or diagnosis_description
            else ""
        )

        fields = [
            (set_id, {"name": "DG1_Set_ID"}),
            (coding_method, {"name": "DG1_Coding_Method"}),
            (
                diag_value,
                {"fuzzable": "diagnosis_code" in fuzzable, "max_len": 200, "name": "DG1_Code"},
            ),
            (
                diagnosis_description,
                {
                    "fuzzable": "diagnosis_description" in fuzzable,
                    "max_len": 500,
                    "name": "DG1_Description",
                },
            ),
            (
                diagnosis_datetime or self._get_timestamp(),
                {"fuzzable": "diagnosis_datetime" in fuzzable, "max_len": 26, "name": "DG1_DT"},
            ),
            (
                diagnosis_type,
                {"fuzzable": "diagnosis_type" in fuzzable, "max_len": 10, "name": "DG1_Type"},
            ),
            ("", {}),  # DG1-7 through DG1-14
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            (
                diagnosis_priority,
                {
                    "fuzzable": "diagnosis_priority" in fuzzable,
                    "max_len": 10,
                    "name": "DG1_Priority",
                },
            ),
            (
                diagnosing_clinician,
                {
                    "fuzzable": "diagnosing_clinician" in fuzzable,
                    "max_len": 200,
                    "name": "DG1_Clinician",
                },
            ),
        ]

        segment = HL7Segment("DG1_Segment", "DG1", fields)
        self.segments.append(segment)

    def add_pr1(
        self,
        procedure_code: str = "",
        procedure_description: str = "",
        procedure_datetime: Optional[str] = None,
        procedure_type: str = "",
        procedure_practitioner: str = "",
        coding_method: str = "CPT",
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add PR1 (Procedure) segment

        Args:
            procedure_code: Procedure code CPT/HCPCS (PR1-3)
            procedure_description: Procedure description (PR1-4)
            procedure_datetime: Procedure date/time (PR1-5)
            procedure_type: Procedure type (PR1-6)
            procedure_practitioner: Procedure practitioner (PR1-8)
            coding_method: Coding method CPT/HCPCS (PR1-2)
            set_id: Set ID (PR1-1)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        proc_value = (
            f"{procedure_code}^{procedure_description}^{coding_method}"
            if procedure_code or procedure_description
            else ""
        )

        fields = [
            (set_id, {"name": "PR1_Set_ID"}),
            (coding_method, {"name": "PR1_Coding_Method"}),
            (
                proc_value,
                {"fuzzable": "procedure_code" in fuzzable, "max_len": 200, "name": "PR1_Code"},
            ),
            (
                procedure_description,
                {
                    "fuzzable": "procedure_description" in fuzzable,
                    "max_len": 500,
                    "name": "PR1_Description",
                },
            ),
            (
                procedure_datetime or self._get_timestamp(),
                {"fuzzable": "procedure_datetime" in fuzzable, "max_len": 26, "name": "PR1_DT"},
            ),
            (
                procedure_type,
                {"fuzzable": "procedure_type" in fuzzable, "max_len": 50, "name": "PR1_Type"},
            ),
            ("", {}),  # PR1-7
            (
                procedure_practitioner,
                {
                    "fuzzable": "procedure_practitioner" in fuzzable,
                    "max_len": 200,
                    "name": "PR1_Practitioner",
                },
            ),
        ]

        segment = HL7Segment("PR1_Segment", "PR1", fields)
        self.segments.append(segment)

    def add_mrg(
        self,
        prior_patient_id: str = "",
        prior_patient_name: str = "",
        prior_visit_number: str = "",
        prior_account_number: str = "",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add MRG (Merge Patient Information) segment

        Used for patient merge attacks (ADT^A40).

        Args:
            prior_patient_id: Prior patient ID to merge FROM (MRG-1)
            prior_patient_name: Prior patient name (MRG-7)
            prior_visit_number: Prior visit number (MRG-3)
            prior_account_number: Prior account number (MRG-3)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        patient_id_value = f"{prior_patient_id}^^^HOSPITAL^MR" if prior_patient_id else ""

        fields = [
            (
                patient_id_value,
                {
                    "fuzzable": "prior_patient_id" in fuzzable,
                    "max_len": 200,
                    "name": "MRG_Patient_ID",
                },
            ),
            ("", {}),  # MRG-2
            (
                prior_visit_number or prior_account_number,
                {
                    "fuzzable": "prior_visit_number" in fuzzable
                    or "prior_account_number" in fuzzable,
                    "max_len": 100,
                    "name": "MRG_Account",
                },
            ),
            ("", {}),  # MRG-4 through MRG-6
            ("", {}),
            ("", {}),
            (
                prior_patient_name,
                {
                    "fuzzable": "prior_patient_name" in fuzzable,
                    "max_len": 200,
                    "name": "MRG_Patient_Name",
                },
            ),
        ]

        segment = HL7Segment("MRG_Segment", "MRG", fields)
        self.segments.append(segment)

    def add_ft1(
        self,
        transaction_id: str = "",
        transaction_batch_id: str = "",
        transaction_date: Optional[str] = None,
        transaction_type: str = "",
        transaction_code: str = "",
        transaction_description: str = "",
        transaction_quantity: str = "",
        transaction_amount: str = "",
        insurance_plan_id: str = "",
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add FT1 (Financial Transaction) segment

        Args:
            transaction_id: Transaction ID (FT1-1)
            transaction_batch_id: Transaction batch ID (FT1-2)
            transaction_date: Transaction date (FT1-4)
            transaction_type: Transaction type (FT1-6)
            transaction_code: Transaction code (FT1-7)
            transaction_description: Transaction description (FT1-8)
            transaction_quantity: Transaction quantity (FT1-10)
            transaction_amount: Transaction amount (FT1-11)
            insurance_plan_id: Insurance plan ID (FT1-14)
            set_id: Set ID
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        fields = [
            (set_id, {"name": "FT1_Set_ID"}),
            (
                transaction_id,
                {"fuzzable": "transaction_id" in fuzzable, "max_len": 100, "name": "FT1_Trans_ID"},
            ),
            (
                transaction_batch_id,
                {
                    "fuzzable": "transaction_batch_id" in fuzzable,
                    "max_len": 100,
                    "name": "FT1_Batch_ID",
                },
            ),
            (
                transaction_date or self._get_timestamp(),
                {"fuzzable": "transaction_date" in fuzzable, "max_len": 26, "name": "FT1_Date"},
            ),
            ("", {}),  # FT1-5
            (
                transaction_type,
                {"fuzzable": "transaction_type" in fuzzable, "max_len": 50, "name": "FT1_Type"},
            ),
            (
                transaction_code,
                {"fuzzable": "transaction_code" in fuzzable, "max_len": 100, "name": "FT1_Code"},
            ),
            (
                transaction_description,
                {
                    "fuzzable": "transaction_description" in fuzzable,
                    "max_len": 500,
                    "name": "FT1_Description",
                },
            ),
            ("", {}),  # FT1-9
            (
                transaction_quantity,
                {
                    "fuzzable": "transaction_quantity" in fuzzable,
                    "max_len": 50,
                    "name": "FT1_Quantity",
                },
            ),
            (
                transaction_amount,
                {"fuzzable": "transaction_amount" in fuzzable, "max_len": 50, "name": "FT1_Amount"},
            ),
            ("", {}),  # FT1-12, FT1-13
            ("", {}),
            (
                insurance_plan_id,
                {
                    "fuzzable": "insurance_plan_id" in fuzzable,
                    "max_len": 100,
                    "name": "FT1_Insurance",
                },
            ),
        ]

        segment = HL7Segment("FT1_Segment", "FT1", fields)
        self.segments.append(segment)

    def add_gt1(
        self,
        guarantor_number: str = "",
        guarantor_name: str = "",
        guarantor_address: str = "",
        guarantor_phone: str = "",
        guarantor_ssn: str = "",
        guarantor_employer: str = "",
        guarantor_relationship: str = "",
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add GT1 (Guarantor) segment

        Args:
            guarantor_number: Guarantor number (GT1-2)
            guarantor_name: Guarantor name (GT1-3)
            guarantor_address: Guarantor address (GT1-5)
            guarantor_phone: Guarantor phone (GT1-6)
            guarantor_ssn: Guarantor SSN (GT1-12)
            guarantor_employer: Guarantor employer (GT1-16)
            guarantor_relationship: Guarantor relationship (GT1-11)
            set_id: Set ID (GT1-1)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        fields = [
            (set_id, {"name": "GT1_Set_ID"}),
            (
                guarantor_number,
                {"fuzzable": "guarantor_number" in fuzzable, "max_len": 100, "name": "GT1_Number"},
            ),
            (
                guarantor_name,
                {"fuzzable": "guarantor_name" in fuzzable, "max_len": 200, "name": "GT1_Name"},
            ),
            ("", {}),  # GT1-4
            (
                guarantor_address,
                {
                    "fuzzable": "guarantor_address" in fuzzable,
                    "max_len": 500,
                    "name": "GT1_Address",
                },
            ),
            (
                guarantor_phone,
                {"fuzzable": "guarantor_phone" in fuzzable, "max_len": 50, "name": "GT1_Phone"},
            ),
            ("", {}),  # GT1-7 through GT1-10
            ("", {}),
            ("", {}),
            ("", {}),
            (
                guarantor_relationship,
                {
                    "fuzzable": "guarantor_relationship" in fuzzable,
                    "max_len": 50,
                    "name": "GT1_Relationship",
                },
            ),
            (
                guarantor_ssn,
                {"fuzzable": "guarantor_ssn" in fuzzable, "max_len": 20, "name": "GT1_SSN"},
            ),
            ("", {}),  # GT1-13 through GT1-15
            ("", {}),
            ("", {}),
            (
                guarantor_employer,
                {
                    "fuzzable": "guarantor_employer" in fuzzable,
                    "max_len": 200,
                    "name": "GT1_Employer",
                },
            ),
        ]

        segment = HL7Segment("GT1_Segment", "GT1", fields)
        self.segments.append(segment)

    def add_in1(
        self,
        insurance_plan_id: str = "",
        insurance_company_id: str = "",
        insurance_company_name: str = "",
        insurance_company_address: str = "",
        group_number: str = "",
        insured_name: str = "",
        insured_address: str = "",
        _policy_number: str = "",  # TODO: implement IN1-36 field
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add IN1 (Insurance) segment

        Args:
            insurance_plan_id: Insurance plan ID (IN1-2)
            insurance_company_id: Insurance company ID (IN1-3)
            insurance_company_name: Insurance company name (IN1-4)
            insurance_company_address: Insurance company address (IN1-5)
            group_number: Group number (IN1-8)
            insured_name: Insured name (IN1-16)
            insured_address: Insured address (IN1-19)
            _policy_number: Policy number (IN1-36) - not yet implemented
            set_id: Set ID (IN1-1)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        fields = [
            (set_id, {"name": "IN1_Set_ID"}),
            (
                insurance_plan_id,
                {
                    "fuzzable": "insurance_plan_id" in fuzzable,
                    "max_len": 100,
                    "name": "IN1_Plan_ID",
                },
            ),
            (
                insurance_company_id,
                {
                    "fuzzable": "insurance_company_id" in fuzzable,
                    "max_len": 100,
                    "name": "IN1_Company_ID",
                },
            ),
            (
                insurance_company_name,
                {
                    "fuzzable": "insurance_company_name" in fuzzable,
                    "max_len": 200,
                    "name": "IN1_Company_Name",
                },
            ),
            (
                insurance_company_address,
                {
                    "fuzzable": "insurance_company_address" in fuzzable,
                    "max_len": 500,
                    "name": "IN1_Company_Addr",
                },
            ),
            ("", {}),  # IN1-6, IN1-7
            ("", {}),
            (
                group_number,
                {"fuzzable": "group_number" in fuzzable, "max_len": 50, "name": "IN1_Group"},
            ),
            ("", {}),  # IN1-9 through IN1-15
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            ("", {}),
            (
                insured_name,
                {
                    "fuzzable": "insured_name" in fuzzable,
                    "max_len": 200,
                    "name": "IN1_Insured_Name",
                },
            ),
            ("", {}),  # IN1-17, IN1-18
            ("", {}),
            (
                insured_address,
                {
                    "fuzzable": "insured_address" in fuzzable,
                    "max_len": 500,
                    "name": "IN1_Insured_Addr",
                },
            ),
        ]

        segment = HL7Segment("IN1_Segment", "IN1", fields)
        self.segments.append(segment)

    def add_nk1(
        self,
        name: str = "",
        relationship: str = "",
        address: str = "",
        phone: str = "",
        business_phone: str = "",
        contact_role: str = "",
        set_id: str = "1",
        fuzzable: Optional[List[str]] = None,
    ):
        """Add NK1 (Next of Kin) segment

        Args:
            name: Name (NK1-2)
            relationship: Relationship (NK1-3)
            address: Address (NK1-4)
            phone: Phone number (NK1-5)
            business_phone: Business phone (NK1-6)
            contact_role: Contact role (NK1-7)
            set_id: Set ID (NK1-1)
            fuzzable: List of field names to fuzz
        """
        fuzzable = set(fuzzable or [])

        fields = [
            (set_id, {"name": "NK1_Set_ID"}),
            (
                name,
                {"fuzzable": "name" in fuzzable, "max_len": 200, "name": "NK1_Name"},
            ),
            (
                relationship,
                {"fuzzable": "relationship" in fuzzable, "max_len": 50, "name": "NK1_Relationship"},
            ),
            (
                address,
                {"fuzzable": "address" in fuzzable, "max_len": 500, "name": "NK1_Address"},
            ),
            (
                phone,
                {"fuzzable": "phone" in fuzzable, "max_len": 50, "name": "NK1_Phone"},
            ),
            (
                business_phone,
                {
                    "fuzzable": "business_phone" in fuzzable,
                    "max_len": 50,
                    "name": "NK1_Business_Phone",
                },
            ),
            (
                contact_role,
                {"fuzzable": "contact_role" in fuzzable, "max_len": 50, "name": "NK1_Contact_Role"},
            ),
        ]

        segment = HL7Segment("NK1_Segment", "NK1", fields)
        self.segments.append(segment)


# =============================================================================
# Attack Helpers
# =============================================================================


def build_delimiter_injection_values(base_value: str = "TEST") -> List[bytes]:
    """Generate delimiter injection attack values for HL7

    These test delimiter handling vulnerabilities (CVE-2022-38756 style):
    - Field separator injection
    - Component separator injection
    - Segment terminator injection
    - Escape sequence injection

    Args:
        base_value: Base string to inject delimiters into

    Returns:
        List of injection test values as bytes
    """
    return [
        # Pipe (field separator) injection
        f"{base_value}|INJECTED".encode(),
        f"{base_value}||DOUBLE".encode(),
        # Caret (component separator) injection
        f"{base_value}^COMPONENT".encode(),
        f"{base_value}^^DOUBLE".encode(),
        # Tilde (repetition separator) injection
        f"{base_value}~REPEAT~AGAIN".encode(),
        # Ampersand (subcomponent separator) injection
        f"{base_value}&SUB&COMPONENT".encode(),
        # Backslash (escape char) injection
        f"{base_value}\\ESCAPE\\CHAR".encode(),
        f"{base_value}\\F\\FIELD".encode(),  # HL7 escape for |
        f"{base_value}\\S\\COMPONENT".encode(),  # HL7 escape for ^
        f"{base_value}\\T\\SUBCOMP".encode(),  # HL7 escape for &
        f"{base_value}\\R\\REPEAT".encode(),  # HL7 escape for ~
        f"{base_value}\\E\\ESCAPE".encode(),  # HL7 escape for \
        # Combined delimiter attack
        f"{base_value}|^~\\&|ALL".encode(),
        # Null injection
        f'{base_value}""NULL'.encode(),
        # Segment terminator in value
        f"{base_value}\rEVN|A01".encode(),
        # Common injection patterns
        f"{base_value}'".encode(),  # SQL apostrophe
        f'{base_value}"'.encode(),  # Quote
        f"{base_value}<SCRIPT>".encode(),  # XSS attempt
        f"{base_value};DROP TABLE;".encode(),  # SQL injection
    ]


def build_oversized_field_values(
    sizes: Optional[List[int]] = None,
    char: str = "A",
) -> List[bytes]:
    """Generate oversized field values for buffer overflow testing

    These test buffer overflow vulnerabilities (CVE-2023-45232 style).

    Args:
        sizes: List of sizes to test (default: [1000, 5000, 10000, 50000])
        char: Character to use for padding

    Returns:
        List of oversized values as bytes
    """
    if sizes is None:
        sizes = [1000, 5000, 10000, 50000]

    return [(char * size).encode() for size in sizes]


def build_mllp_corruption_values() -> Tuple[List[bytes], List[bytes]]:
    """Generate MLLP framing corruption values

    These test MLLP frame handling vulnerabilities (CVE-2021-43267 style).

    Returns:
        Tuple of (start_marker_values, end_marker_values)
    """
    start_values = [
        b"\x0b",  # Valid start
        b"",  # Missing start
        b"\x0b\x0b",  # Double start
        b"\x00",  # Null byte
        b"\x1c",  # End marker as start
        b"\x0d",  # CR as start
        b"\x0a",  # LF as start
        b"\xff",  # High byte
        b"\x0b\x00",  # Start + null
    ]

    end_values = [
        b"\x1c\x0d",  # Valid end
        b"",  # Missing end
        b"\x1c",  # Missing CR
        b"\x0d",  # Missing FS
        b"\x1c\x1c\x0d",  # Double FS
        b"\x1c\x0d\x0d",  # Double CR
        b"\x0d\x1c",  # Reversed order
        b"\x1c\x0a",  # LF instead of CR
        b"\x00\x00",  # Null bytes
    ]

    return start_values, end_values


def build_encoding_char_values() -> List[bytes]:
    """Generate encoding character manipulation values

    These test encoding character handling (CVE-2020-35497 style).

    Returns:
        List of encoding character test values
    """
    return [
        b"^~\\&",  # Standard
        b"^~\\",  # Missing subcomponent separator
        b"^~",  # Missing escape and subcomponent
        b"^",  # Only component separator
        b"",  # Empty
        b"^^^^",  # All same char
        b"~~~~",  # All tildes
        b"\\\\\\\\",  # All escapes
        b"&&&&",  # All ampersands
        b"^~\\&|",  # Extra delimiter
        b"^~\\&^~\\&",  # Doubled
        b"\x00\x00\x00\x00",  # Null bytes
        b"\xff\xff\xff\xff",  # High bytes
        b"^~|&",  # Pipe in encoding chars
        b"A~B&C",  # Letters as separators
    ]


def build_segment_fuzzing_values() -> List[bytes]:
    """Generate malformed segment test values

    Returns:
        List of malformed segment values
    """
    return [
        # Valid but rarely used segments
        b"ZZZ|Custom|Segment|Data\r",
        b"ZPD|Patient|Custom|Data\r",
        # Invalid segment IDs
        b"XXX|Invalid|Segment\r",
        b"123|Numeric|ID\r",
        b"|Empty|Segment|ID\r",
        b"TOOLONG|Segment|ID|Four|Chars\r",
        b"AB|Two|Char|Segment\r",
        # Malformed segments
        b"MSH\r",  # No fields
        b"PID\r",  # No data
        b"|\r",  # Just delimiter
        b"\r",  # Empty segment
        # Segment with excessive fields
        b"OBX|" + b"|".join([b"FIELD"] * 100) + b"\r",
        # Binary data in segment
        b"BIN|\x00\x01\x02\x03\r",
        # Unicode in segment
        b"UNI|Test\x00Null|Test\xffHigh\r",
    ]
