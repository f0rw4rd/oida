"""
ASTM Record Builder

Helper class for building ASTM E1381/E1394 (CLSI LIS01/LIS02) message records
with proper field population.

Supports:
- H (Header) - Message header with sender/receiver info
- P (Patient) - Patient demographic information
- O (Order) - Test order information
- R (Result) - Test result data
- C (Comment) - Comments and additional info
- Q (Query) - Request for information
- L (Terminator) - Message terminator

ASTM Field Delimiters:
- Field: |
- Repeat: \\
- Component: ^
- Escape: &
"""

from datetime import datetime
from typing import List


class ASTMRecordBuilder:
    """Build ASTM message records with proper field population"""

    def __init__(self, version: str = "E1394"):
        """
        Initialize record builder.

        Args:
            version: ASTM version (E1381 or E1394)
        """
        self.version = version
        self.field_delimiter = "|"

    def _get_timestamp(self) -> str:
        """Get current timestamp in ASTM format (YYYYMMDDHHMMSS)"""
        return datetime.now().strftime("%Y%m%d%H%M%S")

    def _escape_field(self, value: str) -> str:
        """Escape special characters in field values per ASTM E1394 spec.

        Order matters: escape character (&) first, then repeat delimiter (\\),
        then component delimiter (^), then field delimiter (|).
        """
        if not value:
            return ""
        value = value.replace("&", "&E&")
        value = value.replace("\\", "&R&")
        value = value.replace("^", "&S&")
        value = value.replace("|", "&F&")
        return value

    def _join_fields(self, fields: List[str]) -> str:
        """Join fields with field delimiter"""
        return self.field_delimiter.join(fields)

    def _calculate_checksum(self, data: bytes) -> bytes:
        """
        Calculate ASTM checksum.

        The checksum is the modulus-256 sum of the bytes from the frame number
        to and including the ETX/ETB character, formatted as 2 uppercase hex chars.

        Args:
            data: Bytes from frame number through ETX/ETB

        Returns:
            2-byte hex checksum (e.g., b"A5")
        """
        total = sum(data) % 256
        return f"{total:02X}".encode()

    def build_header(
        self,
        sender_name: str = "OIDA",
        sender_id: str = "",
        receiver_name: str = "",
        receiver_id: str = "",
        processing_id: str = "P",
        message_datetime: str = "",
    ) -> str:
        """
        Build H (Header) record.

        Similar to HL7 MSH segment - identifies sender, receiver, and message metadata.

        Args:
            sender_name: Sending system name (H-5)
            sender_id: Sending system ID (H-5 component)
            receiver_name: Receiving system name (H-10)
            receiver_id: Receiving system ID (H-10 component)
            processing_id: P=Production, D=Debug, T=Training (H-11)
            message_datetime: Message date/time (H-13)

        Returns:
            Formatted H record string
        """
        # H|\\^&|||sender^id|||||||receiver^id|P|version|datetime
        fields = [
            "H",  # Record type
            "\\^&",  # Delimiter definition
            "",  # Message ID (optional)
            "",  # Access password (optional)
            f"{sender_name}^{sender_id}" if sender_id else sender_name,  # Sender
            "",  # Sender address (optional)
            "",  # Reserved
            "",  # Sender phone (optional)
            "",  # Sender characteristics (optional)
            "",  # Receiver ID (optional)
            f"{receiver_name}^{receiver_id}" if receiver_id else receiver_name,  # Receiver
            processing_id or "P",  # Processing ID
            self.version,  # Version
            message_datetime or self._get_timestamp(),  # Date/Time
        ]
        return self._join_fields(fields)

    def build_patient(
        self,
        sequence: int = 1,
        patient_id: str = "",
        lab_patient_id: str = "",
        patient_name: str = "",
        dob: str = "",
        sex: str = "",
        race: str = "",
        address: str = "",
        phone: str = "",
        physician_id: str = "",
        special_field_1: str = "",
        special_field_2: str = "",
        height: str = "",
        weight: str = "",
        diagnosis: str = "",
        medications: str = "",
        diet: str = "",
        practice_field_1: str = "",
        practice_field_2: str = "",
        admission_date: str = "",
        admission_status: str = "",
        location: str = "",
    ) -> str:
        """
        Build P (Patient) record.

        Similar to HL7 PID segment - patient demographics.

        Args:
            sequence: Sequence number (P-2)
            patient_id: Practice patient ID (P-3)
            lab_patient_id: Laboratory patient ID (P-4)
            patient_name: Patient name LAST^FIRST^MIDDLE (P-6)
            dob: Date of birth YYYYMMDD (P-8)
            sex: Sex M/F/U (P-9)
            race: Race/ethnic origin (P-10)
            address: Patient address (P-11)
            phone: Phone number (P-14)
            physician_id: Attending physician ID (P-15)
            special_field_1: User-defined (P-16)
            special_field_2: User-defined (P-17)
            height: Patient height (P-18)
            weight: Patient weight (P-19)
            diagnosis: Known diagnosis (P-20)
            medications: Active medications (P-21)
            diet: Special diet (P-22)
            practice_field_1: Practice-defined (P-23)
            practice_field_2: Practice-defined (P-24)
            admission_date: Admission date (P-25)
            admission_status: Admission status (P-26)
            location: Patient location (P-27)

        Returns:
            Formatted P record string
        """
        # P|seq|practice_id|lab_id||name||dob|sex|race|address|||phone|physician|...
        fields = [
            "P",  # Record type
            str(sequence),  # Sequence number
            patient_id,  # Practice patient ID
            lab_patient_id,  # Lab patient ID
            "",  # Patient ID #3 (optional)
            patient_name,  # Patient name
            "",  # Mother's maiden name (optional)
            dob,  # Birthdate
            sex,  # Sex
            race,  # Race
            address,  # Address
            "",  # Reserved
            "",  # Reserved
            phone,  # Phone
            physician_id,  # Attending physician
            special_field_1,  # Special field 1
            special_field_2,  # Special field 2
            height,  # Height
            weight,  # Weight
            diagnosis,  # Known diagnosis
            medications,  # Medications
            diet,  # Diet
            practice_field_1,  # Practice field 1
            practice_field_2,  # Practice field 2
            admission_date,  # Admission date
            admission_status,  # Admission status
            location,  # Location
        ]
        return self._join_fields(fields)

    def build_order(
        self,
        sequence: int = 1,
        sample_id: str = "",
        instrument_specimen_id: str = "",
        test_id: str = "",
        priority: str = "R",
        order_datetime: str = "",
        collection_datetime: str = "",
        collection_end_datetime: str = "",
        volume: str = "",
        collector_id: str = "",
        action_code: str = "N",
        danger_code: str = "",
        clinical_info: str = "",
        specimen_received_datetime: str = "",
        specimen_descriptor: str = "",
        ordering_physician: str = "",
        physician_phone: str = "",
        user_field_1: str = "",
        user_field_2: str = "",
        lab_field_1: str = "",
        lab_field_2: str = "",
        report_datetime: str = "",
        instrument_charge: str = "",
        instrument_section: str = "",
        report_type: str = "",
    ) -> str:
        """
        Build O (Order) record.

        Similar to HL7 OBR/ORC segments - test order information.

        Args:
            sequence: Sequence number (O-2)
            sample_id: Specimen/sample ID (O-3)
            instrument_specimen_id: Instrument specimen ID (O-4)
            test_id: Universal test ID (O-5)
            priority: R=Routine, S=Stat, A=ASAP (O-6)
            order_datetime: Order date/time (O-7)
            collection_datetime: Specimen collection date/time (O-8)
            collection_end_datetime: Collection end time (O-9)
            volume: Collection volume (O-10)
            collector_id: Collector ID (O-11)
            action_code: N=New, A=Add, C=Cancel, P=Pending (O-12)
            danger_code: Danger code (O-13)
            clinical_info: Relevant clinical info (O-14)
            specimen_received_datetime: Date/time specimen received (O-15)
            specimen_descriptor: Specimen descriptor (O-16)
            ordering_physician: Ordering physician (O-17)
            physician_phone: Physician phone (O-18)
            user_field_1: User field 1 (O-19)
            user_field_2: User field 2 (O-20)
            lab_field_1: Lab field 1 (O-21)
            lab_field_2: Lab field 2 (O-22)
            report_datetime: Date/time results reported (O-23)
            instrument_charge: Instrument charge (O-24)
            instrument_section: Instrument section (O-25)
            report_type: F=Final, P=Preliminary (O-26)

        Returns:
            Formatted O record string
        """
        fields = [
            "O",  # Record type
            str(sequence),  # Sequence number
            sample_id,  # Specimen ID
            instrument_specimen_id,  # Instrument specimen ID
            test_id,  # Universal test ID
            priority,  # Priority
            order_datetime or self._get_timestamp(),  # Requested/ordered datetime
            collection_datetime,  # Specimen collection datetime
            collection_end_datetime,  # Collection end time
            volume,  # Collection volume
            collector_id,  # Collector ID
            action_code,  # Action code
            danger_code,  # Danger code
            clinical_info,  # Clinical info
            specimen_received_datetime,  # Date received
            specimen_descriptor,  # Specimen descriptor
            ordering_physician,  # Ordering physician
            physician_phone,  # Physician phone
            user_field_1,  # User field 1
            user_field_2,  # User field 2
            lab_field_1,  # Lab field 1
            lab_field_2,  # Lab field 2
            report_datetime,  # Report datetime
            instrument_charge,  # Instrument charge
            instrument_section,  # Instrument section
            report_type or "F",  # Report type
        ]
        return self._join_fields(fields)

    def build_result(
        self,
        sequence: int = 1,
        test_id: str = "",
        value: str = "",
        units: str = "",
        reference_range: str = "",
        abnormal_flag: str = "",
        nature_of_abnormality: str = "",
        result_status: str = "F",
        norms_changed_datetime: str = "",
        operator_id: str = "",
        test_started_datetime: str = "",
        test_completed_datetime: str = "",
        instrument_id: str = "",
    ) -> str:
        """
        Build R (Result) record.

        Similar to HL7 OBX segment - test result data.

        Args:
            sequence: Sequence number (R-2)
            test_id: Universal test ID (R-3)
            value: Data/measurement value (R-4)
            units: Units (R-5)
            reference_range: Reference ranges (R-6)
            abnormal_flag: L=Low, H=High, N=Normal, A=Abnormal (R-7)
            nature_of_abnormality: Nature of abnormality (R-8)
            result_status: F=Final, P=Preliminary, C=Corrected (R-9)
            norms_changed_datetime: Date of norms change (R-10)
            operator_id: Operator identification (R-11)
            test_started_datetime: Date/time test started (R-12)
            test_completed_datetime: Date/time test completed (R-13)
            instrument_id: Instrument identification (R-14)

        Returns:
            Formatted R record string
        """
        fields = [
            "R",  # Record type
            str(sequence),  # Sequence number
            test_id,  # Universal test ID
            value,  # Data/measurement value
            units,  # Units
            reference_range,  # Reference ranges
            abnormal_flag,  # Abnormal flag
            nature_of_abnormality,  # Nature of abnormality
            result_status,  # Result status
            norms_changed_datetime,  # Date norms changed
            operator_id,  # Operator ID
            test_started_datetime,  # Test started
            test_completed_datetime or self._get_timestamp(),  # Test completed
            instrument_id,  # Instrument ID
        ]
        return self._join_fields(fields)

    def build_comment(
        self,
        sequence: int = 1,
        source: str = "L",
        comment_text: str = "",
        comment_type: str = "G",
    ) -> str:
        """
        Build C (Comment) record.

        Similar to HL7 NTE segment - comments and notes.

        Args:
            sequence: Sequence number (C-2)
            source: Comment source L=Lab, I=Instrument, O=Operator (C-3)
            comment_text: Comment text (C-4)
            comment_type: G=Generic, P=Patient, T=Test, I=Instrument (C-5)

        Returns:
            Formatted C record string
        """
        fields = [
            "C",  # Record type
            str(sequence),  # Sequence number
            source,  # Comment source
            self._escape_field(comment_text),  # Comment text (escaped)
            comment_type,  # Comment type
        ]
        return self._join_fields(fields)

    def build_query(
        self,
        sequence: int = 1,
        starting_range: str = "",
        ending_range: str = "",
        universal_test_id: str = "",
        nature_of_request: str = "O",
        requested_datetime: str = "",
        beginning_request_datetime: str = "",
        ending_request_datetime: str = "",
        requesting_physician: str = "",
        requesting_phone: str = "",
        user_field_1: str = "",
        user_field_2: str = "",
        request_status_codes: str = "",
    ) -> str:
        """
        Build Q (Query) record.

        Similar to HL7 QRY segment - request for information.

        Args:
            sequence: Sequence number (Q-2)
            starting_range: Starting range ID (Q-3)
            ending_range: Ending range ID (Q-4)
            universal_test_id: Universal test ID (Q-5)
            nature_of_request: O=Order, R=Results, S=Demographics, A=All (Q-6)
            requested_datetime: Request date/time (Q-7)
            beginning_request_datetime: Beginning date (Q-8)
            ending_request_datetime: Ending date (Q-9)
            requesting_physician: Requesting physician (Q-10)
            requesting_phone: Requesting phone (Q-11)
            user_field_1: User field 1 (Q-12)
            user_field_2: User field 2 (Q-13)
            request_status_codes: Status codes (Q-14)

        Returns:
            Formatted Q record string
        """
        fields = [
            "Q",  # Record type
            str(sequence),  # Sequence number
            starting_range,  # Starting range ID
            ending_range,  # Ending range ID
            universal_test_id,  # Universal test ID
            nature_of_request,  # Nature of request
            requested_datetime or self._get_timestamp(),  # Request datetime
            beginning_request_datetime,  # Beginning request datetime
            ending_request_datetime,  # Ending request datetime
            requesting_physician,  # Requesting physician
            requesting_phone,  # Requesting phone
            user_field_1,  # User field 1
            user_field_2,  # User field 2
            request_status_codes,  # Status codes
        ]
        return self._join_fields(fields)

    def build_terminator(
        self,
        sequence: int = 1,
        terminator_code: str = "N",
    ) -> str:
        """
        Build L (Terminator) record.

        Signals end of message. No HL7 equivalent.

        Args:
            sequence: Sequence number (L-2)
            terminator_code: N=Normal, Q=Exit query, I=Ignore, E=Error (L-3)

        Returns:
            Formatted L record string
        """
        fields = [
            "L",  # Record type
            str(sequence),  # Sequence number
            terminator_code,  # Terminator code
        ]
        return self._join_fields(fields)


# ASTM Protocol Constants
STX = b"\x02"  # Start of text
ETX = b"\x03"  # End of text
EOT = b"\x04"  # End of transmission
ENQ = b"\x05"  # Enquiry
ACK = b"\x06"  # Acknowledgment
NAK = b"\x15"  # Negative acknowledgment
ETB = b"\x17"  # End of transmission block (intermediate frame)
CR = b"\x0d"  # Carriage return
LF = b"\x0a"  # Line feed

# Analyzer/Instrument vendor mapping
ASTM_VENDOR_MAP = {
    # Chemistry Analyzers
    "COBAS": ("Roche", "cobas Chemistry"),
    "COBAS_6000": ("Roche", "cobas 6000"),
    "COBAS_8000": ("Roche", "cobas 8000"),
    "C311": ("Roche", "cobas c 311"),
    "C501": ("Roche", "cobas c 501"),
    "C502": ("Roche", "cobas c 502"),
    "INTEGRA": ("Roche", "cobas INTEGRA"),
    "ARCHITECT": ("Abbott", "ARCHITECT Clinical Chemistry"),
    "ARCHITECT_C": ("Abbott", "ARCHITECT c Systems"),
    "ALINITY_C": ("Abbott", "Alinity c"),
    "AU480": ("Beckman Coulter", "AU480 Chemistry"),
    "AU680": ("Beckman Coulter", "AU680 Chemistry"),
    "AU5800": ("Beckman Coulter", "AU5800 Chemistry"),
    "DXC": ("Beckman Coulter", "DxC Chemistry"),
    "VITROS": ("Ortho Clinical", "VITROS Chemistry"),
    "VITROS_5600": ("Ortho Clinical", "VITROS 5600"),
    "VITROS_XT": ("Ortho Clinical", "VITROS XT 7600"),
    "ADVIA": ("Siemens", "ADVIA Chemistry"),
    "ADVIA_1800": ("Siemens", "ADVIA 1800"),
    "ADVIA_2400": ("Siemens", "ADVIA 2400"),
    "DIMENSION": ("Siemens", "Dimension Clinical Chemistry"),
    "DIMENSION_EXL": ("Siemens", "Dimension EXL"),
    "ATELLICA": ("Siemens", "Atellica CH"),
    # Hematology Analyzers
    "SYSMEX": ("Sysmex", "Hematology Analyzer"),
    "XN-1000": ("Sysmex", "XN-1000"),
    "XN-2000": ("Sysmex", "XN-2000"),
    "XN-3000": ("Sysmex", "XN-3000"),
    "XN-9000": ("Sysmex", "XN-9000"),
    "XS-1000": ("Sysmex", "XS-1000i"),
    "XT-2000": ("Sysmex", "XT-2000i"),
    "XE-2100": ("Sysmex", "XE-2100"),
    "XE-5000": ("Sysmex", "XE-5000"),
    "CS-5100": ("Sysmex", "CS-5100 Coagulation"),
    "CELL-DYN": ("Abbott", "CELL-DYN Hematology"),
    "CELL-DYN_RUBY": ("Abbott", "CELL-DYN Ruby"),
    "CELL-DYN_EMERALD": ("Abbott", "CELL-DYN Emerald"),
    "CELL-DYN_SAPPHIRE": ("Abbott", "CELL-DYN Sapphire"),
    "DXH": ("Beckman Coulter", "DxH Hematology"),
    "DXH_900": ("Beckman Coulter", "DxH 900"),
    "LH_750": ("Beckman Coulter", "LH 750"),
    "LH_780": ("Beckman Coulter", "LH 780"),
    "ADVIA2120": ("Siemens", "ADVIA 2120i Hematology"),
    "ADVIA_560": ("Siemens", "ADVIA 560"),
    # Immunoassay
    "ELECSYS": ("Roche", "Elecsys Immunoassay"),
    "COBAS_E": ("Roche", "cobas e Immunoassay"),
    "E411": ("Roche", "cobas e 411"),
    "E601": ("Roche", "cobas e 601"),
    "E801": ("Roche", "cobas e 801"),
    "ACCESS": ("Beckman Coulter", "Access Immunoassay"),
    "ACCESS_2": ("Beckman Coulter", "Access 2"),
    "DXI": ("Beckman Coulter", "UniCel DxI"),
    "IMMULITE": ("Siemens", "IMMULITE Immunoassay"),
    "IMMULITE_2000": ("Siemens", "IMMULITE 2000"),
    "ATELLICA_IM": ("Siemens", "Atellica IM"),
    "ARCHITECT_I": ("Abbott", "ARCHITECT i Systems"),
    "ALINITY_I": ("Abbott", "Alinity i"),
    # Urinalysis
    "CLINITEK": ("Siemens", "CLINITEK Urinalysis"),
    "CLINITEK_500": ("Siemens", "CLINITEK Status+"),
    "CLINITEK_NOVUS": ("Siemens", "CLINITEK Novus"),
    "IRIS": ("Beckman Coulter", "iQ200 Urinalysis"),
    "IQ200": ("Beckman Coulter", "iQ200 SPRINT"),
    "AUTION": ("Beckman Coulter", "Aution MAX"),
    "UF-1000I": ("Sysmex", "UF-1000i"),
    "UF-5000": ("Sysmex", "UF-5000"),
    "UC-3500": ("Sysmex", "UC-3500"),
    # Blood Gas
    "ABL": ("Radiometer", "ABL Blood Gas"),
    "ABL800": ("Radiometer", "ABL800 FLEX"),
    "ABL90": ("Radiometer", "ABL90 FLEX PLUS"),
    "RAPIDPOINT": ("Siemens", "RAPIDPoint Blood Gas"),
    "RAPIDPOINT_500": ("Siemens", "RAPIDPoint 500"),
    "GEM": ("Werfen", "GEM Blood Gas"),
    "GEM_5000": ("Werfen", "GEM Premier 5000"),
    "EPOC": ("Siemens", "epoc Blood Analysis"),
    "ISTAT": ("Abbott", "i-STAT System"),
    # Coagulation
    "STA": ("Diagnostica Stago", "STA Coagulation"),
    "STA_R": ("Diagnostica Stago", "STA-R Max"),
    "STA_COMPACT": ("Diagnostica Stago", "STA Compact Max"),
    "ACL": ("Werfen", "ACL TOP Coagulation"),
    "ACL_TOP": ("Werfen", "ACL TOP Family"),
    "ACL_ELITE": ("Werfen", "ACL ELITE Pro"),
    "BCS": ("Siemens", "BCS XP Coagulation"),
    "CS-2500": ("Sysmex", "CS-2500"),
    # Microbiology
    "VITEK": ("bioMerieux", "VITEK Microbiology"),
    "VITEK_2": ("bioMerieux", "VITEK 2"),
    "VITEK_MS": ("bioMerieux", "VITEK MS"),
    "PHOENIX": ("BD", "Phoenix Microbiology"),
    "PHOENIX_M50": ("BD", "BD Phoenix M50"),
    "MALDI": ("Bruker", "MALDI Biotyper"),
    "BACTEC": ("BD", "BACTEC Blood Culture"),
    "BACT_ALERT": ("bioMerieux", "BacT/ALERT"),
    # Molecular
    "COBAS_4800": ("Roche", "cobas 4800"),
    "COBAS_6800": ("Roche", "cobas 6800/8800"),
    "GENEXPERT": ("Cepheid", "GeneXpert"),
    "M2000": ("Abbott", "m2000 RealTime"),
    "ALINITY_M": ("Abbott", "Alinity m"),
    "PANTHER": ("Hologic", "Panther System"),
    "VERIGENE": ("Luminex", "Verigene"),
}

# Common lab test codes with names and units
LAB_TEST_TYPES = {
    # Chemistry - Basic Metabolic Panel
    "GLU": ("Glucose", "mg/dL", "70-100"),
    "BUN": ("Blood Urea Nitrogen", "mg/dL", "7-20"),
    "CREAT": ("Creatinine", "mg/dL", "0.7-1.3"),
    "NA": ("Sodium", "mEq/L", "136-145"),
    "K": ("Potassium", "mEq/L", "3.5-5.0"),
    "CL": ("Chloride", "mEq/L", "98-106"),
    "CO2": ("Carbon Dioxide", "mEq/L", "23-29"),
    "CA": ("Calcium", "mg/dL", "8.5-10.5"),
    # Chemistry - Comprehensive Metabolic Panel
    "ALT": ("Alanine Aminotransferase", "U/L", "7-56"),
    "AST": ("Aspartate Aminotransferase", "U/L", "10-40"),
    "ALKP": ("Alkaline Phosphatase", "U/L", "44-147"),
    "TBIL": ("Total Bilirubin", "mg/dL", "0.1-1.2"),
    "DBIL": ("Direct Bilirubin", "mg/dL", "0.0-0.3"),
    "TP": ("Total Protein", "g/dL", "6.0-8.3"),
    "ALB": ("Albumin", "g/dL", "3.5-5.0"),
    "GLOB": ("Globulin", "g/dL", "2.0-3.5"),
    "GGT": ("Gamma-GT", "U/L", "0-51"),
    "LDH": ("Lactate Dehydrogenase", "U/L", "140-280"),
    # Hematology - CBC
    "WBC": ("White Blood Cell Count", "10^3/uL", "4.5-11.0"),
    "RBC": ("Red Blood Cell Count", "10^6/uL", "4.5-5.5"),
    "HGB": ("Hemoglobin", "g/dL", "12.0-17.5"),
    "HCT": ("Hematocrit", "%", "36-50"),
    "PLT": ("Platelet Count", "10^3/uL", "150-400"),
    "MCV": ("Mean Corpuscular Volume", "fL", "80-100"),
    "MCH": ("Mean Corpuscular Hemoglobin", "pg", "27-31"),
    "MCHC": ("Mean Corpuscular Hemoglobin Concentration", "g/dL", "32-36"),
    "RDW": ("Red Cell Distribution Width", "%", "11.5-14.5"),
    "MPV": ("Mean Platelet Volume", "fL", "7.5-11.5"),
    "NEUT": ("Neutrophils", "%", "40-70"),
    "LYMPH": ("Lymphocytes", "%", "20-40"),
    "MONO": ("Monocytes", "%", "2-8"),
    "EOS": ("Eosinophils", "%", "1-4"),
    "BASO": ("Basophils", "%", "0-1"),
    # Urinalysis
    "UA-GLUC": ("Urine Glucose", "mg/dL", "Negative"),
    "UA-PROT": ("Urine Protein", "mg/dL", "Negative"),
    "UA-PH": ("Urine pH", "", "5.0-8.0"),
    "UA-SG": ("Urine Specific Gravity", "", "1.005-1.030"),
    "UA-BLOOD": ("Urine Blood", "", "Negative"),
    "UA-KET": ("Urine Ketones", "", "Negative"),
    "UA-BILI": ("Urine Bilirubin", "", "Negative"),
    "UA-LEUK": ("Urine Leukocytes", "", "Negative"),
    "UA-NIT": ("Urine Nitrite", "", "Negative"),
    # Coagulation
    "PT": ("Prothrombin Time", "sec", "11-13.5"),
    "INR": ("International Normalized Ratio", "", "0.8-1.1"),
    "PTT": ("Partial Thromboplastin Time", "sec", "25-35"),
    "APTT": ("Activated PTT", "sec", "25-35"),
    "FIB": ("Fibrinogen", "mg/dL", "200-400"),
    "DIMER": ("D-Dimer", "ng/mL", "<500"),
    # Cardiac Markers
    "TROP": ("Troponin I", "ng/mL", "<0.04"),
    "TROPT": ("Troponin T", "ng/mL", "<0.01"),
    "BNP": ("B-Natriuretic Peptide", "pg/mL", "<100"),
    "PROBNP": ("NT-proBNP", "pg/mL", "<125"),
    "CKMB": ("Creatine Kinase MB", "ng/mL", "<5.0"),
    "CK": ("Creatine Kinase", "U/L", "30-200"),
    "MYO": ("Myoglobin", "ng/mL", "<90"),
    # Thyroid
    "TSH": ("Thyroid Stimulating Hormone", "mIU/L", "0.4-4.0"),
    "T4": ("Thyroxine", "ug/dL", "4.5-12.0"),
    "FT4": ("Free T4", "ng/dL", "0.8-1.8"),
    "T3": ("Triiodothyronine", "ng/dL", "80-200"),
    "FT3": ("Free T3", "pg/mL", "2.3-4.2"),
    # Lipid Panel
    "CHOL": ("Total Cholesterol", "mg/dL", "<200"),
    "TRIG": ("Triglycerides", "mg/dL", "<150"),
    "HDL": ("HDL Cholesterol", "mg/dL", ">40"),
    "LDL": ("LDL Cholesterol", "mg/dL", "<100"),
    "VLDL": ("VLDL Cholesterol", "mg/dL", "5-40"),
    # Diabetes
    "HBA1C": ("Hemoglobin A1c", "%", "<5.7"),
    "GLUF": ("Fasting Glucose", "mg/dL", "70-99"),
    # Blood Gas
    "PH": ("pH", "", "7.35-7.45"),
    "PCO2": ("pCO2", "mmHg", "35-45"),
    "PO2": ("pO2", "mmHg", "80-100"),
    "HCO3": ("Bicarbonate", "mEq/L", "22-26"),
    "BE": ("Base Excess", "mEq/L", "-2 to +2"),
    "O2SAT": ("Oxygen Saturation", "%", "94-100"),
    "LAC": ("Lactate", "mmol/L", "0.5-2.2"),
}


# Module exports
__all__ = [
    "ASTMRecordBuilder",
    "STX",
    "ETX",
    "EOT",
    "ENQ",
    "ACK",
    "NAK",
    "ETB",
    "CR",
    "LF",
    "ASTM_VENDOR_MAP",
    "LAB_TEST_TYPES",
]
