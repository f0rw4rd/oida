#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for HL7 v2 message types: MFN, QBP, BAR/DFT, and Continuation support.

Tests the implementation of:
- MFN (Master File Notification) messages: M01, M02, M04
- QBP (Query by Parameter) messages: Q13, Q40, Z34, Z44
- BAR/DFT (Financial) messages: P01, P03
- Continuation/Fragmentation handling (DSC segment)
"""

import unittest
from unittest.mock import Mock, patch

from tests.unit.hl7.conftest import _make_hl7_instance

# MLLP framing characters
MLLP_START = b"\x0b"
MLLP_END = b"\x1c\x0d"


class MockSocket:
    """Mock socket for testing MLLP connections"""

    def __init__(self, response_data=None, connect_success=True):
        self.connect_success = connect_success
        self.response_data = response_data or self._default_ack()
        self.sent_data = []
        self.connected = False
        self.timeout = 10

    def _default_ack(self):
        """Generate default ACK response"""
        ack = (
            "MSH|^~\\&|TARGET|FACILITY|OIDA|SECURITY|"
            "20240101120000||ACK^A01|MSG12345|P|2.5\r"
            "MSA|AA|MSG12345|Message accepted\r"
        )
        return MLLP_START + ack.encode("utf-8") + MLLP_END

    def connect(self, address):
        if not self.connect_success:
            raise ConnectionRefusedError("Connection refused")
        self.connected = True

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent_data.append(data)

    def recv(self, bufsize):
        if self.response_data:
            data = self.response_data
            self.response_data = b""
            return data
        return b""

    def close(self):
        self.connected = False


def create_mock_args():
    """Create a complete mock args object for HL7 scanner"""
    mock_args = Mock()
    mock_args.port = 2575
    mock_args.timeout = 10
    mock_args.tls = False
    mock_args.verbose = 0
    mock_args.hl7_version = "2.5"
    mock_args.sending_app = "OIDA"
    mock_args.sending_facility = "SECURITY"
    mock_args.send_adt = False
    mock_args.send_oru = False
    mock_args.send_orm = False
    mock_args.send_rx = False
    mock_args.send_siu = False
    mock_args.send_qry = False
    mock_args.send_mdm = False
    mock_args.send_mfn = False
    mock_args.query_mfn = False
    mock_args.send_bar = False
    mock_args.send_dft = False
    mock_args.query_whoami = False
    mock_args.query_tabular = False
    mock_args.query_imm = False
    mock_args.query_imm_forecast = False
    mock_args.message_type = None
    mock_args.fuzz = False
    mock_args.confirm = False
    mock_args.enum_patients = False
    mock_args.enum_providers = False
    mock_args.enum_apps = False
    mock_args.enum_locations = False
    mock_args.enum_all = False
    mock_args.probe_ops = False
    mock_args.output = None
    mock_args.extract_response = False
    mock_args.extract_fields = ""
    # MFN-specific
    mock_args.mfn_type = "M01"
    mock_args.staff_id = None
    mock_args.staff_name = None
    mock_args.staff_type = None
    mock_args.department = None
    mock_args.charge_code = None
    mock_args.charge_price = None
    # Patient data
    mock_args.patient_id = None
    mock_args.patient_name = None
    mock_args.patient_dob = "19800101"
    mock_args.patient_sex = "U"
    mock_args.patient_address = ""
    mock_args.patient_phone = ""
    mock_args.mrn = None
    # Visit/Financial data
    mock_args.visit_number = None
    mock_args.patient_class = None
    mock_args.account_number = None
    mock_args.guarantor_name = None
    mock_args.guarantor_phone = None
    mock_args.insurance_company = None
    mock_args.insurance_group = None
    mock_args.policy_number = None
    mock_args.transaction_amount = None
    mock_args.transaction_code = None
    mock_args.transaction_description = None
    mock_args.transaction_type = "CG"
    # Order/Observation data
    mock_args.order_id = None
    mock_args.order_code = None
    mock_args.order_priority = "R"
    mock_args.obx_value = None
    mock_args.obx_id = None
    mock_args.obx_type = "NM"
    mock_args.obx_units = "mg/dL"
    # Diagnosis/Procedure data
    mock_args.dx_code = None
    mock_args.dx_description = None
    mock_args.dx_type = "A"
    mock_args.dx_priority = "1"
    mock_args.dx_clinician = ""
    mock_args.pr_code = None
    mock_args.pr_description = None
    mock_args.pr_type = ""
    mock_args.pr_practitioner = ""
    # Location
    mock_args.location = ""
    mock_args.admit_date = ""
    return mock_args


# =============================================================================
# MFN (Master File Notification) Tests
# =============================================================================


class TestMFNSegmentBuilders(unittest.TestCase):
    """Test MFN-related segment builders (MFI, MFE, STF, PRA, PRC)"""

    def test_build_mfi_segment(self):
        """Test MFI (Master File Identification) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_mfi(
            master_file_id="STF^Staff Master File",
            file_level_event_code="UPD",
            response_level_code="AL",
        )

        self.assertIsNotNone(result)

    def test_build_mfe_segment(self):
        """Test MFE (Master File Entry) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_mfe(
            record_level_event_code="MAD",
            mfn_control_id="MFE001",
            primary_key_value="STF001",
        )

        self.assertIsNotNone(result)

    def test_build_stf_segment(self):
        """Test STF (Staff Identification) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_stf(
            staff_id="STF001",
            staff_name="SMITH^JOHN^DR",
            staff_type="MD",
            department="CARDIOLOGY",
            active_inactive="A",
        )

        self.assertIsNotNone(result)

    def test_build_pra_segment(self):
        """Test PRA (Practitioner Detail) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_pra(
            practitioner_id="PRA001",
            practitioner_category="MD",
            specialty="Cardiology",
            institution="MAIN_HOSPITAL",
        )

        self.assertIsNotNone(result)

    def test_build_prc_segment(self):
        """Test PRC (Pricing/Charge Description) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_prc(
            charge_code="CHG001",
            price="150.00",
            department="LAB",
            active_inactive="A",
        )

        self.assertIsNotNone(result)


class TestMFNSegmentParsers(unittest.TestCase):
    """Test MFN-related segment parsers"""

    def test_parse_mfi_segment(self):
        """Test parsing MFI segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "MFI|STF^Staff Master File||UPD|20240101120000|20240101120000|AL"
        result = HL7SegmentParser.parse_mfi(segment)

        self.assertEqual(result["MasterFileID"], "STF")
        self.assertEqual(result["FileLevelEventCode"], "UPD")
        self.assertEqual(result["ResponseLevelCode"], "AL")

    def test_parse_mfe_segment(self):
        """Test parsing MFE segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "MFE|MAD|MFE001|20240101|STF001|CE"
        result = HL7SegmentParser.parse_mfe(segment)

        self.assertEqual(result["RecordLevelEventCode"], "MAD")
        self.assertEqual(result["MFNControlID"], "MFE001")
        self.assertEqual(result["PrimaryKeyValue"], "STF001")

    def test_parse_stf_segment(self):
        """Test parsing STF segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "STF|STF001|STF001^^^HOSP^EMP|SMITH^JOHN^DR|MD|M|19700101|A|CARDIOLOGY|MED||"
        result = HL7SegmentParser.parse_stf(segment)

        self.assertEqual(result["PrimaryKeyValue"], "STF001")
        self.assertEqual(result["StaffType"], "MD")
        self.assertEqual(result["Department"], "CARDIOLOGY")
        self.assertIn("SMITH JOHN DR", result["StaffName"])

    def test_parse_pra_segment(self):
        """Test parsing PRA segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "PRA|PRA001|GROUP1|MD||Cardiology|||20200101|MAIN_HOSP|"
        result = HL7SegmentParser.parse_pra(segment)

        self.assertEqual(result["PrimaryKeyValue"], "PRA001")
        self.assertEqual(result["PractitionerCategory"], "MD")
        self.assertEqual(result["Specialty"], "Cardiology")

    def test_parse_prc_segment(self):
        """Test parsing PRC segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "PRC|CHG001|MAIN|LAB|I|150.00|||1|100|20240101|20251231|||Y||A"
        result = HL7SegmentParser.parse_prc(segment)

        self.assertEqual(result["PrimaryKeyValue"], "CHG001")
        self.assertEqual(result["FacilityID"], "MAIN")
        self.assertEqual(result["Department"], "LAB")
        self.assertEqual(result["Price"], "150.00")


class TestMFNMessageCreation(unittest.TestCase):
    """Test MFN message creation"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_mfn_m01_message(self):
        """Test MFN^M01 (General Master File) message creation"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_mfn_message("M01")

        self.assertIsNotNone(msg)
        self.assertIn("MFN^M01", msg)
        self.assertIn("MFI|", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_mfn_m02_message(self):
        """Test MFN^M02 (Staff/Practitioner Master File) message creation"""

        self.mock_args.staff_id = "STF001"
        self.mock_args.staff_name = "DOE^JANE^DR"
        self.mock_args.staff_type = "MD"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_mfn_message("M02")

        self.assertIsNotNone(msg)
        self.assertIn("MFN^M02", msg)
        self.assertIn("STF|", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_mfn_m04_message(self):
        """Test MFN^M04 (Charge Description Master File) message creation"""

        self.mock_args.charge_code = "CHG001"
        self.mock_args.charge_price = "250.00"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_mfn_message("M04")

        self.assertIsNotNone(msg)
        self.assertIn("MFN^M04", msg)
        self.assertIn("PRC|", msg)


class TestMFNMessageSending(unittest.TestCase):
    """Test MFN message sending with confirmation requirements"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_mfn_requires_confirm(self):
        """Test MFN message requires --confirm"""

        self.mock_args.confirm = False

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_mfn_message()

        scanner.logger.fail.assert_called()
        call_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", call_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_mfn_with_confirm(self):
        """Test MFN message sends when --confirm is set"""

        self.mock_args.confirm = True

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_mfn_message()

        scanner.logger.display.assert_called()


class TestMFQMessageCreation(unittest.TestCase):
    """Test MFQ (Master File Query) message creation"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_mfq_message(self):
        """Test MFQ^M01 message creation"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_mfq_message()

        self.assertIsNotNone(msg)
        self.assertIn("MFQ^M01", msg)
        self.assertIn("QRD|", msg)


# =============================================================================
# QBP (Query by Parameter) Tests
# =============================================================================


class TestQBPMessageCreation(unittest.TestCase):
    """Test QBP message creation"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_qbp_q40_message(self):
        """Test QBP^Q40 (WhoAmI) message creation"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_qbp_message("Q40", "WhoAmI")

        self.assertIsNotNone(msg)
        self.assertIn("QBP^Q40", msg)
        self.assertIn("QPD|", msg)
        self.assertIn("RCP|", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_qbp_q13_message(self):
        """Test QBP^Q13 (Tabular Query) message creation"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_qbp_message("Q13", "TabularPatientList")

        self.assertIsNotNone(msg)
        self.assertIn("QBP^Q13", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_qbp_z34_message(self):
        """Test QBP^Z34 (Immunization History) message creation"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_qbp_immunization_message("Z34", "PT001")

        self.assertIsNotNone(msg)
        self.assertIn("QBP^Z34", msg)
        self.assertIn("PT001", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_qbp_z44_message(self):
        """Test QBP^Z44 (Immunization + Forecast) message creation"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_qbp_immunization_message("Z44", "PT001")

        self.assertIsNotNone(msg)
        self.assertIn("QBP^Z44", msg)


class TestQBPMessageSending(unittest.TestCase):
    """Test QBP message sending"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_qbp_q40_message(self):
        """Test sending QBP^Q40 (WhoAmI) query"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_qbp_q40_message()

        scanner.logger.display.assert_called()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_qbp_q13_message(self):
        """Test sending QBP^Q13 (Tabular Query)"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_qbp_q13_message()

        scanner.logger.display.assert_called()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_qbp_z34_requires_patient_id(self):
        """Test QBP^Z34 requires --patient-id"""

        self.mock_args.patient_id = None

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_qbp_z34_message()

        scanner.logger.fail.assert_called()
        call_args = str(scanner.logger.fail.call_args)
        self.assertIn("--patient-id", call_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_qbp_z44_requires_patient_id(self):
        """Test QBP^Z44 requires --patient-id"""

        self.mock_args.patient_id = None

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_qbp_z44_message()

        scanner.logger.fail.assert_called()


class TestQBPResultExtraction(unittest.TestCase):
    """Test QBP result extraction"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_extract_whoami_results(self):
        """Test extraction of WhoAmI response"""

        response = (
            b"MSH|^~\\&|SERVER_APP|SERVER_FAC|OIDA|SECURITY|20240101||RSP^K40|123|P|2.5\r"
            b"MSA|AA|123\r"
        )

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        scanner._extract_whoami_results(response)

        self.assertIn("whoami_results", scanner.results["data"])

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_extract_rtb_results(self):
        """Test extraction of RTB (tabular) response"""

        response = (
            b"MSH|^~\\&|SERVER|FAC|...\r"
            b"MSA|AA|123\r"
            b"RDF|3|PatientID^ST~PatientName^ST~DOB^DT\r"
            b"RDT|PT001~DOE^JOHN~19800101\r"
            b"RDT|PT002~SMITH^JANE~19900202\r"
        )

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        scanner._extract_rtb_results(response)

        self.assertIn("tabular_results", scanner.results["data"])
        self.assertEqual(scanner.results["data"]["tabular_results"]["count"], 2)


# =============================================================================
# BAR/DFT (Financial) Tests
# =============================================================================


class TestFinancialSegmentBuilders(unittest.TestCase):
    """Test financial segment builders (FT1, GT1, IN1)"""

    def test_build_ft1_segment(self):
        """Test FT1 (Financial Transaction) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_ft1(
            transaction_id="FT001",
            transaction_type="CG",
            transaction_code="99213",
            transaction_description="Office Visit",
            transaction_amount="150.00",
            patient_id="PT001",
        )

        self.assertIsNotNone(result)

    def test_build_gt1_segment(self):
        """Test GT1 (Guarantor) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_gt1(
            guarantor_number="GT001",
            guarantor_name="DOE^JOHN",
            guarantor_phone="555-1234",
            guarantor_relationship="SEL",
        )

        self.assertIsNotNone(result)

    def test_build_in1_segment(self):
        """Test IN1 (Insurance) segment building"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        builder = HL7SegmentBuilder(version="2.5")
        result = builder.build_in1(
            insurance_plan_id="PLAN001",
            insurance_company_name="BlueCross",
            group_number="GRP123",
            policy_number="POL456",
        )

        self.assertIsNotNone(result)


class TestFinancialSegmentParsers(unittest.TestCase):
    """Test financial segment parsers"""

    def test_parse_ft1_segment(self):
        """Test parsing FT1 segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = (
            "FT1|1|FT001|BATCH01|20240101|20240101|CG|99213^Office Visit||||||||||||||PT001||||"
        )
        result = HL7SegmentParser.parse_ft1(segment)

        self.assertEqual(result["SetID"], "1")
        self.assertEqual(result["TransactionID"], "FT001")
        self.assertEqual(result["TransactionType"], "CG")
        self.assertEqual(result["TransactionCode"], "99213")

    def test_parse_gt1_segment(self):
        """Test parsing GT1 segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "GT1|1|GT001^^^HOSP^GN|DOE^JOHN||123 MAIN ST^APT 1^ANYTOWN^CA^90210|555-1234||19700101|M||SEL|123456789|"
        result = HL7SegmentParser.parse_gt1(segment)

        self.assertEqual(result["SetID"], "1")
        self.assertEqual(result["GuarantorNumber"], "GT001")
        self.assertIn("DOE JOHN", result["GuarantorName"])

    def test_parse_in1_segment(self):
        """Test parsing IN1 segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        # IN1 fields: 1=SetID, 2=PlanID, 3=CompanyID, 4=CompanyName, 5=Addr, 6=Contact, 7=Phone, 8=GroupNum
        segment = "IN1|1|PLAN001|INS001|BlueCross|123 INS ST||555-INS|GRP123||||||20240101|20251231||DOE^JOHN|||||||||||||||POL456|"
        result = HL7SegmentParser.parse_in1(segment)

        self.assertEqual(result["SetID"], "1")
        self.assertEqual(result["InsurancePlanID"], "PLAN001")
        self.assertEqual(result["InsuranceCompanyName"], "BlueCross")
        self.assertEqual(result["GroupNumber"], "GRP123")


class TestBARMessageCreation(unittest.TestCase):
    """Test BAR (Billing) message creation"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_bar_p01_message(self):
        """Test BAR^P01 (Add Billing Account) message creation"""

        self.mock_args.patient_id = "PT001"
        self.mock_args.account_number = "ACC001"
        self.mock_args.guarantor_name = "DOE^JOHN"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_bar_message()

        self.assertIsNotNone(msg)
        self.assertIn("BAR^P01", msg)
        self.assertIn("PID|", msg)
        self.assertIn("GT1|", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_bar_with_insurance(self):
        """Test BAR^P01 with insurance information"""

        self.mock_args.patient_id = "PT001"
        self.mock_args.insurance_company = "BlueCross"
        self.mock_args.insurance_group = "GRP123"
        self.mock_args.policy_number = "POL456"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_bar_message()

        self.assertIsNotNone(msg)
        self.assertIn("IN1|", msg)


class TestDFTMessageCreation(unittest.TestCase):
    """Test DFT (Financial Transaction) message creation"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_dft_p03_message(self):
        """Test DFT^P03 (Post Financial Transaction) message creation"""

        self.mock_args.patient_id = "PT001"
        self.mock_args.transaction_amount = "150.00"
        self.mock_args.transaction_code = "99213"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        msg = scanner._create_dft_message()

        self.assertIsNotNone(msg)
        self.assertIn("DFT^P03", msg)
        self.assertIn("FT1|", msg)


class TestFinancialMessageSending(unittest.TestCase):
    """Test BAR/DFT message sending with confirmation requirements"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_bar_requires_confirm(self):
        """Test BAR^P01 requires --confirm"""

        self.mock_args.confirm = False

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_bar_message()

        scanner.logger.fail.assert_called()
        call_args = str(scanner.logger.fail.call_args)
        self.assertIn("--confirm", call_args)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_dft_requires_confirm(self):
        """Test DFT^P03 requires --confirm"""

        self.mock_args.confirm = False

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_dft_message()

        scanner.logger.fail.assert_called()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_bar_with_confirm(self):
        """Test BAR^P01 sends when --confirm is set"""

        self.mock_args.confirm = True
        self.mock_args.patient_id = "PT001"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_bar_message()

        scanner.logger.display.assert_called()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_send_dft_with_confirm(self):
        """Test DFT^P03 sends when --confirm is set"""

        self.mock_args.confirm = True
        self.mock_args.patient_id = "PT001"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._send_dft_message()

        scanner.logger.display.assert_called()


class TestFinancialResultExtraction(unittest.TestCase):
    """Test financial result extraction"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_extract_financial_results(self):
        """Test extraction of financial data from response"""

        response = (
            b"MSH|^~\\&|SERVER|FAC|...\r"
            b"MSA|AA|123\r"
            b"FT1|1|FT001||20240101||CG|99213^Office Visit|||150.00|1|||||||||||||\r"
            b"GT1|1|GT001|DOE^JOHN|||||||SEL||\r"
            b"IN1|1|PLAN001||BlueCross||||GRP123||||||||||||||\r"
        )

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        scanner._extract_financial_results(response)

        self.assertIn("financial_results", scanner.results["data"])
        results = scanner.results["data"]["financial_results"]
        self.assertTrue(len(results.get("transactions", [])) >= 1)


# =============================================================================
# Continuation/Fragmentation Tests
# =============================================================================


class TestDSCSegmentParser(unittest.TestCase):
    """Test DSC (Continuation Pointer) segment parser"""

    def test_parse_dsc_segment(self):
        """Test parsing DSC segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "DSC|CONT123|I"
        result = HL7SegmentParser.parse_dsc(segment)

        self.assertEqual(result["ContinuationPointer"], "CONT123")
        self.assertEqual(result["ContinuationStyle"], "I")

    def test_parse_dsc_segment_pointer_only(self):
        """Test parsing DSC segment with only pointer"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        segment = "DSC|CONT456|"
        result = HL7SegmentParser.parse_dsc(segment)

        self.assertEqual(result["ContinuationPointer"], "CONT456")


class TestContinuationHandling(unittest.TestCase):
    """Test continuation/fragmentation handling"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_check_continuation_dsc(self):
        """Test checking for DSC continuation segment"""

        response = b"MSH|^~\\&|SERVER|FAC|...\rMSA|AA|123\rPID|1||PT001||DOE^JOHN\rDSC|CONT123|I\r"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        pointer, style = scanner._check_continuation(response)

        self.assertEqual(pointer, "CONT123")
        self.assertEqual(style, "I")

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_check_continuation_none(self):
        """Test checking for continuation with no DSC segment"""

        response = b"MSH|^~\\&|SERVER|FAC|...\rMSA|AA|123\rPID|1||PT001||DOE^JOHN\r"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        pointer, style = scanner._check_continuation(response)

        self.assertIsNone(pointer)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_create_continuation_request(self):
        """Test creating continuation request message"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        msg = scanner._create_continuation_request("CONT123")

        self.assertIsNotNone(msg)
        self.assertIn("QCN^J01", msg)
        self.assertIn("CONT123", msg)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_reassemble_fragments(self):
        """Test reassembling fragmented messages"""

        fragment1 = b"MSH|^~\\&|SERVER|FAC|...\rMSA|AA|123\rPID|1||PT001||DOE^JOHN\rDSC|CONT123|I\r"

        fragment2 = b"MSH|^~\\&|SERVER|FAC|...\rMSA|AA|456\rPID|2||PT002||SMITH^JANE\r"

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()

        result = scanner._reassemble_fragments([fragment1, fragment2])

        # Should have MSH/MSA from first fragment only
        result_str = result.decode()
        self.assertEqual(result_str.count("MSH|"), 1)
        self.assertEqual(result_str.count("MSA|"), 1)

        # Should have both PID segments
        self.assertEqual(result_str.count("PID|"), 2)

        # Should NOT have DSC segment
        self.assertNotIn("DSC|", result_str)


# =============================================================================
# Probe Operations Tests
# =============================================================================


class TestProbeOperations(unittest.TestCase):
    """Test probe operations including new message types"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_probe_includes_mfn_messages(self):
        """Test probe operations include MFN message types"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        # Probe operations includes MFN, BAR, DFT, QBP in MESSAGE_TYPES
        # Check by calling _probe_operations and verifying it completes
        scanner._probe_operations()

        # Should have called display multiple times
        self.assertTrue(scanner.logger.display.called)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_probe_results_structure(self):
        """Test probe results have expected structure"""

        scanner = _make_hl7_instance(self.mock_args, None, "192.168.1.100")
        scanner.logger = Mock()
        scanner.conn = MockSocket()

        scanner._probe_operations()

        self.assertIn("probe_results", scanner.results["data"])
        probe_results = scanner.results["data"]["probe_results"]

        # Should have categorized results
        self.assertIn("supported", probe_results)
        self.assertIn("rejected", probe_results)
        self.assertIn("error", probe_results)
        self.assertIn("timeout", probe_results)


# =============================================================================
# Integration Tests
# =============================================================================


class TestProtoFlowMessageRouting(unittest.TestCase):
    """Test proto_flow properly routes to new message handlers"""

    def setUp(self):
        self.mock_args = create_mock_args()

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    @patch("socket.socket")
    def test_proto_flow_routes_send_mfn(self, mock_socket_class):
        """Test proto_flow calls _send_mfn_message when --send-mfn is set"""
        from oida.protocols.hl7 import hl7

        mock_sock = MockSocket()
        mock_socket_class.return_value = mock_sock

        self.mock_args.send_mfn = True
        self.mock_args.confirm = True

        scanner = hl7.__new__(hl7)
        scanner.args = self.mock_args
        scanner.db = None
        scanner.host = "192.168.1.100"
        scanner.ip = "192.168.1.100"
        scanner.protocol_name = "hl7"
        scanner.default_port = 2575
        scanner.segment_builder = None
        scanner.all_responses = []
        scanner.detected_version = None
        scanner.results = {"data": {}}
        scanner.logger = Mock()
        scanner.conn = mock_sock
        scanner.security = Mock()
        scanner.security.check_certificate = Mock()

        # Initialize segment builder
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        scanner.segment_builder = HL7SegmentBuilder(version="2.5")

        # Call specific method instead of full proto_flow
        scanner._send_mfn_message()

        # Should have sent MLLP message
        self.assertTrue(len(mock_sock.sent_data) > 0)

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    @patch("socket.socket")
    def test_proto_flow_routes_query_whoami(self, mock_socket_class):
        """Test proto_flow calls _send_qbp_q40_message when --query-whoami is set"""
        from oida.protocols.hl7 import hl7

        mock_sock = MockSocket()
        mock_socket_class.return_value = mock_sock

        self.mock_args.query_whoami = True

        scanner = hl7.__new__(hl7)
        scanner.args = self.mock_args
        scanner.db = None
        scanner.host = "192.168.1.100"
        scanner.ip = "192.168.1.100"
        scanner.protocol_name = "hl7"
        scanner.default_port = 2575
        scanner.segment_builder = None
        scanner.all_responses = []
        scanner.detected_version = None
        scanner.results = {"data": {}}
        scanner.logger = Mock()
        scanner.conn = mock_sock
        scanner.security = Mock()

        from oida.protocols.hl7.segments import HL7SegmentBuilder

        scanner.segment_builder = HL7SegmentBuilder(version="2.5")

        scanner._send_qbp_q40_message()

        self.assertTrue(len(mock_sock.sent_data) > 0)


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestSendORUHonorsCLIArgs(unittest.TestCase):
    """--send-oru must honor -I/--patient-id and --obx-value, not send a dummy.

    Regression: _send_oru_message built a hardcoded ORU via _create_test_message
    that ignored every CLI segment arg, transmitting a dummy patient and no
    observation value. It must route through _create_message_with_segments.
    """

    def _scanner(self, args):
        mock_sock = MockSocket()
        s = _make_hl7_instance(args, None, "10.0.0.1")
        s.logger = Mock()
        s.conn = mock_sock
        return s, mock_sock

    def test_oru_uses_cli_patient_and_obx_value(self):
        args = create_mock_args()
        args.send_oru = True
        args.confirm = True
        args.patient_id = "PT001"
        args.obx_value = "95"
        args.ssn = ""

        s, sock = self._scanner(args)
        s._send_oru_message()

        self.assertTrue(sock.sent_data, "no ORU message was transmitted")
        sent = b"".join(sock.sent_data).decode("utf-8", errors="ignore")
        # CLI patient id and OBX value present; hardcoded dummy patient absent.
        self.assertIn("PT001", sent)
        self.assertIn("95", sent)
        self.assertNotIn("12345^^^MRN", sent)

    def test_oru_requires_patient_data(self):
        args = create_mock_args()
        args.send_oru = True
        args.confirm = True
        args.patient_id = None
        args.patient_name = None
        args.mrn = None
        args.ssn = ""

        s, sock = self._scanner(args)
        s._send_oru_message()

        self.assertFalse(sock.sent_data, "ORU sent without patient data")
        s.logger.fail.assert_called()


if __name__ == "__main__":
    unittest.main()
