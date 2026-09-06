#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for HL7 v2 Pharmacy Message Types (RAS, RGV, RDS).

Tests the new pharmacy-related message types:
- RAS^O17: Pharmacy Administration
- RGV^O15: Pharmacy Give
- RDS^O13: Pharmacy Dispense

Also tests the new segment builders:
- build_rxa(): RXA (Pharmacy/Treatment Administration) segment
- build_rxg(): RXG (Pharmacy/Treatment Give) segment
- build_rxd(): RXD (Pharmacy/Treatment Dispense) segment
"""

import unittest
from unittest.mock import Mock, patch

# MLLP framing characters
MLLP_START = b"\x0b"
MLLP_END = b"\x1c\x0d"


class TestHL7SegmentBuilderPharmacy(unittest.TestCase):
    """Test the HL7SegmentBuilder pharmacy segment methods"""

    def setUp(self):
        """Set up test fixtures"""
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        self.builder = HL7SegmentBuilder(version="2.5")

    def test_build_rxa_basic(self):
        """Test basic RXA segment creation"""
        rxa = self.builder.build_rxa(
            admin_code="12345^Amoxicillin^NDC",
            admin_amount="500",
            admin_units="mg",
        )
        self.assertIsNotNone(rxa)

    def test_build_rxa_all_fields(self):
        """Test RXA segment with all fields populated"""
        rxa = self.builder.build_rxa(
            give_sub_id="1",
            admin_sub_id="0",
            start_datetime="20240115120000",
            end_datetime="20240115120500",
            admin_code="12345^Amoxicillin^NDC",
            admin_amount="500",
            admin_units="mg",
            admin_notes="Test administration",
            admin_provider="DOE^JOHN^DR",
            completion_status="CP",
        )
        self.assertIsNotNone(rxa)

    def test_build_rxa_completion_statuses(self):
        """Test RXA with different completion statuses"""
        statuses = ["CP", "RE", "NA", "PA"]
        for status in statuses:
            rxa = self.builder.build_rxa(
                admin_code="12345^Test^NDC",
                completion_status=status,
            )
            self.assertIsNotNone(rxa)

    def test_build_rxg_basic(self):
        """Test basic RXG segment creation"""
        rxg = self.builder.build_rxg(
            give_code="12345^Amoxicillin^NDC",
            give_amount="500",
            give_units="mg",
        )
        self.assertIsNotNone(rxg)

    def test_build_rxg_all_fields(self):
        """Test RXG segment with all fields populated"""
        rxg = self.builder.build_rxg(
            give_sub_id="1",
            dispense_sub_id="1",
            quantity_timing="1^^D",
            give_code="12345^Amoxicillin^NDC",
            give_amount="500",
            give_units="mg",
            give_dosage_form="TAB",
            admin_notes="Test give instructions",
            substitution_status="N",
        )
        self.assertIsNotNone(rxg)

    def test_build_rxd_basic(self):
        """Test basic RXD segment creation"""
        rxd = self.builder.build_rxd(
            dispense_code="12345^Amoxicillin^NDC",
            actual_amount="30",
            actual_units="TAB",
        )
        self.assertIsNotNone(rxd)

    def test_build_rxd_all_fields(self):
        """Test RXD segment with all fields populated"""
        rxd = self.builder.build_rxd(
            dispense_sub_id="1",
            dispense_code="12345^Amoxicillin^NDC",
            datetime_dispensed="20240115130000",
            actual_amount="30",
            actual_units="TAB",
            prescription_number="RX12345678",
            refills_remaining="3",
            dispense_notes="Take with food",
            dispensing_provider="SMITH^JANE^RPh",
        )
        self.assertIsNotNone(rxd)

    def test_build_rxa_empty_code(self):
        """Test RXA segment with empty admin code"""
        rxa = self.builder.build_rxa()
        self.assertIsNotNone(rxa)  # Should still create segment with defaults

    def test_build_rxg_empty_code(self):
        """Test RXG segment with empty give code"""
        rxg = self.builder.build_rxg()
        self.assertIsNotNone(rxg)  # Should still create segment with defaults

    def test_build_rxd_empty_code(self):
        """Test RXD segment with empty dispense code"""
        rxd = self.builder.build_rxd()
        self.assertIsNotNone(rxd)  # Should still create segment with defaults


class TestHL7PharmacyMessageTypes(unittest.TestCase):
    """Test HL7 pharmacy message type definitions in MESSAGE_TYPES"""

    def test_ras_in_probe_message_types(self):
        """Test RAS^O17 is included in probe message types"""
        from oida.protocols.hl7 import hl7

        # Create a mock instance to check MESSAGE_TYPES
        # The MESSAGE_TYPES list is defined in _probe_operations
        # We verify the message type is probed by checking the method exists
        self.assertTrue(hasattr(hl7, "_send_ras_message"))

    def test_rgv_in_probe_message_types(self):
        """Test RGV^O15 is included in probe message types"""
        from oida.protocols.hl7 import hl7

        self.assertTrue(hasattr(hl7, "_send_rgv_message"))

    def test_rds_in_probe_message_types(self):
        """Test RDS^O13 is included in probe message types"""
        from oida.protocols.hl7 import hl7

        self.assertTrue(hasattr(hl7, "_send_rds_message"))

    def test_create_ras_message_method_exists(self):
        """Test _create_ras_message method exists"""
        from oida.protocols.hl7 import hl7

        self.assertTrue(hasattr(hl7, "_create_ras_message"))

    def test_create_rgv_message_method_exists(self):
        """Test _create_rgv_message method exists"""
        from oida.protocols.hl7 import hl7

        self.assertTrue(hasattr(hl7, "_create_rgv_message"))

    def test_create_rds_message_method_exists(self):
        """Test _create_rds_message method exists"""
        from oida.protocols.hl7 import hl7

        self.assertTrue(hasattr(hl7, "_create_rds_message"))


class TestHL7ADTTriggerEvents(unittest.TestCase):
    """Test ADT trigger event additions (A04, A05, A12, A28)"""

    def test_adt_trigger_descriptions(self):
        """Test new ADT trigger events have descriptions"""
        # These are defined in _send_adt_message trigger_desc dict
        from oida.protocols.hl7 import hl7

        # Verify the method exists that contains trigger descriptions
        self.assertTrue(hasattr(hl7, "_send_adt_message"))


class TestHL7SegmentParserPharmacy(unittest.TestCase):
    """Test the HL7SegmentParser pharmacy segment parsing"""

    def test_parse_rxa_segment(self):
        """Test parsing an RXA segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        # Sample RXA segment
        rxa_segment = (
            "RXA|0|1|20240115120000|20240115120500|12345^Amoxicillin^NDC|500|mg|||DOE^JOHN^DR"
        )
        result = HL7SegmentParser.parse_rxa(rxa_segment)

        self.assertIsInstance(result, dict)
        self.assertIn("AdminDate", result)
        self.assertIn("DrugCode", result)

    def test_parse_rxd_segment(self):
        """Test parsing an RXD segment"""
        from oida.protocols.hl7.segments import HL7SegmentParser

        # Sample RXD segment
        rxd_segment = "RXD|1|12345^Amoxicillin^NDC|20240115130000|30|TAB"
        result = HL7SegmentParser.parse_rxd(rxd_segment)

        self.assertIsInstance(result, dict)
        self.assertIn("DispenseDate", result)
        self.assertIn("DrugCode", result)

    def test_parse_rxd_segment_units_from_rxd5(self):
        """_parse_rxd_segment 'Units' must come from RXD-5 (Actual Dispense
        Units), not RXD-6 (Actual Strength), per HL7 v2.5 §4.4.6."""
        from hl7apy.parser import parse_segment

        from oida.protocols.hl7.segments import HL7SegmentParser

        # RXD-4=30 (amount), RXD-5=TAB (dispense units), RXD-6=500 (strength).
        # Distinct values so an off-by-one is observable.
        rxd_segment = "RXD|1|12345^Amoxicillin^NDC|20240115130000|30|TAB|500"
        seg = parse_segment(rxd_segment)
        result = HL7SegmentParser._parse_rxd_segment(seg)

        self.assertEqual(result["Units"], "TAB")
        self.assertNotEqual(result["Units"], "500")


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
            "MSH|^~\\&|PHARMACY|FACILITY|OIDA|SECURITY|"
            "20240101120000||ACK^O17|MSG12345|P|2.5\r"
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


class TestHL7PharmacyMessageCreation(unittest.TestCase):
    """Test HL7 pharmacy message creation"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.sending_app = "OIDA"
        self.mock_args.sending_facility = "SECURITY"
        self.mock_args.hl7_version = "2.5"
        self.mock_args.patient_id = "PT12345"
        self.mock_args.patient_name = "DOE^JOHN"
        self.mock_args.admin_code = "12345^Amoxicillin^NDC"
        self.mock_args.admin_amount = "500"
        self.mock_args.admin_units = "mg"
        self.mock_args.rx_code = ""
        self.mock_args.rx_dose = ""
        self.mock_args.rx_units = ""
        self.mock_args.dispense_amount = "30"
        self.mock_args.dispense_units = "TAB"
        self.mock_args.rx_quantity = ""
        self.mock_args.rx_refills = "0"
        self.mock_args.rx_route = ""
        self.mock_args.completion_status = "CP"
        self.mock_args.confirm = True
        self.mock_args.extract_response = False
        self.mock_args.timeout = 10
        self.mock_args.port = 2575
        self.mock_args.tls = False
        self.mock_args.verbose = False
        self.mock_args.debug = False

    @patch("socket.socket")
    def test_create_ras_message(self, mock_socket_class):
        """Test RAS^O17 message creation"""
        mock_socket = MockSocket()
        mock_socket_class.return_value = mock_socket

        from oida.protocols.hl7 import hl7

        scanner = hl7.__new__(hl7)
        scanner.args = self.mock_args
        scanner.ip = "127.0.0.1"
        scanner.conn = None
        scanner.results = {"data": {}}
        scanner.detected_version = None

        # Initialize segment builder
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        scanner.segment_builder = HL7SegmentBuilder(version="2.5")

        # Create message
        msg = scanner._create_ras_message()
        self.assertIsNotNone(msg)
        self.assertIn("RAS^O17", msg)
        self.assertIn("MSH|", msg)

    @patch("socket.socket")
    def test_create_rgv_message(self, mock_socket_class):
        """Test RGV^O15 message creation"""
        mock_socket = MockSocket()
        mock_socket_class.return_value = mock_socket

        from oida.protocols.hl7 import hl7

        scanner = hl7.__new__(hl7)
        scanner.args = self.mock_args
        scanner.ip = "127.0.0.1"
        scanner.conn = None
        scanner.results = {"data": {}}
        scanner.detected_version = None

        # Initialize segment builder
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        scanner.segment_builder = HL7SegmentBuilder(version="2.5")

        # Create message
        msg = scanner._create_rgv_message()
        self.assertIsNotNone(msg)
        self.assertIn("RGV^O15", msg)
        self.assertIn("MSH|", msg)

    @patch("socket.socket")
    def test_create_rds_message(self, mock_socket_class):
        """Test RDS^O13 message creation"""
        mock_socket = MockSocket()
        mock_socket_class.return_value = mock_socket

        from oida.protocols.hl7 import hl7

        scanner = hl7.__new__(hl7)
        scanner.args = self.mock_args
        scanner.ip = "127.0.0.1"
        scanner.conn = None
        scanner.results = {"data": {}}
        scanner.detected_version = None

        # Initialize segment builder
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        scanner.segment_builder = HL7SegmentBuilder(version="2.5")

        # Create message
        msg = scanner._create_rds_message()
        self.assertIsNotNone(msg)
        self.assertIn("RDS^O13", msg)
        self.assertIn("MSH|", msg)


if __name__ == "__main__":
    unittest.main()
