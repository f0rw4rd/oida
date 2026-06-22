"""
Unit tests for ASTM/LIS Protocol Scanner

Tests:
- ASTM framing (checksum calculation, frame building)
- Record builders (H, P, O, R, Q, C, L records)
- Response parsing
- Vendor identification
- Constants and mappings
"""

import pytest
from unittest.mock import MagicMock, patch
from argparse import Namespace


class TestASTMRecordBuilder:
    """Test ASTM record builder functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        from oida.protocols.astm.records import ASTMRecordBuilder

        self.builder = ASTMRecordBuilder(version="E1394")

    def test_builder_initialization(self):
        """Test builder initializes with correct defaults"""
        assert self.builder.version == "E1394"
        assert self.builder.field_delimiter == "|"

    def test_build_header_basic(self):
        """Test basic header record generation"""
        header = self.builder.build_header(sender_name="OIDA")

        assert header.startswith("H|")
        assert "OIDA" in header
        assert "\\^&" in header  # Delimiter definition
        assert "E1394" in header  # Version

    def test_build_header_full(self):
        """Test header with all fields"""
        header = self.builder.build_header(
            sender_name="TEST_LIS",
            sender_id="ID123",
            receiver_name="ANALYZER",
            receiver_id="AID456",
            processing_id="P",
        )

        assert "TEST_LIS^ID123" in header
        assert "ANALYZER^AID456" in header

    def test_build_patient_basic(self):
        """Test basic patient record generation"""
        patient = self.builder.build_patient(
            patient_id="P001",
            patient_name="DOE^JOHN",
        )

        assert patient.startswith("P|")
        assert "P001" in patient
        assert "DOE^JOHN" in patient

    def test_build_patient_full(self):
        """Test patient with all fields"""
        patient = self.builder.build_patient(
            sequence=1,
            patient_id="P001",
            lab_patient_id="LAB001",
            patient_name="DOE^JOHN^M",
            dob="19800101",
            sex="M",
            address="123 Main St",
            phone="555-1234",
            physician_id="DR001",
        )

        assert "P001" in patient
        assert "LAB001" in patient
        assert "DOE^JOHN^M" in patient
        assert "19800101" in patient
        assert "M" in patient

    def test_build_order_basic(self):
        """Test basic order record generation"""
        order = self.builder.build_order(
            sample_id="S001",
            test_id="GLU",
        )

        assert order.startswith("O|")
        assert "S001" in order
        assert "GLU" in order

    def test_build_order_with_priority(self):
        """Test order with priority settings"""
        order = self.builder.build_order(
            sample_id="S002",
            test_id="CBC",
            priority="S",  # Stat
            action_code="N",  # New
        )

        assert "S002" in order
        assert "CBC" in order

    def test_build_result_basic(self):
        """Test basic result record generation"""
        result = self.builder.build_result(
            test_id="GLU",
            value="100",
            units="mg/dL",
        )

        assert result.startswith("R|")
        assert "GLU" in result
        assert "100" in result
        assert "mg/dL" in result

    def test_build_result_with_flags(self):
        """Test result with abnormal flags"""
        result = self.builder.build_result(
            test_id="GLU",
            value="250",
            units="mg/dL",
            reference_range="70-100",
            abnormal_flag="H",  # High
            result_status="F",  # Final
        )

        assert "250" in result
        assert "70-100" in result

    def test_build_query_basic(self):
        """Test basic query record generation"""
        query = self.builder.build_query(starting_range="*")

        assert query.startswith("Q|")

    def test_build_query_patient(self):
        """Test patient-specific query"""
        query = self.builder.build_query(
            starting_range="P001",
            nature_of_request="S",  # Demographics
        )

        assert "P001" in query

    def test_build_comment_basic(self):
        """Test basic comment record generation"""
        comment = self.builder.build_comment(comment_text="Test comment")

        assert comment.startswith("C|")
        assert "Test comment" in comment

    def test_build_terminator_basic(self):
        """Test terminator record generation"""
        terminator = self.builder.build_terminator()

        assert terminator.startswith("L|")
        assert "N" in terminator  # Normal termination

    def test_build_terminator_with_code(self):
        """Test terminator with different codes"""
        term_error = self.builder.build_terminator(terminator_code="E")
        assert "E" in term_error

    def test_escape_special_characters(self):
        """Test escaping of special characters"""
        # Test the escape method
        text = "test|value^with&special\\chars"
        escaped = self.builder._escape_field(text)

        assert "&F&" in escaped  # | escaped
        assert "&S&" in escaped  # ^ escaped
        assert "&E&" in escaped  # & escaped


class TestASTMConstants:
    """Test ASTM protocol constants"""

    def test_framing_constants(self):
        """Test framing constants are correct bytes"""
        from oida.protocols.astm.records import STX, ETX, EOT, ENQ, ACK, NAK, ETB, CR, LF

        assert STX == b"\x02"
        assert ETX == b"\x03"
        assert EOT == b"\x04"
        assert ENQ == b"\x05"
        assert ACK == b"\x06"
        assert NAK == b"\x15"
        assert ETB == b"\x17"
        assert CR == b"\x0d"
        assert LF == b"\x0a"


class TestASTMVendorMapping:
    """Test ASTM vendor identification"""

    def test_vendor_map_structure(self):
        """Test vendor map has correct structure"""
        from oida.protocols.astm.records import ASTM_VENDOR_MAP

        assert len(ASTM_VENDOR_MAP) > 50  # Should have many entries

        # Check structure of entries
        for name, (vendor, product) in ASTM_VENDOR_MAP.items():
            assert isinstance(name, str)
            assert isinstance(vendor, str)
            assert isinstance(product, str)

    def test_common_analyzers_present(self):
        """Test common analyzer names are in map"""
        from oida.protocols.astm.records import ASTM_VENDOR_MAP

        common_analyzers = ["COBAS", "SYSMEX", "ARCHITECT", "VITROS", "ADVIA"]

        for analyzer in common_analyzers:
            assert analyzer in ASTM_VENDOR_MAP, f"{analyzer} should be in vendor map"

    def test_vendor_categories(self):
        """Test various vendor categories are represented"""
        from oida.protocols.astm.records import ASTM_VENDOR_MAP

        vendors = set(vendor for vendor, _ in ASTM_VENDOR_MAP.values())

        # Major vendors should be present
        expected_vendors = ["Roche", "Sysmex", "Abbott", "Siemens", "Beckman Coulter"]
        for expected in expected_vendors:
            assert expected in vendors, f"{expected} should be in vendors"


class TestLabTestTypes:
    """Test lab test type definitions"""

    def test_test_types_structure(self):
        """Test lab test types have correct structure"""
        from oida.protocols.astm.records import LAB_TEST_TYPES

        assert len(LAB_TEST_TYPES) > 30  # Should have many entries

        # Check structure
        for code, (name, units, ref_range) in LAB_TEST_TYPES.items():
            assert isinstance(code, str)
            assert isinstance(name, str)
            assert isinstance(units, str)
            assert isinstance(ref_range, str)

    def test_common_tests_present(self):
        """Test common lab tests are defined"""
        from oida.protocols.astm.records import LAB_TEST_TYPES

        common_tests = ["GLU", "WBC", "HGB", "PLT", "BUN", "CREAT", "NA", "K"]

        for test in common_tests:
            assert test in LAB_TEST_TYPES, f"{test} should be in test types"

    def test_test_categories(self):
        """Test various test categories are represented"""
        from oida.protocols.astm.records import LAB_TEST_TYPES

        # Check for chemistry, hematology, coagulation tests
        assert "GLU" in LAB_TEST_TYPES  # Chemistry
        assert "WBC" in LAB_TEST_TYPES  # Hematology
        assert "PT" in LAB_TEST_TYPES  # Coagulation
        assert "TSH" in LAB_TEST_TYPES  # Thyroid


class TestASTMChecksum:
    """Test ASTM checksum calculation (framing mixin)"""

    def setup_method(self):
        """FramingMixin._calculate_checksum delegates to the attached
        ASTMRecordBuilder; attach one and exercise the delegation path."""
        from oida.protocols.astm.mixins import FramingMixin
        from oida.protocols.astm.records import ASTMRecordBuilder

        self.framing = FramingMixin()
        self.framing.record_builder = ASTMRecordBuilder(version="E1394")

    def test_checksum_calculation(self):
        """Test checksum calculation is correct"""
        # Test known checksum
        data = b"1H|\\^&"
        checksum = self.framing._calculate_checksum(data)

        # Checksum should be 2 uppercase hex characters
        assert len(checksum) == 2
        assert checksum.decode().isalnum()

    def test_checksum_modulus(self):
        """Test checksum uses modulus 256"""
        # Sum > 255 should wrap around
        data = bytes([255, 255, 255])  # Sum = 765, 765 % 256 = 253 = 0xFD
        checksum = self.framing._calculate_checksum(data)
        assert checksum == b"FD"


class TestASTMScannerClass:
    """Test ASTM scanner class structure"""

    def test_scanner_class_exists(self):
        """Test scanner class can be imported"""
        from oida.protocols.astm import astm

        assert astm is not None

    def test_scanner_attributes(self):
        """Test scanner has required attributes"""
        from oida.protocols.astm import astm

        # Create mock args
        Namespace(
            port=1394,
            timeout=10,
            tls=False,
            sender_name="TEST",
            sender_id="",
            receiver_name="",
            receiver_id="",
            astm_version="E1394",
            probe_ops=False,
            send_query=False,
            send_patient=False,
            send_order=False,
            send_result=False,
            fuzz=False,
            enum_tests=False,
            enum_instruments=False,
            enum_patients=False,
            confirm=False,
            output=None,
            format="json",
        )

        # Check class-level attributes
        assert hasattr(astm, "__init__")
        assert hasattr(astm, "proto_flow")
        assert hasattr(astm, "create_conn_obj")
        assert hasattr(astm, "enum_host_info")
        assert hasattr(astm, "print_host_info")


class TestASTMFraming:
    """Test ASTM framing methods"""

    @patch("socket.socket")
    def test_send_enq(self, mock_socket_class):
        """Test ENQ sending"""
        from oida.protocols.astm.records import ENQ, ACK

        # Setup mock socket
        mock_socket = MagicMock()
        mock_socket.recv.return_value = ACK
        mock_socket_class.return_value = mock_socket

        # We can't easily test the full scanner without a real connection,
        # but we can verify the constants are correct
        assert ENQ == b"\x05"
        assert ACK == b"\x06"

    def test_frame_structure(self):
        """Test ASTM frame structure constants"""
        from oida.protocols.astm.records import STX, ETX, CR, LF

        # Frame format: STX + frame_num + data + ETX + checksum + CR + LF
        assert STX == b"\x02"
        assert ETX == b"\x03"
        assert CR == b"\x0d"
        assert LF == b"\x0a"


class TestProtoArgs:
    """Test proto_args.py CLI argument definitions"""

    def test_proto_args_function_exists(self):
        """Test proto_args function exists"""
        from oida.protocols.astm.proto_args import proto_args

        assert callable(proto_args)

    def test_proto_args_creates_parser(self):
        """Test proto_args creates a valid parser"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        # Create parent parser
        parent = argparse.ArgumentParser(add_help=False)

        # Create main parser with subparsers
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        # Call proto_args
        astm_parser = proto_args(subparsers, [parent])

        assert astm_parser is not None

    def test_proto_args_default_port(self):
        """Default port is 12000 (most common ASTM/LIS instrument port)."""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        # Parse with just target
        args = main_parser.parse_args(["astm", "192.168.1.100"])
        assert args.port == 12000


class TestDataModification:
    """Test data modification features (action codes, result status)"""

    def setup_method(self):
        """Setup test fixtures"""
        from oida.protocols.astm.records import ASTMRecordBuilder

        self.builder = ASTMRecordBuilder(version="E1394")

    def test_order_with_action_code_new(self):
        """Test order with action code N (New)"""
        order = self.builder.build_order(
            sample_id="S001",
            test_id="CBC",
            action_code="N",
        )
        assert order.startswith("O|")
        assert "S001" in order
        assert "N" in order

    def test_order_with_action_code_cancel(self):
        """Test order with action code C (Cancel)"""
        order = self.builder.build_order(
            sample_id="S001",
            test_id="CBC",
            action_code="C",
        )
        assert order.startswith("O|")
        # Action code should be in the order
        fields = order.split("|")
        assert len(fields) > 11

    def test_order_with_priority_stat(self):
        """Test order with priority S (Stat)"""
        order = self.builder.build_order(
            sample_id="S001",
            test_id="CBC",
            priority="S",
        )
        assert order.startswith("O|")
        assert "S" in order

    def test_result_with_status_final(self):
        """Test result with status F (Final)"""
        result = self.builder.build_result(
            test_id="GLU",
            value="100",
            units="mg/dL",
            result_status="F",
        )
        assert result.startswith("R|")
        assert "100" in result
        assert "F" in result

    def test_result_with_status_corrected(self):
        """Test result with status C (Corrected)"""
        result = self.builder.build_result(
            test_id="GLU",
            value="95",
            units="mg/dL",
            result_status="C",
        )
        assert result.startswith("R|")
        assert "95" in result
        # Status should be in the result
        fields = result.split("|")
        assert len(fields) > 8

    def test_result_with_status_canceled(self):
        """Test result with status X (Canceled)"""
        result = self.builder.build_result(
            test_id="GLU",
            value="",
            units="",
            result_status="X",
        )
        assert result.startswith("R|")

    def test_result_with_abnormal_flag_high(self):
        """Test result with abnormal flag H (High)"""
        result = self.builder.build_result(
            test_id="GLU",
            value="250",
            units="mg/dL",
            abnormal_flag="H",
            result_status="F",
        )
        assert result.startswith("R|")
        assert "250" in result
        assert "H" in result

    def test_result_with_abnormal_flag_critical_low(self):
        """Test result with abnormal flag LL (Critical Low)"""
        result = self.builder.build_result(
            test_id="GLU",
            value="30",
            units="mg/dL",
            abnormal_flag="LL",
            reference_range="70-100",
            result_status="F",
        )
        assert result.startswith("R|")
        assert "30" in result
        assert "LL" in result
        assert "70-100" in result

    def test_result_with_reference_range(self):
        """Test result with reference range"""
        result = self.builder.build_result(
            test_id="HGB",
            value="14.5",
            units="g/dL",
            reference_range="12.0-17.5",
            result_status="F",
        )
        assert result.startswith("R|")
        assert "14.5" in result
        assert "12.0-17.5" in result


class TestProtoArgsDataModification:
    """Test CLI arguments for data modification"""

    def test_action_code_argument(self):
        """Test --action-code argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--action-code", "C"])
        assert args.action_code == "C"

    def test_result_status_argument(self):
        """Test --result-status argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--result-status", "C"])
        assert args.result_status == "C"

    def test_cancel_order_argument(self):
        """Test --cancel-order argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--cancel-order"])
        assert args.cancel_order is True

    def test_correct_result_argument(self):
        """Test --correct-result argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--correct-result"])
        assert args.correct_result is True

    def test_delete_result_argument(self):
        """Test --delete-result argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--delete-result"])
        assert args.delete_result is True

    def test_priority_argument(self):
        """Test --priority argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--priority", "S"])
        assert args.priority == "S"

    def test_abnormal_flag_argument(self):
        """Test --abnormal-flag argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--abnormal-flag", "H"])
        assert args.abnormal_flag == "H"

    def test_result_units_argument(self):
        """Test --result-units argument"""
        import argparse
        from oida.protocols.astm.proto_args import proto_args

        parent = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["astm", "192.168.1.100", "--result-units", "mmol/L"])
        assert args.result_units == "mmol/L"


class TestModuleExports:
    """Test module exports"""

    def test_records_exports(self):
        """Test records.py exports all required items"""
        from oida.protocols.astm.records import (
            ASTMRecordBuilder,
            ASTM_VENDOR_MAP,
            LAB_TEST_TYPES,
        )

        assert ASTMRecordBuilder is not None
        assert isinstance(ASTM_VENDOR_MAP, dict)
        assert isinstance(LAB_TEST_TYPES, dict)

    def test_main_module_exports(self):
        """Test main module exports astm class"""
        from oida.protocols.astm import astm

        assert astm is not None


class TestFuzzTLSPeek:
    """Regression: TLS fuzz peek must not be miscounted as an error.

    ssl.SSLSocket.recv() raises ValueError for any non-zero flags
    (including socket.MSG_PEEK). _fuzz_records must treat that as the
    expected no-response path, not a fuzz error.
    """

    def _make_scanner(self, conn):
        from oida.protocols.astm.mixins.security import SecurityMixin

        scanner = SecurityMixin.__new__(SecurityMixin)
        scanner.conn = conn
        scanner.logger = MagicMock()
        scanner.args = Namespace(
            fuzz_iterations=1,
            fuzz_record=None,
            fuzz_frame=True,
        )
        scanner.results = {"data": {}}
        scanner.create_conn_obj = MagicMock(return_value=True)
        # Stub the string-payload (record-level) send path so this test
        # isolates the raw-byte peek branch under test.
        scanner._send_enq = MagicMock(return_value=False)
        scanner._send_frame = MagicMock()
        scanner._send_eot = MagicMock()
        scanner.record_builder = MagicMock()
        return scanner

    def test_sslsocket_peek_valueerror_not_counted_as_error(self):
        """A ValueError from recv(MSG_PEEK) on an SSLSocket is not a fuzz error."""
        import socket

        conn = MagicMock()
        conn.recv.side_effect = ValueError(
            "non-zero flags not allowed in calls to recv() on SSLSocket"
        )

        scanner = self._make_scanner(conn)
        scanner._fuzz_records()

        # The frame-level (raw byte) cases were sent; the peek raised
        # ValueError but must be swallowed, so errors stays at 0.
        conn.recv.assert_called_with(1, socket.MSG_PEEK)
        assert scanner.results["data"]["fuzz_results"]["errors"] == 0

    def test_other_exception_still_counted_as_error(self):
        """A non-Timeout/ValueError from recv still increments error_count."""
        conn = MagicMock()
        conn.recv.side_effect = RuntimeError("boom")

        scanner = self._make_scanner(conn)
        scanner._fuzz_records()

        assert scanner.results["data"]["fuzz_results"]["errors"] > 0


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
