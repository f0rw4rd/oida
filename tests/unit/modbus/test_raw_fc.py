#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for Modbus custom function code (--raw-fc) feature.
"""

import unittest
from unittest.mock import Mock, patch
import os
import tempfile
import argparse


class TestPayloadParsing(unittest.TestCase):
    """Test payload parsing from various formats."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a minimal mock for the modbus class
        self.mock_args = argparse.Namespace(
            payload=None,
            payload_hex=None,
            payload_file=None,
        )

    def _create_mock_modbus(self, args):
        """Create a mock modbus instance with _parse_payload method."""
        from oida.protocols.modbus import modbus

        # Create minimal args
        mock_args = argparse.Namespace(
            target="127.0.0.1",
            port=502,
            timeout=5.0,
            debug=False,
            verbose=0,
            format=None,
            output=None,
            threads=1,
            **vars(args),
        )

        # Mock the parent class init
        with patch.object(modbus, "__init__", lambda self, *a, **kw: None):
            instance = modbus.__new__(modbus)
            instance.args = mock_args
            instance.logger = Mock()
            return instance

    def test_parse_payload_hex_spaces(self):
        """Test parsing '01 02 0a 0b' format."""
        args = argparse.Namespace(
            payload="01 02 0a 0b",
            payload_hex=None,
            payload_file=None,
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload("01 02 0a 0b")

        self.assertEqual(result, b"\x01\x02\x0a\x0b")

    def test_parse_payload_hex_spaces_uppercase(self):
        """Test parsing 'FF EE DD CC' format (uppercase)."""
        args = argparse.Namespace(
            payload="FF EE DD CC",
            payload_hex=None,
            payload_file=None,
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload("FF EE DD CC")

        self.assertEqual(result, b"\xff\xee\xdd\xcc")

    def test_parse_payload_hex_continuous(self):
        """Test parsing '01020a0b' format."""
        args = argparse.Namespace(
            payload="01020a0b",  # Continuous hex uses payload arg directly
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload("01020a0b")

        self.assertEqual(result, b"\x01\x02\x0a\x0b")

    def test_parse_payload_hex_continuous_with_spaces(self):
        """Test parsing hex string with spaces (space-separated format)."""
        args = argparse.Namespace(
            payload="01 02 0a 0b",  # Space-separated hex uses payload arg directly
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload("01 02 0a 0b")

        self.assertEqual(result, b"\x01\x02\x0a\x0b")

    def test_parse_payload_from_file(self):
        """Test reading payload from binary file using @file syntax."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x01\x02\x03\x04")
            temp_path = f.name

        try:
            args = argparse.Namespace(
                payload=f"@{temp_path}",  # File reference uses @path syntax
            )
            instance = self._create_mock_modbus(args)

            result = instance._parse_payload(f"@{temp_path}")

            self.assertEqual(result, b"\x01\x02\x03\x04")
        finally:
            os.unlink(temp_path)

    def test_parse_payload_file_not_found(self):
        """Test handling of missing payload file using @file syntax."""
        args = argparse.Namespace(
            payload="@/nonexistent/path/to/file.bin",  # File reference uses @path syntax
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload("@/nonexistent/path/to/file.bin")

        self.assertEqual(result, b"")
        instance.logger.warning.assert_called()

    def test_parse_payload_empty(self):
        """Test parsing when no payload specified."""
        args = argparse.Namespace(
            payload=None,
            payload_hex=None,
            payload_file=None,
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload(None)

        self.assertEqual(result, b"")

    def test_parse_payload_invalid_hex(self):
        """Test handling of invalid hex string."""
        args = argparse.Namespace(
            payload="ZZ XX",  # Invalid hex
            payload_hex=None,
            payload_file=None,
        )
        instance = self._create_mock_modbus(args)

        result = instance._parse_payload("ZZ XX")

        self.assertEqual(result, b"")
        instance.logger.warning.assert_called()


class TestResponseFormatting(unittest.TestCase):
    """Test response formatting helpers (_display_hexdump)."""

    def _create_mock_modbus(self):
        """Create a mock modbus instance."""
        from oida.protocols.modbus import modbus

        with patch.object(modbus, "__init__", lambda self, *a, **kw: None):
            instance = modbus.__new__(modbus)
            instance.logger = Mock()
            return instance

    def test_format_response_hex_empty(self):
        """Test hexdump with empty data produces no output."""
        instance = self._create_mock_modbus()
        instance._display_hexdump(b"")
        instance.logger.display.assert_not_called()

    def test_format_response_hex_single_byte(self):
        """Test hexdump with single byte."""
        instance = self._create_mock_modbus()
        instance._display_hexdump(b"\x0a")
        instance.logger.display.assert_called()
        output = instance.logger.display.call_args[0][0]
        self.assertIn("0A", output.upper())

    def test_format_response_hex_multiple_bytes(self):
        """Test hexdump with multiple bytes."""
        instance = self._create_mock_modbus()
        instance._display_hexdump(b"\x01\x02\x0a\xff")
        instance.logger.display.assert_called()
        output = instance.logger.display.call_args[0][0]
        self.assertIn("01", output.upper())
        self.assertIn("FF", output.upper())

    def test_format_response_hexdump_empty(self):
        """Test hexdump formatting with empty data."""
        instance = self._create_mock_modbus()
        instance._display_hexdump(b"")
        instance.logger.display.assert_not_called()

    def test_format_response_hexdump_short(self):
        """Test hexdump formatting with short data."""
        instance = self._create_mock_modbus()
        instance._display_hexdump(b"\x01\x02\x03")
        instance.logger.display.assert_called()
        output = instance.logger.display.call_args[0][0]
        self.assertIn("0000", output)

    def test_format_response_hexdump_multiline(self):
        """Test hexdump formatting with data spanning multiple lines."""
        instance = self._create_mock_modbus()
        data = bytes(range(32))  # 32 bytes = 2 lines
        instance._display_hexdump(data)
        # Should be called twice (2 lines of 16 bytes each)
        self.assertEqual(instance.logger.display.call_count, 2)


class TestSendCustomFC(unittest.TestCase):
    """Test the send_custom_fc method."""

    def _create_mock_scanner(self):
        """Create a mock ModbusScanner instance."""
        from oida.protocols.modbus.scanner import ModbusScanner

        with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
            instance = ModbusScanner.__new__(ModbusScanner)
            instance.logger = Mock()
            return instance

    def test_send_custom_fc_invalid_fc_low(self):
        """Test validation rejects FC < 1."""
        instance = self._create_mock_scanner()
        mock_client = Mock()

        result = instance.send_custom_fc(mock_client, fc=0, payload=b"", unit_id=1)

        self.assertFalse(result["success"])
        self.assertIn("must be 1-127", result["error"])

    def test_send_custom_fc_invalid_fc_high(self):
        """Test validation rejects FC > 127."""
        instance = self._create_mock_scanner()
        mock_client = Mock()

        result = instance.send_custom_fc(mock_client, fc=128, payload=b"", unit_id=1)

        self.assertFalse(result["success"])
        self.assertIn("must be 1-127", result["error"])

    def test_send_custom_fc_timeout(self):
        """Test handling of timeout (no response)."""
        instance = self._create_mock_scanner()
        mock_client = Mock()
        mock_client.execute.return_value = None

        result = instance.send_custom_fc(mock_client, fc=65, payload=b"\x01", unit_id=1)

        self.assertFalse(result["success"])
        self.assertIn("timeout", result["error"].lower())

    def test_send_custom_fc_exception_response(self):
        """Test handling of exception response."""
        instance = self._create_mock_scanner()
        mock_client = Mock()

        # Create mock exception response
        mock_response = Mock()
        mock_response.function_code = 0xC1  # 65 + 0x80 = exception
        mock_response.exception_code = 1  # ILLEGAL FUNCTION
        mock_response.encode = Mock(return_value=b"")
        mock_client.execute.return_value = mock_response

        result = instance.send_custom_fc(mock_client, fc=65, payload=b"\x01", unit_id=1)

        self.assertTrue(result["success"])
        self.assertTrue(result["is_exception"])
        self.assertEqual(result["exception_code"], 1)
        self.assertEqual(result["exception_name"], "ILLEGAL FUNCTION")


class TestSaveResponseToFile(unittest.TestCase):
    """Test saving response to file."""

    def _create_mock_modbus(self):
        """Create a mock modbus instance."""
        from oida.protocols.modbus import modbus

        with patch.object(modbus, "__init__", lambda self, *a, **kw: None):
            instance = modbus.__new__(modbus)
            instance.logger = Mock()
            return instance

    def test_save_response_to_file_success(self):
        """Test successful file save."""
        instance = self._create_mock_modbus()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            instance._save_response_to_file(temp_path, b"\x01\x02\x03\x04")

            with open(temp_path, "rb") as f:
                content = f.read()

            self.assertEqual(content, b"\x01\x02\x03\x04")
            instance.logger.success.assert_called()
        finally:
            os.unlink(temp_path)

    def test_save_response_to_file_error(self):
        """Test handling of file write error."""
        instance = self._create_mock_modbus()

        instance._save_response_to_file("/nonexistent/dir/file.bin", b"\x01\x02")

        instance.logger.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
