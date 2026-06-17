"""
Unit tests for BACnet PropertiesMixin.
"""

import unittest
from unittest.mock import Mock

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    """Create bacnet instance bypassing __init__."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {
        1001: {"device_id": 1001, "address": "192.168.1.100"},
    }
    instance.objects = {
        1001: {
            "analogInput": [1, 2, 3],
            "analogOutput": [1],
            "binaryOutput": [1],
        },
    }
    instance.bacnet = Mock()
    return instance


class TestHandleEnumerateProperties(unittest.TestCase):
    """Test _handle_enumerate_properties."""

    def test_enumerate_properties_no_objects(self):
        scanner = _create_instance()
        scanner.objects = {}
        scanner._handle_enumerate_properties()
        scanner.logger.warning.assert_called()

    def test_enumerate_properties_reads_common_props(self):
        scanner = _create_instance()
        scanner.bacnet.read = Mock(return_value="test_value")
        scanner._handle_enumerate_properties()
        scanner.logger.display.assert_called()


class TestHandlePresentValues(unittest.TestCase):
    """Test _handle_present_values."""

    def test_present_values_with_objects(self):
        scanner = _create_instance()
        scanner.bacnet.read = Mock(side_effect=lambda *a: "value_42")
        scanner._handle_present_values()
        scanner.logger.display.assert_called()


class TestHandleRead(unittest.TestCase):
    """Test _handle_read."""

    def test_read_valid_spec(self):
        scanner = _create_instance(read="analogInput:1:presentValue")
        scanner.bacnet.read = Mock(return_value=42.5)
        scanner._handle_read()
        scanner.logger.success.assert_called()

    def test_read_invalid_spec_format(self):
        scanner = _create_instance(read="invalid")
        scanner._handle_read()
        scanner.logger.fail.assert_called()

    def test_read_no_value(self):
        scanner = _create_instance(read="analogInput:1:presentValue")
        scanner.bacnet.read = Mock(return_value=None)
        scanner._handle_read()
        scanner.logger.warning.assert_called()


class TestHandleWrite(unittest.TestCase):
    """Test _handle_write."""

    def test_write_requires_confirm(self):
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=False)
        scanner._handle_write()
        scanner.logger.fail.assert_called()

    def test_write_valid_spec(self):
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=True)
        scanner.bacnet.write = Mock(return_value=True)
        scanner._handle_write()
        scanner.logger.success.assert_called()

    def test_write_invalid_spec_format(self):
        scanner = _create_instance(write="invalid", confirm=True)
        scanner._handle_write()
        scanner.logger.fail.assert_called()

    def test_write_failure(self):
        scanner = _create_instance(write="analogValue:1:presentValue:42", confirm=True)
        scanner.bacnet.write = Mock(side_effect=Exception("write rejected"))
        scanner._handle_write()
        scanner.logger.fail.assert_called()


class TestReadProperty(unittest.TestCase):
    """Test _read_property."""

    def test_read_property_success(self):
        scanner = _create_instance()
        scanner.bacnet.read = Mock(return_value=42.5)
        result = scanner._read_property("192.168.1.100", "analogInput", 1, "presentValue")
        self.assertEqual(result, 42.5)

    def test_read_property_failure(self):
        scanner = _create_instance()
        scanner.bacnet.read = Mock(side_effect=Exception("read error"))
        result = scanner._read_property("192.168.1.100", "analogInput", 1, "presentValue")
        self.assertIsNone(result)


class TestWriteProperty(unittest.TestCase):
    """Test _write_property."""

    def test_write_property_success(self):
        scanner = _create_instance()
        scanner.bacnet.write = Mock()
        result = scanner._write_property("192.168.1.100", "analogValue", 1, "presentValue", 42.0)
        self.assertTrue(result)

    def test_write_property_with_priority(self):
        scanner = _create_instance()
        scanner.bacnet.write = Mock()
        result = scanner._write_property(
            "192.168.1.100", "analogValue", 1, "presentValue", 42.0, priority=8
        )
        self.assertTrue(result)
        # Verify priority was included in write call
        call_args = scanner.bacnet.write.call_args[0][0]
        self.assertIn("8", call_args)

    def test_write_property_failure(self):
        scanner = _create_instance()
        scanner.bacnet.write = Mock(side_effect=Exception("write error"))
        result = scanner._write_property("192.168.1.100", "analogValue", 1, "presentValue", 42.0)
        self.assertFalse(result)


class TestReadAllProperties(unittest.TestCase):
    """Test _read_all_properties."""

    def test_read_all_properties(self):
        scanner = _create_instance()
        scanner.bacnet.read = Mock(return_value="test_value")
        result = scanner._read_all_properties("192.168.1.100", "analogInput", 1)
        self.assertIsInstance(result, dict)
        self.assertIn("objectName", result)

    def test_read_all_properties_partial_failures(self):
        call_count = [0]

        def mock_read(*args):
            call_count[0] += 1
            if call_count[0] % 3 == 0:
                raise Exception("read error")
            return f"value_{call_count[0]}"

        scanner = _create_instance()
        scanner.bacnet.read = Mock(side_effect=mock_read)
        result = scanner._read_all_properties("192.168.1.100", "analogInput", 1)
        self.assertIsInstance(result, dict)
        self.assertTrue(len(result) > 0)


if __name__ == "__main__":
    unittest.main()
