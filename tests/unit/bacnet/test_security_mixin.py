"""
Unit tests for BACnet SecurityMixin.
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
            "analogValue": [1, 2],
            "binaryValue": [1],
            "analogOutput": [1],
            "binaryOutput": [1],
            "analogInput": [1, 2, 3],
        },
    }
    instance.bacnet = Mock()
    return instance


class TestSecurityAssessment(unittest.TestCase):
    """Test _handle_security_assessment."""

    def test_assessment_reports_anonymous_access(self):
        # --assess now requires --confirm.
        scanner = _create_instance(confirm=True)
        scanner.bacnet.read = Mock(return_value=42)
        scanner.bacnet.write = Mock(return_value=True)
        scanner._handle_security_assessment()
        scanner.logger.display.assert_called()
        scanner.logger.security_finding.assert_called()

    def test_assessment_with_no_devices(self):
        scanner = _create_instance(confirm=True)
        scanner.devices = {}
        scanner._handle_security_assessment()
        scanner.logger.display.assert_called()

    def test_assessment_refuses_without_confirm(self):
        """Verify the --confirm gate on the security assessment."""
        scanner = _create_instance(confirm=False)
        scanner._handle_security_assessment()
        scanner.logger.fail.assert_called()


class TestTestWrite(unittest.TestCase):
    """Test _handle_test_write."""

    def test_write_test_no_objects(self):
        scanner = _create_instance()
        scanner.objects = {}
        scanner._handle_test_write()
        # Should return early without error

    def test_write_test_finds_writable(self):
        # --test-write now requires --confirm.
        scanner = _create_instance(confirm=True)
        scanner.bacnet.read = Mock(return_value=42.0)
        scanner.bacnet.write = Mock(return_value=True)
        scanner._handle_test_write()
        scanner.logger.security_finding.assert_called()

    def test_write_test_no_writable(self):
        scanner = _create_instance(confirm=True)
        scanner.bacnet.read = Mock(return_value=None)
        scanner._handle_test_write()
        scanner.logger.display.assert_called()

    def test_write_test_refuses_without_confirm(self):
        scanner = _create_instance(confirm=False)
        scanner.bacnet.read = Mock(return_value=42.0)
        scanner._handle_test_write()
        scanner.logger.fail.assert_called()


class TestEnumerateWritable(unittest.TestCase):
    """Test _handle_enumerate_writable."""

    def test_enumerate_writable_no_objects(self):
        scanner = _create_instance()
        scanner.objects = {}
        scanner._handle_enumerate_writable()

    def test_enumerate_writable_finds_some(self):
        # --enumerate-writable now requires --confirm.
        scanner = _create_instance(confirm=True)
        scanner.bacnet.read = Mock(return_value=42.0)
        scanner.bacnet.write = Mock(return_value=True)
        scanner._handle_enumerate_writable()
        scanner.logger.security_finding.assert_called()

    def test_enumerate_writable_refuses_without_confirm(self):
        scanner = _create_instance(confirm=False)
        scanner._handle_enumerate_writable()
        scanner.logger.fail.assert_called()


class TestCheckOOS(unittest.TestCase):
    """Test _handle_check_oos."""

    def test_check_oos_no_objects(self):
        scanner = _create_instance()
        scanner.objects = {}
        scanner._handle_check_oos()

    def test_check_oos_readable(self):
        scanner = _create_instance()
        scanner.bacnet.read = Mock(return_value=False)
        scanner._handle_check_oos()
        scanner.logger.warning.assert_called()


class TestCheckReinit(unittest.TestCase):
    """Test _handle_check_reinit."""

    def test_check_reinit_displays_message(self):
        scanner = _create_instance()
        scanner._handle_check_reinit()
        scanner.logger.display.assert_called()


class TestGetPasswordList(unittest.TestCase):
    """Test _get_password_list."""

    def test_default_passwords(self):
        scanner = _create_instance()
        passwords = scanner._get_password_list()
        self.assertIsInstance(passwords, list)
        self.assertIn("", passwords)  # Empty password
        self.assertIn("admin", passwords)
        self.assertIn("bacnet", passwords)
        self.assertTrue(len(passwords) > 20)

    def test_single_password(self):
        scanner = _create_instance(password="secret123")
        passwords = scanner._get_password_list()
        self.assertEqual(passwords, ["secret123"])

    def test_password_file_missing(self):
        scanner = _create_instance(password_list="/nonexistent/file.txt")
        passwords = scanner._get_password_list()
        # Falls back to default list
        self.assertTrue(len(passwords) > 20)


if __name__ == "__main__":
    unittest.main()
