#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP protocol constants.

Tests cover:
- ENIP encapsulation command codes
- CIP Security class definitions
- CIP General Status codes
"""

import unittest

import pytest

pytestmark = pytest.mark.core


class TestEnipCommands(unittest.TestCase):
    """Test EtherNet/IP encapsulation command constants."""

    def test_list_services_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_LIST_SERVICES

        self.assertEqual(ENIP_CMD_LIST_SERVICES, 0x0004)

    def test_list_identity_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_LIST_IDENTITY

        self.assertEqual(ENIP_CMD_LIST_IDENTITY, 0x0063)

    def test_list_interfaces_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_LIST_INTERFACES

        self.assertEqual(ENIP_CMD_LIST_INTERFACES, 0x0064)

    def test_register_session_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_REGISTER_SESSION

        self.assertEqual(ENIP_CMD_REGISTER_SESSION, 0x0065)

    def test_unregister_session_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_UNREGISTER_SESSION

        self.assertEqual(ENIP_CMD_UNREGISTER_SESSION, 0x0066)

    def test_send_rr_data_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_SEND_RR_DATA

        self.assertEqual(ENIP_CMD_SEND_RR_DATA, 0x006F)

    def test_send_unit_data_value(self):
        from oida.protocols.ethernetip.constants import ENIP_CMD_SEND_UNIT_DATA

        self.assertEqual(ENIP_CMD_SEND_UNIT_DATA, 0x0070)

    def test_commands_are_unique(self):
        from oida.protocols.ethernetip.constants import (
            ENIP_CMD_LIST_IDENTITY,
            ENIP_CMD_LIST_INTERFACES,
            ENIP_CMD_LIST_SERVICES,
            ENIP_CMD_REGISTER_SESSION,
            ENIP_CMD_SEND_RR_DATA,
            ENIP_CMD_SEND_UNIT_DATA,
            ENIP_CMD_UNREGISTER_SESSION,
        )

        values = [
            ENIP_CMD_LIST_SERVICES,
            ENIP_CMD_LIST_IDENTITY,
            ENIP_CMD_LIST_INTERFACES,
            ENIP_CMD_REGISTER_SESSION,
            ENIP_CMD_UNREGISTER_SESSION,
            ENIP_CMD_SEND_RR_DATA,
            ENIP_CMD_SEND_UNIT_DATA,
        ]
        self.assertEqual(len(values), len(set(values)))


class TestCipSecurityClasses(unittest.TestCase):
    """Test CIP Security class definitions."""

    def test_cip_security_classes_defined(self):
        from oida.protocols.ethernetip.constants import CIP_SECURITY_CLASSES

        self.assertIsInstance(CIP_SECURITY_CLASSES, dict)
        self.assertGreater(len(CIP_SECURITY_CLASSES), 0)

    def test_cip_security_class_ids(self):
        from oida.protocols.ethernetip.constants import CIP_SECURITY_CLASSES

        self.assertIn(0x5D, CIP_SECURITY_CLASSES)
        self.assertIn(0x5E, CIP_SECURITY_CLASSES)
        self.assertIn(0x5F, CIP_SECURITY_CLASSES)
        self.assertIn(0x60, CIP_SECURITY_CLASSES)
        self.assertIn(0x61, CIP_SECURITY_CLASSES)
        self.assertIn(0x62, CIP_SECURITY_CLASSES)

    def test_cip_security_class_names(self):
        from oida.protocols.ethernetip.constants import CIP_SECURITY_CLASSES

        self.assertEqual(CIP_SECURITY_CLASSES[0x5D], "CIP Security")
        self.assertEqual(CIP_SECURITY_CLASSES[0x5E], "EtherNet/IP Security")
        self.assertEqual(CIP_SECURITY_CLASSES[0x5F], "Certificate Management")
        self.assertEqual(CIP_SECURITY_CLASSES[0x60], "Authority")
        self.assertEqual(CIP_SECURITY_CLASSES[0x61], "Password Authenticator")
        self.assertEqual(CIP_SECURITY_CLASSES[0x62], "Certificate Authenticator")


class TestCipGeneralStatus(unittest.TestCase):
    """Test CIP General Status code definitions."""

    def test_status_codes_defined(self):
        from oida.protocols.ethernetip.constants import CIP_GENERAL_STATUS

        self.assertIsInstance(CIP_GENERAL_STATUS, dict)
        self.assertGreater(len(CIP_GENERAL_STATUS), 0)

    def test_success_code(self):
        from oida.protocols.ethernetip.constants import CIP_GENERAL_STATUS

        self.assertEqual(CIP_GENERAL_STATUS[0x00], "Success")

    def test_common_error_codes(self):
        from oida.protocols.ethernetip.constants import CIP_GENERAL_STATUS

        self.assertIn(0x01, CIP_GENERAL_STATUS)  # Connection failure
        self.assertIn(0x04, CIP_GENERAL_STATUS)  # Path segment error
        self.assertIn(0x08, CIP_GENERAL_STATUS)  # Service not supported
        self.assertIn(0x14, CIP_GENERAL_STATUS)  # Attribute not supported
        self.assertIn(0x16, CIP_GENERAL_STATUS)  # Object does not exist
        self.assertIn(0xFF, CIP_GENERAL_STATUS)  # Object specific error

    def test_privilege_violation_code(self):
        from oida.protocols.ethernetip.constants import CIP_GENERAL_STATUS

        self.assertEqual(CIP_GENERAL_STATUS[0x0F], "Privilege violation")


class TestModuleExports(unittest.TestCase):
    """Test that __all__ exports match expected constants."""

    def test_all_exports_exist(self):
        from oida.protocols.ethernetip import constants

        for name in constants.__all__:
            self.assertTrue(hasattr(constants, name), f"Missing export: {name}")


if __name__ == "__main__":
    unittest.main()
