#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for custom exception hierarchy.
"""

import unittest
from oida.utils.exceptions import (
    ICSProtocolError,
    ICSConnectionError,
    AuthenticationError,
    ProtocolError,
    DependencyError,
    ModbusError,
    OPCUAError,
    EtherCATError,
)


class TestBaseExceptions(unittest.TestCase):
    """Test base exception classes"""

    def test_ics_protocol_error(self):
        """Test ICSProtocolError base class"""
        error = ICSProtocolError("Test error", protocol="Modbus", error_code="E001")

        self.assertEqual(error.message, "Test error")
        self.assertEqual(error.protocol, "Modbus")
        self.assertEqual(error.error_code, "E001")
        self.assertEqual(str(error), "[Modbus] Test error")

    def test_ics_protocol_error_no_protocol(self):
        """Test ICSProtocolError without protocol"""
        error = ICSProtocolError("Generic error")

        self.assertEqual(error.message, "Generic error")
        self.assertEqual(error.protocol, "")
        self.assertEqual(str(error), "Generic error")

    def test_connection_error(self):
        """Test ICSConnectionError"""
        error = ICSConnectionError("Failed to connect", protocol="OPC UA")

        self.assertIsInstance(error, ICSProtocolError)
        self.assertEqual(error.protocol, "OPC UA")
        self.assertEqual(str(error), "[OPC UA] Failed to connect")

    def test_authentication_error(self):
        """Test AuthenticationError"""
        error = AuthenticationError("Invalid credentials", protocol="Modbus")

        self.assertIsInstance(error, ICSProtocolError)
        self.assertEqual(error.protocol, "Modbus")

    def test_dependency_error(self):
        """Test DependencyError"""
        error = DependencyError("Missing pymodbus library", protocol="Modbus")

        self.assertIsInstance(error, ICSProtocolError)
        self.assertEqual(error.protocol, "Modbus")


class TestProtocolSpecificExceptions(unittest.TestCase):
    """Test protocol-specific exception classes"""

    def test_modbus_error(self):
        """Test ModbusError"""
        error = ModbusError("Illegal function", function_code=1, exception_code=1)

        self.assertIsInstance(error, ProtocolError)
        self.assertEqual(error.protocol, "Modbus")
        self.assertEqual(error.function_code, 1)
        self.assertEqual(error.exception_code, 1)

    def test_opcua_error(self):
        """Test OPCUAError"""
        error = OPCUAError("Bad session closed", status_code="BadSessionClosed")

        self.assertIsInstance(error, ProtocolError)
        self.assertEqual(error.protocol, "OPC UA")
        self.assertEqual(error.status_code, "BadSessionClosed")

    def test_ethercat_error(self):
        """Test EtherCATError"""
        error = EtherCATError("AL Status Error", al_status=0x001E)

        self.assertIsInstance(error, ProtocolError)
        self.assertEqual(error.protocol, "EtherCAT")
        self.assertEqual(error.al_status, 0x001E)


if __name__ == "__main__":
    unittest.main()
