#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for error handling and edge cases across the ICS scanning framework.
"""

import unittest

from oida.utils.exceptions import (
    ICSProtocolError,
    ICSConnectionError,
    AuthenticationError,
    ICSTimeoutError,
    ModbusError,
    OPCUAError,
    EtherCATError,
)


class TestExceptionHierarchy(unittest.TestCase):
    """Test the custom exception hierarchy"""

    def test_base_exception_creation(self):
        """Test ICSProtocolError base exception"""
        error = ICSProtocolError("Test error", protocol="TestProtocol", error_code="E001")

        self.assertEqual(error.message, "Test error")
        self.assertEqual(error.protocol, "TestProtocol")
        self.assertEqual(error.error_code, "E001")
        self.assertIn("TestProtocol", str(error))

    def test_exception_inheritance(self):
        """Test that all exceptions inherit from base class"""
        connection_error = ICSConnectionError("Connection failed")
        auth_error = AuthenticationError("Auth failed")
        timeout_error = ICSTimeoutError("Timeout occurred")

        self.assertIsInstance(connection_error, ICSProtocolError)
        self.assertIsInstance(auth_error, ICSProtocolError)
        self.assertIsInstance(timeout_error, ICSProtocolError)

    def test_protocol_specific_exceptions(self):
        """Test protocol-specific exception attributes"""
        # Modbus error
        modbus_error = ModbusError("Illegal function", function_code=3, exception_code=1)
        self.assertEqual(modbus_error.protocol, "Modbus")
        self.assertEqual(modbus_error.function_code, 3)
        self.assertEqual(modbus_error.exception_code, 1)

        # OPC UA error
        opcua_error = OPCUAError("Bad session", status_code="BadSessionClosed")
        self.assertEqual(opcua_error.protocol, "OPC UA")
        self.assertEqual(opcua_error.status_code, "BadSessionClosed")

        # EtherCAT error
        ethercat_error = EtherCATError("AL Status error", al_status=0x001E)
        self.assertEqual(ethercat_error.protocol, "EtherCAT")
        self.assertEqual(ethercat_error.al_status, 0x001E)


if __name__ == "__main__":
    unittest.main()
