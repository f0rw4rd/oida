#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for OPC UA NXC connection class.
"""

import unittest
from unittest.mock import Mock, patch


class MockArgs:
    """Mock args object for testing"""

    def __init__(self, **kwargs):
        self.port = kwargs.get("port", 4840)
        self.timeout = kwargs.get("timeout", 5)
        self.username = kwargs.get("username", None)
        self.password = kwargs.get("password", None)
        self.confirm = kwargs.get("confirm", False)
        self.fuzz = kwargs.get("fuzz", None)
        self.fuzz_node = kwargs.get("fuzz_node", None)
        self.fuzz_method = kwargs.get("fuzz_method", None)
        self.dump = kwargs.get("dump", False)
        self.dump_all = kwargs.get("dump_all", False)
        self.node_id = kwargs.get("node_id", None)


class TestOpcuaClassInit(unittest.TestCase):
    """Test opcua class initialization"""

    @patch("oida.protocols.opcua.cli_runner._normalize_opcua_url")
    @patch("oida.protocols.opcua.cli_runner._parse_opcua_url")
    @patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__")
    def test_init_normalizes_url(self, mock_super, mock_parse, mock_normalize):
        """Test that __init__ normalizes the OPC UA URL"""
        mock_normalize.return_value = "opc.tcp://192.168.1.100:4840"
        mock_parse.return_value = ("192.168.1.100", 4840, "")
        mock_super.return_value = None

        from oida.protocols.opcua.cli_runner import opcua

        args = MockArgs()
        db = Mock()
        host = "192.168.1.100"

        opcua(args, db, host)

        mock_normalize.assert_called_once_with(host, 4840)
        mock_parse.assert_called_once()

    @patch("oida.protocols.opcua.cli_runner._normalize_opcua_url")
    @patch("oida.protocols.opcua.cli_runner._parse_opcua_url")
    @patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__")
    def test_init_sets_protocol_name(self, mock_super, mock_parse, mock_normalize):
        """Test that __init__ sets protocol_name to the 'OPC UA' display name.

        Layer-2 connection classes carry a human-readable protocol_name used in
        the NXC-style banner/log lines (e.g. "Modbus", "IEC 104", "EtherNet/IP"),
        not the lowercase loader key. opcua follows that convention with "OPC UA".
        """
        mock_normalize.return_value = "opc.tcp://192.168.1.100:4840"
        mock_parse.return_value = ("192.168.1.100", 4840, "")
        mock_super.return_value = None

        from oida.protocols.opcua.cli_runner import opcua

        args = MockArgs()
        db = Mock()
        instance = opcua(args, db, "192.168.1.100")

        self.assertEqual(instance.protocol_name, "OPC UA")

    @patch("oida.protocols.opcua.cli_runner._normalize_opcua_url")
    @patch("oida.protocols.opcua.cli_runner._parse_opcua_url")
    @patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__")
    def test_init_sets_default_port(self, mock_super, mock_parse, mock_normalize):
        """Test that __init__ sets default_port to 4840"""
        mock_normalize.return_value = "opc.tcp://192.168.1.100:4840"
        mock_parse.return_value = ("192.168.1.100", 4840, "")
        mock_super.return_value = None

        from oida.protocols.opcua.cli_runner import opcua

        args = MockArgs()
        db = Mock()
        instance = opcua(args, db, "192.168.1.100")

        self.assertEqual(instance.default_port, 4840)


class TestGenerateFuzzValue(unittest.TestCase):
    """Test fuzz value generation"""

    def setUp(self):
        """Set up test instance with mocked parent"""
        with (
            patch("oida.protocols.opcua.cli_runner._normalize_opcua_url") as mock_norm,
            patch("oida.protocols.opcua.cli_runner._parse_opcua_url") as mock_parse,
            patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__") as mock_super,
        ):
            mock_norm.return_value = "opc.tcp://192.168.1.100:4840"
            mock_parse.return_value = ("192.168.1.100", 4840, "")
            mock_super.return_value = None

            from oida.protocols.opcua.cli_runner import opcua

            self.instance = opcua(MockArgs(), Mock(), "192.168.1.100")

    def test_boolean_fuzz(self):
        """Test Boolean type fuzzing"""
        result = self.instance._generate_fuzz_value(1, 0)
        self.assertIn(result, [True, False])

    def test_sbyte_fuzz(self):
        """Test SByte type fuzzing (type_id=2)"""
        result = self.instance._generate_fuzz_value(2, 0)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, -128)
        self.assertLessEqual(result, 127)

    def test_byte_fuzz(self):
        """Test Byte type fuzzing (type_id=3)"""
        result = self.instance._generate_fuzz_value(3, 0)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 255)

    def test_int16_fuzz(self):
        """Test Int16 type fuzzing (type_id=4)"""
        result = self.instance._generate_fuzz_value(4, 0)
        self.assertIsInstance(result, int)

    def test_uint16_fuzz(self):
        """Test UInt16 type fuzzing (type_id=5)"""
        result = self.instance._generate_fuzz_value(5, 0)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)

    def test_int32_fuzz(self):
        """Test Int32 type fuzzing (type_id=6)"""
        result = self.instance._generate_fuzz_value(6, 0)
        self.assertIsInstance(result, int)

    def test_float_fuzz(self):
        """Test Float type fuzzing (type_id=10)"""
        result = self.instance._generate_fuzz_value(10, 0)
        self.assertIsInstance(result, float)

    def test_double_fuzz(self):
        """Test Double type fuzzing (type_id=11)"""
        result = self.instance._generate_fuzz_value(11, 0)
        self.assertIsInstance(result, float)

    def test_string_fuzz(self):
        """Test String type fuzzing (type_id=12)"""
        result = self.instance._generate_fuzz_value(12, 0)
        self.assertIsInstance(result, str)

    def test_datetime_fuzz(self):
        """Test DateTime type fuzzing (type_id=13)"""
        from datetime import datetime

        result = self.instance._generate_fuzz_value(13, 0)
        self.assertIsInstance(result, datetime)

    def test_iteration_varies_results(self):
        """Test that different iterations produce different values"""
        results = [self.instance._generate_fuzz_value(2, i) for i in range(5)]
        # At least some should be different
        self.assertGreater(len(set(results)), 1)


class TestGetTypeName(unittest.TestCase):
    """Test type name mapping"""

    def setUp(self):
        """Set up test instance"""
        with (
            patch("oida.protocols.opcua.cli_runner._normalize_opcua_url") as mock_norm,
            patch("oida.protocols.opcua.cli_runner._parse_opcua_url") as mock_parse,
            patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__") as mock_super,
        ):
            mock_norm.return_value = "opc.tcp://192.168.1.100:4840"
            mock_parse.return_value = ("192.168.1.100", 4840, "")
            mock_super.return_value = None

            from oida.protocols.opcua.cli_runner import opcua

            self.instance = opcua(MockArgs(), Mock(), "192.168.1.100")

    def test_boolean_type_name(self):
        """Test Boolean type name (type_id=1)"""
        result = self.instance._get_type_name(1)
        self.assertEqual(result, "Boolean")

    def test_int32_type_name(self):
        """Test Int32 type name (type_id=6)"""
        result = self.instance._get_type_name(6)
        self.assertEqual(result, "Int32")

    def test_string_type_name(self):
        """Test String type name (type_id=12)"""
        result = self.instance._get_type_name(12)
        self.assertEqual(result, "String")

    def test_unknown_type_name(self):
        """Test unknown type returns Unknown(id)"""
        result = self.instance._get_type_name(999)
        self.assertEqual(result, "Unknown(999)")


class TestConvertValue(unittest.TestCase):
    """Test value conversion for writes"""

    def setUp(self):
        """Set up test instance"""
        with (
            patch("oida.protocols.opcua.cli_runner._normalize_opcua_url") as mock_norm,
            patch("oida.protocols.opcua.cli_runner._parse_opcua_url") as mock_parse,
            patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__") as mock_super,
        ):
            mock_norm.return_value = "opc.tcp://192.168.1.100:4840"
            mock_parse.return_value = ("192.168.1.100", 4840, "")
            mock_super.return_value = None

            from oida.protocols.opcua.cli_runner import opcua

            self.instance = opcua(MockArgs(), Mock(), "192.168.1.100")

    def test_convert_boolean_true(self):
        """Test converting 'true' to Boolean"""
        result = self.instance._convert_value("true", "Boolean", False)
        self.assertTrue(result)

    def test_convert_boolean_false(self):
        """Test converting 'false' to Boolean"""
        result = self.instance._convert_value("false", "Boolean", True)
        self.assertFalse(result)

    def test_convert_boolean_1(self):
        """Test converting '1' to Boolean"""
        result = self.instance._convert_value("1", "Boolean", False)
        self.assertTrue(result)

    def test_convert_int32(self):
        """Test converting string to Int32"""
        result = self.instance._convert_value("42", "Int32", 0)
        self.assertEqual(result, 42)

    def test_convert_float(self):
        """Test converting string to Float"""
        result = self.instance._convert_value("3.14", "Float", 0.0)
        self.assertAlmostEqual(result, 3.14, places=2)

    def test_convert_double(self):
        """Test converting string to Double"""
        result = self.instance._convert_value("3.14159", "Double", 0.0)
        self.assertAlmostEqual(result, 3.14159, places=5)

    def test_convert_string(self):
        """Test string passthrough"""
        result = self.instance._convert_value("hello", "String", "")
        self.assertEqual(result, "hello")


class TestParseArgument(unittest.TestCase):
    """Test OPC UA argument parsing"""

    def setUp(self):
        """Set up test instance"""
        with (
            patch("oida.protocols.opcua.cli_runner._normalize_opcua_url") as mock_norm,
            patch("oida.protocols.opcua.cli_runner._parse_opcua_url") as mock_parse,
            patch("oida.protocols.opcua.cli_runner.NetworkConnection.__init__") as mock_super,
        ):
            mock_norm.return_value = "opc.tcp://192.168.1.100:4840"
            mock_parse.return_value = ("192.168.1.100", 4840, "")
            mock_super.return_value = None

            from oida.protocols.opcua.cli_runner import opcua

            self.instance = opcua(MockArgs(), Mock(), "192.168.1.100")

    def test_parse_argument_with_name(self):
        """Test parsing argument with Name attribute"""
        arg = Mock()
        arg.Name = "temperature"
        arg.DataType = Mock()
        arg.DataType.Identifier = 11  # Double
        arg.Description = Mock()
        arg.Description.Text = "Temperature value"

        result = self.instance._parse_argument(arg)

        self.assertEqual(result["name"], "temperature")

    def test_parse_argument_returns_dict(self):
        """Test that parse_argument returns a dict"""
        arg = Mock()
        arg.Name = "test"
        arg.DataType = Mock()
        arg.DataType.Identifier = 6
        arg.Description = None

        result = self.instance._parse_argument(arg)

        self.assertIsInstance(result, dict)
        self.assertIn("name", result)
        self.assertIn("data_type", result)


if __name__ == "__main__":
    unittest.main()
