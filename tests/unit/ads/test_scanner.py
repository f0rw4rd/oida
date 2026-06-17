#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for ADS (Beckhoff Automation Device Specification) scanner functionality.

Updated for the refactored NXC-style ADS module.
"""

import ctypes
import unittest
from unittest.mock import Mock, patch


class MockADSConnection:
    """Mock ADS connection for testing"""

    def __init__(self, connect_success=True):
        self.connect_success = connect_success
        self.connected = False
        self.ams_netid = "192.168.1.100.1.1"

    def open(self):
        if not self.connect_success:
            raise Exception("Failed to connect")
        self.connected = True

    def close(self):
        self.connected = False

    def read_state(self):
        if not self.connected:
            raise Exception("Not connected")

        return (5, 0)  # (ads_state=RUN, device_state)

    def read_device_info(self):
        if not self.connected:
            raise Exception("Not connected")

        # Real pyads read_device_info() returns a (name, AdsVersion) tuple.
        version = Mock()
        version.version = 3
        version.revision = 1
        version.build = 4024
        return "TC3PLC1", version

    def get_all_symbols(self):
        if not self.connected:
            raise Exception("Not connected")

        symbols = []
        for i in range(5):
            symbol = Mock()
            symbol.name = f"MAIN.Variable{i}"
            symbol.symbol_type = "INT"
            # Real pyads AdsSymbol exposes a ctypes plc_type (sizeof -> size),
            # not a .size attribute; c_int16 matches INT (2 bytes).
            symbol.plc_type = ctypes.c_int16
            symbol.offset = i * 2
            symbols.append(symbol)
        return symbols

    def read_by_name(self, name):
        if not self.connected:
            raise Exception("Not connected")

        if "Variable0" in name:
            return 42
        elif "Variable1" in name:
            return 100
        else:
            raise Exception("Symbol not found")

    def write_by_name(self, name, value):
        if not self.connected:
            raise Exception("Not connected")

        if "Variable0" in name:
            return True
        else:
            raise Exception("Access denied")

    def read(self, group, offset, size):
        if not self.connected:
            raise Exception("Not connected")

        # Route list requests (group 0x323) should fail with "no routes"
        if group == 0x323:
            raise Exception("ADS error 1814: no more entries")

        # Return mock data based on memory group
        return b"\x00" * size


class TestADSDataStructures(unittest.TestCase):
    """Test ADS data structures and types"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner

    def test_ads_port_mapping(self):
        """Test ADS port type mapping"""
        args = {"host": "192.168.1.100", "port": 48898}
        scanner = self.ADSScanner(args)

        # Test port mapping
        scanner.port_type = "TC3PLC1"
        self.assertEqual(scanner._get_ads_port(), 851)

        scanner.port_type = "TC3PLC2"
        self.assertEqual(scanner._get_ads_port(), 852)

        scanner.port_type = "NC"
        self.assertEqual(scanner._get_ads_port(), 500)

        scanner.port_type = "CNC"
        self.assertEqual(scanner._get_ads_port(), 100)

        scanner.port_type = "CUSTOMER1"
        self.assertEqual(scanner._get_ads_port(), 900)

    def test_explicit_ads_port(self):
        """Test explicit ADS port override"""
        args = {"host": "192.168.1.100", "port": 48898, "ads-port": 999}
        scanner = self.ADSScanner(args)

        # Explicit port should override port-type
        self.assertEqual(scanner._get_ads_port(), 999)

    def test_ams_netid_generation(self):
        """Test automatic AMS Net ID generation from host IP"""
        args = {"host": "192.168.1.100", "port": 48898}
        scanner = self.ADSScanner(args)

        # Target AMS Net ID should be derived from host IP
        self.assertEqual(scanner.ams_netid, "192.168.1.100.1.1")
        # Local Net ID is auto-detected (will vary by machine)
        self.assertIsNotNone(scanner.local_netid)
        self.assertTrue(scanner.local_netid.endswith(".1.1"))

    def test_custom_ams_netid(self):
        """Test custom AMS Net ID configuration"""
        args = {
            "host": "192.168.1.100",
            "port": 48898,
            "ams-netid": "10.0.0.1.1.1",
            "local-netid": "10.0.0.2.1.1",
        }
        scanner = self.ADSScanner(args)

        self.assertEqual(scanner.ams_netid, "10.0.0.1.1.1")
        self.assertEqual(scanner.local_netid, "10.0.0.2.1.1")


class TestADSConstants(unittest.TestCase):
    """Test ADS constants and enums"""

    def test_ads_constants(self):
        """Test ADS constant imports"""
        from oida.protocols.ads import (
            ADS_STATE_MAP,
            ADS_PORT_MAP,
            _get_memory_areas,
        )

        # State map should include common states
        self.assertEqual(ADS_STATE_MAP[5], "RUN")
        self.assertEqual(ADS_STATE_MAP[6], "STOP")
        self.assertEqual(ADS_STATE_MAP[0], "INVALID")

        # Port map should include all port types
        self.assertEqual(ADS_PORT_MAP["TC3PLC1"], 851)
        self.assertEqual(ADS_PORT_MAP["NC"], 500)

        # Memory areas should be defined (lazy-loaded function)
        memory_areas = _get_memory_areas()
        self.assertIsInstance(memory_areas, list)
        self.assertTrue(len(memory_areas) > 0)

    def test_port_types_in_protocol_options(self):
        """Test ADS port type enumeration in protocol options"""
        from oida.protocols.ads import protocol_options

        port_type_options = protocol_options["port-type"]["values"]
        self.assertIn("TC3PLC1", port_type_options)
        self.assertIn("TC3PLC2", port_type_options)
        self.assertIn("NC", port_type_options)
        self.assertIn("CNC", port_type_options)
        self.assertIn("CUSTOMER1", port_type_options)


class TestADSScannerInit(unittest.TestCase):
    """Test ADS scanner initialization"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner

    def test_basic_initialization(self):
        """Test basic scanner initialization"""
        args = {"host": "192.168.1.100", "port": 48898}
        scanner = self.ADSScanner(args)

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 48898)
        self.assertEqual(scanner.port_type, "TC3PLC1")
        self.assertEqual(scanner.max_symbols, 1000)  # Default is 1000

    def test_custom_initialization(self):
        """Test scanner initialization with custom parameters"""
        args = {
            "host": "10.0.0.1",
            "port": 48898,
            "port-type": "NC",
            "max-symbols": 50,
        }
        scanner = self.ADSScanner(args)

        self.assertEqual(scanner.host, "10.0.0.1")
        self.assertEqual(scanner.port_type, "NC")
        self.assertEqual(scanner.max_symbols, 50)

    def test_protocol_name(self):
        """Test protocol name"""
        args = {"host": "192.168.1.100", "port": 48898}
        scanner = self.ADSScanner(args)

        self.assertEqual(scanner.get_protocol_name(), "ADS")

    def test_default_port(self):
        """Test default port"""
        args = {"host": "192.168.1.100", "port": 48898}
        scanner = self.ADSScanner(args)

        self.assertEqual(scanner.get_default_port(), 48898)


class TestADSProtocolLogic(unittest.TestCase):
    """Test ADS protocol implementation logic"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner
        self.args = {"host": "192.168.1.100", "port": 48898}

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_connection_logic(self, mock_get_pyads):
        """Test ADS connection establishment"""
        scanner = self.ADSScanner(self.args)
        mock_connection = MockADSConnection()
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = mock_connection
        mock_get_pyads.return_value = mock_pyads

        result = scanner.connect()

        self.assertIsNotNone(result)
        mock_pyads.open_port.assert_called_once()
        mock_pyads.set_local_address.assert_called_once()

    def test_device_info_extraction(self):
        """Test device information extraction"""
        scanner = self.ADSScanner(self.args)
        mock_connection = MockADSConnection()
        mock_connection.connected = True

        info = scanner._get_device_info(mock_connection)

        self.assertEqual(info["ams_netid"], "192.168.1.100.1.1")
        self.assertEqual(info["ads_port"], 851)
        self.assertEqual(info["port_type"], "TC3PLC1")
        self.assertTrue(info["connected"])
        self.assertEqual(info["device_name"], "TC3PLC1")
        self.assertEqual(info["major_version"], 3)
        self.assertEqual(info["minor_version"], 1)
        self.assertEqual(info["build"], 4024)

    def test_state_extraction(self):
        """Test PLC state extraction"""
        scanner = self.ADSScanner(self.args)
        mock_connection = MockADSConnection()
        mock_connection.connected = True

        state = scanner._get_state(mock_connection)

        self.assertEqual(state["ads_state"], 5)
        self.assertEqual(state["ads_state_name"], "RUN")
        self.assertEqual(state["device_state"], 0)

    def test_symbol_discovery(self):
        """Test symbol discovery logic"""
        scanner = self.ADSScanner(self.args)
        scanner.max_symbols = 3
        mock_connection = MockADSConnection()
        mock_connection.connected = True

        result = scanner._discover_symbols(mock_connection)

        self.assertIn("symbols", result)
        self.assertIn("MAIN.Variable0", result["symbols"])
        self.assertEqual(result["symbols"]["MAIN.Variable0"]["name"], "MAIN.Variable0")
        self.assertEqual(result["symbols"]["MAIN.Variable0"]["type"], "INT")
        self.assertTrue(result["symbols"]["MAIN.Variable0"]["readable"])
        self.assertEqual(result["symbols"]["MAIN.Variable0"]["value"], "42")

    def test_memory_access_testing(self):
        """Test memory access testing functionality"""
        scanner = self.ADSScanner(self.args)
        mock_connection = MockADSConnection()
        mock_connection.connected = True

        results = scanner._test_memory_access(mock_connection)

        self.assertIn("accessible", results)
        self.assertIn("denied", results)
        self.assertIn("areas_tested", results)
        self.assertEqual(results["areas_tested"], 5)  # 5 memory areas


class TestADSMockOperations(unittest.TestCase):
    """Test ADS operations with mocked dependencies"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner
        self.args = {"host": "192.168.1.100", "port": 48898}

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_full_scan_workflow(self, mock_get_pyads):
        """Test complete ADS scan workflow"""
        scanner = self.ADSScanner(self.args)
        mock_connection = MockADSConnection()
        mock_connection.connected = True
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = mock_connection
        mock_get_pyads.return_value = mock_pyads

        scanner.connect = Mock(return_value=mock_connection)
        scanner.disconnect = Mock()

        results = scanner.run_scan()

        self.assertIn("device_info", results)
        self.assertIn("state", results)
        self.assertIn("security_analysis", results)
        scanner.connect.assert_called_once()
        scanner.disconnect.assert_called_once()

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_route_scanning(self, mock_get_pyads):
        """Test AMS route scanning"""
        scanner = self.ADSScanner(self.args)
        mock_connection = MockADSConnection()
        mock_connection.connected = True

        # Mock the pyads module for the new connection created in _scan_routes
        mock_sys_conn = MockADSConnection()
        mock_sys_conn.connected = True
        mock_pyads = Mock()
        mock_pyads.Connection.return_value = mock_sys_conn
        mock_get_pyads.return_value = mock_pyads

        routes = scanner._scan_routes(mock_connection)

        self.assertIn("local", routes)
        self.assertIn("target", routes)
        self.assertEqual(routes["target"]["netid"], "192.168.1.100.1.1")

    def test_security_analysis(self):
        """Test security analysis functionality"""
        scanner = self.ADSScanner(self.args)

        results = {
            "symbols": {
                "symbols": {
                    "var1": {"readable": True, "writable": True},
                    "var2": {"readable": True, "writable": False},
                    "var3": {"readable": True, "writable": True},
                }
            },
            "memory_access": {"accessible": [1, 2, 3]},
        }

        analysis = scanner._analyze_security(results)

        # SecurityAnalyzer returns: security_score, max_score, security_percentage, security_level, issues
        self.assertIn("security_level", analysis)
        self.assertIn("security_percentage", analysis)
        self.assertIn("issues", analysis)
        self.assertEqual(analysis["security_level"], "low")  # ADS has no auth by design
        self.assertTrue(any("writable" in issue for issue in analysis["issues"]))


class TestADSErrorHandling(unittest.TestCase):
    """Test ADS error handling"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner
        self.args = {"host": "192.168.1.100", "port": 48898}

    @patch("oida.protocols.ads.scanner._get_pyads")
    def test_connection_failure(self, mock_get_pyads):
        """Test handling of connection failures"""
        scanner = self.ADSScanner(self.args)
        mock_pyads = Mock()
        mock_pyads.open_port.side_effect = Exception("Connection failed")
        mock_get_pyads.return_value = mock_pyads

        result = scanner.connect()

        self.assertIsNone(result)

    def test_symbol_read_error(self):
        """Test handling of symbol read errors"""
        scanner = self.ADSScanner(self.args)
        mock_connection = Mock()
        mock_connection.get_all_symbols.side_effect = Exception("Access denied")

        result = scanner._discover_symbols(mock_connection)

        self.assertEqual(result.get("symbols", {}), {})
        self.assertIn("error", result)

    def test_invalid_port_type(self):
        """Test handling of invalid port type"""
        scanner = self.ADSScanner(self.args)
        scanner.port_type = "INVALID"

        # Should return default port (851)
        self.assertEqual(scanner._get_ads_port(), 851)

    def test_memory_access_error(self):
        """Test handling of memory access errors"""
        scanner = self.ADSScanner(self.args)
        mock_connection = Mock()
        mock_connection.read.side_effect = Exception("Memory access denied")

        results = scanner._test_memory_access(mock_connection)

        self.assertEqual(len(results["accessible"]), 0)
        self.assertTrue(len(results["denied"]) > 0)


class TestADSSecurityAnalysis(unittest.TestCase):
    """Test ADS security analysis features"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner
        self.args = {"host": "192.168.1.100", "port": 48898}

    def test_authentication_assessment(self):
        """Test authentication security assessment"""
        scanner = self.ADSScanner(self.args)

        results = {"symbols": {"symbols": {}}, "memory_access": {}}
        analysis = scanner._analyze_security(results)

        # SecurityAnalyzer returns: security_score, max_score, security_percentage, security_level, issues
        self.assertEqual(analysis["security_level"], "low")  # ADS has no auth
        self.assertIn("issues", analysis)
        self.assertTrue(any("authentication" in issue.lower() for issue in analysis["issues"]))

    def test_writable_symbol_detection(self):
        """Test detection of writable symbols"""
        scanner = self.ADSScanner(self.args)

        results = {
            "symbols": {
                "symbols": {
                    "var1": {"readable": True, "writable": True},
                    "var2": {"readable": True, "writable": True},
                    "var3": {"readable": True, "writable": False},
                }
            },
            "memory_access": {},
        }

        analysis = scanner._analyze_security(results)

        writable_issue = next((i for i in analysis["issues"] if "writable" in i.lower()), None)
        self.assertIsNotNone(writable_issue)
        self.assertIn("2", writable_issue)  # 2 writable symbols

    def test_memory_access_security(self):
        """Test memory access security assessment"""
        scanner = self.ADSScanner(self.args)

        results = {
            "symbols": {"symbols": {}},
            "memory_access": {"accessible": [{"name": "Memory Byte"}, {"name": "Memory Bit"}]},
        }

        analysis = scanner._analyze_security(results)

        memory_issue = next((i for i in analysis["issues"] if "memory" in i.lower()), None)
        self.assertIsNotNone(memory_issue)
        self.assertIn("2", memory_issue)  # 2 accessible ranges


class TestADSIntegration(unittest.TestCase):
    """Test ADS scanner integration with framework"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner, metadata

        self.ADSScanner = ADSScanner
        self.metadata = metadata
        self.args = {"host": "192.168.1.100", "port": 48898}

    def test_metadata_structure(self):
        """Test module metadata structure"""
        self.assertIn("name", self.metadata)
        self.assertIn("description", self.metadata)
        self.assertIn("authors", self.metadata)
        self.assertIn("references", self.metadata)
        self.assertIn("options", self.metadata)

        # Check default port
        self.assertEqual(self.metadata["options"]["rport"]["default"], 48898)

    def test_protocol_options(self):
        """Test protocol-specific options"""
        options = self.metadata["options"]

        self.assertIn("ams-netid", options)
        self.assertIn("local-netid", options)
        self.assertIn("port-type", options)
        self.assertIn("max-symbols", options)

    def test_check_dependencies(self):
        """Test dependency checking"""
        scanner = self.ADSScanner(self.args)
        result = scanner.check_dependencies()
        # Should return True since pyads is installed
        self.assertTrue(result)


class TestADSNXCClass(unittest.TestCase):
    """Test NXC-style ADS class"""

    def test_nxc_class_exists(self):
        """Test that NXC-style class exists"""
        from oida.protocols.ads import ads

        self.assertIsNotNone(ads)

    def test_nxc_class_attributes(self):
        """Test NXC class has required attributes"""
        from oida.protocols.ads import ads

        # Check class has required methods
        self.assertTrue(hasattr(ads, "proto_flow"))
        self.assertTrue(hasattr(ads, "create_conn_obj"))
        self.assertTrue(hasattr(ads, "enum_host_info"))
        self.assertTrue(hasattr(ads, "print_host_info"))
        self.assertTrue(hasattr(ads, "cleanup"))
        self.assertTrue(hasattr(ads, "check_dependencies"))


class TestADSValueFormatting(unittest.TestCase):
    """Test value formatting utilities"""

    def setUp(self):
        from oida.protocols.ads import ADSScanner

        self.ADSScanner = ADSScanner
        self.args = {"host": "192.168.1.100", "port": 48898}

    def test_format_bytes(self):
        """Test formatting of bytes values"""
        scanner = self.ADSScanner(self.args)

        result = scanner._format_value(b"\x01\x02\x03")
        self.assertEqual(result, "010203")

    def test_format_list(self):
        """Test formatting of list values"""
        scanner = self.ADSScanner(self.args)

        # Short list
        result = scanner._format_value([1, 2, 3])
        self.assertEqual(result, "[1, 2, 3]")

        # Long list (rendered as string)
        long_list = list(range(20))
        result = scanner._format_value(long_list)
        self.assertIn("0", result)

    def test_format_simple(self):
        """Test formatting of simple values"""
        scanner = self.ADSScanner(self.args)

        self.assertEqual(scanner._format_value(42), "42")
        self.assertEqual(scanner._format_value(3.14), "3.14")
        self.assertEqual(scanner._format_value("test"), "test")
        self.assertEqual(scanner._format_value(True), "True")


if __name__ == "__main__":
    unittest.main()
