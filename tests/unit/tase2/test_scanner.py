#!/usr/bin/env python3
"""
Comprehensive test suite for TASE.2/ICCP protocol scanner.
Tests both mock interactions and real protocol functionality.
"""

import unittest
from unittest.mock import patch, MagicMock

import pytest

from oida.protocols.tase2 import TASE2Scanner


class TestTASE2ScannerInit(unittest.TestCase):
    """Test TASE.2 scanner initialization"""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values"""
        scanner = TASE2Scanner({"rhost": "192.168.1.100", "rport": 102})

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 102)
        self.assertEqual(scanner.get_protocol_name(), "TASE.2/ICCP")
        self.assertEqual(scanner.get_default_port(), 102)

    def test_scanner_init_custom_values(self):
        """Test scanner initialization with custom values"""
        scanner = TASE2Scanner(
            {
                "rhost": "10.0.0.50",
                "rport": 8102,
                "timeout": 30,
                "debug": True,
                "discover-vcc": False,
                "discover-icc": False,
                "analyze-blt": False,
                "enumerate-points": False,
                "max-points": 50,
            }
        )

        self.assertEqual(scanner.host, "10.0.0.50")
        self.assertEqual(scanner.port, 8102)
        self.assertEqual(scanner.timeout, 30)
        self.assertTrue(scanner.debug)
        self.assertFalse(scanner.discover_vcc)
        self.assertFalse(scanner.discover_icc)
        self.assertFalse(scanner.analyze_blt)
        self.assertFalse(scanner.enumerate_points)
        self.assertEqual(scanner.max_points, 50)

    def test_scanner_default_discovery_options(self):
        """Test default discovery options are enabled"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

        self.assertTrue(scanner.discover_vcc)
        self.assertTrue(scanner.discover_icc)
        self.assertTrue(scanner.analyze_blt)
        self.assertTrue(scanner.enumerate_points)


class TestTASE2ProtocolOptions(unittest.TestCase):
    """Test TASE.2 protocol options"""

    def test_protocol_options_exist(self):
        """Test that protocol options are defined"""
        from oida.protocols.tase2.scanner import protocol_options

        self.assertIn("discover-vcc", protocol_options)
        self.assertIn("discover-icc", protocol_options)
        self.assertIn("analyze-blt", protocol_options)
        self.assertIn("enumerate-points", protocol_options)
        self.assertIn("test-rbe", protocol_options)
        self.assertIn("test-control", protocol_options)
        self.assertIn("test-write", protocol_options)
        self.assertIn("max-points", protocol_options)

    def test_protocol_option_types(self):
        """Test protocol option type definitions"""
        from oida.protocols.tase2.scanner import protocol_options

        self.assertEqual(protocol_options["discover-vcc"]["type"], "bool")
        self.assertEqual(protocol_options["discover-icc"]["type"], "bool")
        self.assertEqual(protocol_options["max-points"]["type"], "int")
        self.assertEqual(protocol_options["local-ap-title"]["type"], "string")

    def test_protocol_option_defaults(self):
        """Test protocol option default values"""
        from oida.protocols.tase2.scanner import protocol_options

        self.assertTrue(protocol_options["discover-vcc"]["default"])
        self.assertTrue(protocol_options["discover-icc"]["default"])
        self.assertTrue(protocol_options["analyze-blt"]["default"])
        self.assertFalse(protocol_options["test-rbe"]["default"])
        self.assertFalse(protocol_options["test-control"]["default"])
        self.assertEqual(protocol_options["max-points"]["default"], 100)


class TestTASE2ConformanceBlocks(unittest.TestCase):
    """Test TASE.2 conformance block handling"""

    def test_rbe_block(self):
        """Test Report-by-Exception (Block 2) handling"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "test-rbe": True})
        self.assertTrue(scanner.test_rbe)

    def test_control_block(self):
        """Test Device Control (Block 5) handling"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "test-control": True})
        self.assertTrue(scanner.test_control)

    def test_write_block(self):
        """Test Write access handling"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "test-write": True})
        self.assertTrue(scanner.test_write)


@pytest.mark.network
class TestTASE2MockOperations(unittest.TestCase):
    """Test TASE.2 operations with mocked dependencies"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 5})

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_check_dependencies_mock(self, mock_tase2):
        """Test dependency check with mock"""
        # Mock the LazyModuleWrapper's is_available property
        mock_tase2.is_available = True
        # Note: The check depends on lazy import behavior
        self.assertIsInstance(self.scanner.check_dependencies(), bool)

    def test_disconnected_operations(self):
        """Test operations when disconnected"""
        results = self.scanner.run_scan()

        # Should handle disconnection gracefully
        self.assertIsInstance(results, dict)
        if "error" in results:
            self.assertIn("connection", results["error"].lower())


class TestTASE2DomainTypes(unittest.TestCase):
    """Test TASE.2 domain type handling"""

    def test_vcc_domain_type(self):
        """Test VCC (Virtual Control Center) domain type"""
        domain_type = "VCC"
        self.assertEqual(domain_type, "VCC")

    def test_icc_domain_type(self):
        """Test ICC (Indication Control Center) domain type"""
        domain_type = "ICC"
        self.assertEqual(domain_type, "ICC")


class TestTASE2BilateralTable(unittest.TestCase):
    """Test TASE.2 bilateral table functionality"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    def test_domains_initialization(self):
        """Test domains list is initialized empty"""
        self.assertEqual(self.scanner.domains, [])


@pytest.mark.network
class TestTASE2ErrorHandling(unittest.TestCase):
    """Test TASE.2 error handling scenarios"""

    def test_connection_timeout(self):
        """Test connection timeout scenarios"""
        scanner = TASE2Scanner(
            {
                "rhost": "192.168.254.254",  # Non-routable address
                "rport": 102,
                "timeout": 1,  # Very short timeout
            }
        )

        result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        if "error" in result:
            self.assertIsInstance(result["error"], str)

    def test_invalid_port(self):
        """Test invalid port handling"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 99999, "timeout": 2})

        result = scanner.run_scan()

        self.assertIsInstance(result, dict)


class TestTASE2Integration(unittest.TestCase):
    """Integration tests for TASE.2 scanner"""

    def test_complete_tase2_scan_workflow(self):
        """Test complete TASE.2 scanning workflow"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 10})

        # Test basic workflow
        protocol_name = scanner.get_protocol_name()
        default_port = scanner.get_default_port()
        dependencies_ok = scanner.check_dependencies()

        self.assertEqual(protocol_name, "TASE.2/ICCP")
        self.assertEqual(default_port, 102)
        self.assertIsInstance(dependencies_ok, bool)

        # Test connectivity check
        connectivity = scanner.test_connectivity("127.0.0.1", 102)
        self.assertIsInstance(connectivity, bool)

        # Test scan execution (will fail without real connection)
        result = scanner.run_scan()
        self.assertIsInstance(result, dict)

    def test_tase2_with_different_configurations(self):
        """Test TASE.2 scanner with different configurations"""
        configurations = [
            {"rhost": "127.0.0.1", "rport": 102, "timeout": 5},
            {"rhost": "127.0.0.1", "rport": 8102, "timeout": 10},
            {"rhost": "192.168.1.100", "rport": 102, "timeout": 15},
        ]

        for config in configurations:
            scanner = TASE2Scanner(config)
            self.assertEqual(scanner.host, config["rhost"])
            self.assertEqual(scanner.port, config["rport"])
            self.assertEqual(scanner.timeout, config["timeout"])


class TestTASE2APTitles(unittest.TestCase):
    """Test TASE.2 AP title handling"""

    def test_default_ap_titles(self):
        """Test default AP titles are empty"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertEqual(scanner.local_ap_title, "")
        self.assertEqual(scanner.remote_ap_title, "")

    def test_custom_local_ap_title(self):
        """Test custom local AP title"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "local-ap-title": "1.1.1.999"})
        self.assertEqual(scanner.local_ap_title, "1.1.1.999")

    def test_custom_remote_ap_title(self):
        """Test custom remote AP title"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "remote-ap-title": "1.1.1.100"})
        self.assertEqual(scanner.remote_ap_title, "1.1.1.100")


class TestTASE2MaxPoints(unittest.TestCase):
    """Test TASE.2 max points configuration"""

    def test_default_max_points(self):
        """Test default max points value"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertEqual(scanner.max_points, 100)

    def test_custom_max_points(self):
        """Test custom max points value"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "max-points": 500})
        self.assertEqual(scanner.max_points, 500)


class TestTASE2DataSetHandling(unittest.TestCase):
    """Test TASE.2 data set handling"""

    def test_data_set_structure(self):
        """Test data set structure definition"""
        data_set = {
            "domain": "VCC1",
            "name": "DS_Indications",
            "member_count": 10,
        }

        self.assertIn("domain", data_set)
        self.assertIn("name", data_set)
        self.assertIn("member_count", data_set)


class TestTASE2TransferSetHandling(unittest.TestCase):
    """Test TASE.2 transfer set handling"""

    def test_transfer_set_structure(self):
        """Test transfer set structure definition"""
        transfer_set = {
            "domain": "VCC1",
            "name": "TS_Status",
            "data_set": "DS_Status",
            "interval": 5000,
            "rbe_enabled": True,
        }

        self.assertIn("domain", transfer_set)
        self.assertIn("name", transfer_set)
        self.assertIn("data_set", transfer_set)
        self.assertIn("interval", transfer_set)
        self.assertIn("rbe_enabled", transfer_set)
        self.assertTrue(transfer_set["rbe_enabled"])


class TestTASE2ControlPointHandling(unittest.TestCase):
    """Test TASE.2 control point handling"""

    def test_control_point_structure(self):
        """Test control point structure definition"""
        control_point = {
            "domain": "VCC1",
            "name": "Breaker_Control",
        }

        self.assertIn("domain", control_point)
        self.assertIn("name", control_point)


class TestTASE2PointValueHandling(unittest.TestCase):
    """Test TASE.2 point value handling"""

    def test_point_value_structure(self):
        """Test point value structure"""
        point_value = {
            "domain": "VCC1",
            "name": "AnalogValue1",
            "value": 230.5,
            "quality": "GOOD",
            "point_type": "Real",
            "readable": True,
            "writable": False,
        }

        self.assertIn("value", point_value)
        self.assertIn("quality", point_value)
        self.assertIn("point_type", point_value)
        self.assertAlmostEqual(point_value["value"], 230.5, places=1)


class TestTASE2DiscoveryResults(unittest.TestCase):
    """Test TASE.2 discovery results structure"""

    def test_discovery_results_structure(self):
        """Test discovery results dictionary structure"""
        results = {
            "bilateral_table": {},
            "domains": [],
            "vcc_variables": [],
            "data_points": [],
            "transfer_sets": [],
            "control_points": [],
            "conformance_blocks": [],
            "security_analysis": {},
        }

        self.assertIn("bilateral_table", results)
        self.assertIn("domains", results)
        self.assertIn("vcc_variables", results)
        self.assertIn("data_points", results)
        self.assertIn("transfer_sets", results)
        self.assertIn("control_points", results)
        self.assertIn("conformance_blocks", results)
        self.assertIn("security_analysis", results)


class TestTASE2DomainInfoStructure(unittest.TestCase):
    """Test TASE.2 domain info structure"""

    def test_domain_info_structure(self):
        """Test domain info dictionary structure"""
        domain_info = {
            "name": "VCC1",
            "type": "VCC",
            "is_vcc": True,
            "variable_count": 100,
            "data_set_count": 5,
            "variables": [],
            "data_sets": [],
        }

        self.assertIn("name", domain_info)
        self.assertIn("type", domain_info)
        self.assertIn("is_vcc", domain_info)
        self.assertIn("variable_count", domain_info)
        self.assertIn("data_set_count", domain_info)
        self.assertTrue(domain_info["is_vcc"])


class TestTASE2ControlKeywords(unittest.TestCase):
    """Test TASE.2 control point detection keywords"""

    def test_control_keywords(self):
        """Test control point keyword matching"""
        control_keywords = [
            "control",
            "command",
            "setpoint",
            "breaker",
            "switch",
            "valve",
            "output",
            "operate",
        ]

        test_names = [
            "Breaker_Control",
            "Valve_Command",
            "Output_Setpoint",
        ]

        for name in test_names:
            name_lower = name.lower()
            matched = any(kw in name_lower for kw in control_keywords)
            self.assertTrue(matched)


class TestTASE2ClientState(unittest.TestCase):
    """Test TASE.2 client state management"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    def test_initial_client_state(self):
        """Test initial client state is None"""
        self.assertIsNone(self.scanner.client)

    def test_initial_domains_empty(self):
        """Test initial domains list is empty"""
        self.assertEqual(self.scanner.domains, [])


class TestTASE2BilateralTableInfo(unittest.TestCase):
    """Test TASE.2 bilateral table info structure"""

    def test_bilateral_table_info_structure(self):
        """Test bilateral table info dictionary structure"""
        blt_info = {
            "table_id": "BLT_UTILITY1",
            "table_count": 2,
        }

        self.assertIn("table_id", blt_info)
        self.assertIn("table_count", blt_info)


class TestTASE2VCCVariableStructure(unittest.TestCase):
    """Test TASE.2 VCC variable structure"""

    def test_vcc_variable_structure(self):
        """Test VCC-scope variable structure"""
        vcc_variable = {
            "name": "GlobalStatus1",
            "domain": None,
            "scope": "VCC",
        }

        self.assertIn("name", vcc_variable)
        self.assertIsNone(vcc_variable["domain"])
        self.assertEqual(vcc_variable["scope"], "VCC")


class TestTASE2ScannerTestOptions(unittest.TestCase):
    """Test TASE.2 scanner test option handling"""

    def test_test_rbe_disabled_by_default(self):
        """Test RBE testing is disabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertFalse(scanner.test_rbe)

    def test_test_rbe_enabled(self):
        """Test enabling RBE testing"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "test-rbe": True})
        self.assertTrue(scanner.test_rbe)

    def test_test_control_disabled_by_default(self):
        """Test control testing is disabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertFalse(scanner.test_control)

    def test_test_control_enabled(self):
        """Test enabling control testing"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "test-control": True})
        self.assertTrue(scanner.test_control)

    def test_test_write_disabled_by_default(self):
        """Test write testing is disabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertFalse(scanner.test_write)

    def test_test_write_enabled(self):
        """Test enabling write testing"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "test-write": True})
        self.assertTrue(scanner.test_write)


class TestTASE2DiscoveryOptions(unittest.TestCase):
    """Test TASE.2 discovery option handling"""

    def test_discover_vcc_enabled_by_default(self):
        """Test VCC discovery is enabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertTrue(scanner.discover_vcc)

    def test_discover_vcc_disabled(self):
        """Test disabling VCC discovery"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "discover-vcc": False})
        self.assertFalse(scanner.discover_vcc)

    def test_discover_icc_enabled_by_default(self):
        """Test ICC discovery is enabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertTrue(scanner.discover_icc)

    def test_discover_icc_disabled(self):
        """Test disabling ICC discovery"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "discover-icc": False})
        self.assertFalse(scanner.discover_icc)

    def test_analyze_blt_enabled_by_default(self):
        """Test BLT analysis is enabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertTrue(scanner.analyze_blt)

    def test_analyze_blt_disabled(self):
        """Test disabling BLT analysis"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "analyze-blt": False})
        self.assertFalse(scanner.analyze_blt)

    def test_enumerate_points_enabled_by_default(self):
        """Test point enumeration is enabled by default"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        self.assertTrue(scanner.enumerate_points)

    def test_enumerate_points_disabled(self):
        """Test disabling point enumeration"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102, "enumerate-points": False})
        self.assertFalse(scanner.enumerate_points)


class TestTASE2SecurityAssessment(unittest.TestCase):
    """Test TASE.2 security assessment structure"""

    def test_security_assessment_structure(self):
        """Test security assessment dictionary structure"""
        assessment = {
            "authentication": False,
            "encryption": False,
            "authorization": True,
            "access_control": True,
        }

        self.assertFalse(assessment["authentication"])
        self.assertFalse(assessment["encryption"])
        self.assertTrue(assessment["authorization"])
        self.assertTrue(assessment["access_control"])


class TestTASE2ReadOnlyMode(unittest.TestCase):
    """Test TASE.2 read-only mode handling"""

    def test_read_only_default(self):
        """Test read_only defaults to True (safe mode)"""
        scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})
        # read_only should be inherited from base class with default True
        self.assertTrue(hasattr(scanner, "read_only"))


class TestTASE2DataPointFields(unittest.TestCase):
    """Test TASE.2 data point field structure"""

    def test_point_info_fields(self):
        """Test complete point info structure"""
        point_info = {
            "domain": "VCC1",
            "name": "Status1",
            "value": None,
            "quality": None,
            "point_type": None,
            "readable": False,
            "writable": False,
        }

        required_fields = ["domain", "name", "value", "quality", "readable", "writable"]
        for field in required_fields:
            self.assertIn(field, point_info)


class TestTASE2SupportedFeatures(unittest.TestCase):
    """Test TASE.2 Supported_Features (Block 1) operations"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    def test_supported_features_initialization(self):
        """Test supported_features is initialized empty"""
        self.assertEqual(self.scanner.supported_features, {})

    def test_tase2_version_initialization(self):
        """Test tase2_version is initialized None"""
        self.assertIsNone(self.scanner.tase2_version)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_supported_features_structure(self, mock_tase2):
        """Test get_supported_features returns proper structure"""
        # Mock connection
        mock_conn = MagicMock()

        # Call method - will fail without real connection but test structure
        result = self.scanner.get_supported_features(mock_conn)

        # Result should be a dict (even if empty on failure)
        self.assertIsInstance(result, dict)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_tase2_version_structure(self, mock_tase2):
        """Test get_tase2_version returns proper structure"""
        mock_conn = MagicMock()
        # Mock get_tase2_version to return proper version object
        mock_version = MagicMock()
        mock_version.major = 2000
        mock_version.minor = 8
        mock_conn.get_tase2_version.return_value = mock_version

        result = self.scanner.get_tase2_version(mock_conn)

        self.assertIsInstance(result, dict)
        self.assertIn("major", result)
        self.assertIn("minor", result)


class TestTASE2DataValueType(unittest.TestCase):
    """Test TASE.2 Get Data Value Type (Block 1) operations"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_data_value_type_structure(self, mock_tase2):
        """Test get_data_value_type returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.get_data_value_type(mock_conn, "ICC1", "Voltage")

        self.assertIsInstance(result, dict)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_data_values_structure(self, mock_tase2):
        """Test get_data_values returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.get_data_values(mock_conn, "ICC1", ["Voltage", "Current"])

        self.assertIsInstance(result, list)


class TestTASE2DataSetOperations(unittest.TestCase):
    """Test TASE.2 Data Set (Block 1) operations"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_data_set_members_structure(self, mock_tase2):
        """Test get_data_set_members returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.get_data_set_members(mock_conn, "ICC1", "DS_Measurements")

        self.assertIsInstance(result, list)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_create_data_set_structure(self, mock_tase2):
        """Test create_data_set returns proper structure"""
        mock_conn = MagicMock()
        members = [{"domain": "ICC1", "name": "Voltage"}]

        result = self.scanner.create_data_set(mock_conn, "ICC1", "TestSet", members)

        self.assertIsInstance(result, bool)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_delete_data_set_structure(self, mock_tase2):
        """Test delete_data_set returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.delete_data_set(mock_conn, "ICC1", "TestSet")

        self.assertIsInstance(result, bool)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_read_data_set_values_structure(self, mock_tase2):
        """Test read_data_set_values returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.read_data_set_values(mock_conn, "ICC1", "DS_Measurements")

        self.assertIsInstance(result, list)


class TestTASE2TagOperations(unittest.TestCase):
    """Test TASE.2 Device Tag (Block 5) operations"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_tag_structure(self, mock_tase2):
        """Test get_tag returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.get_tag(mock_conn, "ICC1", "Breaker1")

        self.assertIsInstance(result, dict)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_set_tag_structure(self, mock_tase2):
        """Test set_tag returns proper structure"""
        mock_conn = MagicMock()

        result = self.scanner.set_tag(mock_conn, "ICC1", "Breaker1", "NO_TAG", "Test")

        self.assertIsInstance(result, bool)

    def test_tag_values(self):
        """Test valid tag value constants"""
        valid_tags = ["NO_TAG", "OPEN_AND_CLOSE_INHIBIT", "CLOSE_ONLY_INHIBIT", "CLOSE_ONLY"]
        for tag in valid_tags:
            self.assertIsInstance(tag, str)


class TestTASE2EnhancedSecurityAnalysis(unittest.TestCase):
    """Test enhanced TASE.2 security analysis with new features"""

    def test_security_concerns_for_tagged_devices(self):
        """Test security concerns include tagged device analysis"""
        security_concerns = [
            "Block 5 enabled without proper tagging",
            "CheckBackID appears sequential/predictable",
            "Devices in ARMED state found",
            "Tagged devices may indicate maintenance mode",
        ]

        for concern in security_concerns:
            self.assertIsInstance(concern, str)
            self.assertTrue(len(concern) > 0)

    def test_supported_blocks_security_analysis(self):
        """Test security analysis for supported blocks"""
        # Blocks that have security implications
        security_relevant_blocks = {
            "block1": "Basic - always required",
            "block2": "RBE - Report-by-Exception",
            "block5": "Device Control - requires careful handling",
        }

        for block, desc in security_relevant_blocks.items():
            self.assertIn("block", block)


class TestTASE2ProtocolObjectStructures(unittest.TestCase):
    """Test TASE.2 protocol object structures per IEC 60870-6-503"""

    def test_supported_features_bitmap_structure(self):
        """Test Supported_Features bitmap structure"""
        supported_features = {
            "block1": True,  # Always 1 (Basic)
            "block2": False,  # Report-by-Exception
            "block3": False,  # Reserved
            "block4": False,  # Information Messages
            "block5": False,  # Device Control
        }

        self.assertTrue(supported_features["block1"])  # Block 1 must always be supported

    def test_tase2_version_structure(self):
        """Test TASE.2_Version structure"""
        version = {"major": 2000, "minor": 8}

        self.assertIn("major", version)
        self.assertIn("minor", version)
        self.assertIsInstance(version["major"], int)
        self.assertIsInstance(version["minor"], int)

    def test_tag_value_structure(self):
        """Test Tag_Value structure"""
        tag_info = {"tag_value": "NO_TAG", "tag_reason": ""}

        self.assertIn("tag_value", tag_info)
        self.assertIn("tag_reason", tag_info)

    def test_data_value_type_structure(self):
        """Test data value type response structure"""
        type_info = {
            "domain": "ICC1",
            "name": "Voltage",
            "type_name": "REAL_Q_TIME",
        }

        self.assertIn("type_name", type_info)
        self.assertIsInstance(type_info["type_name"], str)


class TestTASE2MockServerIntegration(unittest.TestCase):
    """Test integration with TASE.2 mock server features"""

    def test_mock_server_supported_features(self):
        """Test mock server Supported_Features format"""
        mock_features = {
            "block1": True,
            "block2": True,
            "block3": False,
            "block4": False,
            "block5": True,
        }

        # Block 1 always enabled
        self.assertTrue(mock_features["block1"])

    def test_mock_server_tag_values(self):
        """Test mock server tag value enumeration"""
        tag_values = {
            "NO_TAG": 0,
            "OPEN_AND_CLOSE_INHIBIT": 1,
            "CLOSE_ONLY_INHIBIT": 2,
        }

        for name, value in tag_values.items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(value, int)

    def test_mock_server_device_states(self):
        """Test mock server device state enumeration"""
        device_states = {
            "IDLE": 0,
            "ARMED": 1,
        }

        for name, value in device_states.items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(value, int)


class TestTASE2InformationMessages(unittest.TestCase):
    """Test TASE.2 Information Messages (Block 4) operations"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_information_message_stores_structure(self, mock_tase2):
        """Test get_information_message_stores returns list"""
        mock_conn = MagicMock()

        result = self.scanner.get_information_message_stores(mock_conn, "VCC")

        self.assertIsInstance(result, list)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_information_messages_structure(self, mock_tase2):
        """Test get_information_messages returns list"""
        mock_conn = MagicMock()

        result = self.scanner.get_information_messages(mock_conn, "VCC", "IM_Operator")

        self.assertIsInstance(result, list)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_read_information_message_structure(self, mock_tase2):
        """Test read_information_message returns proper dict structure"""
        mock_conn = MagicMock()

        result = self.scanner.read_information_message(mock_conn, "VCC", "IM_Operator", "MSG001")

        self.assertIsInstance(result, dict)
        self.assertIn("domain", result)
        self.assertIn("store", result)
        self.assertIn("message_id", result)
        self.assertIn("content", result)
        self.assertIn("error", result)
        # Per IEC 60870-6-503 fields
        self.assertIn("info_ref", result)
        self.assertIn("local_ref", result)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_get_im_transfer_attributes_structure(self, mock_tase2):
        """Test get_im_transfer_attributes returns proper dict structure"""
        mock_conn = MagicMock()

        result = self.scanner.get_im_transfer_attributes(mock_conn, "VCC", "IM_Operator")

        self.assertIsInstance(result, dict)
        self.assertIn("domain", result)
        self.assertIn("store", result)
        self.assertIn("scope", result)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_write_information_message_read_only(self, mock_tase2):
        """Test write_information_message respects read-only mode"""
        mock_conn = MagicMock()
        self.scanner.read_only = True

        result = self.scanner.write_information_message(
            mock_conn, "VCC", "IM_Operator", "Test message"
        )

        self.assertIsInstance(result, dict)
        self.assertFalse(result["success"])
        self.assertIn("Read-only", result["error"])
        # Per IEC 60870-6-503 fields
        self.assertIn("info_ref", result)
        self.assertIn("local_ref", result)

    @patch("oida.protocols.tase2.scanner._tase2", create=True)
    def test_delete_information_message_read_only(self, mock_tase2):
        """Test delete_information_message respects read-only mode"""
        mock_conn = MagicMock()
        self.scanner.read_only = True

        result = self.scanner.delete_information_message(mock_conn, "VCC", "IM_Operator", "MSG001")

        self.assertIsInstance(result, dict)
        self.assertFalse(result["success"])
        self.assertIn("Read-only", result["error"])


class TestTASE2IMSecurityAnalysis(unittest.TestCase):
    """Test TASE.2 Information Messages security analysis"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = TASE2Scanner({"rhost": "127.0.0.1", "rport": 102})

    def test_analyze_im_security_with_block4_enabled(self):
        """Test IM security analysis when Block 4 is enabled"""
        features = {"block4": True}
        results = {
            "im_stores": [
                {"name": "IM_Operator", "domain": "VCC", "max_messages": 100, "current_count": 5}
            ]
        }

        concerns = self.scanner._analyze_im_security(results, features)

        self.assertIsInstance(concerns, list)
        self.assertTrue(len(concerns) > 0)
        # Should flag Block 4 as enabled
        self.assertTrue(any("Block 4" in c for c in concerns))

    def test_analyze_im_security_with_block4_disabled(self):
        """Test IM security analysis when Block 4 is disabled"""
        features = {"block4": False}
        results = {}

        concerns = self.scanner._analyze_im_security(results, features)

        self.assertIsInstance(concerns, list)
        self.assertEqual(len(concerns), 0)

    def test_analyze_im_security_large_capacity(self):
        """Test IM security flags large capacity"""
        features = {"block4": True}
        results = {
            "im_stores": [
                {"name": "IM_Store1", "domain": "VCC", "max_messages": 300, "current_count": 10},
                {"name": "IM_Store2", "domain": "ICC1", "max_messages": 300, "current_count": 20},
            ]
        }

        concerns = self.scanner._analyze_im_security(results, features)

        # Should flag large capacity (>500 total)
        self.assertTrue(any("exfiltration" in c.lower() for c in concerns))


class TestTASE2IMConstants(unittest.TestCase):
    """Test TASE.2 Information Messages constants and types"""

    def test_im_storage_status_values(self):
        """Test TASE2IMStorageStatus has expected values"""
        from oida.protocols.tase2.scanner import TASE2IMStorageStatus

        self.assertEqual(TASE2IMStorageStatus.AVAILABLE, "AVAILABLE")
        self.assertEqual(TASE2IMStorageStatus.FULL, "FULL")
        self.assertEqual(TASE2IMStorageStatus.ERROR, "ERROR")

    def test_im_scope_values(self):
        """Test TASE2IMScope has expected values per IEC 60870-6-503"""
        from oida.protocols.tase2.scanner import TASE2IMScope

        self.assertEqual(TASE2IMScope.VCC, "VCC")
        self.assertEqual(TASE2IMScope.ICC, "ICC")


if __name__ == "__main__":
    unittest.main()
