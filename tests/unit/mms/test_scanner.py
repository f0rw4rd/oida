#!/usr/bin/env python3
"""
Comprehensive test suite for MMS (IEC 61850) protocol scanner
Tests both mock interactions and real protocol functionality

Note: Tests use @patch to mock the pyiec61850 library functions since
we use raw SWIG bindings, not a high-level wrapper API.
"""

import unittest
from unittest.mock import patch, MagicMock

import pytest

from oida.protocols.mms import MMSScanner, _Lib


class TestMMSScannerInit(unittest.TestCase):
    """Test MMS scanner initialization"""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values"""
        scanner = MMSScanner({"rhost": "192.168.1.100", "rport": 102})

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 102)
        self.assertEqual(scanner.get_protocol_name(), "IEC 61850 MMS")
        self.assertEqual(scanner.get_default_port(), 102)

    def test_scanner_init_custom_values(self):
        """Test scanner initialization with custom values"""
        scanner = MMSScanner({"rhost": "10.0.0.50", "rport": 8102, "timeout": 30, "debug": True})

        self.assertEqual(scanner.host, "10.0.0.50")
        self.assertEqual(scanner.port, 8102)
        self.assertEqual(scanner.timeout, 30)
        self.assertTrue(scanner.debug)

    def test_scanner_protocol_options(self):
        """Test scanner respects protocol-specific options"""
        scanner = MMSScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 102,
                "discover-logical-devices": True,
                "read-values": False,
                "test-write": False,
                "max-objects": 500,
            }
        )

        self.assertTrue(scanner.discover_logical_devices)
        self.assertFalse(scanner.read_values)
        self.assertFalse(scanner.test_write)
        self.assertEqual(scanner.max_objects, 500)


class TestMMSMockOperations(unittest.TestCase):
    """Test MMS scanner with mocked pyiec61850 library"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 5})

    def _create_mock_linked_list(self, items):
        """Create a mock LinkedList that yields items via LinkedList_getNext/getData"""
        mock_lib = MagicMock()

        # Create mock list nodes
        nodes = []
        for item in items:
            node = MagicMock()
            node.data = item.encode() if isinstance(item, str) else item
            nodes.append(node)

        # Add terminal None
        nodes.append(None)

        # Setup getNext to return each node in sequence
        head = MagicMock()
        call_count = [0]

        def mock_get_next(node):
            if call_count[0] >= len(nodes):
                return None
            result = nodes[call_count[0]]
            call_count[0] += 1
            return result

        mock_lib.LinkedList_getNext.side_effect = mock_get_next

        # Setup getData to return the data
        def mock_get_data(node):
            if node is None or not hasattr(node, "data"):
                return None
            return id(node)  # Return address-like value for ctypes conversion

        mock_lib.LinkedList_getData.side_effect = mock_get_data

        return mock_lib, head

    @patch.object(_Lib, "safe_linked_list_destroy")
    @patch.object(_Lib, "safe_linked_list_iter", return_value=iter([]))
    @patch.object(_Lib, "unpack_result", return_value=(MagicMock(), 0, True))
    @patch.object(_Lib, "iec61850")
    def test_discover_logical_devices_with_mock(
        self, mock_lib, mock_unpack, mock_iter, mock_destroy
    ):
        """Test _discover_logical_devices with mocked library"""
        mock_linked_list = MagicMock()
        mock_lib.IedConnection_getLogicalDeviceList.return_value = (mock_linked_list, 0)

        mock_connection = MagicMock()
        result = self.scanner._discover_logical_devices(mock_connection)

        mock_lib.IedConnection_getLogicalDeviceList.assert_called_once_with(mock_connection)
        self.assertEqual(len(result), 0)

    @patch.object(_Lib, "safe_linked_list_destroy")
    @patch.object(_Lib, "safe_linked_list_iter", return_value=iter([]))
    @patch.object(_Lib, "unpack_result", return_value=(MagicMock(), 0, True))
    @patch.object(_Lib, "iec61850")
    def test_get_logical_nodes_with_mock(self, mock_lib, mock_unpack, mock_iter, mock_destroy):
        """Test _get_logical_nodes with mocked library"""
        mock_linked_list = MagicMock()
        mock_lib.IedConnection_getLogicalDeviceDirectory.return_value = (mock_linked_list, 0)

        mock_connection = MagicMock()
        result = self.scanner._get_logical_nodes(mock_connection, "PROT")

        mock_lib.IedConnection_getLogicalDeviceDirectory.assert_called_once_with(
            mock_connection, "PROT"
        )
        self.assertEqual(len(result), 0)

    @patch.object(_Lib, "safe_linked_list_destroy")
    @patch.object(_Lib, "safe_linked_list_iter", return_value=iter([]))
    @patch.object(_Lib, "unpack_result", return_value=(MagicMock(), 0, True))
    @patch.object(_Lib, "iec61850")
    def test_get_data_objects_with_mock(self, mock_lib, mock_unpack, mock_iter, mock_destroy):
        """Test _get_data_objects with mocked library"""
        mock_linked_list = MagicMock()
        mock_lib.IedConnection_getLogicalNodeDirectory.return_value = (mock_linked_list, 0)
        mock_lib.ACSI_CLASS_DATA_OBJECT = 0

        mock_connection = MagicMock()
        result = self.scanner._get_data_objects(mock_connection, "PROT", "LLN0")

        self.assertEqual(len(result), 0)

    @patch.object(_Lib, "safe_linked_list_destroy")
    @patch.object(_Lib, "safe_linked_list_iter", return_value=iter([]))
    @patch.object(_Lib, "unpack_result", return_value=(MagicMock(), 0, True))
    @patch.object(_Lib, "safe_identity_destroy")
    @patch.object(_Lib, "safe_to_char_p", side_effect=lambda x: x)
    @patch.object(_Lib, "iec61850")
    def test_get_server_info_with_mock(
        self, mock_lib, mock_char_p, mock_id_destroy, mock_unpack, mock_iter, mock_destroy
    ):
        """Test _get_server_info with mocked library"""
        mock_mms_conn = MagicMock()
        mock_lib.IedConnection_getMmsConnection.return_value = mock_mms_conn

        mock_error = MagicMock()
        mock_lib.MmsError_create.return_value = mock_error

        mock_identity = MagicMock()
        mock_identity.vendorName = "TestVendor"
        mock_identity.modelName = "TestModel"
        mock_identity.revision = "1.0"
        mock_lib.MmsConnection_identify.return_value = mock_identity

        mock_connection = MagicMock()
        result = self.scanner._get_server_info(mock_connection)

        self.assertEqual(result.get("vendor"), "TestVendor")
        self.assertEqual(result.get("model"), "TestModel")
        self.assertEqual(result.get("revision"), "1.0")

    def test_empty_logical_devices(self):
        """Test handling of empty logical device list"""
        with (
            patch.object(_Lib, "safe_linked_list_destroy"),
            patch.object(_Lib, "unpack_result", return_value=(None, 0, False)),
            patch.object(_Lib, "iec61850") as mock_lib,
        ):
            mock_lib.IedConnection_getLogicalDeviceList.return_value = (None, 0)

            mock_connection = MagicMock()
            result = self.scanner._discover_logical_devices(mock_connection)

            self.assertEqual(len(result), 0)

    def test_exception_handling_in_discovery(self):
        """Test exception handling during discovery"""
        with (
            patch.object(_Lib, "safe_linked_list_destroy"),
            patch.object(_Lib, "iec61850") as mock_lib,
        ):
            mock_lib.IedConnection_getLogicalDeviceList.side_effect = Exception("Connection lost")

            mock_connection = MagicMock()
            result = self.scanner._discover_logical_devices(mock_connection)

            # Should return empty list, not crash
            self.assertEqual(len(result), 0)

    @pytest.mark.network
    def test_disconnected_operations(self):
        """Test operations when disconnected"""
        results = self.scanner.run_scan()

        # Should handle disconnection/missing deps gracefully
        self.assertIsInstance(results, dict)
        if "error" in results:
            # Accept connection errors or missing dependency errors
            error_lower = results["error"].lower()
            valid_errors = ["connection", "missing_dependencies", "dependency", "not available"]
            self.assertTrue(any(e in error_lower for e in valid_errors))


@pytest.mark.network
class TestMMSErrorHandling(unittest.TestCase):
    """Test MMS error handling scenarios"""

    def test_connection_timeout(self):
        """Test connection timeout scenarios"""
        scanner = MMSScanner(
            {
                "rhost": "192.168.254.254",  # Non-routable address
                "rport": 102,
                "timeout": 1,  # Very short timeout
            }
        )

        result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        if "error" in result:
            # Accept connection, timeout, or missing dependency errors
            valid_errors = [
                "connection_failed",
                "timeout",
                "connection_timeout",
                "missing_dependencies",
            ]
            error_val = result["error"].lower()
            self.assertTrue(any(e in error_val for e in valid_errors))

    def test_invalid_port(self):
        """Test invalid port handling"""
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 99999, "timeout": 2})

        result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        # Should handle invalid port gracefully (either error or empty result)

    def test_mms_protocol_errors(self):
        """Test MMS protocol-specific error handling"""
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102})
        result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        if "error" in result:
            self.assertIsInstance(result["error"], str)


class TestMMSIntegration(unittest.TestCase):
    """Integration tests for MMS scanner"""

    @pytest.mark.network
    def test_complete_mms_scan_workflow(self):
        """Test complete MMS scanning workflow"""
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 10})

        # Test basic workflow
        protocol_name = scanner.get_protocol_name()
        default_port = scanner.get_default_port()
        dependencies_ok = scanner.check_dependencies()

        self.assertEqual(protocol_name, "IEC 61850 MMS")
        self.assertEqual(default_port, 102)
        # Note: dependencies_ok depends on pyiec61850-ng being installed
        self.assertIsInstance(dependencies_ok, bool)

        # Test connectivity check
        connectivity = scanner.test_connectivity("127.0.0.1", 102)
        self.assertIsInstance(connectivity, bool)

        # Test scan execution
        result = scanner.run_scan()
        self.assertIsInstance(result, dict)

    def test_mms_with_different_configurations(self):
        """Test MMS scanner with different configurations"""
        configurations = [
            {"rhost": "127.0.0.1", "rport": 102, "timeout": 5},
            {"rhost": "127.0.0.1", "rport": 8102, "timeout": 10},  # Alternative port
            {"rhost": "192.168.1.100", "rport": 102, "timeout": 15},
        ]

        for config in configurations:
            scanner = MMSScanner(config)
            self.assertEqual(scanner.host, config["rhost"])
            self.assertEqual(scanner.port, config["rport"])
            self.assertEqual(scanner.timeout, config["timeout"])

    @patch.object(_Lib, "safe_linked_list_destroy")
    @patch.object(_Lib, "safe_linked_list_iter", return_value=iter([]))
    @patch.object(_Lib, "safe_identity_destroy")
    @patch.object(_Lib, "unpack_result", return_value=(None, 0, False))
    @patch.object(_Lib, "safe_to_char_p", return_value=None)
    @patch.object(_Lib, "iec61850")
    def test_discover_method_returns_expected_structure(
        self, mock_lib, mock_char_p, mock_unpack, mock_id_destroy, mock_iter, mock_destroy
    ):
        """Test that discover() returns expected result structure"""
        mock_lib.IedConnection_getMmsConnection.return_value = None
        mock_lib.IedConnection_getLogicalDeviceList.return_value = (None, 0)

        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102})
        mock_conn = MagicMock()

        result = scanner.discover(mock_conn)

        expected_keys = [
            "server_info",
            "logical_devices",
            "logical_nodes",
            "data_objects",
            "security_analysis",
        ]
        for key in expected_keys:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
