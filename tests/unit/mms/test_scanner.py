#!/usr/bin/env python3
"""
Comprehensive test suite for MMS (IEC 61850) protocol scanner
Tests both mock interactions and real protocol functionality

The scanner runs on pyiec61850-ng's high-level ``MMSClient``. Discovery /
read / server-info tests pass a ``MagicMock()`` standing in for that client
(``connection``) and stub its high-level methods (``get_logical_devices`` etc.);
connect() tests patch ``_Lib.MMSClient`` / ``_Lib.require`` so no real socket
is opened.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

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
    """Test MMS scanner against a mocked high-level MMSClient connection."""

    def setUp(self):
        """Set up test environment"""
        self.scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 5})

    def test_discover_logical_devices_with_mock(self):
        """_discover_logical_devices delegates to connection.get_logical_devices()."""
        connection = MagicMock()
        connection.get_logical_devices.return_value = ["LD0", "LD1"]

        result = self.scanner._discover_logical_devices(connection)

        connection.get_logical_devices.assert_called_once_with()
        self.assertEqual([d["name"] for d in result], ["LD0", "LD1"])
        self.assertTrue(all(d["accessible"] for d in result))

    def test_get_logical_nodes_with_mock(self):
        """_get_logical_nodes delegates to connection.get_logical_nodes(device)."""
        connection = MagicMock()
        connection.get_logical_nodes.return_value = ["LLN0", "MMXU1"]

        result = self.scanner._get_logical_nodes(connection, "PROT")

        connection.get_logical_nodes.assert_called_once_with("PROT")
        self.assertEqual([n["name"] for n in result], ["LLN0", "MMXU1"])
        self.assertEqual(result[0]["full_reference"], "PROT/LLN0")

    def test_get_data_objects_with_mock(self):
        """_get_data_objects delegates to connection.get_data_objects(device, ln)."""
        connection = MagicMock()
        connection.get_data_objects.return_value = ["Mod", "Beh"]

        result = self.scanner._get_data_objects(connection, "PROT", "LLN0")

        connection.get_data_objects.assert_called_once_with("PROT", "LLN0")
        self.assertEqual([o["name"] for o in result], ["Mod", "Beh"])
        self.assertEqual(result[0]["full_reference"], "PROT/LLN0.Mod")

    def test_get_server_info_with_mock(self):
        """_get_server_info combines get_server_identity() and device count."""
        connection = MagicMock()
        connection.get_logical_devices.return_value = ["LD0", "LD1"]
        connection.get_server_identity.return_value = SimpleNamespace(
            vendor="TestVendor", model="TestModel", revision="1.0"
        )

        result = self.scanner._get_server_info(connection)

        self.assertEqual(result.get("vendor"), "TestVendor")
        self.assertEqual(result.get("model"), "TestModel")
        self.assertEqual(result.get("revision"), "1.0")
        self.assertEqual(result.get("logical_device_count"), 2)

    def test_empty_logical_devices(self):
        """Test handling of empty logical device list"""
        connection = MagicMock()
        connection.get_logical_devices.return_value = []

        result = self.scanner._discover_logical_devices(connection)

        self.assertEqual(len(result), 0)

    def test_exception_handling_in_discovery(self):
        """Test exception handling during discovery"""
        connection = MagicMock()
        connection.get_logical_devices.side_effect = Exception("Connection lost")

        result = self.scanner._discover_logical_devices(connection)

        # Should return empty list, not crash
        self.assertEqual(len(result), 0)

    def test_connect_returns_client_and_emits_finding(self):
        """connect() builds an MMSClient, calls .connect(host, port), returns it."""
        client = MagicMock()
        self.scanner.logger = MagicMock()
        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "MMSClient", return_value=client) as ctor,
        ):
            result = self.scanner.connect()

        self.assertIs(result, client)
        ctor.assert_called_once_with(timeout=self.scanner.timeout * 1000)
        client.connect.assert_called_once_with("127.0.0.1", 102)
        # cleartext-transport security finding is emitted on success
        self.scanner.logger.security_finding.assert_called_once()

    def test_connect_returns_none_on_connection_failed(self):
        """connect() returns None when MMSClient.connect raises ConnectionFailedError."""

        class _ConnFailed(Exception):
            pass

        client = MagicMock()
        client.connect.side_effect = _ConnFailed("refused")
        self.scanner.logger = MagicMock()
        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "ConnectionFailedError", _ConnFailed),
            patch.object(_Lib, "MMSClient", return_value=client),
        ):
            result = self.scanner.connect()

        self.assertIsNone(result)
        self.scanner.logger.security_finding.assert_not_called()

    def test_disconnect_delegates_to_client(self):
        """disconnect() calls connection.disconnect()."""
        connection = MagicMock()
        self.scanner.disconnect(connection)
        connection.disconnect.assert_called_once_with()

    def test_disconnect_none_is_noop(self):
        """disconnect(None) must not raise."""
        self.scanner.disconnect(None)

    def test_disconnected_operations(self):
        """Test run_scan handles a failed connection gracefully (no real socket).

        Mocks the connection layer so connect() returns None, exercising the
        run_scan() connection-failure path without opening a real socket.
        """
        with (
            patch.object(MMSScanner, "check_dependencies", return_value=True),
            patch.object(MMSScanner, "test_connectivity", return_value=False),
            patch.object(MMSScanner, "connect", return_value=None),
            patch.object(MMSScanner, "export_results"),
        ):
            results = self.scanner.run_scan()

        # Should handle disconnection gracefully (no crash, structured error)
        self.assertIsInstance(results, dict)
        self.assertEqual(results.get("error"), "connection_failed")


class TestMMSErrorHandling(unittest.TestCase):
    """Test MMS error handling scenarios (connection layer mocked, no real sockets)."""

    def test_connection_timeout(self):
        """Test that a failed/timed-out connection yields a structured error."""
        scanner = MMSScanner(
            {
                "rhost": "192.168.254.254",  # Non-routable address
                "rport": 102,
                "timeout": 1,  # Very short timeout
            }
        )

        with (
            patch.object(MMSScanner, "check_dependencies", return_value=True),
            patch.object(MMSScanner, "test_connectivity", return_value=False),
            patch.object(MMSScanner, "connect", return_value=None),
            patch.object(MMSScanner, "export_results"),
        ):
            result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("error"), "connection_failed")

    def test_missing_dependencies(self):
        """Test that run_scan short-circuits cleanly when deps are unavailable."""
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 2})

        with patch.object(MMSScanner, "check_dependencies", return_value=False):
            result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("error"), "missing_dependencies")

    def test_mms_protocol_errors(self):
        """Test that an exception raised by connect() is captured as a string error."""
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102})

        with (
            patch.object(MMSScanner, "check_dependencies", return_value=True),
            patch.object(MMSScanner, "test_connectivity", return_value=True),
            patch.object(MMSScanner, "connect", side_effect=Exception("MMS protocol error")),
            patch.object(MMSScanner, "export_results"),
        ):
            result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIsInstance(result["error"], str)
        self.assertIn("MMS protocol error", result["error"])


class TestMMSIntegration(unittest.TestCase):
    """Integration tests for MMS scanner"""

    def test_complete_mms_scan_workflow(self):
        """Test the complete MMS scanning workflow with the connection layer mocked.

        Exercises run_scan() end-to-end (connectivity -> connect -> discover)
        without any real socket, by mocking connect()/discover().
        """
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 10})

        # Test basic workflow
        protocol_name = scanner.get_protocol_name()
        default_port = scanner.get_default_port()
        dependencies_ok = scanner.check_dependencies()

        self.assertEqual(protocol_name, "IEC 61850 MMS")
        self.assertEqual(default_port, 102)
        # Note: dependencies_ok depends on pyiec61850-ng being installed
        self.assertIsInstance(dependencies_ok, bool)

        discover_result = {
            "server_info": {"vendor": "TestVendor"},
            "logical_devices": [],
            "logical_nodes": [],
            "data_objects": [],
            "security_analysis": {},
        }

        with (
            patch.object(MMSScanner, "check_dependencies", return_value=True),
            patch.object(MMSScanner, "test_connectivity", return_value=True),
            patch.object(MMSScanner, "connect", return_value=MagicMock()),
            patch.object(MMSScanner, "discover", return_value=discover_result),
            patch.object(MMSScanner, "disconnect"),
            patch.object(MMSScanner, "export_results"),
        ):
            result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        self.assertEqual(result, discover_result)

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

    def test_discover_method_returns_expected_structure(self):
        """Test that discover() returns expected result structure"""
        scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102})
        connection = MagicMock()
        connection.get_logical_devices.return_value = []
        connection.get_server_identity.return_value = SimpleNamespace(
            vendor=None, model=None, revision=None
        )

        result = scanner.discover(connection)

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
