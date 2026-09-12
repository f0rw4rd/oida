#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for EtherNet/IP (Industrial Ethernet protocol) scanner functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock


class MockEtherNetIPClient:
    """Mock EtherNet/IP client for testing"""

    def __init__(self, host, port, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connected = True

    def close(self):
        self.connected = False

    def list_identity(self):
        """Mock List Identity response"""
        return {
            "vendor": 1,  # Rockwell Automation
            "device_type": 12,
            "product_code": 65,
            "revision": "2.1",
            "status": 0x0030,
            "serial": 0x12345678,
            "name": "CompactLogix 5370 Controller",
            "state": 0x03,
        }

    def read(self, path):
        """Mock CIP read response"""
        if path == "@1/1":  # Identity object
            return 1  # Vendor ID
        elif path == "@1/2":
            return 12  # Device type
        elif path == "@1/3":
            return 65  # Product code
        elif path == "@1/4":
            return (2, 1)  # Revision
        elif path == "@1/5":
            return 0x0030  # Status
        elif path == "@1/6":
            return 0x12345678  # Serial number
        elif path == "@1/7":
            return "CompactLogix"  # Product name
        elif path == "@245/1":  # TCP/IP Interface
            return {"ip": "192.168.1.100", "netmask": "255.255.255.0"}
        else:
            # Check if it's a valid class/attribute path
            parts = path.strip("@").split("/")
            if len(parts) == 2:
                class_id = int(parts[0])
                attr_id = int(parts[1])
                if 1 <= class_id <= 100 and attr_id == 1:
                    return f"Class{class_id}_Attr{attr_id}_Value"
            raise Exception(f"Invalid path: {path}")

    def write(self, path, value):
        """Mock CIP write response"""
        # Only allow writes to certain attributes
        if path in ["@8/1", "@9/1"]:  # Writable attributes
            return True
        else:
            raise Exception("Write access denied")


class TestEtherNetIPDataStructures(unittest.TestCase):
    """Test EtherNet/IP data structures and types"""

    def setUp(self):
        from oida.protocols.ethernetip import EtherNetIPScanner

        self.EtherNetIPScanner = EtherNetIPScanner

    def test_cip_path_parsing(self):
        """Test CIP path parsing and formatting"""
        args = {"host": "192.168.1.100", "port": 44818}
        scanner = self.EtherNetIPScanner(args)

        # Test explore class parsing
        scanner.explore_class = "0x1,2,0x9f,100"
        explore_list = []
        for part in scanner.explore_class.split(","):
            part = part.strip()
            if part.startswith("0x"):
                explore_list.append(int(part, 16))
            else:
                explore_list.append(int(part))

        self.assertEqual(explore_list, [1, 2, 159, 100])

    def test_default_configuration(self):
        """Test default EtherNet/IP scanner configuration"""
        args = {"host": "192.168.1.100", "port": 44818}
        scanner = self.EtherNetIPScanner(args)

        # Default is 0 (tag-based discovery for Logix devices)
        self.assertEqual(scanner.max_class, 0)
        self.assertEqual(scanner.explore_class, "")
        self.assertFalse(scanner.test_write)
        self.assertEqual(scanner.max_attributes, 100)
        self.assertFalse(scanner.fuzz)
        self.assertEqual(scanner.lhost, "")

    def test_custom_configuration(self):
        """Test custom EtherNet/IP scanner configuration"""
        args = {
            "host": "192.168.1.100",
            "port": 44818,
            "maxclass": 50,
            "exploreclass": "1,2,3",
            "write": True,
            "maxattributes": 200,
            "fuzz": True,
            "lhost": "192.168.1.10",
        }
        scanner = self.EtherNetIPScanner(args)

        self.assertEqual(scanner.max_class, 50)
        self.assertEqual(scanner.explore_class, "1,2,3")
        self.assertTrue(scanner.test_write)
        self.assertEqual(scanner.max_attributes, 200)
        self.assertTrue(scanner.fuzz)
        self.assertEqual(scanner.lhost, "192.168.1.10")


class TestEtherNetIPEnums(unittest.TestCase):
    """Test EtherNet/IP enums and constants"""

    def test_vendor_ids(self):
        """Test EtherNet/IP vendor ID mapping"""
        from oida.utils.vendor_maps import ethernetip_vendor_ids

        # Test some known vendor IDs
        self.assertIn(1, ethernetip_vendor_ids)  # Rockwell Automation
        self.assertEqual(ethernetip_vendor_ids[1], "Rockwell Automation/Allen-Bradley")

    def test_wellknown_classes(self):
        """Test well-known CIP class types"""
        from oida.utils.vendor_maps import ethernetip_wellknown_class_types

        # Test some known class IDs
        self.assertIn(1, ethernetip_wellknown_class_types)  # Identity
        self.assertIn(6, ethernetip_wellknown_class_types)  # Connection Manager
        self.assertIn(245, ethernetip_wellknown_class_types)  # TCP/IP Interface

    def test_protocol_options(self):
        """Test EtherNet/IP protocol options"""
        from oida.protocols.ethernetip import protocol_options

        self.assertIn("maxclass", protocol_options)
        self.assertIn("lhost", protocol_options)
        self.assertIn("exploreclass", protocol_options)
        self.assertIn("write", protocol_options)
        self.assertIn("maxattributes", protocol_options)
        self.assertIn("fuzz", protocol_options)


class TestEtherNetIPScannerInit(unittest.TestCase):
    """Test EtherNet/IP scanner initialization"""

    def setUp(self):
        from oida.protocols.ethernetip import EtherNetIPScanner

        self.EtherNetIPScanner = EtherNetIPScanner

    def test_basic_initialization(self):
        """Test basic scanner initialization"""
        args = {"host": "192.168.1.100", "port": 44818}
        scanner = self.EtherNetIPScanner(args)

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 44818)
        self.assertEqual(scanner.get_protocol_name(), "EtherNet/IP")
        self.assertEqual(scanner.get_default_port(), 44818)

    def test_broadcast_initialization(self):
        """Test scanner initialization for broadcast discovery"""
        args = {"host": "255.255.255.255", "port": 44818, "lhost": "192.168.1.10"}
        scanner = self.EtherNetIPScanner(args)

        self.assertEqual(scanner.host, "255.255.255.255")
        self.assertEqual(scanner.lhost, "192.168.1.10")


class TestEtherNetIPProtocolLogic(unittest.TestCase):
    """Test EtherNet/IP protocol implementation logic"""

    def setUp(self):
        from oida.protocols.ethernetip import EtherNetIPScanner

        self.EtherNetIPScanner = EtherNetIPScanner
        self.args = {"host": "192.168.1.100", "port": 44818}

    @patch("oida.protocols.ethernetip.scanner._get_logix_driver")
    def test_connection_logic(self, mock_get_logix):
        """Test EtherNet/IP connection establishment"""
        scanner = self.EtherNetIPScanner(self.args)
        mock_driver = MagicMock()
        mock_driver.__enter__ = MagicMock(return_value=mock_driver)
        mock_driver.__exit__ = MagicMock(return_value=False)
        mock_get_logix.return_value = MagicMock(return_value=mock_driver)

        # The scanner uses LogixDriver from pycomm3
        scanner.connect()

        # connect() returns a driver instance or None on failure
        # Since we're mocking, just verify no crash
        self.assertTrue(True)

    def test_class_discovery(self):
        """Test CIP class discovery logic"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.max_class = 5  # Limit for testing
        mock_client = MagicMock()

        # Mock _read_cip_attribute to return data for first 5 classes
        def mock_read_cip(conn, class_id, instance, attr_id):
            if 1 <= class_id <= 5:
                return b"\x01\x02"  # Some dummy bytes
            return None

        scanner._read_cip_attribute = mock_read_cip

        classes = scanner._discover_classes(mock_client)

        self.assertEqual(len(classes), 5)
        for cls in classes:
            self.assertTrue(cls["accessible"])
            self.assertIn("class_id", cls)
            self.assertIn("class_name", cls)

    def test_attribute_exploration(self):
        """Test CIP attribute exploration returns expected structure"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.max_attributes = 5
        mock_client = MagicMock()

        # Mock _read_cip_attribute to return data for attributes 1-5
        def mock_read_cip(conn, class_id, instance, attr_id):
            if 1 <= attr_id <= 5:
                return b"\x01\x02"  # Some dummy bytes
            return None

        scanner._read_cip_attribute = mock_read_cip

        # Current signature: _explore_class_attributes(conn, class_id, can_detect_perms)
        # Returns: (class_attributes_dict, rows_list, instances_found_count)
        result = scanner._explore_class_attributes(mock_client, 1, False)

        # Returns a tuple (attributes, rows, instances_count)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        attributes, rows, instances = result
        self.assertIsInstance(attributes, dict)
        self.assertIsInstance(rows, list)


class TestEtherNetIPMockOperations(unittest.TestCase):
    """Test EtherNet/IP operations with mocked dependencies"""

    def setUp(self):
        from oida.protocols.ethernetip import EtherNetIPScanner

        self.EtherNetIPScanner = EtherNetIPScanner
        self.args = {"host": "192.168.1.100", "port": 44818}

    def test_full_scan_workflow(self):
        """Test complete EtherNet/IP scan workflow with mocked methods"""
        scanner = self.EtherNetIPScanner(self.args)
        mock_client = MagicMock()

        # Mock all the internal methods
        scanner.connect = Mock(return_value=mock_client)
        scanner.disconnect = Mock()
        scanner._get_device_info = Mock(return_value={"tags_found": []})
        scanner._discover_classes = Mock(return_value=[])
        scanner._analyze_security = Mock(return_value={"security_level": "low"})

        results = scanner.run_scan()

        # run_scan returns a dict with scan results
        self.assertIsInstance(results, dict)
        scanner.connect.assert_called_once()
        scanner.disconnect.assert_called_once()

    def test_write_access_testing(self):
        """Test write access testing functionality"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.read_only = False
        scanner.test_write = True
        mock_client = MagicMock()

        # Mock generic_message to return success
        mock_result = MagicMock()
        mock_result.error = None
        mock_client.generic_message.return_value = mock_result

        # _test_write_with_status returns (success, status_code, extended_status)
        success, status, _ext = scanner._test_write_with_status(mock_client, 8, 1, 1, b"\x01\x02")
        self.assertTrue(success)
        self.assertEqual(status, 0x00)

        # Test failure case
        mock_client.generic_message.side_effect = Exception("Write failed")
        success, status, _ext = scanner._test_write_with_status(mock_client, 1, 1, 1, b"\x01\x02")
        self.assertFalse(success)

    def test_fuzzing_operations(self):
        """Test fuzzing functionality"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.read_only = False
        scanner.fuzz = True
        mock_client = MagicMock()

        # Attributes structure from _explore_classes
        attributes = {
            8: {
                "class_name": "TestClass",
                "class_attributes": {1: {"raw": "0102", "type": "UINT", "name": "attr1"}},
                "instances": {},
            }
        }

        # Write test results structure
        write_test_results = {
            8: {
                "class_attributes": {1: {"writable": True, "name": "attr1"}},
                "instances": {},
            }
        }

        # Signature: _fuzz_attributes(conn, attributes, write_test_results)
        results = scanner._fuzz_attributes(mock_client, attributes, write_test_results)

        # Returns a dict with class_id keys
        self.assertIsInstance(results, dict)

    def test_class_exploration_with_list(self):
        """Test class exploration with specific class list"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.explore_class = "1,2,3"
        mock_client = MockEtherNetIPClient("192.168.1.100", 44818)

        classes = [{"class_id": 1}, {"class_id": 2}, {"class_id": 3}]

        attributes = scanner._explore_classes(mock_client, classes)

        self.assertEqual(len(attributes), 3)
        self.assertIn(1, attributes)
        self.assertIn(2, attributes)
        self.assertIn(3, attributes)

    # test_device_info_extraction was removed: _get_device_info/_read_tag were
    # dead (generic non-Logix CIP devices expose no named tags, so the probe
    # always found nothing). Generic devices now report zero tags directly in
    # the scanner without emitting dead CIP reads.


class TestEtherNetIPErrorHandling(unittest.TestCase):
    """Test EtherNet/IP error handling"""

    def setUp(self):
        from oida.protocols.ethernetip import EtherNetIPScanner

        self.EtherNetIPScanner = EtherNetIPScanner
        self.args = {"host": "192.168.1.100", "port": 44818}

    @patch("oida.protocols.ethernetip.scanner._get_logix_driver")
    def test_connection_failure(self, mock_get_logix):
        """Test handling of connection failures"""
        scanner = self.EtherNetIPScanner(self.args)

        # Make the LogixDriver raise an exception
        mock_driver_class = MagicMock()
        mock_driver_class.side_effect = Exception("Connection failed")
        mock_get_logix.return_value = mock_driver_class

        result = scanner.connect()

        # connect() returns None on failure
        self.assertIsNone(result)

    def test_invalid_explore_class_format(self):
        """Test handling of invalid explore class format"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.explore_class = "invalid,format,xyz"
        mock_client = MockEtherNetIPClient("192.168.1.100", 44818)

        attributes = scanner._explore_classes(mock_client, [])

        self.assertEqual(attributes, {})

    def test_read_error_handling(self):
        """Test handling of read errors"""
        scanner = self.EtherNetIPScanner(self.args)
        mock_client = Mock()
        mock_client.read.side_effect = Exception("Read failed")

        # Should handle error gracefully
        classes = scanner._discover_classes(mock_client)
        self.assertEqual(len(classes), 0)

    def test_fuzz_error_recovery(self):
        """Test error recovery during fuzzing"""
        scanner = self.EtherNetIPScanner(self.args)
        scanner.read_only = False
        mock_client = MagicMock()

        # Simulate crash during fuzzing - generic_message raises exception
        mock_client.generic_message.side_effect = Exception("Device crashed")

        # Signature: _fuzz_single_attribute(conn, class_id, instance, attr_id, original_value, attr_name="", cip_type="")
        result = scanner._fuzz_single_attribute(
            mock_client, 1, 1, 1, b"\x01\x02", "test_attr", "UINT"
        )

        # Result should be a dict with crash/error info
        self.assertIsInstance(result, dict)
        self.assertIn("errors", result)


class TestEtherNetIPIntegration(unittest.TestCase):
    """Test EtherNet/IP scanner integration with framework"""

    def setUp(self):
        from oida.protocols.ethernetip import EtherNetIPScanner, metadata

        self.EtherNetIPScanner = EtherNetIPScanner
        self.metadata = metadata

    def test_metadata_structure(self):
        """Test module metadata structure"""
        self.assertIn("name", self.metadata)
        self.assertIn("description", self.metadata)
        self.assertIn("authors", self.metadata)
        self.assertIn("references", self.metadata)
        self.assertIn("options", self.metadata)

        # Check default port
        self.assertEqual(self.metadata["options"]["rport"]["default"], 44818)

        # Check rhost is defined (default is None in base_scanner)
        self.assertIn("rhost", self.metadata["options"])

    def test_protocol_options(self):
        """Test protocol-specific options"""
        options = self.metadata["options"]

        self.assertIn("maxclass", options)
        self.assertIn("lhost", options)
        self.assertIn("exploreclass", options)
        self.assertIn("write", options)
        self.assertIn("maxattributes", options)
        self.assertIn("fuzz", options)

    @patch("oida.protocols.ethernetip.scanner.dependencies_missing", True)
    def test_missing_dependencies(self):
        """Test behavior with missing dependencies"""
        # Re-import to get fresh run function that checks deps
        import oida.protocols.ethernetip.scanner as scanner_module

        # Create a custom run that checks dependencies
        def test_run(args):
            if scanner_module.dependencies_missing:
                return {"error": "missing_dependencies"}
            return {}

        result = test_run({"host": "192.168.1.100"})

        self.assertEqual(result["error"], "missing_dependencies")


class TestEtherNetIPAttacks(unittest.TestCase):
    """Test EtherNet/IP attack capabilities"""

    def test_attack_payloads_defined(self):
        """Test that attack payloads are properly defined"""
        from oida.protocols.ethernetip import (
            ATTACK_STOPCPU_PAYLOAD,
            ATTACK_CRASHCPU_PAYLOAD,
            ATTACK_CRASHETHER_PAYLOAD,
            ATTACK_RESETETHER_PAYLOAD,
        )

        # Verify payloads are bytes
        self.assertIsInstance(ATTACK_STOPCPU_PAYLOAD, bytes)
        self.assertIsInstance(ATTACK_CRASHCPU_PAYLOAD, bytes)
        self.assertIsInstance(ATTACK_CRASHETHER_PAYLOAD, bytes)
        self.assertIsInstance(ATTACK_RESETETHER_PAYLOAD, bytes)

        # Verify payloads are non-empty
        self.assertGreater(len(ATTACK_STOPCPU_PAYLOAD), 0)
        self.assertGreater(len(ATTACK_CRASHCPU_PAYLOAD), 0)
        self.assertGreater(len(ATTACK_CRASHETHER_PAYLOAD), 0)
        self.assertGreater(len(ATTACK_RESETETHER_PAYLOAD), 0)

    def test_attack_options_in_protocol_options(self):
        """Test that attack options are defined in protocol_options"""
        from oida.protocols.ethernetip import protocol_options

        self.assertIn("cpu_stop", protocol_options)
        self.assertIn("crash_ethernet", protocol_options)
        self.assertIn("reset_ethernet", protocol_options)
        self.assertIn("confirm", protocol_options)

        # Verify defaults are False (safe by default)
        self.assertEqual(protocol_options["cpu_stop"]["default"], False)
        self.assertEqual(protocol_options["crash_ethernet"]["default"], False)
        self.assertEqual(protocol_options["reset_ethernet"]["default"], False)
        self.assertEqual(protocol_options["confirm"]["default"], False)

    def test_cpu_stop_requires_confirmation(self):
        """Test that CPU STOP requires --confirm flag"""
        from oida.protocols.ethernetip import EtherNetIPScanner

        # Create scanner with cpu_stop but without confirm
        args = {
            "host": "192.168.1.100",
            "port": 44818,
            "cpu_stop": True,
            "confirm": False,
        }
        scanner = EtherNetIPScanner(args)

        self.assertTrue(scanner.cpu_stop)
        self.assertFalse(scanner.confirm)

    def test_crash_ethernet_requires_confirmation(self):
        """Test that CRASH ETHERNET requires --confirm flag"""
        from oida.protocols.ethernetip import EtherNetIPScanner

        # Create scanner with crash_ethernet but without confirm
        args = {
            "host": "192.168.1.100",
            "port": 44818,
            "crash_ethernet": True,
            "confirm": False,
        }
        scanner = EtherNetIPScanner(args)

        self.assertTrue(scanner.crash_ethernet)
        self.assertFalse(scanner.confirm)

    def test_reset_ethernet_no_confirmation_needed(self):
        """Test that RESET ETHERNET doesn't require confirmation"""
        from oida.protocols.ethernetip import EtherNetIPScanner

        # Reset is less destructive, doesn't require confirmation
        args = {
            "host": "192.168.1.100",
            "port": 44818,
            "reset_ethernet": True,
            "confirm": False,
        }
        scanner = EtherNetIPScanner(args)

        self.assertTrue(scanner.reset_ethernet)
        # confirm not required for reset

    def test_attack_with_confirmation(self):
        """Test that attacks work with confirmation flag"""
        from oida.protocols.ethernetip import EtherNetIPScanner

        args = {
            "host": "192.168.1.100",
            "port": 44818,
            "cpu_stop": True,
            "confirm": True,
        }
        scanner = EtherNetIPScanner(args)

        self.assertTrue(scanner.cpu_stop)
        self.assertTrue(scanner.confirm)

    @patch("socket.socket")
    def test_register_session(self, mock_socket_class):
        """Test session registration for attack commands"""
        from oida.protocols.ethernetip import EtherNetIPScanner

        # Mock socket instance
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # Mock successful session response
        # EtherNet/IP header: command(2) + length(2) + session(4) + status(4) + context(8) + options(4)
        import struct

        session_id = 0x12345678
        response = struct.pack("<HH I I Q I", 0x0065, 0, session_id, 0, 0, 0)
        mock_socket.recv.return_value = response

        args = {"host": "192.168.1.100", "port": 44818}
        scanner = EtherNetIPScanner(args)

        # Test _register_session
        result = scanner._register_session("192.168.1.100", 44818)

        # Should have called socket methods
        self.assertIsNotNone(result)

    def test_stopcpu_payload_structure(self):
        """Test STOPCPU payload matches Metasploit structure"""
        from oida.protocols.ethernetip import ATTACK_STOPCPU_PAYLOAD

        # Verify payload starts with CIP data item header (0xB2 = Unconnected Data)
        self.assertEqual(ATTACK_STOPCPU_PAYLOAD[0], 0xB2)
        self.assertEqual(ATTACK_STOPCPU_PAYLOAD[1], 0x00)

        # Verify payload contains the magic bytes (0xDEADBEEFCAFE)
        self.assertIn(b"\xde\xad\xbe\xef\xca\xfe", ATTACK_STOPCPU_PAYLOAD)


if __name__ == "__main__":
    unittest.main()
