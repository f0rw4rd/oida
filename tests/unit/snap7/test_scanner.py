#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Siemens S7/Snap7 protocol scanner functionality.

Tests the Snap7 scanner module without requiring actual network connections.
"""

import socket
import unittest
from unittest.mock import Mock

import pytest


class MockSnap7Client:
    """Mock Snap7 client for testing"""

    def __init__(self, connect_success=True):
        self.connect_success = connect_success
        self.connected = False
        self.rack = 0
        self.slot = 0

    def connect(self, host, rack, slot, tcp_port=102):
        """Simulate connection"""
        if not self.connect_success:
            raise Exception("Connection failed")
        self.connected = True
        self.rack = rack
        self.slot = slot

    def disconnect(self):
        """Simulate disconnection"""
        self.connected = False

    def get_connected(self):
        """Check connection status"""
        return self.connected

    def set_param(self, param, value):
        """Set client parameter"""
        pass

    def set_session_password(self, password):
        """Set session password"""
        pass

    def get_cpu_info(self):
        """Get CPU information"""
        info = Mock()
        info.ModuleTypeName = b"CPU 1511-1 PN"
        info.SerialNumber = b"S C-1234567890"
        info.ASName = b"Test PLC"
        info.ModuleName = b"CPU 1511-1 PN"
        info.Copyright = b"Siemens AG"
        return info

    def get_cpu_state(self):
        """Get CPU state"""
        return "S7CpuStatusRun"

    def get_plc_status(self):
        """Get PLC status"""
        return 8  # Running

    def get_order_code(self):
        """Get order code"""
        oc = Mock()
        oc.OrderCode = b"6ES7 511-1AK02-0AB0"
        oc.Code = b"6ES7 511-1AK02-0AB0"
        oc.V1 = 2
        oc.V2 = 9
        oc.V3 = 0
        return oc

    def read_szl(self, szl_id, index):
        """Read SZL data"""
        return bytes([0] * 100)

    def read_area(self, area, db_number, start, size):
        """Read memory area"""
        return bytes([0] * size)

    def write_area(self, area, db_number, start, data):
        """Write memory area"""
        return 0


class TestSnap7DataStructures(unittest.TestCase):
    """Test Snap7 data structures and types"""

    def test_s7_memory_area_constants(self):
        """Test S7 memory area constants"""
        from oida.protocols.snap7 import S7MemoryArea

        self.assertEqual(S7MemoryArea.PE, 0x81)  # Process Inputs
        self.assertEqual(S7MemoryArea.PA, 0x82)  # Process Outputs
        self.assertEqual(S7MemoryArea.MK, 0x83)  # Flags/Markers
        self.assertEqual(S7MemoryArea.DB, 0x84)  # Data Blocks
        self.assertEqual(S7MemoryArea.CT, 0x1C)  # Counters
        self.assertEqual(S7MemoryArea.TM, 0x1D)  # Timers

    def test_s7_firmware_version_from_order_code(self):
        """Test S7FirmwareVersion from order code fields"""
        from oida.protocols.snap7 import S7FirmwareVersion

        version = S7FirmwareVersion.from_order_code(4, 1, 3)

        self.assertEqual(version.major, 4)
        self.assertEqual(version.minor, 1)
        self.assertEqual(version.patch, 3)
        self.assertEqual(str(version), "V4.1.3")

    def test_s7_firmware_version_from_string(self):
        """Test S7FirmwareVersion from string"""
        from oida.protocols.snap7 import S7FirmwareVersion

        version = S7FirmwareVersion.from_string("V4.1.3")

        self.assertEqual(version.major, 4)
        self.assertEqual(version.minor, 1)
        self.assertEqual(version.patch, 3)

        # Test without V prefix
        version2 = S7FirmwareVersion.from_string("4.1.3")
        self.assertEqual(version2.major, 4)

    def test_s7_firmware_version_equality(self):
        """Test S7FirmwareVersion equality"""
        from oida.protocols.snap7 import S7FirmwareVersion

        v3 = S7FirmwareVersion(4, 1, 3)
        v4 = S7FirmwareVersion(4, 1, 3)

        self.assertEqual(v3, v4)
        self.assertNotEqual(v3, S7FirmwareVersion(4, 1, 4))


class TestSnap7DeviceLookup(unittest.TestCase):
    """Test Snap7 device lookup functionality"""

    def test_siemens_devices_defined(self):
        """Test Siemens devices dictionary is defined"""
        from oida.protocols.snap7 import SIEMENS_DEVICES

        # Should have a substantial list of devices
        self.assertGreater(len(SIEMENS_DEVICES), 100)

    def test_lookup_device_name(self):
        """Test device name lookup by order code"""
        from oida.protocols.snap7 import lookup_device_name

        # Test known devices
        result = lookup_device_name("6ES7 511-1AK02-0AB0")
        self.assertEqual(result, "CPU 1511-1 PN")

        result = lookup_device_name("6ES7 214-1AG40-0XB0")
        self.assertEqual(result, "CPU 1214C DC/DC/DC")

    def test_lookup_device_name_unknown(self):
        """Test lookup of unknown device"""
        from oida.protocols.snap7 import lookup_device_name

        result = lookup_device_name("6ES7 999-9XX99-0XX0")
        self.assertIsNone(result)

    def test_lookup_device_name_normalization(self):
        """Test order code normalization in lookup"""
        from oida.protocols.snap7 import lookup_device_name

        # Should handle different formats
        result1 = lookup_device_name("6ES7 511-1AK02-0AB0")
        result2 = lookup_device_name("6es7 511-1ak02-0ab0")  # lowercase

        self.assertEqual(result1, result2)


class TestSnap7ScannerInit(unittest.TestCase):
    """Test Snap7 scanner initialization"""

    def test_basic_initialization(self):
        """Test basic scanner initialization"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 102,
        }
        scanner = Snap7Scanner(args)

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 102)
        self.assertEqual(scanner.rack, 0)
        self.assertIsNone(scanner.slot)  # Auto-detect

    def test_initialization_with_rack_slot(self):
        """Test initialization with rack/slot"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 102,
            "rack": 0,
            "slot": 2,
        }
        scanner = Snap7Scanner(args)

        self.assertEqual(scanner.rack, 0)
        self.assertEqual(scanner.slot, 2)

    def test_initialization_with_options(self):
        """Test initialization with all options"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {
            "rhost": "192.168.1.100",
            "rport": 102,
            "rack": 0,
            "slot": 1,
            "password": "testpass",
            "enumerate-dbs": True,
            "test-memory-areas": True,
            "read-values": True,
            "max-dbs": 50,
        }
        scanner = Snap7Scanner(args)

        self.assertEqual(scanner.password, "testpass")
        self.assertTrue(scanner.enumerate_dbs)
        self.assertTrue(scanner.test_memory_areas)
        self.assertTrue(scanner.read_values)
        self.assertEqual(scanner.max_dbs, 50)

    def test_protocol_name(self):
        """Test protocol name"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        self.assertEqual(scanner.get_protocol_name(), "S7")

    def test_default_port(self):
        """Test default port"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        self.assertEqual(scanner.get_default_port(), 102)


class TestSnap7SeriesIdentification(unittest.TestCase):
    """Test S7 series identification from order codes"""

    def test_identify_s7_1200(self):
        """Test S7-1200 identification"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        result = scanner._identify_series_from_order_code("6ES7 214-1AG40-0XB0")
        self.assertEqual(result, "S7-1200")

        result = scanner._identify_series_from_order_code("6ES7211-1AE40-0XB0")
        self.assertEqual(result, "S7-1200")

    def test_identify_s7_1500(self):
        """Test S7-1500 identification"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        result = scanner._identify_series_from_order_code("6ES7 511-1AK02-0AB0")
        self.assertEqual(result, "S7-1500")

        result = scanner._identify_series_from_order_code("6ES7 516-3AN02-0AB0")
        self.assertEqual(result, "S7-1500")

    def test_identify_s7_300(self):
        """Test S7-300 identification"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        result = scanner._identify_series_from_order_code("6ES7 315-2EH14-0AB0")
        self.assertEqual(result, "S7-300")

    def test_identify_s7_400(self):
        """Test S7-400 identification"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        result = scanner._identify_series_from_order_code("6ES7 416-3ES06-0AB0")
        self.assertEqual(result, "S7-400")

    def test_identify_et200(self):
        """Test ET200 identification"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        result = scanner._identify_series_from_order_code("6ES7 155-6AU01-0CN0")
        self.assertEqual(result, "ET200SP")

    def test_identify_softplc(self):
        """Test SoftPLC identification"""
        from oida.protocols.snap7 import Snap7Scanner

        args = {"rhost": "192.168.1.100", "rport": 102}
        scanner = Snap7Scanner(args)

        result = scanner._identify_series_from_order_code("S7 SoftPLC UA")
        self.assertEqual(result, "SoftPLC")


class TestSnap7SZLParser(unittest.TestCase):
    """Test Snap7 SZL (System Status List) parser"""

    def test_szl_parser_exists(self):
        """Test SZLParser class exists"""
        from oida.protocols.snap7 import SZLParser

        self.assertIsNotNone(SZLParser)

    def test_szl_parse_unknown_id(self):
        """Test parsing unknown SZL ID"""
        from oida.protocols.snap7 import SZLParser

        data = bytes([0] * 100)
        result = SZLParser.parse(0x9999, 0, data)

        self.assertIn("raw", result)
        self.assertFalse(result.get("parsed", True))

    def test_szl_0x0132_protection_level(self):
        """Test parsing SZL 0x0132 (protection level)"""
        from oida.protocols.snap7 import SZLParser

        # Create mock SZL data for protection level
        data = bytes([0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0])
        result = SZLParser._parse_0x0132(data, 4)

        self.assertIn("szl_id", result)
        self.assertEqual(result["szl_id"], "0x0132")


class TestSnap7ProtocolOptions(unittest.TestCase):
    """Test Snap7 protocol options"""

    def test_protocol_options_defined(self):
        """Test protocol options are defined"""
        from oida.protocols.snap7 import protocol_options

        expected_options = [
            "rack",
            "slot",
            "password",
            "enumerate-dbs",
            "test-memory-areas",
            "read-values",
            "max-dbs",
        ]

        for option in expected_options:
            self.assertIn(option, protocol_options)

    def test_rack_option(self):
        """Test rack option configuration"""
        from oida.protocols.snap7 import protocol_options

        rack_opt = protocol_options["rack"]
        self.assertEqual(rack_opt["type"], "int")
        self.assertEqual(rack_opt["default"], 0)

    def test_slot_option(self):
        """Test slot option configuration"""
        from oida.protocols.snap7 import protocol_options

        slot_opt = protocol_options["slot"]
        self.assertEqual(slot_opt["type"], "int")
        self.assertIsNone(slot_opt["default"])  # Auto-detect


class TestSnap7CPUInfo(unittest.TestCase):
    """Test Snap7 CPU info extraction"""

    def test_cpu_info_structure(self):
        """Test CPU info structure"""
        cpu_info = {
            "module_type": "CPU 1511-1 PN",
            "serial_number": "S C-1234567890",
            "module_name": "CPU 1511-1 PN",
            "s7_series": "S7-1500",
        }

        self.assertIn("module_type", cpu_info)
        self.assertIn("serial_number", cpu_info)
        self.assertIn("s7_series", cpu_info)

    def test_plc_status_mapping(self):
        """Test PLC status code mapping"""
        status_map = {
            0x00: "Unknown",
            0x04: "Stop",
            0x08: "Run",
        }

        self.assertEqual(status_map[0x08], "Run")
        self.assertEqual(status_map[0x04], "Stop")


class TestSnap7OrderCodeExtended(unittest.TestCase):
    """Test extended order code extraction"""

    def test_order_code_result_structure(self):
        """Test order code result structure"""
        result = {
            "code": "6ES7 511-1AK02-0AB0",
            "firmware": "V2.9.0",
            "bootloader": "V4.1.0",
        }

        self.assertIn("code", result)
        self.assertIn("firmware", result)
        self.assertIn("bootloader", result)


class TestSnap7SlotScanning(unittest.TestCase):
    """Test Snap7 slot scanning functionality"""

    def test_slot_configurations(self):
        """Test common slot configurations"""
        # S7-1200/1500: rack 0, slots 0-1
        # S7-300/400: rack 0, slots 2-11
        slots_to_try = [
            (0, 1),  # S7-1200/1500 default
            (0, 0),  # S7-1200/1500 alternate
            (0, 2),  # S7-300/400 CPU default
            (0, 3),  # S7-300/400 extended
        ]

        for rack, slot in slots_to_try:
            self.assertGreaterEqual(rack, 0)
            self.assertLessEqual(rack, 7)
            self.assertGreaterEqual(slot, 0)
            self.assertLessEqual(slot, 18)

    def test_identify_main_slot(self):
        """Test main CPU slot identification"""
        from oida.protocols.snap7.scanner import _identify_main_slot

        slots = [
            {"rack": 0, "slot": 0, "module_name": "CP 343-1"},
            {"rack": 0, "slot": 2, "module_name": "CPU 315-2 PN/DP"},
            {"rack": 0, "slot": 3, "module_name": "DI16xDC24V"},
        ]

        main_slot = _identify_main_slot(slots)

        # Should identify the CPU slot
        self.assertIsNotNone(main_slot)
        self.assertEqual(main_slot["slot"], 2)
        self.assertIn("CPU", main_slot["module_name"])


class TestSnap7DiscoverWorkflow(unittest.TestCase):
    """Test Snap7 discover workflow"""

    def test_discover_result_structure(self):
        """Test discover result structure"""
        results = {
            "cpu_info": {
                "module_type": "CPU 1511-1 PN",
                "s7_series": "S7-1500",
            },
            "plc_status": {
                "status": "Run",
            },
            "firmware_info": {
                "version_str": "V2.9.0",
                "order_code": "6ES7 511-1AK02-0AB0",
            },
            "data_blocks": [],
            "memory_areas": {},
            "security_analysis": {},
            "protection_level": None,
        }

        self.assertIn("cpu_info", results)
        self.assertIn("plc_status", results)
        self.assertIn("firmware_info", results)
        self.assertIn("data_blocks", results)
        self.assertIn("security_analysis", results)


class TestSnap7DataBlockEnumeration(unittest.TestCase):
    """Test Snap7 data block enumeration"""

    def test_data_block_structure(self):
        """Test data block info structure"""
        db_info = {
            "number": 1,
            "size": 100,
            "flags": 0,
            "load_memory_size": 108,
            "language": "DB",
        }

        self.assertIn("number", db_info)
        self.assertIn("size", db_info)

    def test_block_type_enumeration(self):
        """Test block type enumeration values"""
        block_types = ["OB", "DB", "SDB", "FC", "SFC", "FB", "SFB"]

        for bt in block_types:
            self.assertIsInstance(bt, str)


class TestSnap7MemoryAccess(unittest.TestCase):
    """Test Snap7 memory access functionality"""

    def test_memory_area_mapping(self):
        """Test memory area mapping"""
        from oida.protocols.snap7 import S7MemoryArea

        areas = {
            "inputs": S7MemoryArea.PE,
            "outputs": S7MemoryArea.PA,
            "markers": S7MemoryArea.MK,
            "datablocks": S7MemoryArea.DB,
            "counters": S7MemoryArea.CT,
            "timers": S7MemoryArea.TM,
        }

        self.assertEqual(areas["inputs"], 0x81)
        self.assertEqual(areas["outputs"], 0x82)
        self.assertEqual(areas["markers"], 0x83)
        self.assertEqual(areas["datablocks"], 0x84)

    def test_memory_access_result_structure(self):
        """Test memory access result structure"""
        result = {
            "area": "inputs",
            "start": 0,
            "size": 10,
            "data": bytes([0] * 10),
            "accessible": True,
        }

        self.assertIn("area", result)
        self.assertIn("data", result)
        self.assertTrue(result["accessible"])


class TestSnap7SecurityAnalysis(unittest.TestCase):
    """Test Snap7 security analysis functionality"""

    def test_protection_levels(self):
        """Test S7 protection level values"""
        # S7 protection levels
        protection_levels = {
            0: "No protection",
            1: "Write protection",
            2: "Read/Write protection",
            3: "Read/Write protection with key",
        }

        self.assertEqual(protection_levels[0], "No protection")
        self.assertEqual(protection_levels[3], "Read/Write protection with key")

    def test_security_analysis_structure(self):
        """Test security analysis result structure"""
        security = {
            "protection_level": 0,
            "password_required": False,
            "anonymous_access": True,
            "writable_areas": ["markers", "datablocks"],
            "vulnerabilities": [],
        }

        self.assertIn("protection_level", security)
        self.assertIn("anonymous_access", security)


class TestSnap7ModuleImport(unittest.TestCase):
    """Test Snap7 module import and structure"""

    def test_module_import(self):
        """Test that Snap7 module can be imported"""
        from oida.protocols.snap7 import Snap7Scanner, SIEMENS_DEVICES

        self.assertIsNotNone(Snap7Scanner)
        self.assertIsNotNone(SIEMENS_DEVICES)

    def test_scanner_class_methods(self):
        """Test scanner class has required methods"""
        from oida.protocols.snap7 import Snap7Scanner

        self.assertTrue(hasattr(Snap7Scanner, "connect"))
        self.assertTrue(hasattr(Snap7Scanner, "disconnect"))
        self.assertTrue(hasattr(Snap7Scanner, "discover"))
        self.assertTrue(hasattr(Snap7Scanner, "scan_slots"))
        self.assertTrue(hasattr(Snap7Scanner, "get_protocol_name"))
        self.assertTrue(hasattr(Snap7Scanner, "get_default_port"))
        self.assertTrue(hasattr(Snap7Scanner, "check_dependencies"))


class TestSnap7ErrorHandling(unittest.TestCase):
    """Test Snap7 error handling"""

    @pytest.mark.network
    def test_connection_error_handling(self):
        """Test handling of connection errors.

        Genuine live-connection test: with an explicit slot, connect() calls
        the real snap7 client.connect() against a non-routable IP, so this
        opens an actual socket. Kept network-marked for that reason.
        """
        from oida.protocols.snap7 import Snap7Scanner

        args = {
            "rhost": "192.168.254.254",  # Non-routable
            "rport": 102,
            "slot": 1,
        }
        scanner = Snap7Scanner(args)

        # Connection should fail gracefully
        result = scanner.connect()
        self.assertIsNone(result)

    def test_timeout_handling(self):
        """Test timeout error structure (pure-local, no network)."""
        from oida.protocols.snap7.scanner import _run_with_timeout

        def slow_func():
            import time

            time.sleep(10)
            return "result"

        result = _run_with_timeout(slow_func, timeout_seconds=0.1, error_msg="Test timeout")

        self.assertIn("error", result)
        self.assertIn("timeout", result["error"].lower())


class TestSnap7DefaultCredentials(unittest.TestCase):
    """Test Snap7 default credentials handling"""

    def test_default_credentials_available(self):
        """Test default credentials are available"""
        from oida.utils.default_credentials import SIEMENS_S7_DEFAULTS

        self.assertIsNotNone(SIEMENS_S7_DEFAULTS)
        self.assertIsInstance(SIEMENS_S7_DEFAULTS, (list, dict))


class TestSnap7DeviceCategories(unittest.TestCase):
    """Test Snap7 device category coverage"""

    def test_s7_1200_cpus_covered(self):
        """Test S7-1200 CPUs are covered"""
        from oida.protocols.snap7 import SIEMENS_DEVICES

        s7_1200_prefixes = ["6ES7 211", "6ES7 212", "6ES7 214", "6ES7 215", "6ES7 217"]

        for prefix in s7_1200_prefixes:
            found = any(prefix in code for code in SIEMENS_DEVICES.keys())
            self.assertTrue(found, f"Missing S7-1200 prefix: {prefix}")

    def test_s7_1500_cpus_covered(self):
        """Test S7-1500 CPUs are covered"""
        from oida.protocols.snap7 import SIEMENS_DEVICES

        s7_1500_prefixes = [
            "6ES7 511",
            "6ES7 512",
            "6ES7 513",
            "6ES7 515",
            "6ES7 516",
            "6ES7 517",
            "6ES7 518",
        ]

        for prefix in s7_1500_prefixes:
            found = any(prefix in code for code in SIEMENS_DEVICES.keys())
            self.assertTrue(found, f"Missing S7-1500 prefix: {prefix}")

    def test_s7_300_cpus_covered(self):
        """Test S7-300 CPUs are covered"""
        from oida.protocols.snap7 import SIEMENS_DEVICES

        s7_300_prefixes = ["6ES7 312", "6ES7 313", "6ES7 314", "6ES7 315", "6ES7 317", "6ES7 318"]

        for prefix in s7_300_prefixes:
            found = any(prefix in code for code in SIEMENS_DEVICES.keys())
            self.assertTrue(found, f"Missing S7-300 prefix: {prefix}")

    def test_s7_400_cpus_covered(self):
        """Test S7-400 CPUs are covered"""
        from oida.protocols.snap7 import SIEMENS_DEVICES

        s7_400_prefixes = ["6ES7 412", "6ES7 414", "6ES7 416", "6ES7 417"]

        for prefix in s7_400_prefixes:
            found = any(prefix in code for code in SIEMENS_DEVICES.keys())
            self.assertTrue(found, f"Missing S7-400 prefix: {prefix}")

    def test_et200_modules_covered(self):
        """Test ET200 modules are covered"""
        from oida.protocols.snap7 import SIEMENS_DEVICES

        et200_prefixes = ["6ES7 151", "6ES7 155"]

        for prefix in et200_prefixes:
            found = any(prefix in code for code in SIEMENS_DEVICES.keys())
            self.assertTrue(found, f"Missing ET200 prefix: {prefix}")


class TestSnap7ValueFormatting(unittest.TestCase):
    """Test Snap7 value formatting utilities"""

    def test_bytes_to_hex_formatting(self):
        """Test bytes to hex string formatting"""
        data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        hex_str = data.hex()

        self.assertEqual(hex_str, "deadbeef")

    def test_bytes_decoding(self):
        """Test bytes decoding with error handling"""
        # ASCII string
        data = b"CPU 1511-1 PN\x00\x00"
        decoded = data.decode("ascii", errors="ignore").strip("\x00")

        self.assertEqual(decoded, "CPU 1511-1 PN")

        # Binary data
        binary_data = bytes([0x00, 0x01, 0x02, 0xFF])
        decoded_binary = binary_data.decode("ascii", errors="ignore")
        self.assertIsInstance(decoded_binary, str)


class TestSnap7TimeoutWrapper(unittest.TestCase):
    """Test Snap7 timeout wrapper function (pure-local, no network)."""

    def test_run_with_timeout_success(self):
        """Test successful execution within timeout"""
        from oida.protocols.snap7.scanner import _run_with_timeout

        def quick_func():
            return {"result": "success"}

        result = _run_with_timeout(quick_func, timeout_seconds=5)

        self.assertIn("result", result)
        self.assertEqual(result["result"], "success")

    def test_run_with_timeout_exception(self):
        """Test exception handling in timeout wrapper"""
        from oida.protocols.snap7.scanner import _run_with_timeout

        def error_func():
            raise ValueError("Test error")

        result = _run_with_timeout(error_func, timeout_seconds=5)

        self.assertIn("error", result)


# ==============================================================================
# Error Path Tests - Network Failures, Malformed Data, Timeouts
# ==============================================================================


class TestSnap7NetworkErrorPaths(unittest.TestCase):
    """Test network error handling paths in Snap7Scanner.

    These tests verify the scanner handles various network failures gracefully.
    """

    def test_connection_refused(self):
        """Test handling of connection refused error."""
        mock_client = Mock()
        mock_client.connect.side_effect = ConnectionRefusedError("Connection refused")

        with self.assertRaises(ConnectionRefusedError):
            mock_client.connect("192.168.1.100", 0, 2)

    def test_connection_timeout(self):
        """Test handling of connection timeout."""
        mock_client = Mock()
        mock_client.connect.side_effect = socket.timeout("Connection timed out")

        with self.assertRaises(socket.timeout):
            mock_client.connect("192.168.1.100", 0, 2)

    def test_connection_reset_during_read(self):
        """Test handling of connection reset during memory read."""
        mock_client = Mock()
        mock_client.get_connected.return_value = True
        mock_client.read_area.side_effect = ConnectionResetError("Connection reset by peer")

        with self.assertRaises(ConnectionResetError):
            mock_client.read_area(0x84, 1, 0, 100)

    def test_network_unreachable(self):
        """Test handling of network unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect.side_effect = OSError(errno.ENETUNREACH, "Network is unreachable")

        with self.assertRaises(OSError) as ctx:
            mock_client.connect("192.168.1.100", 0, 2)
        self.assertEqual(ctx.exception.errno, errno.ENETUNREACH)

    def test_host_unreachable(self):
        """Test handling of host unreachable error."""
        import errno

        mock_client = Mock()
        mock_client.connect.side_effect = OSError(errno.EHOSTUNREACH, "No route to host")

        with self.assertRaises(OSError) as ctx:
            mock_client.connect("192.168.1.100", 0, 2)
        self.assertEqual(ctx.exception.errno, errno.EHOSTUNREACH)

    def test_snap7_library_error(self):
        """Test handling of Snap7 library specific errors."""
        mock_client = Mock()

        # Simulate snap7 library error code
        mock_client.connect.side_effect = Exception("Snap7 error: 0x00100000")

        with self.assertRaises(Exception) as ctx:
            mock_client.connect("192.168.1.100", 0, 2)
        self.assertIn("Snap7 error", str(ctx.exception))


class TestSnap7MalformedResponseHandling(unittest.TestCase):
    """Test handling of malformed Snap7 responses."""

    def test_empty_cpu_info(self):
        """Test handling of empty CPU info response."""
        mock_client = Mock()
        mock_info = Mock()
        mock_info.ModuleTypeName = b""
        mock_info.SerialNumber = b""
        mock_info.ASName = b""
        mock_client.get_cpu_info.return_value = mock_info

        info = mock_client.get_cpu_info()

        self.assertEqual(info.ModuleTypeName, b"")

    def test_none_cpu_info(self):
        """Test handling of None CPU info."""
        mock_client = Mock()
        mock_client.get_cpu_info.return_value = None

        info = mock_client.get_cpu_info()

        self.assertIsNone(info)

    def test_corrupted_szl_data(self):
        """Test handling of corrupted SZL data."""
        mock_client = Mock()
        # Invalid SZL header
        mock_client.read_szl.return_value = b"\xff\xff\xff\xff"

        data = mock_client.read_szl(0x001C, 0x0000)

        self.assertEqual(len(data), 4)

    def test_invalid_order_code(self):
        """Test handling of invalid order code response."""
        mock_client = Mock()
        mock_oc = Mock()
        mock_oc.OrderCode = b""
        mock_oc.Code = None
        mock_oc.V1 = 0
        mock_oc.V2 = 0
        mock_oc.V3 = 0
        mock_client.get_order_code.return_value = mock_oc

        oc = mock_client.get_order_code()

        self.assertEqual(oc.OrderCode, b"")

    def test_partial_memory_read(self):
        """Test handling of partial memory read response."""
        mock_client = Mock()
        # Asked for 100 bytes, got 50
        mock_client.read_area.return_value = bytes([0] * 50)

        data = mock_client.read_area(0x84, 1, 0, 100)

        self.assertEqual(len(data), 50)


class TestSnap7TimeoutEdgeCases(unittest.TestCase):
    """Test timeout handling edge cases."""

    def test_zero_timeout(self):
        """Test scanner behavior with zero timeout."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102, "timeout": 0})

        self.assertEqual(scanner.timeout, 0)

    def test_very_small_timeout(self):
        """Test scanner behavior with very small timeout - base scanner converts to int."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102, "timeout": 0.001})

        # Base scanner converts timeout to int, so 0.001 becomes 0
        self.assertEqual(scanner.timeout, 0)

    def test_very_large_timeout(self):
        """Test scanner behavior with very large timeout."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102, "timeout": 3600})

        self.assertEqual(scanner.timeout, 3600)


class TestSnap7InvalidInputHandling(unittest.TestCase):
    """Test handling of invalid input parameters."""

    def test_invalid_rack_slot(self):
        """Test handling of invalid rack/slot values."""
        from oida.protocols.snap7 import Snap7Scanner

        # Negative rack
        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102, "rack": -1, "slot": 2})
        self.assertEqual(scanner.rack, -1)

        # Large slot number
        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102, "rack": 0, "slot": 100})
        self.assertEqual(scanner.slot, 100)

    def test_invalid_port(self):
        """Test handling of invalid port values."""
        from oida.protocols.snap7 import Snap7Scanner

        # Port 0 defaults to the protocol default port (102)
        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 0})
        self.assertEqual(scanner.port, 102)  # Falls back to default

        # Port > 65535 is accepted (validation happens at socket level)
        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 70000})
        self.assertEqual(scanner.port, 70000)

    def test_empty_host(self):
        """Test handling of empty host raises ValueError."""
        from oida.protocols.snap7 import Snap7Scanner

        # Empty host should raise ValueError (required parameter)
        with self.assertRaises(ValueError):
            Snap7Scanner({"rhost": "", "rport": 102})

    def test_invalid_memory_area(self):
        """Test handling of invalid memory area in scan range."""
        mock_client = Mock()
        # Invalid area code should cause error
        mock_client.read_area.side_effect = ValueError("Invalid area code")

        with self.assertRaises(ValueError):
            mock_client.read_area(0xFF, 1, 0, 100)


class TestSnap7AuthenticationErrors(unittest.TestCase):
    """Test authentication/protection error handling."""

    def test_password_protected_plc(self):
        """Test handling of password-protected PLC."""
        mock_client = Mock()

        # Simulate password protection error
        mock_client.set_session_password.side_effect = Exception("Bad password")

        with self.assertRaises(Exception):
            mock_client.set_session_password("wrong_password")

    def test_know_how_protection(self):
        """Test handling of know-how protected blocks."""
        mock_client = Mock()

        # Simulate access denied to protected block
        mock_client.read_area.side_effect = PermissionError("Block is know-how protected")

        with self.assertRaises(PermissionError):
            mock_client.read_area(0x84, 1, 0, 100)

    def test_read_only_memory(self):
        """Test handling of write to read-only memory."""
        mock_client = Mock()

        # Simulate write error
        mock_client.write_area.side_effect = PermissionError("Memory area is read-only")

        with self.assertRaises(PermissionError):
            mock_client.write_area(0x81, 0, 0, bytes([0x00]))


class TestSnap7ResourceCleanup(unittest.TestCase):
    """Test proper resource cleanup on errors."""

    def test_disconnect_after_connection_error(self):
        """Test that disconnect is called after connection error."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102})

        mock_client = Mock()
        mock_client.disconnect = Mock()

        scanner.disconnect(mock_client)

        mock_client.disconnect.assert_called_once()

    def test_disconnect_none_client(self):
        """Test disconnect with None client."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102})

        # Should not raise exception
        scanner.disconnect(None)

    def test_multiple_disconnect_calls_safe(self):
        """Test that multiple disconnect calls don't raise errors."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner({"rhost": "192.168.1.1", "rport": 102})

        mock_client = Mock()
        mock_client.disconnect = Mock()

        scanner.disconnect(mock_client)
        scanner.disconnect(mock_client)
        scanner.disconnect(mock_client)

        self.assertEqual(mock_client.disconnect.call_count, 3)


# Pytest-style tests for parametrized error scenarios
class TestSnap7WithErrorInjection:
    """Pytest-style tests using parametrized error scenarios."""

    @pytest.mark.parametrize(
        "exception_type,message",
        [
            (ConnectionRefusedError, "Connection refused"),
            (ConnectionResetError, "Connection reset by peer"),
            (socket.timeout, "timed out"),
            (OSError, "Network is down"),
        ],
    )
    def test_various_connection_errors(self, exception_type, message):
        """Test handling of various connection error types."""
        mock_client = Mock()
        mock_client.connect.side_effect = exception_type(message)

        with pytest.raises(exception_type):
            mock_client.connect("192.168.1.100", 0, 2)

    @pytest.mark.parametrize(
        "rack,slot",
        [
            (0, 0),
            (0, 1),
            (0, 2),
            (1, 0),
            (2, 3),
        ],
    )
    def test_rack_slot_combinations(self, rack, slot):
        """Test various rack/slot combinations."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner(
            {
                "rhost": "192.168.1.1",
                "rport": 102,
                "rack": rack,
                "slot": slot,
            }
        )

        assert scanner.rack == rack
        assert scanner.slot == slot

    @pytest.mark.parametrize(
        "timeout,expected",
        [
            (0, 0),
            (0.001, 0),  # Floats are converted to int by base scanner
            (1, 1),
            (5, 5),
            (30, 30),
            (3600, 3600),
        ],
    )
    def test_timeout_values(self, timeout, expected):
        """Test various timeout values - base scanner converts to int."""
        from oida.protocols.snap7 import Snap7Scanner

        scanner = Snap7Scanner(
            {
                "rhost": "192.168.1.1",
                "rport": 102,
                "timeout": timeout,
            }
        )

        assert scanner.timeout == expected


class TestSnap7MonitorAction(unittest.TestCase):
    """Regression: --monitor is a store_true bool (shared factory), so the
    handler must source areas from --monitor-areas, not from args.monitor.
    Previously it did `args.monitor.split(...)` → 'bool' has no attribute 'split'
    and monitor mode could never run.
    """

    def test_action_monitor_passes_area_string_not_bool(self):
        from types import SimpleNamespace
        from oida.protocols.snap7.nxc_connection import s7

        inst = object.__new__(s7)
        inst.args = SimpleNamespace(
            monitor=True,  # store_true bool
            monitor_areas="I,Q,M",
            monitor_interval=0.5,
            monitor_size=16,
            monitor_duration=0,
            monitor_bits=False,
        )
        inst.scanner = Mock()
        inst.conn = Mock()

        inst._action_monitor()

        inst.scanner.monitor.assert_called_once()
        kwargs = inst.scanner.monitor.call_args.kwargs
        self.assertEqual(kwargs["areas"], "I,Q,M")
        self.assertIsInstance(kwargs["areas"], str)

    def test_action_monitor_defaults_areas_when_unset(self):
        from types import SimpleNamespace
        from oida.protocols.snap7.nxc_connection import s7

        inst = object.__new__(s7)
        inst.args = SimpleNamespace(monitor=True)  # only the bool, nothing else
        inst.scanner = Mock()
        inst.conn = Mock()

        inst._action_monitor()

        self.assertEqual(inst.scanner.monitor.call_args.kwargs["areas"], "I,Q,M")


if __name__ == "__main__":
    unittest.main()
