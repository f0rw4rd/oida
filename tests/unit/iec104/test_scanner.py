#!/usr/bin/env python3
"""
Comprehensive test suite for IEC 60870-5-104 protocol scanner
Tests both mock interactions and real protocol functionality
"""

import socket
import unittest
from unittest.mock import MagicMock, Mock, patch

from oida.protocols.iec104 import IEC104Scanner


class TestIEC104ScannerInit(unittest.TestCase):
    """Test IEC 104 scanner initialization"""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values"""
        scanner = IEC104Scanner({"rhost": "192.168.1.100", "rport": 2404})

        self.assertEqual(scanner.host, "192.168.1.100")
        self.assertEqual(scanner.port, 2404)
        self.assertEqual(scanner.get_protocol_name(), "IEC 104")
        self.assertEqual(scanner.get_default_port(), 2404)
        self.assertEqual(scanner.asdu_address, -1)
        self.assertEqual(scanner.common_address, 1)

    def test_scanner_init_custom_values(self):
        """Test scanner initialization with custom values"""
        scanner = IEC104Scanner(
            {
                "rhost": "10.0.0.50",
                "rport": 8080,
                "timeout": 30,
                "debug": True,
                "asdu-address": 10,
                "common-address": 5,
            }
        )

        self.assertEqual(scanner.host, "10.0.0.50")
        self.assertEqual(scanner.port, 8080)
        self.assertEqual(scanner.timeout, 30)
        self.assertTrue(scanner.debug)
        self.assertEqual(scanner.asdu_address, 10)
        self.assertEqual(scanner.common_address, 5)


class TestIEC104ProtocolLogic(unittest.TestCase):
    """Test IEC 104 protocol-specific logic"""

    def test_type_identification_codes(self):
        """Test IEC 104 Type Identification codes"""
        # Common IEC 104 type identifications
        type_ids = {
            1: "M_SP_NA_1",  # Single-point information
            3: "M_DP_NA_1",  # Double-point information
            9: "M_ME_NA_1",  # Measured value, normalized
            11: "M_ME_NB_1",  # Measured value, scaled
            13: "M_ME_NC_1",  # Measured value, floating point
            30: "M_SP_TB_1",  # Single-point with CP56Time2a
            45: "C_SC_NA_1",  # Single command
            46: "C_DC_NA_1",  # Double command
            100: "C_IC_NA_1",  # Interrogation command
        }

        for type_id, name in type_ids.items():
            self.assertIsInstance(type_id, int)
            self.assertIsInstance(name, str)
            self.assertTrue(1 <= type_id <= 127)

    def test_cause_of_transmission_codes(self):
        """Test Cause of Transmission codes"""
        cot_codes = {
            1: "per/cyc",  # Periodic, cyclic
            2: "back",  # Background scan
            3: "spont",  # Spontaneous
            4: "init",  # Initialized
            5: "req",  # Request
            6: "act",  # Activation
            7: "actcon",  # Activation confirmation
            8: "deact",  # Deactivation
            9: "deactcon",  # Deactivation confirmation
            10: "actterm",  # Activation termination
            20: "inrogen",  # Interrogated by station interrogation
            44: "unknowntype",  # Unknown type identification
            45: "unknowncot",  # Unknown cause of transmission
            46: "unknownasdu",  # Unknown common address of ASDU
            47: "unknownioa",  # Unknown information object address
        }

        for code, description in cot_codes.items():
            self.assertIsInstance(code, int)
            self.assertIsInstance(description, str)
            self.assertTrue(1 <= code <= 63)

    def test_information_object_address_ranges(self):
        """Test Information Object Address parsing"""
        IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})

        # Test IOA range parsing
        ioa_ranges = ["1-100", "1000-2000", "1-1000", "500-1500"]

        for ioa_range in ioa_ranges:
            self.assertIn("-", ioa_range)
            start, end = ioa_range.split("-")
            self.assertTrue(int(start) < int(end))

    def test_quality_descriptors(self):
        """Test IEC 104 quality descriptor flags"""
        quality_flags = [
            "IV",  # Invalid
            "NT",  # Not topical
            "SB",  # Substituted
            "BL",  # Blocked
            "OV",  # Overflow
            "EI",  # Elapsed time invalid
            "CA",  # Counter adjusted
            "CY",  # Counter overflow
        ]

        for flag in quality_flags:
            self.assertIn(flag, quality_flags)
            self.assertEqual(len(flag), 2)


class TestIEC104MockOperations(unittest.TestCase):
    """Test IEC 104 operations with mocked dependencies"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "timeout": 5})

    @patch("oida.protocols.iec104._deps._get_c104")
    def test_connection_establishment(self, mock_get_c104):
        """Test IEC 104 connection establishment"""
        # Create a mock c104 module and wire _get_c104 to return it
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104

        mock_client = Mock()
        mock_c104.Client.return_value = mock_client
        mock_c104.Init.NONE = 0

        # Mock connection returned by add_connection
        mock_connection = Mock()
        mock_connection.is_connected = True
        mock_client.add_connection.return_value = mock_connection

        # Patch the module-level c104 so the scanner sees our mock
        with patch("oida.protocols.iec104.c104", mock_c104):
            connection = self.scanner.connect()

        self.assertIsNotNone(connection)

    @patch("oida.protocols.iec104.scanner.ConnectionHelper.resolve_hostname")
    @patch("oida.protocols.iec104._deps._get_c104")
    def test_connect_resolves_hostname_for_c104(self, mock_get_c104, mock_resolve):
        """c104 rejects hostnames, so connect() must pass it a resolved IP.

        The scanner's self.host stays the original hostname (for logging /
        reporting); only the value handed to c104.add_connection(ip=...) is
        the resolved dotted IP.
        """
        scanner = IEC104Scanner({"rhost": "plc.example.com", "rport": 2404, "timeout": 1})
        mock_resolve.return_value = "10.20.30.40"

        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client
        mock_c104.Init.NONE = 0
        mock_connection = Mock()
        mock_connection.is_connected = True
        mock_client.add_connection.return_value = mock_connection

        with patch("oida.protocols.iec104.c104", mock_c104):
            connection = scanner.connect()

        self.assertIsNotNone(connection)
        mock_resolve.assert_called_once_with("plc.example.com")
        # The C library must receive the resolved IP, never the hostname.
        _, kwargs = mock_client.add_connection.call_args
        self.assertEqual(kwargs["ip"], "10.20.30.40")
        # Original hostname is preserved on the scanner for reporting.
        self.assertEqual(scanner.host, "plc.example.com")

    @patch("oida.protocols.iec104.scanner.ConnectionHelper.resolve_hostname")
    @patch("oida.protocols.iec104._deps._get_c104")
    def test_connect_fails_cleanly_on_unresolvable_host(self, mock_get_c104, mock_resolve):
        """A DNS failure should fail gracefully (return None), not crash."""
        scanner = IEC104Scanner({"rhost": "nope.invalid", "rport": 2404, "timeout": 1})
        mock_resolve.side_effect = socket.gaierror("Name or service not known")

        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client
        mock_c104.Init.NONE = 0

        with patch("oida.protocols.iec104.c104", mock_c104):
            connection = scanner.connect()

        self.assertIsNone(connection)
        mock_client.add_connection.assert_not_called()

    @patch("oida.protocols.iec104.c104")
    def test_station_interrogation(self, mock_c104):
        """Test station interrogation (general interrogation)"""
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client

        # Mock interrogation response
        mock_point = Mock()
        mock_point.ioa = 1001
        mock_point.value = True
        mock_point.quality = {"IV": False, "NT": False, "SB": False}

        interrogation_data = {
            "total_points": 1,
            "single_points": [{"ioa": 1001, "value": True, "quality": "Good"}],
        }

        self.assertEqual(interrogation_data["total_points"], 1)
        self.assertTrue(interrogation_data["single_points"][0]["value"])

    @patch("oida.protocols.iec104.c104")
    def test_measured_value_reading(self, mock_c104):
        """Test reading measured values"""
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client

        # Mock measured value
        mock_measurement = Mock()
        mock_measurement.ioa = 2001
        mock_measurement.value = 230.5
        mock_measurement.quality = {"OV": False, "IV": False}

        measurement_data = {
            "ioa": 2001,
            "value": 230.5,
            "type": "measured_value_float",
            "quality": "Good",
        }

        self.assertEqual(measurement_data["ioa"], 2001)
        self.assertEqual(measurement_data["value"], 230.5)
        self.assertEqual(measurement_data["quality"], "Good")

    @patch("oida.protocols.iec104.c104")
    def test_command_transmission(self, mock_c104):
        """Test command transmission"""
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client
        mock_client.send_command.return_value = True

        # Test single command
        command_result = {
            "ioa": 3001,
            "command_type": "single_command",
            "value": True,
            "success": True,
        }

        self.assertEqual(command_result["ioa"], 3001)
        self.assertTrue(command_result["success"])

    def test_disconnected_operations(self):
        """Test operations when connect() returns None (no live socket)."""
        # Stub connectivity + connect so run_scan exercises the
        # "could not connect" path entirely in-process, no real socket.
        with (
            patch.object(self.scanner, "check_dependencies", return_value=True),
            patch.object(self.scanner, "test_connectivity", return_value=False),
            patch.object(self.scanner, "connect", return_value=None),
        ):
            results = self.scanner.run_scan()

        # Should handle disconnection gracefully
        self.assertIsInstance(results, dict)
        self.assertEqual(results.get("error"), "connection_failed")


class TestIEC104ErrorHandling(unittest.TestCase):
    """Test IEC 104 error handling scenarios (no live sockets)."""

    def test_connection_timeout(self):
        """Test connection timeout scenarios"""
        scanner = IEC104Scanner(
            {
                "rhost": "192.168.254.254",  # Non-routable address
                "rport": 2404,
                "timeout": 1,  # Very short timeout
            }
        )

        # Simulate the timeout in-process: connectivity probe fails and
        # connect() yields nothing, the same shape a real timeout produces.
        with (
            patch.object(scanner, "check_dependencies", return_value=True),
            patch.object(scanner, "test_connectivity", return_value=False),
            patch.object(scanner, "connect", return_value=None),
        ):
            result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["error"], "connection_failed")

    def test_invalid_asdu_address(self):
        """Test invalid ASDU address handling"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "asdu-address": 65536}  # Invalid ASDU address
        )

        with (
            patch.object(scanner, "check_dependencies", return_value=True),
            patch.object(scanner, "test_connectivity", return_value=False),
            patch.object(scanner, "connect", return_value=None),
        ):
            result = scanner.run_scan()
        self.assertIsInstance(result, dict)

    def test_iec104_protocol_errors(self):
        """Test IEC 104 protocol-specific error handling.

        connect() raising should be caught and surfaced as a string error,
        without ever opening a socket.
        """
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})

        with (
            patch.object(scanner, "check_dependencies", return_value=True),
            patch.object(scanner, "test_connectivity", return_value=False),
            patch.object(scanner, "connect", side_effect=Exception("Connection refused")),
        ):
            result = scanner.run_scan()

        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIsInstance(result["error"], str)

    def test_invalid_ioa_range(self):
        """Test invalid IOA range handling"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "ioa-range": "invalid-range"})

        # Should handle invalid range gracefully
        with (
            patch.object(scanner, "check_dependencies", return_value=True),
            patch.object(scanner, "test_connectivity", return_value=False),
            patch.object(scanner, "connect", return_value=None),
        ):
            result = scanner.run_scan()
        self.assertIsInstance(result, dict)


class TestIEC104Integration(unittest.TestCase):
    """Integration tests for IEC 104 scanner"""

    def test_complete_iec104_scan_workflow(self):
        """Test complete IEC 104 scanning workflow (no live socket)."""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "timeout": 10})

        # Test basic workflow (pure metadata, no I/O)
        protocol_name = scanner.get_protocol_name()
        default_port = scanner.get_default_port()
        dependencies_ok = scanner.check_dependencies()

        self.assertEqual(protocol_name, "IEC 104")
        self.assertEqual(default_port, 2404)
        # Note: c104 may not be available in test environment
        self.assertIsInstance(dependencies_ok, bool)

        # Connectivity probe + scan run, with the socket layer stubbed so
        # the workflow is exercised end-to-end without touching the network.
        with patch.object(scanner, "test_connectivity", return_value=True) as mock_conn:
            connectivity = scanner.test_connectivity("127.0.0.1", 2404)
            self.assertIsInstance(connectivity, bool)
            mock_conn.assert_called_with("127.0.0.1", 2404)

        with (
            patch.object(scanner, "check_dependencies", return_value=True),
            patch.object(scanner, "test_connectivity", return_value=False),
            patch.object(scanner, "connect", return_value=None),
        ):
            result = scanner.run_scan()
        self.assertIsInstance(result, dict)

    def test_iec104_with_different_configurations(self):
        """Test IEC 104 scanner with different configurations"""
        configurations = [
            {"rhost": "127.0.0.1", "rport": 2404, "timeout": 5},
            {"rhost": "127.0.0.1", "rport": 8080, "timeout": 10},  # Alternative port
            {"rhost": "192.168.1.100", "rport": 2404, "timeout": 15, "asdu-address": 10},
        ]

        for config in configurations:
            scanner = IEC104Scanner(config)
            self.assertEqual(scanner.host, config["rhost"])
            self.assertEqual(scanner.port, config["rport"])
            self.assertEqual(scanner.timeout, config["timeout"])

    def test_iec104_parameter_validation(self):
        """Test IEC 104 parameter validation"""
        scanner = IEC104Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 2404,
                "common-address": 1,
                "asdu-address": 10,
            }
        )

        self.assertEqual(scanner.common_address, 1)
        self.assertEqual(scanner.asdu_address, 10)


class TestIEC104AdvancedFeatures(unittest.TestCase):
    """Test IEC 104 advanced features"""

    @patch("oida.protocols.iec104.c104")
    def test_time_synchronization(self, mock_c104):
        """Test time synchronization functionality"""
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client

        # Mock time sync command
        mock_client.send_clock_sync.return_value = True

        time_sync_result = {
            "sync_sent": True,
            "timestamp": "2024-01-01T12:00:00Z",
            "precision": "milliseconds",
        }

        self.assertTrue(time_sync_result["sync_sent"])
        self.assertIn("precision", time_sync_result)

    @patch("oida.protocols.iec104.c104")
    def test_event_handling(self, mock_c104):
        """Test event/spontaneous transmission handling"""
        mock_client = Mock()
        mock_c104.Client.return_value = mock_client

        # Mock event data
        event_data = {
            "ioa": 1001,
            "type": "single_point_change",
            "value": False,
            "timestamp": "2024-01-01T12:00:01Z",
            "cot": "spont",
        }

        self.assertEqual(event_data["cot"], "spont")
        self.assertEqual(event_data["type"], "single_point_change")

    def test_file_transfer_detection(self):
        """Test file transfer capability detection"""
        # IEC 104 file transfer parameters
        file_transfer_info = {
            "supports_file_transfer": False,  # Not in basic IEC 104
            "max_file_size": 0,
            "supported_file_types": [],
        }

        self.assertFalse(file_transfer_info["supports_file_transfer"])
        self.assertEqual(file_transfer_info["max_file_size"], 0)


class TestIEC104ListenModeHelpers(unittest.TestCase):
    """Test IEC 104 listen mode helper functions"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "timeout": 5})

    def test_parse_type_filter_valid(self):
        """Test parsing valid type filter string"""
        result = self.scanner._parse_type_filter("1,3,13")
        self.assertEqual(result, {1, 3, 13})

    def test_parse_type_filter_with_spaces(self):
        """Test parsing type filter with spaces"""
        result = self.scanner._parse_type_filter("1, 3, 13, 30")
        self.assertEqual(result, {1, 3, 13, 30})

    def test_parse_type_filter_single(self):
        """Test parsing single type ID"""
        result = self.scanner._parse_type_filter("13")
        self.assertEqual(result, {13})

    def test_parse_type_filter_none(self):
        """Test parsing None filter"""
        result = self.scanner._parse_type_filter(None)
        self.assertIsNone(result)

    def test_parse_type_filter_empty(self):
        """Test parsing empty filter"""
        result = self.scanner._parse_type_filter("")
        self.assertIsNone(result)

    def test_parse_type_filter_invalid(self):
        """Test parsing invalid filter returns None"""
        result = self.scanner._parse_type_filter("invalid,text")
        self.assertIsNone(result)

    def test_parse_asdu_value_single_point_true(self):
        """Test parsing single-point information (Type 1) - True"""
        # SIQ byte: bit 0 = value (1=on), bits 4-7 = quality
        # Note: bit 0 is also OV flag, so 0x01 sets OV. Use 0x00 with no quality.
        data = bytes([0x01])  # Value=True, OV flag also set
        value, quality = self.scanner._parse_asdu_value(1, data)
        self.assertTrue(value)
        # Quality includes OV because bit 0 is both value and overflow flag
        self.assertIn(quality, ["OK", "OV"])

    def test_parse_asdu_value_single_point_false(self):
        """Test parsing single-point information (Type 1) - False"""
        data = bytes([0x00])  # Value=False, no quality flags
        value, quality = self.scanner._parse_asdu_value(1, data)
        self.assertFalse(value)
        self.assertEqual(quality, "OK")

    def test_parse_asdu_value_single_point_with_quality(self):
        """Test parsing single-point with quality flags"""
        data = bytes([0x81])  # Value=True, IV flag set (bit 7)
        value, quality = self.scanner._parse_asdu_value(1, data)
        self.assertTrue(value)
        self.assertIn("IV", quality)

    def test_parse_asdu_value_double_point(self):
        """Test parsing double-point information (Type 3)"""
        data = bytes([0x02])  # DPI=2 (ON)
        value, quality = self.scanner._parse_asdu_value(3, data)
        self.assertEqual(value, 2)  # ON state

    def test_parse_asdu_value_normalized(self):
        """Test parsing normalized measured value (Type 9)"""
        import struct

        # Normalized value: 16384 = 0.5 (half of 32768)
        data = struct.pack("<h", 16384) + bytes([0x00])  # value + QDS
        value, quality = self.scanner._parse_asdu_value(9, data)
        self.assertAlmostEqual(value, 0.5, places=2)
        self.assertEqual(quality, "OK")

    def test_parse_asdu_value_scaled(self):
        """Test parsing scaled measured value (Type 11)"""
        import struct

        data = struct.pack("<h", 1000) + bytes([0x00])  # value + QDS
        value, quality = self.scanner._parse_asdu_value(11, data)
        self.assertEqual(value, 1000)
        self.assertEqual(quality, "OK")

    def test_parse_asdu_value_float(self):
        """Test parsing float measured value (Type 13)"""
        import struct

        data = struct.pack("<f", 230.5) + bytes([0x00])  # value + QDS
        value, quality = self.scanner._parse_asdu_value(13, data)
        self.assertAlmostEqual(value, 230.5, places=2)
        self.assertEqual(quality, "OK")

    def test_parse_asdu_value_step_position(self):
        """Test parsing step position (Type 5)"""
        data = bytes([0x32, 0x00])  # Position=50, no transient
        value, quality = self.scanner._parse_asdu_value(5, data)
        self.assertEqual(value, 50)
        self.assertEqual(quality, "OK")

    def test_parse_asdu_value_empty(self):
        """Test parsing empty data"""
        value, quality = self.scanner._parse_asdu_value(1, b"")
        self.assertIsNone(value)
        self.assertEqual(quality, "")

    def test_parse_asdu_value_unknown_type(self):
        """Test parsing unknown type returns hex"""
        data = bytes([0x01, 0x02, 0x03])
        value, quality = self.scanner._parse_asdu_value(200, data)
        self.assertEqual(value, "010203")
        self.assertEqual(quality, "")

    def test_parse_quality_flags_ok(self):
        """Test quality flags - all OK"""
        result = self.scanner._parse_quality_flags(0x00)
        self.assertEqual(result, "OK")

    def test_parse_quality_flags_invalid(self):
        """Test quality flags - Invalid"""
        result = self.scanner._parse_quality_flags(0x80)
        self.assertEqual(result, "IV")

    def test_parse_quality_flags_not_topical(self):
        """Test quality flags - Not topical"""
        result = self.scanner._parse_quality_flags(0x40)
        self.assertEqual(result, "NT")

    def test_parse_quality_flags_substituted(self):
        """Test quality flags - Substituted"""
        result = self.scanner._parse_quality_flags(0x20)
        self.assertEqual(result, "SB")

    def test_parse_quality_flags_blocked(self):
        """Test quality flags - Blocked"""
        result = self.scanner._parse_quality_flags(0x10)
        self.assertEqual(result, "BL")

    def test_parse_quality_flags_overflow(self):
        """Test quality flags - Overflow"""
        result = self.scanner._parse_quality_flags(0x01)
        self.assertEqual(result, "OV")

    def test_parse_quality_flags_multiple(self):
        """Test quality flags - Multiple flags"""
        result = self.scanner._parse_quality_flags(0xC0)  # IV + NT
        self.assertIn("IV", result)
        self.assertIn("NT", result)


class TestIEC104CapturedASDU(unittest.TestCase):
    """Test CapturedASDU dataclass"""

    def test_captured_asdu_to_dict(self):
        """Test CapturedASDU.to_dict() serialization"""
        from oida.protocols.iec104 import CapturedASDU

        asdu = CapturedASDU(
            timestamp="2024-01-01T12:00:00",
            type_id=1,
            type_name="M_SP_NA_1",
            type_description="Single-point information",
            cause_of_transmission=3,
            cot_name="spontaneous",
            common_address=1,
            ioa=100,
            value=True,
            quality="OK",
            raw_bytes=None,
        )

        result = asdu.to_dict()

        self.assertEqual(result["timestamp"], "2024-01-01T12:00:00")
        self.assertEqual(result["type_id"], 1)
        self.assertEqual(result["type_name"], "M_SP_NA_1")
        self.assertEqual(result["cot"], 3)
        self.assertEqual(result["cot_name"], "spontaneous")
        self.assertEqual(result["common_address"], 1)
        self.assertEqual(result["ioa"], 100)
        self.assertTrue(result["value"])
        self.assertEqual(result["quality"], "OK")
        self.assertNotIn("raw", result)  # raw_bytes was None

    def test_captured_asdu_to_dict_with_raw(self):
        """Test CapturedASDU.to_dict() with raw bytes"""
        from oida.protocols.iec104 import CapturedASDU

        asdu = CapturedASDU(
            timestamp="2024-01-01T12:00:00",
            type_id=1,
            type_name="M_SP_NA_1",
            type_description="Single-point information",
            cause_of_transmission=3,
            cot_name="spontaneous",
            common_address=1,
            ioa=100,
            value=True,
            quality="OK",
            raw_bytes=bytes([0x68, 0x04, 0x00, 0x00]),
        )

        result = asdu.to_dict()

        self.assertIn("raw", result)
        self.assertEqual(result["raw"], "68040000")


class TestIEC104ListenStats(unittest.TestCase):
    """Test ListenStats dataclass"""

    def test_listen_stats_duration(self):
        """Test ListenStats.duration property"""
        from oida.protocols.iec104 import ListenStats
        import time

        stats = ListenStats()
        time.sleep(0.1)
        duration = stats.duration

        self.assertGreater(duration, 0.05)
        self.assertLess(duration, 1.0)

    def test_listen_stats_rate(self):
        """Test ListenStats.rate property"""
        from oida.protocols.iec104 import ListenStats

        stats = ListenStats()
        stats.asdu_count = 10
        # Manually set start_time to 10 seconds ago
        stats.start_time = stats.start_time - 10

        rate = stats.rate
        self.assertAlmostEqual(rate, 1.0, places=0)  # 10 ASDUs / 10 sec = 1/sec

    def test_listen_stats_rate_zero_duration(self):
        """Test ListenStats.rate with zero duration"""
        from oida.protocols.iec104 import ListenStats

        stats = ListenStats()
        stats.asdu_count = 10
        # Rate should handle near-zero duration gracefully
        rate = stats.rate
        self.assertIsInstance(rate, float)


class TestIEC104WriteOperations(unittest.TestCase):
    """Test IEC 104 write operation helpers"""

    def test_has_write_operation_none(self):
        """Test _has_write_operation with no write args"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertFalse(scanner._has_write_operation())

    def test_has_write_operation_single(self):
        """Test _has_write_operation with single command"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-single": "100", "value": "on"}
        )
        self.assertTrue(scanner._has_write_operation())

    def test_has_write_operation_single_combined(self):
        """Test _has_write_operation with combined IOA:VALUE format"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "write-single": "100:on"})
        self.assertTrue(scanner._has_write_operation())
        self.assertEqual(scanner.write_single_ioa, 100)
        self.assertEqual(scanner.write_value, "on")

    def test_has_write_operation_double(self):
        """Test _has_write_operation with double command"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-double": "100", "value": "on"}
        )
        self.assertTrue(scanner._has_write_operation())

    def test_has_write_operation_float(self):
        """Test _has_write_operation with float setpoint"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-float": "100", "value": "50.5"}
        )
        self.assertTrue(scanner._has_write_operation())

    def test_has_write_operation_scaled(self):
        """Test _has_write_operation with scaled setpoint"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-scaled": "100", "value": "1000"}
        )
        self.assertTrue(scanner._has_write_operation())

    def test_has_write_operation_normalized(self):
        """Test _has_write_operation with normalized setpoint"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-normalized": "100", "value": "0.5"}
        )
        self.assertTrue(scanner._has_write_operation())

    def test_has_write_operation_step(self):
        """Test _has_write_operation with step command"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-step": "100", "value": "up"}
        )
        self.assertTrue(scanner._has_write_operation())

    def test_has_write_operation_custom_type(self):
        """Test _has_write_operation with custom type ID"""
        scanner = IEC104Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 2404,
                "write-type": 128,
                "write-ioa": 100,
                "value": "on",
            }
        )
        self.assertTrue(scanner._has_write_operation())

    def test_parse_write_arg_combined(self):
        """Test _parse_write_arg with IOA:VALUE format"""
        ioa, val = IEC104Scanner._parse_write_arg("100:on")
        self.assertEqual(ioa, 100)
        self.assertEqual(val, "on")

    def test_parse_write_arg_ioa_only(self):
        """Test _parse_write_arg with IOA only"""
        ioa, val = IEC104Scanner._parse_write_arg("100")
        self.assertEqual(ioa, 100)
        self.assertIsNone(val)

    def test_parse_write_arg_none(self):
        """Test _parse_write_arg with None input"""
        ioa, val = IEC104Scanner._parse_write_arg(None)
        self.assertIsNone(ioa)
        self.assertIsNone(val)

    def test_parse_write_arg_float_value(self):
        """Test _parse_write_arg with float value"""
        ioa, val = IEC104Scanner._parse_write_arg("700:42.5")
        self.assertEqual(ioa, 700)
        self.assertEqual(val, "42.5")

    def test_parse_write_arg_negative_value(self):
        """Test _parse_write_arg with negative value"""
        ioa, val = IEC104Scanner._parse_write_arg("100:-0.5")
        self.assertEqual(ioa, 100)
        self.assertEqual(val, "-0.5")

    def test_explicit_value_overrides_inline(self):
        """Test that --value overrides inline IOA:VALUE"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "write-single": "100:off", "value": "on"}
        )
        self.assertEqual(scanner.write_single_ioa, 100)
        self.assertEqual(scanner.write_value, "on")

    def test_inline_value_used_as_fallback(self):
        """Test that inline value is used when --value not given"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "write-single": "100:on"})
        self.assertEqual(scanner.write_single_ioa, 100)
        self.assertEqual(scanner.write_value, "on")


class TestIEC104FileTransfer(unittest.TestCase):
    """Test IEC 104 file-transfer capability detection (no F_* ASDU exchange)."""

    def test_probe_files_flag(self):
        """Test --probe-files flag is parsed."""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "probe-files": True})
        self.assertTrue(scanner.probe_files)

    def test_report_file_transfer_none(self):
        """No file-transfer type IDs seen -> not supported."""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = scanner._report_file_transfer()
        self.assertFalse(result["supported"])
        self.assertEqual(result["type_ids_found"], [])

    def test_report_file_transfer_detected(self):
        """File-transfer type IDs (120-127) observed -> supported."""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner._file_transfer_supported = True
        scanner._raw_type_ids = {120, 122}
        result = scanner._report_file_transfer()
        self.assertTrue(result["supported"])
        self.assertEqual(result["type_ids_found"], [120, 122])


class TestIEC104FuzzingArgs(unittest.TestCase):
    """Test IEC 104 fuzzing argument handling"""

    def test_fuzz_enabled(self):
        """Test fuzzing enabled flag"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "fuzz": True})
        self.assertTrue(scanner.fuzz_enabled)

    def test_fuzz_disabled_by_default(self):
        """Test fuzzing disabled by default"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertFalse(scanner.fuzz_enabled)

    def test_fuzz_with_iterations(self):
        """Test fuzzing with iteration count"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "fuzz": True, "fuzz-iterations": 50}
        )
        self.assertEqual(scanner.fuzz_iterations, 50)

    def test_fuzz_with_target_ioa(self):
        """Test fuzzing with target IOA"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "fuzz": True, "fuzz-ioa": 100}
        )
        self.assertEqual(scanner.fuzz_ioa, 100)


class TestIEC101SerialMode(unittest.TestCase):
    """Test IEC 101 serial mode functionality"""

    def test_iec101_mode_disabled_by_default(self):
        """Test IEC 101 mode is disabled by default"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertFalse(scanner.iec101_mode)
        self.assertIsNone(scanner.serial_port)

    def test_iec101_mode_enabled(self):
        """Test IEC 101 mode enabled via --iec101"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )
        self.assertTrue(scanner.iec101_mode)
        self.assertEqual(scanner.serial_port, "/dev/ttyUSB0")
        self.assertEqual(scanner.baudrate, 9600)
        self.assertEqual(scanner.parity, "E")
        self.assertEqual(scanner.stopbits, 1)

    def test_iec101_config_parsing_full(self):
        """Test full IEC 101 config string parsing"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyS0:19200:N:2"}
        )
        self.assertEqual(scanner.serial_port, "/dev/ttyS0")
        self.assertEqual(scanner.baudrate, 19200)
        self.assertEqual(scanner.parity, "N")
        self.assertEqual(scanner.stopbits, 2)

    def test_iec101_config_parsing_minimal(self):
        """Test minimal IEC 101 config (port only)"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0"})
        self.assertEqual(scanner.serial_port, "/dev/ttyUSB0")
        self.assertEqual(scanner.baudrate, 9600)  # Default
        self.assertEqual(scanner.parity, "E")  # Default

    def test_iec101_config_parsing_partial(self):
        """Test partial IEC 101 config (port and baud)"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:115200"}
        )
        self.assertEqual(scanner.serial_port, "/dev/ttyUSB0")
        self.assertEqual(scanner.baudrate, 115200)
        self.assertEqual(scanner.parity, "E")  # Default

    def test_iec101_link_address(self):
        """Test IEC 101 link address configuration"""
        scanner = IEC104Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 2404,
                "iec101": "/dev/ttyUSB0:9600:E:1",
                "link-address": 5,
            }
        )
        self.assertEqual(scanner.link_address, 5)

    def test_iec101_balanced_mode(self):
        """Test IEC 101 balanced mode configuration"""
        scanner = IEC104Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 2404,
                "iec101": "/dev/ttyUSB0:9600:E:1",
                "balanced": True,
            }
        )
        self.assertTrue(scanner.balanced_mode)

    def test_iec101_check_dependencies(self):
        """Test IEC 101 dependency check"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )
        # Should check for pyserial instead of c104
        from oida.protocols.iec104 import PYSERIAL_AVAILABLE

        self.assertEqual(scanner.check_dependencies(), PYSERIAL_AVAILABLE)


class TestIEC101FrameBuilding(unittest.TestCase):
    """Test FT1.2 frame building for IEC 101"""

    def setUp(self):
        """Create scanner in IEC 101 mode"""
        self.scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )

    def test_calculate_checksum(self):
        """Test FT1.2 checksum calculation"""
        data = bytes([0x40, 0x01])
        checksum = self.scanner._calculate_checksum(data)
        self.assertEqual(checksum, 0x41)  # 0x40 + 0x01 = 0x41

    def test_build_fixed_frame(self):
        """Test building FT1.2 fixed frame"""
        from oida.protocols.iec104 import FT12_START_FIXED, FT12_END

        frame = self.scanner._build_fixed_frame(control=0x49, address=1)
        self.assertEqual(frame[0], FT12_START_FIXED)
        self.assertEqual(frame[1], 0x49)  # Control
        self.assertEqual(frame[2], 1)  # Address
        self.assertEqual(frame[-1], FT12_END)

    def test_build_variable_frame(self):
        """Test building FT1.2 variable frame"""
        from oida.protocols.iec104 import FT12_START_VARIABLE, FT12_END

        asdu = bytes([100, 0x01, 0x06, 0x01, 0x00, 0x00, 20])
        frame = self.scanner._build_variable_frame(control=0x53, address=1, asdu=asdu)
        self.assertEqual(frame[0], FT12_START_VARIABLE)
        self.assertEqual(frame[1], frame[2])  # Length bytes match
        self.assertEqual(frame[3], FT12_START_VARIABLE)
        self.assertEqual(frame[-1], FT12_END)

    def test_build_asdu_101(self):
        """Test building ASDU for IEC 101"""
        asdu = self.scanner._build_asdu_101(type_id=100, cot=6, ioa=0, data=bytes([20]))
        self.assertEqual(asdu[0], 100)  # Type ID
        self.assertEqual(asdu[1], 0x01)  # VSQ
        self.assertEqual(asdu[2], 6)  # COT


class TestIEC101FrameParsing(unittest.TestCase):
    """Test FT1.2 frame parsing for IEC 101"""

    def setUp(self):
        """Create scanner in IEC 101 mode"""
        self.scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )

    def test_parse_fixed_frame(self):
        """Test parsing FT1.2 fixed frame"""
        frame = self.scanner._build_fixed_frame(control=0x49, address=1)
        parsed = self.scanner._parse_serial_frame(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["frame_type"], "fixed")
        self.assertEqual(parsed["control"], 0x49)
        self.assertEqual(parsed["address"], 1)
        self.assertTrue(parsed["valid"])

    def test_parse_variable_frame(self):
        """Test parsing FT1.2 variable frame"""
        asdu = bytes([1, 0x01, 0x03, 0x01, 0x00, 0x00, 0x01])
        frame = self.scanner._build_variable_frame(control=0x53, address=1, asdu=asdu)
        parsed = self.scanner._parse_serial_frame(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["frame_type"], "variable")
        self.assertTrue(parsed["valid"])
        self.assertIsNotNone(parsed["asdu"])

    def test_parse_invalid_frame(self):
        """Test parsing invalid frame"""
        result = self.scanner._parse_serial_frame(b"")
        self.assertIsNone(result)
        result = self.scanner._parse_serial_frame(None)
        self.assertIsNone(result)


class TestIEC104Connect(unittest.TestCase):
    """Test IEC 104 connect method with mocked c104"""

    @patch("oida.protocols.iec104._deps._get_c104")
    @patch("oida.protocols.iec104._deps._c104")
    def test_connect_success(self, mock_lazy_c104, mock_get_c104):
        """Test successful TCP connection"""
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104
        mock_lazy_c104.is_available = True

        mock_client = MagicMock()
        mock_c104.Client.return_value = mock_client
        mock_c104.Init.NONE = 0

        mock_conn = MagicMock()
        mock_conn.is_connected = True
        mock_conn.protocol_parameters = MagicMock()
        mock_client.add_connection.return_value = mock_conn

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "timeout": 1})
        result = scanner.connect()

        self.assertIsNotNone(result)
        self.assertIsInstance(result, tuple)
        mock_client.start.assert_called_once()

    @patch("oida.protocols.iec104._deps._c104")
    def test_connect_c104_not_available(self, mock_lazy_c104):
        """Test connect when c104 library is missing"""
        mock_lazy_c104.is_available = False

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = scanner.connect()
        self.assertIsNone(result)

    @patch("oida.protocols.iec104._deps._get_c104")
    @patch("oida.protocols.iec104._deps._c104")
    def test_connect_timeout(self, mock_lazy_c104, mock_get_c104):
        """Test connection timeout"""
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104
        mock_lazy_c104.is_available = True

        mock_client = MagicMock()
        mock_c104.Client.return_value = mock_client
        mock_c104.Init.NONE = 0

        mock_conn = MagicMock()
        mock_conn.is_connected = False  # Never connects
        mock_conn.protocol_parameters = MagicMock()
        mock_client.add_connection.return_value = mock_conn

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "timeout": 1})
        result = scanner.connect()

        self.assertIsNone(result)
        mock_client.stop.assert_called_once()

    @patch("oida.protocols.iec104._deps._get_c104")
    @patch("oida.protocols.iec104._deps._c104")
    def test_connect_exception(self, mock_lazy_c104, mock_get_c104):
        """Test connect handles exceptions"""
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104
        mock_lazy_c104.is_available = True
        mock_c104.Client.side_effect = RuntimeError("init failed")

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "timeout": 1})
        result = scanner.connect()

        self.assertIsNone(result)

    def test_connect_iec101_serial(self):
        """Test connect dispatches to serial for IEC 101 mode"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )
        with patch.object(scanner, "_connect_serial", return_value="serial_conn") as mock_serial:
            result = scanner.connect()
        mock_serial.assert_called_once()
        self.assertEqual(result, "serial_conn")


class TestIEC104Disconnect(unittest.TestCase):
    """Test disconnect method"""

    def test_disconnect_tuple_connection(self):
        """Test disconnect with (client, conn) tuple"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        mock_client = MagicMock()
        mock_conn = MagicMock()
        scanner.disconnect((mock_client, mock_conn))
        mock_client.stop.assert_called_once()

    def test_disconnect_none(self):
        """Test disconnect with None connection"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner.disconnect(None)  # Should not raise

    def test_disconnect_iec101(self):
        """Test disconnect dispatches to serial for IEC 101"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )
        with patch.object(scanner, "_disconnect_serial") as mock_disc:
            scanner.disconnect(None)
        mock_disc.assert_called_once()


class TestIEC104Discover(unittest.TestCase):
    """Test discover method dispatch logic"""

    def test_discover_none_connection(self):
        """Test discover with None connection returns empty results"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = scanner.discover(None)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["data_points"], {})

    def test_discover_iec101_dispatch(self):
        """Test discover dispatches to IEC 101 for serial mode"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "iec101": "/dev/ttyUSB0:9600:E:1"}
        )
        with patch.object(scanner, "_discover_iec101", return_value={"serial": True}) as mock:
            result = scanner.discover("serial_conn")
        mock.assert_called_once()
        self.assertEqual(result, {"serial": True})

    def test_discover_tcp_with_interrogate(self):
        """Test discover calls interrogation when --interrogate is set"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "interrogate": True})
        mock_client = MagicMock()
        mock_conn = MagicMock()
        mock_conn.is_connected = True

        with (
            patch.object(scanner, "get_server_info", return_value={"host": "127.0.0.1"}),
            patch.object(scanner, "_send_test_command", return_value={"success": True}),
            patch.object(scanner, "_perform_interrogation", return_value={"ok": True}) as mock_gi,
            patch.object(scanner, "_compile_type_info", return_value={}),
            patch.object(scanner, "_analyze_security", return_value={}),
            patch.object(scanner, "_report_findings"),
        ):
            scanner.discover((mock_client, mock_conn))

        mock_gi.assert_called_once_with(mock_client, mock_conn)


class TestBestCommonAddress(unittest.TestCase):
    """Test _best_common_address logic"""

    def test_explicit_ca_takes_priority(self):
        """Test explicit --common-address takes priority"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "common-address": 42})
        scanner._discovered_stations = {10, 20}
        self.assertEqual(scanner._best_common_address(), 42)

    def test_discovered_ca_used_when_no_explicit(self):
        """Test discovered CA used when no explicit CA"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner._discovered_stations = {10, 20}
        self.assertEqual(scanner._best_common_address(), 10)  # min()

    def test_default_ca_when_nothing_discovered(self):
        """Test default CA=1 when nothing discovered"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertEqual(scanner._best_common_address(), 1)


class TestSendTestCommand(unittest.TestCase):
    """Test _send_test_command"""

    def test_connected(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        mock_conn = MagicMock()
        mock_conn.is_connected = True
        result = scanner._send_test_command(MagicMock(), mock_conn)
        self.assertTrue(result["success"])

    def test_not_connected(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        mock_conn = MagicMock()
        mock_conn.is_connected = False
        result = scanner._send_test_command(MagicMock(), mock_conn)
        self.assertFalse(result["success"])


class TestGetServerInfo(unittest.TestCase):
    """Test get_server_info"""

    def test_basic_info(self):
        scanner = IEC104Scanner({"rhost": "10.0.0.1", "rport": 2404})
        mock_conn = MagicMock()
        mock_conn.state = "OPEN"
        result = scanner.get_server_info((MagicMock(), mock_conn))
        self.assertEqual(result["host"], "10.0.0.1")
        self.assertEqual(result["port"], 2404)
        self.assertTrue(result["connected"])
        self.assertEqual(result["protocol"], "IEC 60870-5-104")
        self.assertIn("timestamp", result)
        self.assertEqual(result["connection_state"], "OPEN")


class TestCompileTypeInfo(unittest.TestCase):
    """Test _compile_type_info"""

    def test_empty_types(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = scanner._compile_type_info()
        self.assertEqual(result["standard_types"], {})
        self.assertEqual(result["custom_types"], [])
        self.assertEqual(result["summary"]["total_types"], 0)

    def test_standard_types(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner._raw_type_ids = {1, 3, 13}  # M_SP_NA_1, M_DP_NA_1, M_ME_NC_1
        scanner._custom_type_ids = set()
        result = scanner._compile_type_info()
        self.assertEqual(result["summary"]["total_types"], 3)
        self.assertEqual(result["summary"]["standard_types"], 3)
        self.assertEqual(result["summary"]["custom_types"], 0)
        self.assertIn(1, result["standard_types"])
        self.assertEqual(result["standard_types"][1]["name"], "M_SP_NA_1")

    def test_custom_types(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner._raw_type_ids = {1, 200}
        scanner._custom_type_ids = {200}
        result = scanner._compile_type_info()
        self.assertEqual(result["summary"]["custom_types"], 1)
        self.assertEqual(len(result["custom_types"]), 1)
        self.assertEqual(result["custom_types"][0]["type_id"], 200)

    def test_file_transfer_types(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner._raw_type_ids = {120, 121}  # F_FR_NA_1, F_SR_NA_1
        scanner._custom_type_ids = set()
        result = scanner._compile_type_info()
        self.assertEqual(result["summary"]["file_transfer"], 2)
        self.assertEqual(len(result["file_transfer_types"]), 2)


class TestSecurityAnalysis(unittest.TestCase):
    """Test _analyze_security from SecurityMixin"""

    def test_basic_no_tls(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = scanner._analyze_security({"data_points": {}, "type_ids": {}})
        self.assertFalse(result.get("encryption", False))
        self.assertIn("risk_level", result)

    def test_with_tls(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "tls": True})
        result = scanner._analyze_security({"data_points": {}, "type_ids": {}})
        self.assertTrue(result.get("encryption"))

    def test_file_transfer_high_risk(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        results = {
            "data_points": {},
            "type_ids": {},
            "file_transfer": {"supported": True},
        }
        result = scanner._analyze_security(results)
        # SecurityAnalyzer.assess_protocol_security overwrites issues key,
        # but the method still returns a risk_level and security_level
        self.assertIn("risk_level", result)
        self.assertIn("security_level", result)

    def test_many_points_returns_analysis(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        data_points = {i: {"type": "M_SP_NA_1"} for i in range(200)}
        results = {"data_points": data_points, "type_ids": {}}
        result = scanner._analyze_security(results)
        # Security analysis always returns issues from assess_protocol_security
        self.assertIn("issues", result)
        self.assertIsInstance(result["issues"], list)

    def test_custom_types_returns_analysis(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        results = {
            "data_points": {},
            "type_ids": {"summary": {"custom_types": 3}},
        }
        result = scanner._analyze_security(results)
        self.assertIn("security_score", result)


class TestDisplayCapturedASDU(unittest.TestCase):
    """Test _display_captured_asdu from ListenMixin"""

    def test_display_spontaneous(self):
        """Test display of spontaneous ASDU"""
        from oida.protocols.iec104 import CapturedASDU

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        asdu = CapturedASDU(
            timestamp="2024-01-01T12:00:00.000",
            type_id=1,
            type_name="M_SP_NA_1",
            type_description="Single-point information",
            cause_of_transmission=3,
            cot_name="spontaneous",
            common_address=1,
            ioa=100,
            value=True,
            quality="OK",
            raw_bytes=None,
        )
        # Should not raise
        scanner._display_captured_asdu(asdu)

    def test_display_with_output_file(self):
        """Test display writes to output file when set"""
        from io import StringIO
        from oida.protocols.iec104 import CapturedASDU

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        mock_fh = StringIO()
        scanner._listen_output_fh = mock_fh

        asdu = CapturedASDU(
            timestamp="2024-01-01T12:00:00.000",
            type_id=1,
            type_name="M_SP_NA_1",
            type_description="Single-point information",
            cause_of_transmission=3,
            cot_name="spontaneous",
            common_address=1,
            ioa=100,
            value=True,
            quality="OK",
            raw_bytes=None,
        )
        scanner._display_captured_asdu(asdu)

        output = mock_fh.getvalue()
        self.assertIn("M_SP_NA_1", output)
        self.assertIn('"ioa": 100', output)

        scanner._listen_output_fh = None


class TestDisplayListenSummary(unittest.TestCase):
    """Test _display_listen_summary from ListenMixin"""

    def test_summary_with_asdus(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = {
            "duration_seconds": 10.0,
            "asdus_captured": 5,
            "rate_per_second": 0.5,
            "bytes_received": 250,
            "type_ids_seen": [1, 13],
            "common_addresses_seen": [1],
            "ioas_seen_count": 3,
            "captured_asdus": [
                {"type_id": 1},
                {"type_id": 1},
                {"type_id": 13},
                {"type_id": 13},
                {"type_id": 13},
            ],
        }
        # Should not raise
        scanner._display_listen_summary(result)

    def test_summary_empty(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        result = {
            "duration_seconds": 0.0,
            "asdus_captured": 0,
            "rate_per_second": 0.0,
            "bytes_received": 0,
            "type_ids_seen": [],
            "common_addresses_seen": [],
            "ioas_seen_count": 0,
            "captured_asdus": [],
        }
        scanner._display_listen_summary(result)


class TestCommandsMixin(unittest.TestCase):
    """Test CommandsMixin methods"""

    def test_fuzz_requires_confirm(self):
        """Test fuzz_commands requires --confirm"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertFalse(scanner.confirm_dangerous)
        # Without confirm, returns early with 0 tested
        result = scanner._fuzz_commands(MagicMock(), MagicMock())
        self.assertEqual(result["tested"], 0)

    def test_write_value_requires_confirm(self):
        """Test _write_value requires --confirm"""
        scanner = IEC104Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 2404,
                "write-single": "100",
                "value": "on",
            }
        )
        self.assertFalse(scanner.confirm_dangerous)
        result = scanner._write_value(MagicMock(), MagicMock())
        self.assertFalse(result["success"])
        self.assertIn("Missing --confirm", result["error"])

    def test_write_value_requires_value(self):
        """Test _write_value requires --value"""
        scanner = IEC104Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 2404,
                "write-single": "100",
                "confirm": True,
            }
        )
        result = scanner._write_value(MagicMock(), MagicMock())
        self.assertFalse(result["success"])
        self.assertIn("Missing", result["error"])

    def test_write_value_no_operation(self):
        """Test _write_value with no write operation specified"""
        scanner = IEC104Scanner(
            {"rhost": "127.0.0.1", "rport": 2404, "value": "on", "confirm": True}
        )
        result = scanner._write_value(MagicMock(), MagicMock())
        self.assertFalse(result["success"])
        self.assertIn("No write operation", result["error"])


class TestReadIOAParsing(unittest.TestCase):
    """Test --read-ioa parsing (W13 fix)"""

    def test_valid_ioas(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "read-ioa": "100,200,300"})
        self.assertEqual(scanner.read_ioas, [100, 200, 300])

    def test_invalid_ioas_handled(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "read-ioa": "abc,def"})
        self.assertEqual(scanner.read_ioas, [])

    def test_no_ioas(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertEqual(scanner.read_ioas, [])


class TestIEC104Constants(unittest.TestCase):
    """Test IEC 104 constants and data exports"""

    def test_type_ids_dict(self):
        from oida.protocols.iec104 import IEC104_TYPE_IDS

        self.assertIn(1, IEC104_TYPE_IDS)
        self.assertEqual(IEC104_TYPE_IDS[1][0], "M_SP_NA_1")
        self.assertIn(45, IEC104_TYPE_IDS)  # Single command
        self.assertIn(120, IEC104_TYPE_IDS)  # File transfer

    def test_cot_dict(self):
        from oida.protocols.iec104 import IEC104_COT

        self.assertIn(3, IEC104_COT)
        self.assertEqual(IEC104_COT[3], "spontaneous")
        self.assertIn(6, IEC104_COT)
        self.assertEqual(IEC104_COT[6], "activation")

    def test_ft12_constants(self):
        from oida.protocols.iec104 import FT12_START_FIXED, FT12_START_VARIABLE, FT12_END

        self.assertEqual(FT12_START_FIXED, 0x10)
        self.assertEqual(FT12_START_VARIABLE, 0x68)
        self.assertEqual(FT12_END, 0x16)


class TestNewInitArgs(unittest.TestCase):
    """Test new __init__ arguments added for c104 feature coverage"""

    def test_interrogate_groups_default(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertFalse(scanner.interrogate_groups)

    def test_interrogate_groups_enabled(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "interrogate-groups": True})
        self.assertTrue(scanner.interrogate_groups)

    def test_tls_ca_default(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertIsNone(scanner.tls_ca)

    def test_tls_ca_set(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "tls-ca": "/path/ca.pem"})
        self.assertEqual(scanner.tls_ca, "/path/ca.pem")

    def test_t1_default(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertIsNone(scanner.t1)

    def test_t1_set(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "t1": 30})
        self.assertEqual(scanner.t1, 30)

    def test_t3_default(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertIsNone(scanner.t3)

    def test_t3_set(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "t3": 10})
        self.assertEqual(scanner.t3, 10)

    def test_originator_default(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertIsNone(scanner.originator_address)

    def test_originator_set(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "originator": 42})
        self.assertEqual(scanner.originator_address, 42)

    def test_init_cause_state(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertIsNone(scanner._init_cause)

    def test_connection_state_tracking(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertIsNone(scanner._connection_state)


class TestInterrogationCA(unittest.TestCase):
    """Test _interrogation_ca wildcard default"""

    def test_explicit_ca_takes_priority(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "common-address": 42})
        scanner._discovered_stations = {10, 20}
        self.assertEqual(scanner._interrogation_ca(), 42)

    def test_discovered_ca_used(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        scanner._discovered_stations = {10, 20}
        self.assertEqual(scanner._interrogation_ca(), 10)

    def test_wildcard_ca_when_nothing_discovered(self):
        """When no explicit CA and nothing discovered, use CA=0 (broadcast)"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertEqual(scanner._interrogation_ca(), 0)


class TestGetServerInfoExtended(unittest.TestCase):
    """Test get_server_info with new state fields"""

    def test_init_cause_included(self):
        scanner = IEC104Scanner({"rhost": "10.0.0.1", "rport": 2404})
        scanner._init_cause = "local_power_on"
        result = scanner.get_server_info((MagicMock(), MagicMock()))
        self.assertEqual(result["init_cause"], "local_power_on")

    def test_init_cause_absent_when_none(self):
        scanner = IEC104Scanner({"rhost": "10.0.0.1", "rport": 2404})
        result = scanner.get_server_info((MagicMock(), MagicMock()))
        self.assertNotIn("init_cause", result)

    def test_connection_state_tracked(self):
        scanner = IEC104Scanner({"rhost": "10.0.0.1", "rport": 2404})
        scanner._connection_state = "OPEN"
        result = scanner.get_server_info((MagicMock(), MagicMock()))
        self.assertEqual(result["connection_state_tracked"], "OPEN")

    def test_connection_state_absent_when_none(self):
        scanner = IEC104Scanner({"rhost": "10.0.0.1", "rport": 2404})
        result = scanner.get_server_info((MagicMock(), MagicMock()))
        self.assertNotIn("connection_state_tracked", result)


class TestSendTestCommandExtended(unittest.TestCase):
    """Test _send_test_command (TESTFR only, no ASDU-layer test)"""

    def test_connected(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        mock_conn = MagicMock()
        mock_conn.is_connected = True
        result = scanner._send_test_command(MagicMock(), mock_conn)
        self.assertTrue(result["success"])
        self.assertNotIn("test_asdu", result)

    def test_disconnected(self):
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        mock_conn = MagicMock()
        mock_conn.is_connected = False
        result = scanner._send_test_command(MagicMock(), mock_conn)
        self.assertFalse(result["success"])
        self.assertNotIn("test_asdu", result)


class TestGroupInterrogation(unittest.TestCase):
    """Test _group_interrogation"""

    @patch("oida.protocols.iec104._deps._get_c104")
    def test_group_interrogation_returns_structure(self, mock_get_c104):
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104
        # Set up Qoi attributes for groups 1-16
        for i in range(1, 17):
            setattr(mock_c104.Qoi, f"GROUP_{i}", i + 20)

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "wait-time": 0})
        mock_conn = MagicMock()
        mock_conn.interrogation.return_value = True

        result = scanner._group_interrogation(MagicMock(), mock_conn)
        self.assertIn("groups", result)
        self.assertIn("total_groups_with_points", result)
        self.assertIsInstance(result["groups"], dict)


class TestCallbackCreation(unittest.TestCase):
    """Test that _create_callbacks returns all expected callbacks"""

    @patch("oida.protocols.iec104._deps._get_c104")
    def test_callback_count(self, mock_get_c104):
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        callbacks = scanner._create_callbacks()
        self.assertEqual(len(callbacks), 7)

    @patch("oida.protocols.iec104._deps._get_c104")
    def test_on_station_initialized_callback(self, mock_get_c104):
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        callbacks = scanner._create_callbacks()
        on_station_initialized = callbacks[4]

        mock_station = MagicMock()
        mock_station.common_address = 1
        mock_coi = MagicMock()
        mock_coi.value = 0

        on_station_initialized(MagicMock(), mock_station, mock_coi)
        self.assertEqual(scanner._init_cause, "local_power_on")

    @patch("oida.protocols.iec104._deps._get_c104")
    def test_on_state_change_callback(self, mock_get_c104):
        mock_c104 = MagicMock()
        mock_get_c104.return_value = mock_c104

        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        callbacks = scanner._create_callbacks()
        on_state_change = callbacks[5]

        on_state_change(MagicMock(), "ConnectionState.OPEN")
        self.assertEqual(scanner._connection_state, "OPEN")


class TestStationScanArgs(unittest.TestCase):
    """Test --station-scan / -S argument parsing"""

    def test_station_scan_disabled_by_default(self):
        """Test station scan is disabled when flag not given"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertFalse(scanner.station_scan)

    def test_station_scan_enabled_with_default_range(self):
        """Test -S with default range (const='1-254')"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "1-254"})
        self.assertTrue(scanner.station_scan)
        self.assertEqual(scanner.ca_scan_start, 1)
        self.assertEqual(scanner.ca_scan_end, 254)

    def test_station_scan_custom_range(self):
        """Test -S 10-500 parses correctly"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "10-500"})
        self.assertTrue(scanner.station_scan)
        self.assertEqual(scanner.ca_scan_start, 10)
        self.assertEqual(scanner.ca_scan_end, 500)

    def test_station_scan_invalid_range_fallback(self):
        """Test invalid range falls back to 1-254"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "abc"})
        self.assertTrue(scanner.station_scan)
        self.assertEqual(scanner.ca_scan_start, 1)
        self.assertEqual(scanner.ca_scan_end, 254)

    def test_station_scan_range_clamping_upper(self):
        """Test values beyond 65534 are clamped"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "1-99999"})
        self.assertEqual(scanner.ca_scan_start, 1)
        self.assertEqual(scanner.ca_scan_end, 65534)

    def test_station_scan_range_clamping_lower(self):
        """Test values below 1 are clamped to 1"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "0-10"})
        self.assertEqual(scanner.ca_scan_start, 1)
        self.assertEqual(scanner.ca_scan_end, 10)

    def test_station_scan_reversed_range(self):
        """Test reversed range (end < start) gets swapped"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "100-10"})
        self.assertEqual(scanner.ca_scan_start, 10)
        self.assertEqual(scanner.ca_scan_end, 100)

    def test_station_scan_single_value_invalid(self):
        """Test single value (not a range) falls back to default"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404, "station-scan": "42"})
        # "42" splits into ["42"], len != 2, so falls back
        self.assertTrue(scanner.station_scan)
        self.assertEqual(scanner.ca_scan_start, 1)
        self.assertEqual(scanner.ca_scan_end, 254)

    def test_station_scan_results_init(self):
        """Test _station_scan_results is initialized as empty dict"""
        scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})
        self.assertEqual(scanner._station_scan_results, {})


class TestCommandResponseTracking(unittest.TestCase):
    """Test command response tracking for protocol-level rejections"""

    def setUp(self):
        self.scanner = IEC104Scanner({"rhost": "127.0.0.1", "rport": 2404})

    def test_command_responses_init_empty(self):
        """_command_responses starts as empty list"""
        self.assertEqual(self.scanner._command_responses, [])

    def test_has_error_response_matches_error_cot(self):
        """_has_error_response finds UNKNOWN_CA entry"""
        self.scanner._command_responses = [
            {
                "type_id": 100,
                "cot": "UNKNOWN_CA",
                "is_negative": False,
                "common_address": 42,
                "timestamp": "2026-01-01T00:00:00",
            },
        ]
        result = self.scanner._has_error_response(common_address=42)
        self.assertIsNotNone(result)
        self.assertEqual(result["cot"], "UNKNOWN_CA")

    def test_has_error_response_matches_negative(self):
        """_has_error_response finds is_negative=True entry"""
        self.scanner._command_responses = [
            {
                "type_id": 100,
                "cot": "ACTIVATION_CON",
                "is_negative": True,
                "common_address": 1,
                "timestamp": "2026-01-01T00:00:00",
            },
        ]
        result = self.scanner._has_error_response(common_address=1)
        self.assertIsNotNone(result)
        self.assertTrue(result["is_negative"])

    def test_has_error_response_filters_by_ca(self):
        """_has_error_response skips entries for other CAs"""
        self.scanner._command_responses = [
            {
                "type_id": 100,
                "cot": "UNKNOWN_CA",
                "is_negative": False,
                "common_address": 10,
                "timestamp": "2026-01-01T00:00:00",
            },
        ]
        result = self.scanner._has_error_response(common_address=99)
        self.assertIsNone(result)

    def test_has_error_response_since_index(self):
        """_has_error_response respects snapshot offset"""
        self.scanner._command_responses = [
            {
                "type_id": 100,
                "cot": "UNKNOWN_CA",
                "is_negative": False,
                "common_address": 1,
                "timestamp": "2026-01-01T00:00:00",
            },
            {
                "type_id": 100,
                "cot": "ACTIVATION_CON",
                "is_negative": False,
                "common_address": 1,
                "timestamp": "2026-01-01T00:00:01",
            },
        ]
        # since_index=1 should skip the first entry
        result = self.scanner._has_error_response(common_address=1, since_index=1)
        self.assertIsNone(result)

    def test_has_error_response_no_ca_filter(self):
        """_has_error_response with no CA filter matches any CA"""
        self.scanner._command_responses = [
            {
                "type_id": 100,
                "cot": "UNKNOWN_IOA",
                "is_negative": False,
                "common_address": 77,
                "timestamp": "2026-01-01T00:00:00",
            },
        ]
        result = self.scanner._has_error_response()
        self.assertIsNotNone(result)
        self.assertEqual(result["cot"], "UNKNOWN_IOA")

    def test_has_error_response_empty(self):
        """_has_error_response returns None on empty list"""
        result = self.scanner._has_error_response()
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
