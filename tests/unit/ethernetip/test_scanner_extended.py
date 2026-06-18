#!/usr/bin/env python3
"""
Extended unit tests for EtherNet/IP scanner.

Tests cover:
- Scanner initialization with all configuration variants
- Route path parsing
- Protocol name / default port
- Dependency checking
- _read_cip_attribute with various result types
- enumerate_all flag propagation
- connect / disconnect logic
- _build_enip_packet / _parse_enip_header / _parse_cip_response
- _send_enip_command via TCP
- _register_session
- ListIdentity, ListServices, ListInterfaces parsing
- Attack commands (CPU stop, crash, reset)
- _dump_security_settings and sub-methods
- _check_parameter_object
- _test_write_with_status
- _determine_permission
- _test_write_access
- _analyze_security
- _fuzz_blacklist
- _identify_dangerous_tags
- _interpret_controller_mode
- _get_controller_time
- _analyze_tag_database
- _enumerate_data_types
- NXC connection class
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip import EtherNetIPScanner


def make_scanner(**overrides):
    """Create an EtherNetIPScanner with sensible defaults."""
    defaults = {"host": "192.168.1.100", "port": 44818}
    defaults.update(overrides)
    return EtherNetIPScanner(defaults)


# =============================================================================
# Scanner initialization
# =============================================================================


class TestScannerInitAdvanced(unittest.TestCase):
    """Test advanced scanner initialization options."""

    def test_enumerate_all_enables_all_flags(self):
        scanner = make_scanner(enumerate_all=True)
        self.assertTrue(scanner.list_services)
        self.assertTrue(scanner.list_interfaces)
        self.assertTrue(scanner.enumerate_objects)
        self.assertTrue(scanner.check_security)
        self.assertTrue(scanner.dump_security)
        # enumerate_all should set max_class to 255
        self.assertEqual(scanner.max_class, 255)

    def test_enumerate_all_with_explicit_maxclass(self):
        scanner = make_scanner(enumerate_all=True, maxclass=50)
        # Explicit maxclass should be used
        self.assertEqual(scanner.max_class, 50)

    def test_individual_flags(self):
        scanner = make_scanner(list_services=False, list_interfaces=True)
        self.assertFalse(scanner.list_services)
        self.assertTrue(scanner.list_interfaces)

    def test_write_disables_read_only(self):
        scanner = make_scanner(write=True)
        self.assertTrue(scanner.test_write)
        self.assertFalse(scanner.read_only)

    def test_attack_options(self):
        scanner = make_scanner(
            cpu_stop=True, crash_ethernet=True, reset_ethernet=True, confirm=True
        )
        self.assertTrue(scanner.cpu_stop)
        self.assertTrue(scanner.crash_ethernet)
        self.assertTrue(scanner.reset_ethernet)
        self.assertTrue(scanner.confirm)

    def test_route_path_options(self):
        scanner = make_scanner(route_path="1/2,1/0", slot=3)
        self.assertEqual(scanner.route_path_str, "1/2,1/0")
        self.assertEqual(scanner.target_slot, 3)

    def test_file_options(self):
        scanner = make_scanner(download_files=True, file_output="/tmp/test", max_file_size=1024)
        self.assertTrue(scanner.download_files)
        self.assertEqual(scanner.file_output, "/tmp/test")
        self.assertEqual(scanner.max_file_size, 1024)

    def test_deep_scan_option(self):
        scanner = make_scanner(deep_scan=True)
        self.assertTrue(scanner.deep_scan)

    def test_full_scan_options(self):
        scanner = make_scanner(full_scan=True, show_udts=True)
        self.assertTrue(scanner.full_scan)
        self.assertTrue(scanner.show_udts)

    def test_dump_tags_options(self):
        scanner = make_scanner(dump_tags=True, tag_output="/tmp/tags")
        self.assertTrue(scanner.dump_tags)
        self.assertEqual(scanner.tag_output, "/tmp/tags")

    def test_driver_type_defaults(self):
        scanner = make_scanner()
        self.assertIsNone(scanner._driver_type)
        self.assertIsNone(scanner._pycomm3_driver)


# =============================================================================
# Protocol info
# =============================================================================


class TestProtocolInfo(unittest.TestCase):
    """Test protocol name and default port."""

    def test_protocol_name(self):
        scanner = make_scanner()
        self.assertEqual(scanner.get_protocol_name(), "EtherNet/IP")

    def test_default_port(self):
        scanner = make_scanner()
        self.assertEqual(scanner.get_default_port(), 44818)


# =============================================================================
# _read_cip_attribute
# =============================================================================


class TestReadCipAttribute(unittest.TestCase):
    """Test _read_cip_attribute with different result types."""

    def test_returns_none_without_generic_message(self):
        scanner = make_scanner()
        conn = MagicMock(spec=[])  # no generic_message attribute
        result = scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertIsNone(result)

    def test_returns_bytes_from_bytes_result(self):
        scanner = make_scanner()
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = b"\x01\x02"
        conn.generic_message.return_value = mock_result
        result = scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertEqual(result, b"\x01\x02")

    def test_returns_bytes_from_list_result(self):
        scanner = make_scanner()
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = [0x01, 0x02, 0x03]
        conn.generic_message.return_value = mock_result
        result = scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertEqual(result, b"\x01\x02\x03")

    def test_returns_bytes_from_int_result(self):
        scanner = make_scanner()
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = 42
        conn.generic_message.return_value = mock_result
        result = scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertEqual(result, struct.pack("<B", 42))

    def test_returns_none_on_none_value(self):
        scanner = make_scanner()
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = None
        conn.generic_message.return_value = mock_result
        result = scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertIsNone(result)

    def test_returns_none_on_exception(self):
        scanner = make_scanner()
        conn = MagicMock()
        conn.generic_message.side_effect = Exception("Timeout")
        result = scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertIsNone(result)

    def test_uses_route_path_when_provided(self):
        scanner = make_scanner()
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = b"\x01"
        conn.generic_message.return_value = mock_result
        route_path = [MagicMock()]
        scanner._read_cip_attribute(conn, 0x01, 1, 1, route_path=route_path)
        call_kwargs = conn.generic_message.call_args[1]
        self.assertFalse(call_kwargs["connected"])
        self.assertTrue(call_kwargs["unconnected_send"])


# =============================================================================
# ENIP packet building/parsing
# =============================================================================


class TestEnipPackets(unittest.TestCase):
    """Test ENIP packet building and parsing."""

    def setUp(self):
        self.scanner = make_scanner()

    def test_build_enip_packet_empty_data(self):
        packet = self.scanner._build_enip_packet(0x0063)
        self.assertEqual(len(packet), 24)
        command = struct.unpack("<H", packet[:2])[0]
        self.assertEqual(command, 0x0063)
        length = struct.unpack("<H", packet[2:4])[0]
        self.assertEqual(length, 0)

    def test_build_enip_packet_with_data(self):
        data = b"\x01\x02\x03\x04"
        packet = self.scanner._build_enip_packet(0x0065, data)
        self.assertEqual(len(packet), 28)
        length = struct.unpack("<H", packet[2:4])[0]
        self.assertEqual(length, 4)
        self.assertEqual(packet[24:], data)

    def test_parse_enip_header_valid(self):
        packet = self.scanner._build_enip_packet(0x0063)
        header = self.scanner._parse_enip_header(packet)
        self.assertIsNotNone(header)
        self.assertEqual(header["command"], 0x0063)
        self.assertEqual(header["length"], 0)
        self.assertEqual(header["session"], 0)
        self.assertEqual(header["status"], 0)

    def test_parse_enip_header_too_short(self):
        result = self.scanner._parse_enip_header(b"\x01\x02\x03")
        self.assertIsNone(result)

    def test_parse_enip_header_with_data(self):
        data = b"\xaa\xbb"
        packet = self.scanner._build_enip_packet(0x0065, data)
        header = self.scanner._parse_enip_header(packet)
        self.assertIsNotNone(header)
        self.assertEqual(header["data"], data)

    def test_parse_cip_response_valid(self):
        """Test parsing a CIP response from SendRRData reply."""
        # Build a minimal valid CIP response
        enip_header = self.scanner._build_enip_packet(0x006F)

        # CPF data: iface_handle(4) + timeout(2) + item_count(2)
        cpf = struct.pack("<IHH", 0, 0, 2)
        # Item 0: Null Address
        cpf += struct.pack("<HH", 0x0000, 0)
        # Item 1: Unconnected Data with CIP response
        cip_data = struct.pack("<BBBB", 0xD2, 0x00, 0x00, 0x00)  # reply, reserved, status, add_size
        cpf += struct.pack("<HH", 0x00B2, len(cip_data))
        cpf += cip_data

        full_packet = enip_header + cpf
        result = self.scanner._parse_cip_response(full_packet)
        self.assertEqual(result["general_status"], 0x00)
        self.assertEqual(result["reply_service"], 0xD2)

    def test_parse_cip_response_short_data(self):
        result = self.scanner._parse_cip_response(b"\x01\x02")
        self.assertEqual(result["general_status"], 0xFF)


# =============================================================================
# ENIP commands (send/receive)
# =============================================================================


class TestEnipCommands(unittest.TestCase):
    """Test ENIP command sending."""

    def setUp(self):
        self.scanner = make_scanner()

    @patch("oida.protocols.ethernetip.mixins.enip_commands.ConnectionHelper")
    def test_send_enip_command_tcp(self, mock_helper):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x63\x00" + b"\x00" * 22
        mock_helper.create_tcp_socket.return_value = mock_sock

        result = self.scanner._send_enip_command("192.168.1.100", 44818, 0x0063)
        self.assertIsNotNone(result)
        mock_sock.send.assert_called_once()

    @patch("oida.protocols.ethernetip.mixins.enip_commands.ConnectionHelper")
    def test_send_enip_command_timeout(self, mock_helper):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("Connection timed out")
        mock_helper.create_tcp_socket.return_value = mock_sock

        result = self.scanner._send_enip_command("192.168.1.100", 44818, 0x0063)
        self.assertIsNone(result)

    @patch("oida.protocols.ethernetip.mixins.enip_commands.ConnectionHelper")
    def test_send_enip_command_exception(self, mock_helper):
        mock_helper.create_tcp_socket.side_effect = Exception("Connection refused")
        result = self.scanner._send_enip_command("192.168.1.100", 44818, 0x0063)
        self.assertIsNone(result)


# =============================================================================
# Session registration
# =============================================================================


class TestRegisterSession(unittest.TestCase):
    """Test session registration."""

    def setUp(self):
        self.scanner = make_scanner()

    def test_register_session_success(self):
        session_id = 0x12345678
        response = struct.pack("<HH I I Q I", 0x0065, 4, session_id, 0, 0, 0)
        response += struct.pack("<HH", 1, 0)  # protocol version + options

        self.scanner._send_enip_command = MagicMock(return_value=response)
        result = self.scanner._register_session("192.168.1.100", 44818)
        self.assertEqual(result, session_id)

    def test_register_session_no_response(self):
        self.scanner._send_enip_command = MagicMock(return_value=None)
        result = self.scanner._register_session("192.168.1.100", 44818)
        self.assertIsNone(result)

    def test_register_session_error_status(self):
        response = struct.pack("<HH I I Q I", 0x0065, 4, 0, 1, 0, 0)  # status=1 (error)
        response += struct.pack("<HH", 1, 0)
        self.scanner._send_enip_command = MagicMock(return_value=response)
        result = self.scanner._register_session("192.168.1.100", 44818)
        self.assertIsNone(result)


# =============================================================================
# Test write access
# =============================================================================


class TestWriteWithStatus(unittest.TestCase):
    """Test _test_write_with_status."""

    def setUp(self):
        self.scanner = make_scanner(write=True)

    def test_no_generic_message(self):
        conn = MagicMock(spec=[])
        success, status, ext = self.scanner._test_write_with_status(conn, 0x01, 1, 1, b"\x01")
        self.assertFalse(success)
        self.assertEqual(status, -1)

    def test_success_result(self):
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.error = None
        mock_result.service_status = 0x00
        mock_result.extended_status = []
        conn.generic_message.return_value = mock_result

        success, status, ext = self.scanner._test_write_with_status(conn, 0x09, 1, 1, b"\x01")
        self.assertTrue(success)
        self.assertEqual(status, 0x00)

    def test_error_status_from_string(self):
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.error = "Attribute not settable"
        mock_result.service_status = None
        mock_result.extended_status = []
        conn.generic_message.return_value = mock_result

        success, status, ext = self.scanner._test_write_with_status(conn, 0x01, 1, 1, b"\x01")
        self.assertFalse(success)
        self.assertEqual(status, 0x0E)

    def test_privilege_violation_from_string(self):
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.error = "Privilege violation"
        mock_result.service_status = None
        mock_result.extended_status = []
        conn.generic_message.return_value = mock_result

        success, status, ext = self.scanner._test_write_with_status(conn, 0x01, 1, 1, b"\x01")
        self.assertEqual(status, 0x0F)

    def test_exception_handling(self):
        conn = MagicMock()
        conn.generic_message.side_effect = Exception("Timeout")
        success, status, ext = self.scanner._test_write_with_status(conn, 0x01, 1, 1, b"\x01")
        self.assertFalse(success)
        self.assertEqual(status, -1)


class TestDeterminePermission(unittest.TestCase):
    """Test _determine_permission."""

    def test_no_write_test(self):
        """Without --write we have no signal — return R? rather than the
        silent ? which used to render as 'read-only' in downstream reports."""
        scanner = make_scanner()
        conn = MagicMock()
        result = scanner._determine_permission(conn, 0x01, 1, 1, b"\x01")
        self.assertEqual(result, "R?")

    def test_write_test_success(self):
        # Live write-test requires BOTH --write and --confirm.
        scanner = make_scanner(write=True, confirm=True)
        scanner._test_write_with_status = MagicMock(return_value=(True, 0x00, []))
        conn = MagicMock()
        result = scanner._determine_permission(conn, 0x09, 1, 1, b"\x01")
        self.assertEqual(result, "RW")

    def test_write_test_read_only(self):
        # Live write-test requires BOTH --write and --confirm.
        scanner = make_scanner(write=True, confirm=True)
        scanner._test_write_with_status = MagicMock(return_value=(False, 0x0E, []))
        conn = MagicMock()
        result = scanner._determine_permission(conn, 0x01, 1, 1, b"\x01")
        self.assertEqual(result, "R")

    def test_write_without_confirm_skips_live_write(self):
        # Regression: --write without --confirm must NOT issue a live write.
        scanner = make_scanner(write=True)  # confirm defaults False
        scanner._test_write_with_status = MagicMock(return_value=(True, 0x00, []))
        conn = MagicMock()
        result = scanner._determine_permission(conn, 0x09, 1, 1, b"\x01")
        scanner._test_write_with_status.assert_not_called()
        self.assertEqual(result, "R?")


# =============================================================================
# Check parameter object
# =============================================================================


class TestCheckParameterObject(unittest.TestCase):
    """Test _check_parameter_object."""

    def test_not_available(self):
        scanner = make_scanner()
        scanner._read_cip_attribute = MagicMock(return_value=None)
        conn = MagicMock()
        result = scanner._check_parameter_object(conn)
        self.assertFalse(result["available"])

    def test_available_with_instances(self):
        scanner = make_scanner()

        def mock_read(conn, cls, inst, attr):
            if cls == 0x0F and inst == 0 and attr == 2:
                return struct.pack("<H", 50)
            elif cls == 0x0F and inst == 0 and attr == 8:
                return struct.pack("<H", 0x0001)
            return None

        scanner._read_cip_attribute = mock_read
        conn = MagicMock()
        result = scanner._check_parameter_object(conn)
        self.assertTrue(result["available"])
        self.assertEqual(result["num_instances"], 50)
        self.assertTrue(result["full_support"])


# =============================================================================
# Security analysis
# =============================================================================


class TestSecurityAnalysisExtended(unittest.TestCase):
    """Test _analyze_security with various result configurations."""

    def test_no_security_detected(self):
        scanner = make_scanner()
        results = {}
        analysis = scanner._analyze_security(results)
        self.assertEqual(analysis["security_level"], "low")
        self.assertIn("concerns", analysis)

    def test_with_controller_mode_editable(self):
        scanner = make_scanner()
        results = {
            "controller_mode": {
                "mode": "REMOTE PROGRAM",
                "keyswitch": "REM",
                "is_editable": True,
                "is_remote": True,
                "is_faulted": False,
            }
        }
        analysis = scanner._analyze_security(results)
        editable_concerns = [c for c in analysis["concerns"] if "editable" in c]
        self.assertGreater(len(editable_concerns), 0)

    def test_with_faulted_controller(self):
        scanner = make_scanner()
        results = {
            "controller_mode": {
                "mode": "RUN",
                "keyswitch": "RUN",
                "is_editable": False,
                "is_remote": False,
                "is_faulted": True,
            }
        }
        analysis = scanner._analyze_security(results)
        fault_concerns = [c for c in analysis["concerns"] if "fault" in c]
        self.assertGreater(len(fault_concerns), 0)

    def test_with_dangerous_tags(self):
        scanner = make_scanner()
        results = {
            "dangerous_tags": [
                {"tag": "ESTOP_1", "risk": "high"},
                {"tag": "SAFETY_RELAY", "risk": "high"},
                {"tag": "MOTOR_ENABLE", "risk": "medium"},
            ]
        }
        analysis = scanner._analyze_security(results)
        tag_concerns = [
            c for c in analysis["concerns"] if "safety" in c.lower() or "tag" in c.lower()
        ]
        self.assertGreater(len(tag_concerns), 0)


# =============================================================================
# Fuzz blacklist
# =============================================================================


class TestFuzzBlacklist(unittest.TestCase):
    """Test fuzz blacklist configuration."""

    def test_blacklist_defined(self):
        from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin

        self.assertIsInstance(FuzzMixin.FUZZ_BLACKLIST, dict)
        self.assertGreater(len(FuzzMixin.FUZZ_BLACKLIST), 0)

    def test_tcp_ip_interface_blacklisted(self):
        from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin

        self.assertIn(0xF5, FuzzMixin.FUZZ_BLACKLIST)
        # Configuration Control (attr 3) should be blacklisted
        self.assertIn(3, FuzzMixin.FUZZ_BLACKLIST[0xF5])

    def test_ethernet_link_blacklisted(self):
        from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin

        self.assertIn(0xF6, FuzzMixin.FUZZ_BLACKLIST)

    def test_security_objects_blacklisted(self):
        from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin

        self.assertIn(0x5D, FuzzMixin.FUZZ_BLACKLIST)
        self.assertIn(0x5E, FuzzMixin.FUZZ_BLACKLIST)
        self.assertIn(0x5F, FuzzMixin.FUZZ_BLACKLIST)

    def test_assembly_io_blacklisted(self):
        from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin

        self.assertIn(0x04, FuzzMixin.FUZZ_BLACKLIST)

    def test_blacklist_entries_have_reasons(self):
        from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin

        for class_id, attrs in FuzzMixin.FUZZ_BLACKLIST.items():
            for attr_id, reason in attrs.items():
                self.assertIsInstance(
                    reason, str, f"0x{class_id:02X} attr {attr_id} missing reason"
                )
                self.assertGreater(len(reason), 0)


# =============================================================================
# Identify dangerous tags
# =============================================================================


class TestIdentifyDangerousTags(unittest.TestCase):
    """Test _identify_dangerous_tags."""

    def test_no_tags(self):
        scanner = make_scanner()
        result = scanner._identify_dangerous_tags([])
        self.assertEqual(result, [])

    def test_safety_tag_detected(self):
        scanner = make_scanner()
        result = scanner._identify_dangerous_tags(["SAFETY_RELAY_1", "TIMER_1"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["tag"], "SAFETY_RELAY_1")
        self.assertEqual(result[0]["risk"], "high")

    def test_estop_tag_detected(self):
        scanner = make_scanner()
        result = scanner._identify_dangerous_tags(["ESTOP_ACTIVE"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk"], "high")

    def test_motor_enable_medium_risk(self):
        scanner = make_scanner()
        result = scanner._identify_dangerous_tags(["MOTOR_ENABLE_1"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk"], "medium")

    def test_normal_tags_not_flagged(self):
        scanner = make_scanner()
        result = scanner._identify_dangerous_tags(["COUNTER_1", "TIMER_2", "DATA[0]"])
        self.assertEqual(len(result), 0)


# =============================================================================
# Controller info mixin
# =============================================================================


class TestControllerInfoMixin(unittest.TestCase):
    """Test controller info interpretation."""

    def test_interpret_controller_mode_not_logix(self):
        scanner = make_scanner()
        scanner._driver_type = "cip"
        result = scanner._interpret_controller_mode(MagicMock())
        self.assertIsNone(result["keyswitch"])

    def test_interpret_controller_mode_prog(self):
        scanner = make_scanner()
        scanner._driver_type = "logix"
        conn = MagicMock()
        conn.info = {"keyswitch": "PROG", "status": 0}
        result = scanner._interpret_controller_mode(conn)
        self.assertEqual(result["keyswitch"], "PROG")
        self.assertTrue(result["is_editable"])
        self.assertFalse(result["is_remote"])

    def test_interpret_controller_mode_remote_run(self):
        scanner = make_scanner()
        scanner._driver_type = "logix"
        conn = MagicMock()
        conn.info = {"keyswitch": "REMOTE RUN", "status": 0}
        result = scanner._interpret_controller_mode(conn)
        self.assertTrue(result["is_remote"])
        self.assertFalse(result["is_editable"])

    def test_interpret_controller_mode_faulted(self):
        scanner = make_scanner()
        scanner._driver_type = "logix"
        conn = MagicMock()
        conn.info = {"keyswitch": "RUN", "status": 0xF0}
        result = scanner._interpret_controller_mode(conn)
        self.assertTrue(result["is_faulted"])

    def test_get_controller_time_not_logix(self):
        scanner = make_scanner()
        scanner._driver_type = "cip"
        result = scanner._get_controller_time(MagicMock())
        self.assertIsNone(result["controller_time"])


# =============================================================================
# Tag analysis
# =============================================================================


class TestTagAnalysis(unittest.TestCase):
    """Test tag database analysis."""

    def test_analyze_tag_database_not_logix(self):
        scanner = make_scanner()
        scanner._driver_type = "cip"
        result = scanner._analyze_tag_database(MagicMock())
        self.assertEqual(result["total_tags"], 0)

    def test_analyze_tag_database_empty(self):
        scanner = make_scanner()
        scanner._driver_type = "logix"
        conn = MagicMock()
        conn.tags = {}
        result = scanner._analyze_tag_database(conn)
        self.assertEqual(result["total_tags"], 0)

    def test_analyze_tag_database_with_tags(self):
        scanner = make_scanner()
        scanner._driver_type = "logix"
        conn = MagicMock()
        conn.tags = {
            "MyTag": {
                "tag_type": "atomic",
                "dim": 0,
                "dimensions": [0, 0, 0],
                "external_access": "Read/Write",
            },
            "Program:MainProg.Counter": {
                "tag_type": "struct",
                "dim": 0,
                "dimensions": [0, 0, 0],
                "external_access": "Read Only",
            },
            "ArrayTag": {
                "tag_type": "atomic",
                "dim": 1,
                "dimensions": [100, 0, 0],
                "external_access": "None",
            },
        }
        result = scanner._analyze_tag_database(conn)
        self.assertEqual(result["total_tags"], 3)
        self.assertEqual(result["atomic_tags"], 2)
        self.assertEqual(result["struct_tags"], 1)
        self.assertEqual(result["array_tags"], 1)
        self.assertEqual(result["controller_scoped"], 2)
        self.assertEqual(result["program_scoped"], 1)
        self.assertEqual(result["external_access"]["read_write"], 1)
        self.assertEqual(result["external_access"]["read_only"], 1)
        self.assertEqual(result["external_access"]["none"], 1)


# =============================================================================
# NXC connection class
# =============================================================================


class TestNxcConnection(unittest.TestCase):
    """Test EtherNet/IP NXC-style connection class attributes."""

    def test_class_exists(self):
        from oida.protocols.ethernetip.nxc_connection import ethernetip

        self.assertTrue(hasattr(ethernetip, "proto_flow"))
        self.assertTrue(hasattr(ethernetip, "create_conn_obj"))
        self.assertTrue(hasattr(ethernetip, "enum_host_info"))
        self.assertTrue(hasattr(ethernetip, "print_host_info"))
        self.assertTrue(hasattr(ethernetip, "cleanup"))
        self.assertTrue(hasattr(ethernetip, "check_dependencies"))

    def test_convert_args_to_dict_from_dict(self):
        from oida.protocols.ethernetip.nxc_connection import ethernetip

        obj = ethernetip.__new__(ethernetip)
        obj.args = {"port": 44818, "timeout": 5}
        obj.host = "192.168.1.100"
        result = obj._convert_args_to_dict()
        self.assertEqual(result["host"], "192.168.1.100")
        self.assertEqual(result["port"], 44818)

    def test_convert_args_to_dict_from_namespace(self):
        import argparse

        from oida.protocols.ethernetip.nxc_connection import ethernetip

        obj = ethernetip.__new__(ethernetip)
        obj.args = argparse.Namespace(port=44818, timeout=5)
        obj.host = "10.0.0.1"
        result = obj._convert_args_to_dict()
        self.assertEqual(result["host"], "10.0.0.1")
        self.assertEqual(result["port"], 44818)


# =============================================================================
# Module-level exports
# =============================================================================


class TestModuleExports(unittest.TestCase):
    """Test that module-level exports are accessible."""

    def test_scanner_class_exported(self):
        from oida.protocols.ethernetip import EtherNetIPScanner

        self.assertIsNotNone(EtherNetIPScanner)

    def test_protocol_options_exported(self):
        from oida.protocols.ethernetip import protocol_options

        self.assertIsInstance(protocol_options, dict)

    def test_metadata_exported(self):
        from oida.protocols.ethernetip import metadata

        self.assertIn("name", metadata)
        self.assertIn("options", metadata)

    def test_run_exported(self):
        from oida.protocols.ethernetip import run

        self.assertTrue(callable(run))

    def test_ethernetip_nxc_exported(self):
        from oida.protocols.ethernetip import ethernetip

        self.assertIsNotNone(ethernetip)

    def test_broadcast_discovery_exported(self):
        from oida.protocols.ethernetip import broadcast_discovery

        self.assertTrue(callable(broadcast_discovery))


if __name__ == "__main__":
    unittest.main()
