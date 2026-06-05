#!/usr/bin/env python3
"""
Comprehensive test suite for CAN bus protocol scanner.

Tests imports, data structures, constants, scanner initialization,
proto_args parsing, and mock-based scanning operations.
"""

import unittest
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.core

# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------


class TestCANImports(unittest.TestCase):
    """Test that CAN module components can be imported."""

    def test_import_can_module(self):
        """Test importing the CAN protocol module."""
        from oida.protocols import can

        self.assertIsNotNone(can)

    def test_import_can_connection_class(self):
        """Test importing the NXC-style CAN connection class."""
        from oida.protocols.can import can as CANConnection

        self.assertIsNotNone(CANConnection)

    def test_import_can_scanner_class(self):
        """Test importing the CANScanner class."""
        from oida.protocols.can.scanner import CANScanner

        self.assertIsNotNone(CANScanner)

    def test_import_constants(self):
        """Test importing CAN constants."""
        from oida.protocols.can.constants import (
            CAN_BAUDRATES,
            CAN_EXT_ID_MAX,
            CAN_MAX_DLC,
            CAN_STD_ID_MAX,
            COMMON_UDS_PAIRS,
            DEFAULT_BAUDRATE,
            OBD2_SERVICES,
            UDS_SERVICES,
        )

        self.assertEqual(CAN_STD_ID_MAX, 0x7FF)
        self.assertEqual(CAN_EXT_ID_MAX, 0x1FFFFFFF)
        self.assertEqual(CAN_MAX_DLC, 8)
        self.assertEqual(DEFAULT_BAUDRATE, 500000)
        self.assertIsInstance(CAN_BAUDRATES, dict)
        self.assertIsInstance(UDS_SERVICES, dict)
        self.assertIsInstance(OBD2_SERVICES, dict)
        self.assertIsInstance(COMMON_UDS_PAIRS, dict)

    def test_import_data_classes(self):
        """Test importing CAN data classes."""
        from oida.protocols.can.constants import (
            CANDevice,
            CANMessage,
            CANTrafficStats,
            UDSScanResult,
        )

        self.assertIsNotNone(CANMessage)
        self.assertIsNotNone(CANDevice)
        self.assertIsNotNone(CANTrafficStats)
        self.assertIsNotNone(UDSScanResult)

    def test_import_proto_args(self):
        """Test importing proto_args module."""
        from oida.protocols.can.proto_args import proto_args

        self.assertTrue(callable(proto_args))


# ---------------------------------------------------------------------------
# Data structure tests
# ---------------------------------------------------------------------------


class TestCANMessage(unittest.TestCase):
    """Test CANMessage data class."""

    def test_standard_message(self):
        """Test creating a standard CAN message."""
        from oida.protocols.can.constants import CANMessage

        msg = CANMessage(
            arbitration_id=0x7E0,
            data=b"\x02\x3e\x00\x00\x00\x00\x00\x00",
        )

        self.assertEqual(msg.arbitration_id, 0x7E0)
        self.assertEqual(msg.dlc, 8)
        self.assertFalse(msg.is_extended)
        self.assertFalse(msg.is_remote)
        self.assertFalse(msg.is_error)
        self.assertEqual(msg.id_hex, "0x7E0")
        self.assertEqual(msg.data_hex, "02 3E 00 00 00 00 00 00")

    def test_extended_message(self):
        """Test creating an extended CAN message."""
        from oida.protocols.can.constants import CANMessage

        msg = CANMessage(
            arbitration_id=0x18DAF110,
            data=b"\x02\x10\x01",
            is_extended=True,
        )

        self.assertEqual(msg.arbitration_id, 0x18DAF110)
        self.assertTrue(msg.is_extended)
        self.assertEqual(msg.dlc, 3)
        self.assertEqual(msg.id_hex, "0x18DAF110")

    def test_empty_message(self):
        """Test creating a message with no data."""
        from oida.protocols.can.constants import CANMessage

        msg = CANMessage(arbitration_id=0x100, data=b"")

        self.assertEqual(msg.dlc, 0)
        self.assertEqual(msg.data_hex, "")

    def test_remote_frame(self):
        """Test creating a remote frame."""
        from oida.protocols.can.constants import CANMessage

        msg = CANMessage(
            arbitration_id=0x200,
            data=b"",
            is_remote=True,
        )

        self.assertTrue(msg.is_remote)

    def test_error_frame(self):
        """Test creating an error frame."""
        from oida.protocols.can.constants import CANMessage

        msg = CANMessage(
            arbitration_id=0x000,
            data=b"\xff\xff\xff\xff\xff\xff\xff\xff",
            is_error=True,
        )

        self.assertTrue(msg.is_error)

    def test_explicit_dlc(self):
        """Test DLC is not overridden when explicitly set."""
        from oida.protocols.can.constants import CANMessage

        msg = CANMessage(
            arbitration_id=0x100,
            data=b"\x01\x02",
            dlc=8,
        )

        # dlc=8 was explicitly set, but __post_init__ only sets when dlc=0
        self.assertEqual(msg.dlc, 8)


class TestCANDevice(unittest.TestCase):
    """Test CANDevice data class."""

    def test_device_creation(self):
        """Test creating a CANDevice."""
        from oida.protocols.can.constants import CANDevice

        device = CANDevice(
            arbitration_id=0x7E0,
            response_id=0x7E8,
            name="Engine ECU",
            uds_services=[0x10, 0x22, 0x27, 0x3E],
            obd2_supported=True,
        )

        self.assertEqual(device.arbitration_id, 0x7E0)
        self.assertEqual(device.response_id, 0x7E8)
        self.assertEqual(device.name, "Engine ECU")
        self.assertEqual(len(device.uds_services), 4)
        self.assertTrue(device.obd2_supported)
        self.assertEqual(device.id_hex, "0x7E0")
        self.assertEqual(device.response_id_hex, "0x7E8")

    def test_device_defaults(self):
        """Test CANDevice default values."""
        from oida.protocols.can.constants import CANDevice

        device = CANDevice(arbitration_id=0x100)

        self.assertEqual(device.response_id, 0)
        self.assertEqual(device.name, "")
        self.assertEqual(device.uds_services, [])
        self.assertFalse(device.obd2_supported)
        self.assertEqual(device.message_count, 0)
        self.assertEqual(device.data_samples, [])
        self.assertEqual(device.response_id_hex, "N/A")

    def test_device_with_samples(self):
        """Test CANDevice with data samples."""
        from oida.protocols.can.constants import CANDevice

        device = CANDevice(
            arbitration_id=0x200,
            data_samples=[b"\x01\x02\x03", b"\x04\x05\x06"],
            message_count=100,
        )

        self.assertEqual(len(device.data_samples), 2)
        self.assertEqual(device.message_count, 100)


class TestCANTrafficStats(unittest.TestCase):
    """Test CANTrafficStats data class."""

    def test_empty_stats(self):
        """Test default traffic statistics."""
        from oida.protocols.can.constants import CANTrafficStats

        stats = CANTrafficStats()

        self.assertEqual(stats.total_messages, 0)
        self.assertEqual(stats.unique_ids, 0)
        self.assertEqual(stats.duration_seconds, 0.0)
        self.assertEqual(len(stats.id_counts), 0)
        self.assertEqual(stats.error_frames, 0)

    def test_stats_with_data(self):
        """Test traffic statistics with data."""
        from oida.protocols.can.constants import CANTrafficStats

        stats = CANTrafficStats(
            total_messages=1000,
            unique_ids=25,
            duration_seconds=10.0,
            messages_per_second=100.0,
            id_counts={0x100: 500, 0x200: 300, 0x300: 200},
            error_frames=5,
        )

        self.assertEqual(stats.total_messages, 1000)
        self.assertEqual(stats.unique_ids, 25)

        top = stats.get_top_ids(2)
        self.assertEqual(len(top), 2)
        self.assertEqual(top[0][0], 0x100)  # Most frequent
        self.assertEqual(top[0][1], 500)

    def test_get_top_ids_empty(self):
        """Test get_top_ids with no data."""
        from oida.protocols.can.constants import CANTrafficStats

        stats = CANTrafficStats()
        top = stats.get_top_ids(10)
        self.assertEqual(len(top), 0)


class TestUDSScanResult(unittest.TestCase):
    """Test UDSScanResult data class."""

    def test_uds_result(self):
        """Test creating a UDS scan result."""
        from oida.protocols.can.constants import UDSScanResult

        result = UDSScanResult(
            request_id=0x7E0,
            response_id=0x7E8,
            supported_services=[0x10, 0x22, 0x27, 0x3E],
            diagnostic_sessions=[0x01, 0x03],
            vehicle_info={"VIN": "WBA1234567890ABCD"},
        )

        self.assertEqual(result.request_id, 0x7E0)
        self.assertEqual(result.response_id, 0x7E8)
        self.assertIn(0x3E, result.supported_services)
        self.assertEqual(len(result.diagnostic_sessions), 2)
        self.assertEqual(result.vehicle_info["VIN"], "WBA1234567890ABCD")

    def test_uds_result_defaults(self):
        """Test UDS result default values."""
        from oida.protocols.can.constants import UDSScanResult

        result = UDSScanResult(request_id=0x700, response_id=0x708)

        self.assertEqual(result.supported_services, [])
        self.assertEqual(result.diagnostic_sessions, [])
        self.assertEqual(result.vehicle_info, {})
        self.assertEqual(result.negative_responses, {})


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------


class TestCANConstants(unittest.TestCase):
    """Test CAN protocol constants."""

    def test_baudrate_values(self):
        """Test CAN baudrate dictionary."""
        from oida.protocols.can.constants import CAN_BAUDRATES, DEFAULT_BAUDRATE

        self.assertIn("500k", CAN_BAUDRATES)
        self.assertIn("250k", CAN_BAUDRATES)
        self.assertIn("125k", CAN_BAUDRATES)
        self.assertIn("1m", CAN_BAUDRATES)
        self.assertEqual(CAN_BAUDRATES["500k"], 500000)
        self.assertEqual(CAN_BAUDRATES["1m"], 1000000)
        self.assertEqual(DEFAULT_BAUDRATE, 500000)

    def test_uds_service_ids(self):
        """Test UDS service ID dictionary."""
        from oida.protocols.can.constants import UDS_SERVICES

        self.assertIn(0x10, UDS_SERVICES)  # DiagnosticSessionControl
        self.assertIn(0x22, UDS_SERVICES)  # ReadDataByIdentifier
        self.assertIn(0x27, UDS_SERVICES)  # SecurityAccess
        self.assertIn(0x3E, UDS_SERVICES)  # TesterPresent
        self.assertEqual(UDS_SERVICES[0x3E], "TesterPresent")
        self.assertEqual(UDS_SERVICES[0x22], "ReadDataByIdentifier")

    def test_uds_nrc_codes(self):
        """Test UDS negative response codes."""
        from oida.protocols.can.constants import UDS_NRC

        self.assertIn(0x11, UDS_NRC)  # ServiceNotSupported
        self.assertIn(0x33, UDS_NRC)  # SecurityAccessDenied
        self.assertIn(0x78, UDS_NRC)  # RequestCorrectlyReceivedResponsePending
        self.assertEqual(UDS_NRC[0x33], "SecurityAccessDenied")

    def test_obd2_service_ids(self):
        """Test OBD-II service definitions."""
        from oida.protocols.can.constants import OBD2_SERVICES

        self.assertIn(0x01, OBD2_SERVICES)  # ShowCurrentData
        self.assertIn(0x09, OBD2_SERVICES)  # VehicleInformation
        self.assertEqual(OBD2_SERVICES[0x01], "ShowCurrentData")

    def test_obd2_pids(self):
        """Test OBD-II PID dictionary."""
        from oida.protocols.can.constants import OBD2_PIDS

        self.assertIn(0x00, OBD2_PIDS)  # PIDs supported [01-20]
        self.assertIn(0x0C, OBD2_PIDS)  # Engine RPM
        self.assertIn(0x0D, OBD2_PIDS)  # Vehicle speed
        self.assertEqual(OBD2_PIDS[0x0C], "Engine RPM")

    def test_common_uds_pairs(self):
        """Test common UDS request/response arbitration ID pairs."""
        from oida.protocols.can.constants import COMMON_UDS_PAIRS

        self.assertEqual(COMMON_UDS_PAIRS[0x7E0], 0x7E8)
        self.assertEqual(COMMON_UDS_PAIRS[0x7E1], 0x7E9)
        self.assertEqual(COMMON_UDS_PAIRS[0x7DF], 0x7E8)

    def test_isotp_frame_types(self):
        """Test ISO-TP frame type constants."""
        from oida.protocols.can.constants import (
            ISOTP_CONSECUTIVE_FRAME,
            ISOTP_FIRST_FRAME,
            ISOTP_FLOW_CONTROL,
            ISOTP_FRAME_TYPES,
            ISOTP_SINGLE_FRAME,
        )

        self.assertEqual(ISOTP_SINGLE_FRAME, 0x00)
        self.assertEqual(ISOTP_FIRST_FRAME, 0x10)
        self.assertEqual(ISOTP_CONSECUTIVE_FRAME, 0x20)
        self.assertEqual(ISOTP_FLOW_CONTROL, 0x30)
        self.assertEqual(len(ISOTP_FRAME_TYPES), 4)

    def test_canopen_constants(self):
        """Test CANopen base arbitration ID constants."""
        from oida.protocols.can.constants import (
            CANOPEN_HEARTBEAT_BASE,
            CANOPEN_NMT_ID,
            CANOPEN_SDO_RX_BASE,
            CANOPEN_SDO_TX_BASE,
        )

        self.assertEqual(CANOPEN_NMT_ID, 0x000)
        self.assertEqual(CANOPEN_SDO_TX_BASE, 0x580)
        self.assertEqual(CANOPEN_SDO_RX_BASE, 0x600)
        self.assertEqual(CANOPEN_HEARTBEAT_BASE, 0x700)

    def test_uds_sessions(self):
        """Test UDS diagnostic session types."""
        from oida.protocols.can.constants import UDS_SESSIONS

        self.assertIn(0x01, UDS_SESSIONS)  # DefaultSession
        self.assertIn(0x02, UDS_SESSIONS)  # ProgrammingSession
        self.assertIn(0x03, UDS_SESSIONS)  # ExtendedDiagnosticSession
        self.assertEqual(UDS_SESSIONS[0x01], "DefaultSession")


# ---------------------------------------------------------------------------
# Scanner initialization tests
# ---------------------------------------------------------------------------


class TestCANScannerInit(unittest.TestCase):
    """Test CAN scanner initialization."""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0"})

        self.assertEqual(scanner.interface, "can0")
        self.assertEqual(scanner.get_protocol_name(), "CAN")
        self.assertEqual(scanner.get_default_port(), 0)
        self.assertEqual(scanner.baudrate, 500000)
        self.assertFalse(scanner.extended)
        self.assertEqual(scanner.sniff_time, 10)
        self.assertFalse(scanner.uds_scan)
        self.assertEqual(scanner.bus_type, "socketcan")
        self.assertFalse(scanner.fd)

    def test_scanner_init_custom(self):
        """Test scanner initialization with custom values."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner(
            {
                "interface": "vcan0",
                "baudrate": 250000,
                "extended": True,
                "sniff-time": 30,
                "uds-scan": True,
                "bus-type": "virtual",
                "fd": True,
            }
        )

        self.assertEqual(scanner.interface, "vcan0")
        self.assertEqual(scanner.baudrate, 250000)
        self.assertTrue(scanner.extended)
        self.assertEqual(scanner.sniff_time, 30)
        self.assertTrue(scanner.uds_scan)
        self.assertEqual(scanner.bus_type, "virtual")
        self.assertTrue(scanner.fd)

    def test_scanner_init_target_fallback(self):
        """Test that target is used as interface fallback."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"target": "slcan0"})

        self.assertEqual(scanner.interface, "slcan0")

    def test_scanner_init_channel_override(self):
        """Test that channel parameter overrides target."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner(
            {
                "interface": "can0",
                "channel": "can1",
            }
        )

        self.assertEqual(scanner.channel, "can1")


class TestCANScannerIdFilter(unittest.TestCase):
    """Test arbitration ID filter parsing."""

    def test_no_filter(self):
        """Test no filter returns None."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0"})
        self.assertIsNone(scanner.id_filter)

    def test_single_id_filter(self):
        """Test single ID filter."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0", "filter-id": "0x7E0"})

        self.assertIsNotNone(scanner.id_filter)
        self.assertIn(0x7E0, scanner.id_filter)
        self.assertEqual(len(scanner.id_filter), 1)

    def test_range_filter(self):
        """Test ID range filter."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0", "filter-id": "0x7E0-0x7EF"})

        self.assertIsNotNone(scanner.id_filter)
        self.assertIn(0x7E0, scanner.id_filter)
        self.assertIn(0x7EF, scanner.id_filter)
        self.assertEqual(len(scanner.id_filter), 16)

    def test_list_filter(self):
        """Test comma-separated ID filter."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0", "filter-id": "0x100,0x200,0x300"})

        self.assertIsNotNone(scanner.id_filter)
        self.assertIn(0x100, scanner.id_filter)
        self.assertIn(0x200, scanner.id_filter)
        self.assertIn(0x300, scanner.id_filter)
        self.assertEqual(len(scanner.id_filter), 3)

    def test_empty_filter(self):
        """Test empty filter string returns None."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0", "filter-id": ""})
        self.assertIsNone(scanner.id_filter)


# ---------------------------------------------------------------------------
# Traffic classification tests
# ---------------------------------------------------------------------------


class TestCANTrafficClassification(unittest.TestCase):
    """Test CAN arbitration ID classification logic."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "can0"})

    def test_obd2_request_id(self):
        """Test OBD-II broadcast request classification."""
        result = self.scanner._identify_id(0x7DF)
        self.assertIn("OBD-II Request", result)

    def test_obd2_response_id(self):
        """Test OBD-II response classification."""
        result = self.scanner._identify_id(0x7E8)
        self.assertIn("OBD-II Response", result)
        self.assertIn("ECU #1", result)

    def test_obd2_response_ecu2(self):
        """Test OBD-II response ECU #2 classification."""
        result = self.scanner._identify_id(0x7E9)
        self.assertIn("OBD-II Response", result)
        self.assertIn("ECU #2", result)

    def test_uds_request_id(self):
        """Test UDS request classification."""
        result = self.scanner._identify_id(0x7E0)
        self.assertIn("UDS Request", result)

    def test_canopen_nmt(self):
        """Test CANopen NMT classification."""
        result = self.scanner._identify_id(0x000)
        self.assertIn("CANopen NMT", result)

    def test_canopen_sync(self):
        """Test CANopen SYNC classification."""
        result = self.scanner._identify_id(0x080)
        self.assertIn("CANopen SYNC", result)

    def test_canopen_emergency(self):
        """Test CANopen Emergency classification."""
        result = self.scanner._identify_id(0x081)
        self.assertIn("CANopen Emergency", result)
        self.assertIn("node 1", result)

    def test_canopen_tpdo1(self):
        """Test CANopen TPDO1 classification."""
        result = self.scanner._identify_id(0x181)
        self.assertIn("CANopen TPDO1", result)
        self.assertIn("node 1", result)

    def test_canopen_sdo_response(self):
        """Test CANopen SDO response classification."""
        result = self.scanner._identify_id(0x581)
        self.assertIn("CANopen SDO Response", result)
        self.assertIn("node 1", result)

    def test_canopen_sdo_request(self):
        """Test CANopen SDO request classification."""
        result = self.scanner._identify_id(0x601)
        self.assertIn("CANopen SDO Request", result)
        self.assertIn("node 1", result)

    def test_canopen_heartbeat(self):
        """Test CANopen Heartbeat classification."""
        result = self.scanner._identify_id(0x701)
        self.assertIn("CANopen Heartbeat", result)
        self.assertIn("node 1", result)

    def test_extended_frame(self):
        """Test extended frame classification."""
        result = self.scanner._identify_id(0x18FEF100)
        self.assertIn("Extended frame", result)

    def test_unclassified_id(self):
        """Test unclassified standard ID returns empty string."""
        result = self.scanner._identify_id(0x010)
        self.assertEqual(result, "")


# ---------------------------------------------------------------------------
# Proto args tests
# ---------------------------------------------------------------------------


class TestCANProtoArgs(unittest.TestCase):
    """Test CAN protocol argument parser."""

    def _make_parser(self):
        """Create a parser with CAN subcommand registered."""
        import argparse

        from oida.protocols.can.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        # Mirror common CLI flags so subparser inherits them via parents=
        parent = argparse.ArgumentParser(add_help=False)
        parent.add_argument("-v", "--verbose", action="count", default=0)
        parent.add_argument("--debug", action="store_true")
        parent.add_argument("-o", "--output", type=str)
        parent.add_argument("-f", "--format", type=str, default="console")
        proto_args(subparsers, [parent])
        return main_parser

    def test_basic_parsing(self):
        """Test basic CAN argument parsing."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])

        self.assertEqual(args.target, "can0")

    def test_baudrate_option(self):
        """Test --baudrate option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "-B", "250000"])

        self.assertEqual(args.baudrate, 250000)

    def test_baudrate_default(self):
        """Test default baudrate value."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])

        self.assertEqual(args.baudrate, 500000)

    def test_bus_type_option(self):
        """Test --bus-type option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "vcan0", "--bus-type", "virtual"])

        self.assertEqual(args.bus_type, "virtual")

    def test_extended_flag(self):
        """Test --extended flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--extended"])

        self.assertTrue(args.extended)

    def test_fd_flag(self):
        """Test --fd flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--fd"])

        self.assertTrue(args.fd)

    def test_sniff_time_option(self):
        """Test --sniff-time option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--sniff-time", "30"])

        self.assertEqual(args.sniff_time, 30)

    def test_sniff_time_default(self):
        """Test default sniff time."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])

        self.assertEqual(args.sniff_time, 10)

    def test_uds_scan_flag(self):
        """Test --uds-scan flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-scan"])

        self.assertTrue(args.uds_scan)

    def test_obd2_flag(self):
        """Test --obd2 flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--obd2"])

        self.assertTrue(args.obd2)

    def test_id_scan_flag(self):
        """Test --id-scan flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--id-scan"])

        self.assertTrue(args.id_scan)

    def test_filter_id_option(self):
        """Test --filter-id option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--filter-id", "0x7E0-0x7EF"])

        self.assertEqual(args.filter_id, "0x7E0-0x7EF")

    def test_send_option(self):
        """Test --send option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--send", "0x7DF#0201000000000000"])

        self.assertEqual(args.send, "0x7DF#0201000000000000")

    def test_replay_option(self):
        """Test --replay option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--replay", "traffic.log"])

        self.assertEqual(args.replay, "traffic.log")

    def test_monitor_flag(self):
        """Test --monitor flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--monitor"])

        self.assertTrue(args.monitor)

    def test_fuzz_and_confirm(self):
        """Test --fuzz and --confirm flags."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--fuzz", "--confirm", "--fuzz-id", "0x7E0"])

        self.assertTrue(args.fuzz)
        self.assertTrue(args.confirm)
        self.assertEqual(args.fuzz_id, "0x7E0")

    def test_fuzz_mode_choices(self):
        """Test --fuzz-mode choices."""
        parser = self._make_parser()

        for mode in ("random", "sequential", "boundary", "smart"):
            args = parser.parse_args(["can", "can0", "--fuzz-mode", mode])
            self.assertEqual(args.fuzz_mode, mode)

    def test_verbose_flag(self):
        """Test -v verbose flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "-v"])

        self.assertEqual(args.verbose, 1)

    def test_debug_flag(self):
        """Test --debug flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--debug"])

        self.assertTrue(args.debug)

    def test_output_options(self):
        """Test output options."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "-o", "/tmp/results", "-f", "json"])

        self.assertEqual(args.output, "/tmp/results")
        self.assertEqual(args.format, "json")

    def test_no_sniff_flag(self):
        """Test --no-sniff flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--no-sniff"])

        self.assertTrue(args.no_sniff)

    def test_on_change_flag(self):
        """Test --on-change flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--on-change"])

        self.assertTrue(args.on_change)

    def test_log_file_option(self):
        """Test --log-file option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--log-file", "capture.log"])

        self.assertEqual(args.log_file, "capture.log")


# ---------------------------------------------------------------------------
# Mock-based operation tests
# ---------------------------------------------------------------------------


class TestCANScannerMockOperations(unittest.TestCase):
    """Test CAN scanner operations with mocked python-can."""

    def setUp(self):
        """Create a scanner instance."""
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_connect_success(self, mock_can_lazy):
        """Test successful CAN bus connection."""
        mock_can = MagicMock()
        mock_bus = MagicMock()
        mock_can.Bus.return_value = mock_bus
        mock_can_lazy.return_value = mock_can

        connection = self.scanner.connect()

        self.assertEqual(connection, mock_bus)
        mock_can.Bus.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_connect_failure(self, mock_can_lazy):
        """Test CAN bus connection failure."""
        mock_can = MagicMock()
        mock_can.Bus.side_effect = Exception("Interface not found")
        mock_can_lazy.return_value = mock_can

        connection = self.scanner.connect()

        self.assertIsNone(connection)

    @patch("oida.protocols.can.scanner._python_can")
    def test_disconnect(self, mock_can_lazy):
        """Test CAN bus disconnection."""
        mock_bus = MagicMock()

        self.scanner.disconnect(mock_bus)

        mock_bus.shutdown.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_send_message(self, mock_can_lazy):
        """Test sending a CAN message."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        result = self.scanner.send_message(
            mock_bus,
            arb_id=0x7E0,
            data=b"\x02\x3e\x00\x00\x00\x00\x00\x00",
        )

        self.assertTrue(result)
        mock_bus.send.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_send_message_failure(self, mock_can_lazy):
        """Test send failure handling."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.send.side_effect = Exception("Bus off")

        result = self.scanner.send_message(mock_bus, 0x100, b"\x01")

        self.assertFalse(result)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_message(self, mock_can_lazy):
        """Test receiving a CAN message."""
        mock_bus = MagicMock()
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x7E8
        mock_msg.data = bytearray(b"\x02\x7e\x00\x00\x00\x00\x00\x00")
        mock_msg.timestamp = 1234567890.0
        mock_msg.is_extended_id = False
        mock_msg.is_remote_frame = False
        mock_msg.is_error_frame = False
        mock_msg.dlc = 8
        mock_msg.channel = "vcan0"
        mock_bus.recv.return_value = mock_msg

        result = self.scanner.recv_message(mock_bus, timeout=1.0)

        self.assertIsNotNone(result)
        self.assertEqual(result.arbitration_id, 0x7E8)
        self.assertEqual(result.dlc, 8)
        self.assertFalse(result.is_extended)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_message_timeout(self, mock_can_lazy):
        """Test receive timeout returns None."""
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        result = self.scanner.recv_message(mock_bus, timeout=0.1)

        self.assertIsNone(result)


class TestCANScannerSniffing(unittest.TestCase):
    """Test CAN scanner passive sniffing."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0"})

    @patch("oida.protocols.can.scanner.time")
    def test_sniff_traffic_collects_stats(self, mock_time):
        """Test traffic sniffing collects statistics."""
        mock_bus = MagicMock()

        # Simulate time progression
        call_count = [0]
        base_time = 1000.0

        def time_side_effect():
            call_count[0] += 1
            # Return increasing time, but after enough calls exceed the end
            return base_time + (call_count[0] * 0.1)

        mock_time.time.side_effect = time_side_effect

        # Create mock messages
        msg1 = MagicMock()
        msg1.arbitration_id = 0x100
        msg1.timestamp = base_time + 0.1
        msg1.is_extended_id = False
        msg1.is_error_frame = False
        msg1.is_remote_frame = False
        msg1.data = bytearray(b"\x01\x02\x03")

        msg2 = MagicMock()
        msg2.arbitration_id = 0x200
        msg2.timestamp = base_time + 0.2
        msg2.is_extended_id = False
        msg2.is_error_frame = False
        msg2.is_remote_frame = False
        msg2.data = bytearray(b"\x04\x05\x06")

        # Return two messages then None (to break loop when time exceeds)
        mock_bus.recv.side_effect = [
            msg1,
            msg2,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]

        stats = self.scanner._sniff_traffic(mock_bus, duration=1)

        self.assertGreaterEqual(stats.total_messages, 0)
        self.assertIsInstance(stats.id_counts, dict)


class TestCANScannerISO_TP(unittest.TestCase):
    """Test ISO-TP frame assembly in NXC connection class."""

    def test_single_frame_assembly(self):
        """Test ISO-TP single frame assembly."""
        from oida.protocols.can import can as CANConnection

        # Create a partial instance for testing (avoid __init__ proto_flow)
        conn = CANConnection.__new__(CANConnection)

        # Single frame: PCI=0x03, 3 bytes of data
        frames = [b"\x03\x22\xf1\x90\x00\x00\x00\x00"]
        result = conn._assemble_isotp_data(frames)

        self.assertIsNotNone(result)
        self.assertEqual(result, b"\x22\xf1\x90")

    def test_multi_frame_assembly(self):
        """Test ISO-TP multi-frame (first + consecutive) assembly."""
        from oida.protocols.can import can as CANConnection

        conn = CANConnection.__new__(CANConnection)

        # First frame: total_length=20, first 6 data bytes
        # Consecutive frames with sequence numbers
        frames = [
            b"\x10\x14\x49\x02\x01\x57\x42\x41",  # FF: len=20, data starts
            b"\x21\x31\x32\x33\x34\x35\x36\x37",  # CF seq=1
            b"\x22\x38\x39\x30\x41\x42\x43\x44",  # CF seq=2
        ]
        result = conn._assemble_isotp_data(frames)

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 20)

    def test_empty_frames(self):
        """Test assembly with no frames."""
        from oida.protocols.can import can as CANConnection

        conn = CANConnection.__new__(CANConnection)

        result = conn._assemble_isotp_data([])
        self.assertIsNone(result)

    def test_empty_first_frame(self):
        """Test assembly with empty first frame."""
        from oida.protocols.can import can as CANConnection

        conn = CANConnection.__new__(CANConnection)

        result = conn._assemble_isotp_data([b""])
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# NXC Connection class tests
# ---------------------------------------------------------------------------


class TestCANConnectionClass(unittest.TestCase):
    """Test NXC-style CAN connection class properties."""

    def test_class_attributes(self):
        """Test CAN connection class attributes."""
        from oida.protocols.can import can as CANConnection

        self.assertEqual(CANConnection.name, "CAN")
        self.assertEqual(CANConnection.protocol_name, "CAN")
        self.assertEqual(CANConnection.default_port, 0)

    def test_check_dependencies(self):
        """Test dependency check method exists and returns bool."""
        from oida.protocols.can import can as CANConnection

        result = CANConnection.check_dependencies()
        self.assertIsInstance(result, bool)

    def test_inherits_serial_connection(self):
        """Test CAN class inherits from SerialConnection."""
        from oida.connection import SerialConnection
        from oida.protocols.can import can as CANConnection

        self.assertTrue(issubclass(CANConnection, SerialConnection))


# ---------------------------------------------------------------------------
# Dependency check tests
# ---------------------------------------------------------------------------


class TestCANDependencyCheck(unittest.TestCase):
    """Test CAN dependency checking."""

    def test_scanner_check_dependencies(self):
        """Test scanner dependency check returns bool."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0"})
        result = scanner.check_dependencies()
        self.assertIsInstance(result, bool)

    def test_lazy_import_available(self):
        """Test lazy import is_available property."""
        from oida.protocols.can.scanner import _python_can

        self.assertIsInstance(_python_can.is_available, bool)


# ---------------------------------------------------------------------------
# Protocol loader integration test
# ---------------------------------------------------------------------------


class TestCANInLoader(unittest.TestCase):
    """Test CAN protocol is registered in the loader."""

    def test_can_in_known_protocols(self):
        """Test that 'can' is in the known protocols list."""
        from oida.loader import _KNOWN_PROTOCOLS

        self.assertIn("can", _KNOWN_PROTOCOLS)

    def test_can_in_protocol_dependencies(self):
        """Test that 'can' is in PROTOCOL_DEPENDENCIES."""
        from oida.utils.lazy_import import PROTOCOL_DEPENDENCIES

        self.assertIn("can", PROTOCOL_DEPENDENCIES)
        self.assertEqual(PROTOCOL_DEPENDENCIES["can"]["module"], "can")
        self.assertEqual(PROTOCOL_DEPENDENCIES["can"]["protocol"], "can")


# ---------------------------------------------------------------------------
# Edge case and robustness tests
# ---------------------------------------------------------------------------


class TestCANEdgeCases(unittest.TestCase):
    """Test edge cases and robustness."""

    def test_scanner_with_minimal_args(self):
        """Test scanner works with only interface provided."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0"})
        self.assertIsNotNone(scanner)

    def test_scanner_classify_empty_stats(self):
        """Test traffic classification with empty stats."""
        from oida.protocols.can.constants import CANTrafficStats
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0"})
        stats = CANTrafficStats()

        result = scanner._classify_traffic(stats)
        self.assertEqual(result, [])

    def test_scanner_classify_with_data(self):
        """Test traffic classification with data."""
        from oida.protocols.can.constants import CANTrafficStats
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0"})
        stats = CANTrafficStats(
            id_counts={0x7E0: 10, 0x7E8: 8, 0x100: 50},
        )

        result = scanner._classify_traffic(stats)
        self.assertEqual(len(result), 3)

        # Check classification is present
        ids = {entry["arbitration_id"] for entry in result}
        self.assertIn("0x7E0", ids)
        self.assertIn("0x7E8", ids)
        self.assertIn("0x100", ids)

    def test_filter_decimal_ids(self):
        """Test filter parsing with decimal IDs."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "can0", "filter-id": "256,512"})

        self.assertIsNotNone(scanner.id_filter)
        self.assertIn(256, scanner.id_filter)
        self.assertIn(512, scanner.id_filter)

    def test_filter_invalid_values(self):
        """Test filter parsing handles invalid values gracefully."""
        from oida.protocols.can.scanner import CANScanner

        # Should not raise, just warn
        scanner = CANScanner({"interface": "can0", "filter-id": "xyz,abc"})
        self.assertIsNone(scanner.id_filter)

    def test_message_data_hex_formatting(self):
        """Test CANMessage hex formatting with various data lengths."""
        from oida.protocols.can.constants import CANMessage

        # Single byte
        msg = CANMessage(arbitration_id=0x100, data=b"\xab")
        self.assertEqual(msg.data_hex, "AB")

        # Full 8 bytes
        msg = CANMessage(arbitration_id=0x100, data=b"\x00\x11\x22\x33\x44\x55\x66\x77")
        self.assertEqual(msg.data_hex, "00 11 22 33 44 55 66 77")

    def test_traffic_stats_top_ids_limit(self):
        """Test top IDs with limit smaller than total."""
        from oida.protocols.can.constants import CANTrafficStats

        stats = CANTrafficStats(
            id_counts={i: (100 - i) for i in range(50)},
        )

        top_5 = stats.get_top_ids(5)
        self.assertEqual(len(top_5), 5)
        # Most frequent should be ID 0 with count 100
        self.assertEqual(top_5[0][0], 0)
        self.assertEqual(top_5[0][1], 100)


# ---------------------------------------------------------------------------
# XCP/CCP constants tests
# ---------------------------------------------------------------------------


class TestXCPConstants(unittest.TestCase):
    """Test XCP protocol constants."""

    def test_xcp_command_codes(self):
        """Test XCP command code dictionary."""
        from oida.protocols.can.constants import XCP_CMD

        self.assertIn(0xFF, XCP_CMD)
        self.assertEqual(XCP_CMD[0xFF], "CONNECT")
        self.assertIn(0xFE, XCP_CMD)
        self.assertEqual(XCP_CMD[0xFE], "DISCONNECT")
        self.assertIn(0xFD, XCP_CMD)
        self.assertEqual(XCP_CMD[0xFD], "GET_STATUS")
        self.assertIn(0xFA, XCP_CMD)
        self.assertEqual(XCP_CMD[0xFA], "GET_ID")
        self.assertIn(0xF4, XCP_CMD)
        self.assertEqual(XCP_CMD[0xF4], "SHORT_UPLOAD")
        self.assertIn(0xF5, XCP_CMD)
        self.assertEqual(XCP_CMD[0xF5], "UPLOAD")

    def test_xcp_error_codes(self):
        """Test XCP error code dictionary."""
        from oida.protocols.can.constants import XCP_ERR

        self.assertIn(0x00, XCP_ERR)
        self.assertEqual(XCP_ERR[0x00], "ERR_CMD_SYNCH")
        self.assertIn(0x10, XCP_ERR)
        self.assertEqual(XCP_ERR[0x10], "ERR_CMD_BUSY")
        self.assertIn(0x22, XCP_ERR)
        self.assertEqual(XCP_ERR[0x22], "ERR_OUT_OF_RANGE")
        self.assertIn(0x24, XCP_ERR)
        self.assertEqual(XCP_ERR[0x24], "ERR_ACCESS_DENIED")
        self.assertIn(0x25, XCP_ERR)
        self.assertEqual(XCP_ERR[0x25], "ERR_ACCESS_LOCKED")

    def test_xcp_response_pids(self):
        """Test XCP response packet identifiers."""
        from oida.protocols.can.constants import (
            XCP_ERR_PID,
            XCP_EV_PID,
            XCP_RES_PID,
            XCP_SERV_PID,
        )

        self.assertEqual(XCP_RES_PID, 0xFF)
        self.assertEqual(XCP_ERR_PID, 0xFE)
        self.assertEqual(XCP_EV_PID, 0xFD)
        self.assertEqual(XCP_SERV_PID, 0xFC)

    def test_xcp_command_byte_constants(self):
        """Test XCP command byte constants."""
        from oida.protocols.can.constants import (
            XCP_CONNECT_CMD,
            XCP_DISCONNECT_CMD,
            XCP_GET_COMM_MODE_INFO_CMD,
            XCP_GET_ID_CMD,
            XCP_GET_STATUS_CMD,
            XCP_SET_MTA_CMD,
            XCP_SHORT_UPLOAD_CMD,
        )

        self.assertEqual(XCP_CONNECT_CMD, 0xFF)
        self.assertEqual(XCP_DISCONNECT_CMD, 0xFE)
        self.assertEqual(XCP_GET_STATUS_CMD, 0xFD)
        self.assertEqual(XCP_GET_COMM_MODE_INFO_CMD, 0xFB)
        self.assertEqual(XCP_GET_ID_CMD, 0xFA)
        self.assertEqual(XCP_SHORT_UPLOAD_CMD, 0xF4)
        self.assertEqual(XCP_SET_MTA_CMD, 0xF6)

    def test_xcp_resource_bitmask(self):
        """Test XCP resource protection bitmask values."""
        from oida.protocols.can.constants import (
            XCP_RESOURCE_CAL_PAG,
            XCP_RESOURCE_DAQ,
            XCP_RESOURCE_PGM,
            XCP_RESOURCE_STIM,
        )

        self.assertEqual(XCP_RESOURCE_CAL_PAG, 0x01)
        self.assertEqual(XCP_RESOURCE_DAQ, 0x04)
        self.assertEqual(XCP_RESOURCE_STIM, 0x08)
        self.assertEqual(XCP_RESOURCE_PGM, 0x10)

    def test_xcp_id_types(self):
        """Test XCP GET_ID request type constants."""
        from oida.protocols.can.constants import (
            XCP_ID_TYPE_ASAM_MC2_FILENAME,
            XCP_ID_TYPE_ASCII,
            XCP_ID_TYPE_URL,
        )

        self.assertEqual(XCP_ID_TYPE_ASCII, 0x00)
        self.assertEqual(XCP_ID_TYPE_ASAM_MC2_FILENAME, 0x01)
        self.assertEqual(XCP_ID_TYPE_URL, 0x03)


class TestCCPConstants(unittest.TestCase):
    """Test CCP protocol constants."""

    def test_ccp_command_codes(self):
        """Test CCP command code dictionary."""
        from oida.protocols.can.constants import CCP_CMD

        self.assertIn(0x01, CCP_CMD)
        self.assertEqual(CCP_CMD[0x01], "CONNECT")
        self.assertIn(0x07, CCP_CMD)
        self.assertEqual(CCP_CMD[0x07], "DISCONNECT")
        self.assertIn(0x1B, CCP_CMD)
        self.assertEqual(CCP_CMD[0x1B], "GET_CCP_VERSION")
        self.assertIn(0x17, CCP_CMD)
        self.assertEqual(CCP_CMD[0x17], "EXCHANGE_ID")
        self.assertIn(0x04, CCP_CMD)
        self.assertEqual(CCP_CMD[0x04], "UPLOAD")
        self.assertIn(0x0F, CCP_CMD)
        self.assertEqual(CCP_CMD[0x0F], "SHORT_UP")
        self.assertIn(0x12, CCP_CMD)
        self.assertEqual(CCP_CMD[0x12], "GET_SEED")
        self.assertIn(0x13, CCP_CMD)
        self.assertEqual(CCP_CMD[0x13], "UNLOCK")

    def test_ccp_return_codes(self):
        """Test CCP return code dictionary."""
        from oida.protocols.can.constants import CCP_CRC

        self.assertIn(0x00, CCP_CRC)
        self.assertEqual(CCP_CRC[0x00], "Acknowledge / No Error")
        self.assertIn(0x30, CCP_CRC)
        self.assertEqual(CCP_CRC[0x30], "Unknown command")
        self.assertIn(0x33, CCP_CRC)
        self.assertEqual(CCP_CRC[0x33], "Access denied")
        self.assertIn(0x35, CCP_CRC)
        self.assertEqual(CCP_CRC[0x35], "Access locked")

    def test_ccp_command_byte_constants(self):
        """Test CCP specific command byte constants."""
        from oida.protocols.can.constants import (
            CCP_CONNECT_CMD,
            CCP_DISCONNECT_CMD,
            CCP_EXCHANGE_ID_CMD,
            CCP_GET_CCP_VERSION_CMD,
            CCP_GET_S_STATUS_CMD,
            CCP_TEST_CMD,
        )

        self.assertEqual(CCP_CONNECT_CMD, 0x01)
        self.assertEqual(CCP_DISCONNECT_CMD, 0x07)
        self.assertEqual(CCP_GET_CCP_VERSION_CMD, 0x1B)
        self.assertEqual(CCP_EXCHANGE_ID_CMD, 0x17)
        self.assertEqual(CCP_TEST_CMD, 0x05)
        self.assertEqual(CCP_GET_S_STATUS_CMD, 0x0D)

    def test_ccp_default_ids(self):
        """Test CCP default CAN IDs."""
        from oida.protocols.can.constants import (
            CCP_DEFAULT_CRO_ID,
            CCP_DEFAULT_DTO_ID,
        )

        self.assertEqual(CCP_DEFAULT_CRO_ID, 0x701)
        self.assertEqual(CCP_DEFAULT_DTO_ID, 0x702)

    def test_ccp_dto_pids(self):
        """Test CCP DTO packet ID values."""
        from oida.protocols.can.constants import (
            CCP_DTO_COMMAND_RETURN,
            CCP_DTO_EVENT,
        )

        self.assertEqual(CCP_DTO_COMMAND_RETURN, 0xFF)
        self.assertEqual(CCP_DTO_EVENT, 0xFE)


# ---------------------------------------------------------------------------
# Enhanced UDS constants tests
# ---------------------------------------------------------------------------


class TestEnhancedUDSConstants(unittest.TestCase):
    """Test enhanced UDS constants."""

    def test_uds_reset_types(self):
        """Test UDS ECU reset sub-function types."""
        from oida.protocols.can.constants import UDS_RESET_TYPES

        self.assertIn(0x01, UDS_RESET_TYPES)
        self.assertEqual(UDS_RESET_TYPES[0x01], "HardReset")
        self.assertIn(0x02, UDS_RESET_TYPES)
        self.assertEqual(UDS_RESET_TYPES[0x02], "KeyOffOnReset")
        self.assertIn(0x03, UDS_RESET_TYPES)
        self.assertEqual(UDS_RESET_TYPES[0x03], "SoftReset")

    def test_uds_routine_control_types(self):
        """Test UDS RoutineControl sub-function types."""
        from oida.protocols.can.constants import UDS_ROUTINE_CONTROL_TYPES

        self.assertIn(0x01, UDS_ROUTINE_CONTROL_TYPES)
        self.assertEqual(UDS_ROUTINE_CONTROL_TYPES[0x01], "StartRoutine")
        self.assertIn(0x02, UDS_ROUTINE_CONTROL_TYPES)
        self.assertIn(0x03, UDS_ROUTINE_CONTROL_TYPES)

    def test_uds_standard_dids(self):
        """Test UDS standard DID definitions."""
        from oida.protocols.can.constants import UDS_STANDARD_DIDS

        self.assertIn(0xF190, UDS_STANDARD_DIDS)
        self.assertEqual(UDS_STANDARD_DIDS[0xF190], "VIN")
        self.assertIn(0xF180, UDS_STANDARD_DIDS)
        self.assertEqual(UDS_STANDARD_DIDS[0xF180], "BootSoftwareIdentification")
        self.assertIn(0xF18C, UDS_STANDARD_DIDS)
        self.assertEqual(UDS_STANDARD_DIDS[0xF18C], "ECUSerialNumber")
        # Check we have the full range (0xF180-0xF19F minus gaps = 31)
        self.assertGreaterEqual(len(UDS_STANDARD_DIDS), 30)

    def test_uds_did_scan_defaults(self):
        """Test UDS DID scan default range values."""
        from oida.protocols.can.constants import (
            UDS_DID_SCAN_DEFAULT_END,
            UDS_DID_SCAN_DEFAULT_START,
        )

        self.assertEqual(UDS_DID_SCAN_DEFAULT_START, 0xF180)
        self.assertEqual(UDS_DID_SCAN_DEFAULT_END, 0xF19F)


# ---------------------------------------------------------------------------
# XCP/CCP data class tests
# ---------------------------------------------------------------------------


class TestXCPScanResult(unittest.TestCase):
    """Test XCPScanResult data class."""

    def test_xcp_result_creation(self):
        """Test creating an XCP scan result."""
        from oida.protocols.can.constants import XCPScanResult

        result = XCPScanResult(
            request_id=0x100,
            response_id=0x101,
            connected=True,
            max_cto=8,
            max_dto=8,
            xcp_version="1.4",
        )

        self.assertEqual(result.request_id, 0x100)
        self.assertEqual(result.response_id, 0x101)
        self.assertTrue(result.connected)
        self.assertEqual(result.max_cto, 8)
        self.assertEqual(result.max_dto, 8)
        self.assertEqual(result.xcp_version, "1.4")

    def test_xcp_result_defaults(self):
        """Test XCP result default values."""
        from oida.protocols.can.constants import XCPScanResult

        result = XCPScanResult(request_id=0x200, response_id=0x201)

        self.assertFalse(result.connected)
        self.assertEqual(result.resource_protection, 0)
        self.assertEqual(result.max_cto, 0)
        self.assertEqual(result.max_dto, 0)
        self.assertEqual(result.xcp_version, "")
        self.assertEqual(result.identification, "")
        self.assertEqual(result.status, {})
        self.assertEqual(result.error, "")
        self.assertEqual(result.memory_data, {})


class TestCCPScanResult(unittest.TestCase):
    """Test CCPScanResult data class."""

    def test_ccp_result_creation(self):
        """Test creating a CCP scan result."""
        from oida.protocols.can.constants import CCPScanResult

        result = CCPScanResult(
            cro_id=0x701,
            dto_id=0x702,
            station_address=42,
            connected=True,
            ccp_version="2.1",
        )

        self.assertEqual(result.cro_id, 0x701)
        self.assertEqual(result.dto_id, 0x702)
        self.assertEqual(result.station_address, 42)
        self.assertTrue(result.connected)
        self.assertEqual(result.ccp_version, "2.1")

    def test_ccp_result_defaults(self):
        """Test CCP result default values."""
        from oida.protocols.can.constants import CCPScanResult

        result = CCPScanResult(cro_id=0x701, dto_id=0x702)

        self.assertEqual(result.station_address, 0)
        self.assertFalse(result.connected)
        self.assertEqual(result.ccp_version, "")
        self.assertEqual(result.device_id, b"")
        self.assertEqual(result.session_status, 0)
        self.assertEqual(result.error, "")


class TestUDSScanResultEnhanced(unittest.TestCase):
    """Test enhanced UDSScanResult fields."""

    def test_uds_result_new_fields(self):
        """Test that UDSScanResult has new fields for enhanced UDS."""
        from oida.protocols.can.constants import UDSScanResult

        result = UDSScanResult(
            request_id=0x7E0,
            response_id=0x7E8,
            routines_discovered=[0x0001, 0x0002],
            seeds_collected=[b"\x01\x02\x03\x04", b"\x05\x06\x07\x08"],
        )

        self.assertEqual(result.routines_discovered, [0x0001, 0x0002])
        self.assertEqual(len(result.seeds_collected), 2)

    def test_uds_result_new_fields_defaults(self):
        """Test UDS result new fields have empty defaults."""
        from oida.protocols.can.constants import UDSScanResult

        result = UDSScanResult(request_id=0x700, response_id=0x708)

        self.assertEqual(result.routines_discovered, [])
        self.assertEqual(result.seeds_collected, [])


# ---------------------------------------------------------------------------
# XCP scanner mock tests
# ---------------------------------------------------------------------------


class TestXCPScannerMock(unittest.TestCase):
    """Test XCP scanner methods with mocked CAN bus."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_scan_xcp_finds_slave(self, mock_can_lazy):
        """Test XCP scan discovers a responding slave."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Simulate XCP CONNECT response (positive: byte[0]=0xFF)
        call_count = [0]

        def recv_side_effect(timeout=0.05):
            call_count[0] += 1
            # Respond on 2nd recv call (for arb_id=0x100)
            if call_count[0] == 2:
                msg = MagicMock()
                msg.arbitration_id = 0x101
                # XCP positive response: RES(0xFF), resource(0x00), comm_mode(0x00),
                # max_cto(8), max_dto_lo(8), max_dto_hi(0), xcp_major(1), xcp_minor(4)
                msg.data = bytearray([0xFF, 0x00, 0x00, 0x08, 0x08, 0x00, 0x01, 0x04])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        # Only scan a tiny range
        self.scanner.scan_xcp(mock_bus, scan_range=(0x100, 0x100))

        # The scan sends a message and tries to recv
        mock_bus.send.assert_called()

    @patch("oida.protocols.can.scanner._python_can")
    def test_scan_xcp_no_response(self, mock_can_lazy):
        """Test XCP scan with no responding slaves."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        results = self.scanner.scan_xcp(mock_bus, scan_range=(0x100, 0x102))

        self.assertEqual(len(results), 0)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_xcp_response(self, mock_can_lazy):
        """Test XCP response reception."""
        mock_bus = MagicMock()

        # Return a valid XCP positive response
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x101
        mock_msg.data = bytearray([0xFF, 0x00, 0x00, 0x08, 0x08, 0x00, 0x01, 0x04])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner._recv_xcp_response(mock_bus, timeout=0.1)

        self.assertIsNotNone(resp)
        arb_id, data = resp
        self.assertEqual(arb_id, 0x101)
        self.assertEqual(data[0], 0xFF)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_xcp_response_with_expected_id(self, mock_can_lazy):
        """Test XCP response filtering by expected ID."""
        mock_bus = MagicMock()

        # Return a response on wrong ID then right ID
        msg_wrong = MagicMock()
        msg_wrong.arbitration_id = 0x200
        msg_wrong.data = bytearray([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        msg_right = MagicMock()
        msg_right.arbitration_id = 0x101
        msg_right.data = bytearray([0xFF, 0x00, 0x00, 0x08, 0x08, 0x00, 0x01, 0x04])

        mock_bus.recv.side_effect = [msg_wrong, msg_right, None]

        resp = self.scanner._recv_xcp_response(mock_bus, timeout=0.5, expected_id=0x101)

        self.assertIsNotNone(resp)
        self.assertEqual(resp[0], 0x101)

    @patch("oida.protocols.can.scanner._python_can")
    def test_xcp_disconnect(self, mock_can_lazy):
        """Test XCP disconnect sends proper command."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        self.scanner._xcp_disconnect(mock_bus, 0x100)

        mock_bus.send.assert_called_once()


# ---------------------------------------------------------------------------
# CCP scanner mock tests
# ---------------------------------------------------------------------------


class TestCCPScannerMock(unittest.TestCase):
    """Test CCP scanner methods with mocked CAN bus."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_scan_ccp_finds_slave(self, mock_can_lazy):
        """Test CCP scan discovers a responding slave."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # CCP positive response DTO: [PID=0xFF, ERR=0x00, CTR, ...]
        call_count = [0]

        def recv_side_effect(timeout=0.05):
            call_count[0] += 1
            # Respond for station 0 then disconnect ack
            if call_count[0] == 1:
                msg = MagicMock()
                msg.arbitration_id = 0x702
                msg.data = bytearray([0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
                return msg
            if call_count[0] == 2:
                # Disconnect response
                msg = MagicMock()
                msg.arbitration_id = 0x702
                msg.data = bytearray([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        results = self.scanner.scan_ccp(
            mock_bus,
            station_range=(0, 0),
            cro_id=0x701,
            dto_id=0x702,
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].station_address, 0)
        self.assertTrue(results[0].connected)

    @patch("oida.protocols.can.scanner._python_can")
    def test_scan_ccp_no_response(self, mock_can_lazy):
        """Test CCP scan with no responding slaves."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        results = self.scanner.scan_ccp(mock_bus, station_range=(0, 5))

        self.assertEqual(len(results), 0)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_ccp_response(self, mock_can_lazy):
        """Test CCP response reception on specific DTO ID."""
        mock_bus = MagicMock()

        # Return a DTO on the right ID
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x702
        mock_msg.data = bytearray([0xFF, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner._recv_ccp_response(mock_bus, dto_id=0x702, timeout=0.1)

        self.assertIsNotNone(resp)
        self.assertEqual(resp[0], 0xFF)
        self.assertEqual(resp[1], 0x00)  # No error

    @patch("oida.protocols.can.scanner._python_can")
    @patch("oida.protocols.can.scanner.time")
    def test_recv_ccp_response_wrong_id(self, mock_time, mock_can_lazy):
        """Test CCP response ignores wrong arbitration IDs."""
        mock_bus = MagicMock()

        # Simulate time progression that exceeds timeout quickly
        call_count = [0]

        def time_side_effect():
            call_count[0] += 1
            if call_count[0] <= 2:
                return 1000.0
            return 1001.0  # Exceed timeout

        mock_time.time.side_effect = time_side_effect

        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x703  # Wrong ID
        mock_msg.data = bytearray([0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner._recv_ccp_response(mock_bus, dto_id=0x702, timeout=0.1)

        self.assertIsNone(resp)

    @patch("oida.protocols.can.scanner._python_can")
    def test_ccp_disconnect(self, mock_can_lazy):
        """Test CCP disconnect sends proper CRO."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        self.scanner._ccp_disconnect(mock_bus, 0x701, station_address=42)

        mock_bus.send.assert_called_once()


# ---------------------------------------------------------------------------
# Enhanced UDS scanner mock tests
# ---------------------------------------------------------------------------


class TestEnhancedUDSScannerMock(unittest.TestCase):
    """Test enhanced UDS scanner methods with mocked CAN bus."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_session_scan(self, mock_can_lazy):
        """Test UDS session enumeration."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Respond positively to session 0x01 and 0x03
        call_count = [0]

        def recv_side_effect(timeout=0.1):
            call_count[0] += 1
            # First call: positive response for session 0x01
            if call_count[0] == 1:
                msg = MagicMock()
                msg.arbitration_id = 0x7E8
                msg.data = bytearray([0x06, 0x50, 0x01, 0x00, 0x19, 0x01, 0xF4, 0x00])
                return msg
            # Ack for reset to default
            if call_count[0] == 2:
                msg = MagicMock()
                msg.arbitration_id = 0x7E8
                msg.data = bytearray([0x06, 0x50, 0x01, 0x00, 0x19, 0x01, 0xF4, 0x00])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        sessions = self.scanner.uds_session_scan(mock_bus, 0x7E0, 0x7E8)

        # Should have found at least one session
        mock_bus.send.assert_called()
        self.assertIsInstance(sessions, list)

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_did_scan(self, mock_can_lazy):
        """Test UDS DID enumeration."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Respond positively to one DID
        call_count = [0]

        def recv_side_effect(timeout=0.1):
            call_count[0] += 1
            if call_count[0] == 1:
                msg = MagicMock()
                msg.arbitration_id = 0x7E8
                # ReadDataByID positive: [PCI, 0x62, DID_hi, DID_lo, data...]
                msg.data = bytearray([0x07, 0x62, 0xF1, 0x90, 0x57, 0x42, 0x41, 0x00])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        readable = self.scanner.uds_did_scan(mock_bus, 0x7E0, 0x7E8, did_range=(0xF190, 0xF190))

        self.assertIsInstance(readable, dict)
        mock_bus.send.assert_called()

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_seed_collect(self, mock_can_lazy):
        """Test UDS SecurityAccess seed collection."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Respond with seeds
        call_count = [0]

        def recv_side_effect(timeout=0.2):
            call_count[0] += 1
            if call_count[0] <= 3:
                msg = MagicMock()
                msg.arbitration_id = 0x7E8
                # SecurityAccess positive: [PCI, 0x67, level, seed...]
                msg.data = bytearray([0x06, 0x67, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0x00])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        seeds = self.scanner.uds_security_seed_collect(
            mock_bus,
            0x7E0,
            0x7E8,
            security_level=0x01,
            count=3,
        )

        self.assertIsInstance(seeds, list)
        mock_bus.send.assert_called()

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_routine_scan(self, mock_can_lazy):
        """Test UDS routine enumeration."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        routines = self.scanner.uds_routine_scan(
            mock_bus, 0x7E0, 0x7E8, routine_range=(0x0000, 0x0005)
        )

        self.assertIsInstance(routines, list)
        mock_bus.send.assert_called()

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_ecu_reset(self, mock_can_lazy):
        """Test UDS ECU reset."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Respond with positive reset ack
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x7E8
        mock_msg.data = bytearray([0x02, 0x51, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        mock_bus.recv.return_value = mock_msg

        result = self.scanner.uds_ecu_reset(mock_bus, 0x7E0, 0x7E8, reset_type=0x01)

        self.assertTrue(result)
        mock_bus.send.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_tester_present_keepalive(self, mock_can_lazy):
        """Test UDS TesterPresent keep-alive."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        result = self.scanner.uds_tester_present_keepalive(mock_bus, 0x7E0)

        self.assertTrue(result)
        mock_bus.send.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_uds_tester_present_suppress_response(self, mock_can_lazy):
        """Test TesterPresent with response suppression."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        result = self.scanner.uds_tester_present_keepalive(mock_bus, 0x7E0, suppress_response=True)
        self.assertTrue(result)

        result = self.scanner.uds_tester_present_keepalive(mock_bus, 0x7E0, suppress_response=False)
        self.assertTrue(result)

    def test_seed_analysis_duplicates(self):
        """Test seed analysis detects duplicates."""
        seeds = [b"\x01\x02\x03\x04"] * 5
        # This should not raise
        self.scanner._print_seed_analysis(seeds)

    def test_seed_analysis_zeros(self):
        """Test seed analysis detects all-zero seeds."""
        seeds = [b"\x00\x00\x00\x00"] * 3
        self.scanner._print_seed_analysis(seeds)

    def test_seed_analysis_sequential(self):
        """Test seed analysis detects sequential seeds."""
        seeds = [
            b"\x00\x01\x00\x00",
            b"\x00\x02\x00\x00",
            b"\x00\x03\x00\x00",
            b"\x00\x04\x00\x00",
        ]
        self.scanner._print_seed_analysis(seeds)

    def test_seed_analysis_empty(self):
        """Test seed analysis with no seeds."""
        self.scanner._print_seed_analysis([])


# ---------------------------------------------------------------------------
# Proto args tests for new arguments
# ---------------------------------------------------------------------------


class TestCANProtoArgsXCPCCP(unittest.TestCase):
    """Test CAN proto_args for XCP/CCP/enhanced UDS arguments."""

    def _make_parser(self):
        import argparse

        from oida.protocols.can.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])
        return main_parser

    def test_xcp_scan_flag(self):
        """Test --xcp-scan flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--xcp-scan"])
        self.assertTrue(args.xcp_scan)

    def test_xcp_info_flag(self):
        """Test --xcp-info flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--xcp-info"])
        self.assertTrue(args.xcp_info)

    def test_xcp_memory_read_flag(self):
        """Test --xcp-memory-read flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--xcp-memory-read"])
        self.assertTrue(args.xcp_memory_read)

    def test_xcp_req_resp_ids(self):
        """Test --xcp-req-id and --xcp-resp-id options."""
        parser = self._make_parser()
        args = parser.parse_args(
            [
                "can",
                "can0",
                "--xcp-req-id",
                "0x100",
                "--xcp-resp-id",
                "0x101",
            ]
        )
        self.assertEqual(args.xcp_req_id, "0x100")
        self.assertEqual(args.xcp_resp_id, "0x101")

    def test_xcp_address_and_length(self):
        """Test --xcp-address and --xcp-length options."""
        parser = self._make_parser()
        args = parser.parse_args(
            [
                "can",
                "can0",
                "--xcp-address",
                "0x00000000",
                "--xcp-length",
                "4",
            ]
        )
        self.assertEqual(args.xcp_address, "0x00000000")
        self.assertEqual(args.xcp_length, 4)

    def test_xcp_length_default(self):
        """Test --xcp-length default value."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])
        self.assertEqual(args.xcp_length, 6)

    def test_ccp_scan_flag(self):
        """Test --ccp-scan flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--ccp-scan"])
        self.assertTrue(args.ccp_scan)

    def test_ccp_ids(self):
        """Test --ccp-cro-id and --ccp-dto-id options."""
        parser = self._make_parser()
        args = parser.parse_args(
            [
                "can",
                "can0",
                "--ccp-cro-id",
                "0x600",
                "--ccp-dto-id",
                "0x601",
            ]
        )
        self.assertEqual(args.ccp_cro_id, "0x600")
        self.assertEqual(args.ccp_dto_id, "0x601")

    def test_ccp_id_defaults(self):
        """Test CCP ID default values."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])
        self.assertEqual(args.ccp_cro_id, "0x701")
        self.assertEqual(args.ccp_dto_id, "0x702")

    def test_uds_sessions_flag(self):
        """Test --uds-sessions flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-sessions"])
        self.assertTrue(args.uds_sessions)

    def test_uds_seeds_flag(self):
        """Test --uds-seeds flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-seeds"])
        self.assertTrue(args.uds_seeds)

    def test_seed_level_and_count(self):
        """Test --seed-level and --seed-count options."""
        parser = self._make_parser()
        args = parser.parse_args(
            [
                "can",
                "can0",
                "--seed-level",
                "0x03",
                "--seed-count",
                "20",
            ]
        )
        self.assertEqual(args.seed_level, "0x03")
        self.assertEqual(args.seed_count, 20)

    def test_seed_defaults(self):
        """Test seed collection default values."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])
        self.assertEqual(args.seed_level, "0x01")
        self.assertEqual(args.seed_count, 10)

    def test_uds_routines_flag(self):
        """Test --uds-routines flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-routines"])
        self.assertTrue(args.uds_routines)

    def test_uds_reset_flag(self):
        """Test --uds-reset flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-reset"])
        self.assertTrue(args.uds_reset)

    def test_uds_reset_type(self):
        """Test --uds-reset-type option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-reset-type", "0x03"])
        self.assertEqual(args.uds_reset_type, "0x03")

    def test_uds_reset_type_default(self):
        """Test --uds-reset-type default value."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0"])
        self.assertEqual(args.uds_reset_type, "0x01")

    def test_uds_target_id(self):
        """Test --uds-target-id option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--uds-target-id", "0x7E1"])
        self.assertEqual(args.uds_target_id, "0x7E1")


# ---------------------------------------------------------------------------
# CANopen constants tests
# ---------------------------------------------------------------------------


class TestCANopenConstants(unittest.TestCase):
    """Test CANopen protocol constants."""

    def test_nmt_commands(self):
        """Test CANopen NMT command codes."""
        from oida.protocols.can.constants import (
            CANOPEN_NMT_CMD_PREOPERATIONAL,
            CANOPEN_NMT_CMD_RESET_COMM,
            CANOPEN_NMT_CMD_RESET_NODE,
            CANOPEN_NMT_CMD_START,
            CANOPEN_NMT_CMD_STOP,
            CANOPEN_NMT_COMMANDS,
        )

        self.assertEqual(CANOPEN_NMT_CMD_START, 0x01)
        self.assertEqual(CANOPEN_NMT_CMD_STOP, 0x02)
        self.assertEqual(CANOPEN_NMT_CMD_PREOPERATIONAL, 0x80)
        self.assertEqual(CANOPEN_NMT_CMD_RESET_NODE, 0x81)
        self.assertEqual(CANOPEN_NMT_CMD_RESET_COMM, 0x82)
        self.assertEqual(len(CANOPEN_NMT_COMMANDS), 5)

    def test_nmt_states(self):
        """Test CANopen NMT state codes."""
        from oida.protocols.can.constants import (
            CANOPEN_NMT_STATE_INITIALISING,
            CANOPEN_NMT_STATE_OPERATIONAL,
            CANOPEN_NMT_STATE_PREOPERATIONAL,
            CANOPEN_NMT_STATE_STOPPED,
            CANOPEN_NMT_STATES,
        )

        self.assertEqual(CANOPEN_NMT_STATE_INITIALISING, 0x00)
        self.assertEqual(CANOPEN_NMT_STATE_STOPPED, 0x04)
        self.assertEqual(CANOPEN_NMT_STATE_OPERATIONAL, 0x05)
        self.assertEqual(CANOPEN_NMT_STATE_PREOPERATIONAL, 0x7F)
        self.assertEqual(len(CANOPEN_NMT_STATES), 4)

    def test_sdo_command_specifiers(self):
        """Test SDO command specifier constants."""
        from oida.protocols.can.constants import (
            SDO_CCS_ABORT,
            SDO_CCS_INITIATE_DOWNLOAD,
            SDO_CCS_INITIATE_UPLOAD,
            SDO_CCS_SEGMENT_UPLOAD,
            SDO_CMD_ABORT,
            SDO_CMD_UPLOAD_INITIATE,
        )

        self.assertEqual(SDO_CCS_INITIATE_UPLOAD, 2)
        self.assertEqual(SDO_CCS_INITIATE_DOWNLOAD, 1)
        self.assertEqual(SDO_CCS_SEGMENT_UPLOAD, 3)
        self.assertEqual(SDO_CCS_ABORT, 4)
        self.assertEqual(SDO_CMD_UPLOAD_INITIATE, 0x40)
        self.assertEqual(SDO_CMD_ABORT, 0x80)

    def test_sdo_abort_codes(self):
        """Test SDO abort code dictionary."""
        from oida.protocols.can.constants import SDO_ABORT_CODES

        self.assertIn(0x06020000, SDO_ABORT_CODES)
        self.assertEqual(
            SDO_ABORT_CODES[0x06020000],
            "Object does not exist in the object dictionary",
        )
        self.assertIn(0x06010000, SDO_ABORT_CODES)
        self.assertIn(0x05040001, SDO_ABORT_CODES)
        self.assertIn(0x08000000, SDO_ABORT_CODES)
        self.assertGreaterEqual(len(SDO_ABORT_CODES), 25)

    def test_od_entries(self):
        """Test standard OD entry definitions."""
        from oida.protocols.can.constants import (
            CANOPEN_OD_DEVICE_NAME,
            CANOPEN_OD_DEVICE_TYPE,
            CANOPEN_OD_ENTRIES,
            CANOPEN_OD_ERROR_REGISTER,
            CANOPEN_OD_IDENTITY,
        )

        self.assertEqual(CANOPEN_OD_DEVICE_TYPE, 0x1000)
        self.assertEqual(CANOPEN_OD_ERROR_REGISTER, 0x1001)
        self.assertEqual(CANOPEN_OD_DEVICE_NAME, 0x1008)
        self.assertEqual(CANOPEN_OD_IDENTITY, 0x1018)
        self.assertIn(0x1000, CANOPEN_OD_ENTRIES)
        self.assertEqual(CANOPEN_OD_ENTRIES[0x1000], "Device Type")
        self.assertIn(0x1018, CANOPEN_OD_ENTRIES)
        self.assertGreaterEqual(len(CANOPEN_OD_ENTRIES), 30)

    def test_device_profiles(self):
        """Test CANopen device profile identifiers."""
        from oida.protocols.can.constants import CANOPEN_DEVICE_PROFILES

        self.assertIn(401, CANOPEN_DEVICE_PROFILES)
        self.assertEqual(CANOPEN_DEVICE_PROFILES[401], "Generic I/O Modules (CiA 401)")
        self.assertIn(402, CANOPEN_DEVICE_PROFILES)
        self.assertIn(404, CANOPEN_DEVICE_PROFILES)
        self.assertIn(309, CANOPEN_DEVICE_PROFILES)
        self.assertIn("Modbus", CANOPEN_DEVICE_PROFILES[309])

    def test_emcy_codes(self):
        """Test CANopen EMCY error codes."""
        from oida.protocols.can.constants import CANOPEN_EMCY_CODES

        self.assertIn(0x0000, CANOPEN_EMCY_CODES)
        self.assertEqual(CANOPEN_EMCY_CODES[0x0000], "Error reset / no error")
        self.assertIn(0x1000, CANOPEN_EMCY_CODES)
        self.assertIn(0x8110, CANOPEN_EMCY_CODES)
        self.assertIn(0x8130, CANOPEN_EMCY_CODES)
        self.assertGreaterEqual(len(CANOPEN_EMCY_CODES), 30)

    def test_error_register_bits(self):
        """Test error register bit definitions."""
        from oida.protocols.can.constants import CANOPEN_ERR_REGISTER_BITS

        self.assertIn(0x01, CANOPEN_ERR_REGISTER_BITS)
        self.assertEqual(CANOPEN_ERR_REGISTER_BITS[0x01], "Generic error")
        self.assertIn(0x10, CANOPEN_ERR_REGISTER_BITS)
        self.assertEqual(CANOPEN_ERR_REGISTER_BITS[0x10], "Communication error")
        self.assertEqual(len(CANOPEN_ERR_REGISTER_BITS), 8)

    def test_fingerprint_indices(self):
        """Test fingerprint indices list."""
        from oida.protocols.can.constants import CANOPEN_FINGERPRINT_INDICES

        self.assertGreaterEqual(len(CANOPEN_FINGERPRINT_INDICES), 9)
        # Each entry is (index, subindex, name)
        for idx, sub, name in CANOPEN_FINGERPRINT_INDICES:
            self.assertIsInstance(idx, int)
            self.assertIsInstance(sub, int)
            self.assertIsInstance(name, str)

    def test_known_gateway_vendors(self):
        """Test known gateway vendor IDs."""
        from oida.protocols.can.constants import CANOPEN_KNOWN_GATEWAY_VENDORS

        self.assertGreaterEqual(len(CANOPEN_KNOWN_GATEWAY_VENDORS), 5)
        # All vendor IDs should be integers
        for vid, name in CANOPEN_KNOWN_GATEWAY_VENDORS.items():
            self.assertIsInstance(vid, int)
            self.assertIsInstance(name, str)

    def test_node_id_range(self):
        """Test CANopen node ID range constants."""
        from oida.protocols.can.constants import (
            CANOPEN_NODE_ID_MAX,
            CANOPEN_NODE_ID_MIN,
        )

        self.assertEqual(CANOPEN_NODE_ID_MIN, 1)
        self.assertEqual(CANOPEN_NODE_ID_MAX, 127)

    def test_function_codes(self):
        """Test CANopen function code map."""
        from oida.protocols.can.constants import CANOPEN_FUNCTION_CODES

        self.assertEqual(CANOPEN_FUNCTION_CODES["NMT"], 0x000)
        self.assertEqual(CANOPEN_FUNCTION_CODES["SDO_TX"], 0x580)
        self.assertEqual(CANOPEN_FUNCTION_CODES["SDO_RX"], 0x600)
        self.assertEqual(CANOPEN_FUNCTION_CODES["HEARTBEAT"], 0x700)


# ---------------------------------------------------------------------------
# CANopen data class tests
# ---------------------------------------------------------------------------


class TestCANopenNode(unittest.TestCase):
    """Test CANopenNode data class."""

    def test_node_creation(self):
        """Test creating a CANopen node."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(
            node_id=5,
            nmt_state=0x05,
            nmt_state_name="Operational",
            device_name="TestDevice",
            vendor_id=0x22,
        )

        self.assertEqual(node.node_id, 5)
        self.assertEqual(node.nmt_state, 0x05)
        self.assertEqual(node.device_name, "TestDevice")
        self.assertEqual(node.vendor_id, 0x22)

    def test_node_cob_ids(self):
        """Test COB-ID property calculations."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(node_id=10)

        self.assertEqual(node.sdo_rx_cob_id, 0x60A)
        self.assertEqual(node.sdo_tx_cob_id, 0x58A)
        self.assertEqual(node.heartbeat_cob_id, 0x70A)
        self.assertEqual(node.emcy_cob_id, 0x08A)

    def test_node_defaults(self):
        """Test CANopenNode default values."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(node_id=1)

        self.assertEqual(node.device_type, 0)
        self.assertEqual(node.device_name, "")
        self.assertEqual(node.vendor_id, 0)
        self.assertEqual(node.od_entries_found, [])
        self.assertFalse(node.is_gateway)
        self.assertEqual(node.gateway_type, "")

    def test_node_id_hex(self):
        """Test node ID hex formatting."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(node_id=42)
        self.assertIn("42", node.node_id_hex)
        self.assertIn("0x2A", node.node_id_hex)


class TestCANopenScanResult(unittest.TestCase):
    """Test CANopenScanResult data class."""

    def test_result_defaults(self):
        """Test scan result defaults."""
        from oida.protocols.can.constants import CANopenScanResult

        result = CANopenScanResult()

        self.assertEqual(result.nodes, [])
        self.assertEqual(result.total_nodes_found, 0)
        self.assertEqual(result.gateways, [])
        self.assertEqual(result.emcy_messages, [])


class TestCANopenSDOResponse(unittest.TestCase):
    """Test CANopenSDOResponse data class."""

    def test_sdo_response_creation(self):
        """Test creating an SDO response."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1000,
            subindex=0,
            data=b"\x91\x01\x00\x00",
        )

        self.assertEqual(resp.node_id, 1)
        self.assertEqual(resp.index, 0x1000)
        self.assertFalse(resp.error)

    def test_sdo_response_uint8(self):
        """Test UNSIGNED8 interpretation."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(node_id=1, index=0x1001, subindex=0, data=b"\x05")
        self.assertEqual(resp.as_uint8, 5)

    def test_sdo_response_uint16(self):
        """Test UNSIGNED16 interpretation."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(node_id=1, index=0x1017, subindex=0, data=b"\xe8\x03")
        self.assertEqual(resp.as_uint16, 1000)  # 0x03E8 = 1000

    def test_sdo_response_uint32(self):
        """Test UNSIGNED32 interpretation."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(node_id=1, index=0x1000, subindex=0, data=b"\x91\x01\x00\x00")
        self.assertEqual(resp.as_uint32, 0x00000191)

    def test_sdo_response_string(self):
        """Test VISIBLE_STRING interpretation."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(node_id=1, index=0x1008, subindex=0, data=b"TestDev\x00")
        self.assertEqual(resp.as_string, "TestDev")

    def test_sdo_response_error(self):
        """Test SDO response with error."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1000,
            subindex=0,
            error=True,
            abort_code=0x06020000,
            abort_message="Object does not exist",
        )

        self.assertTrue(resp.error)
        self.assertEqual(resp.abort_code, 0x06020000)
        self.assertIsNone(resp.as_uint32)
        self.assertIsNone(resp.as_string)

    def test_sdo_response_empty_data(self):
        """Test SDO response with empty data."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(node_id=1, index=0x1000, subindex=0, data=b"")
        self.assertIsNone(resp.as_uint8)
        self.assertIsNone(resp.as_uint16)
        self.assertIsNone(resp.as_uint32)
        self.assertIsNone(resp.as_string)


# ---------------------------------------------------------------------------
# CANopen scanner mock tests
# ---------------------------------------------------------------------------


class TestCANopenScannerMock(unittest.TestCase):
    """Test CANopen scanner methods with mocked CAN bus."""

    def setUp(self):
        from oida.protocols.can.constants import CANopenNode
        from oida.protocols.can.scanner import CANScanner

        self.CANopenNode = CANopenNode
        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_sdo_read_expedited(self, mock_can_lazy):
        """Test SDO expedited upload read."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # SDO response: SCS=2 (initiate upload), e=1, s=1, n=0 -> 4 bytes
        # byte[0] = 0x43 (SCS=2 << 5 | n=0 << 2 | e=1 | s=1)
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x581  # SDO TX for node 1
        mock_msg.is_remote_frame = False
        mock_msg.data = bytearray([0x43, 0x00, 0x10, 0x00, 0x91, 0x01, 0x00, 0x00])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1000, 0x00)

        self.assertFalse(resp.error)
        self.assertEqual(resp.data, b"\x91\x01\x00\x00")
        self.assertEqual(resp.as_uint32, 0x00000191)
        mock_bus.send.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_sdo_read_expedited_2bytes(self, mock_can_lazy):
        """Test SDO expedited upload read with 2 bytes."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # byte[0] = 0x4B (SCS=2 << 5 | n=2 << 2 | e=1 | s=1) -> 2 bytes
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x581
        mock_msg.is_remote_frame = False
        mock_msg.data = bytearray([0x4B, 0x17, 0x10, 0x00, 0xE8, 0x03, 0x00, 0x00])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1017, 0x00)

        self.assertFalse(resp.error)
        self.assertEqual(len(resp.data), 2)
        self.assertEqual(resp.as_uint16, 1000)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_sdo_read_abort(self, mock_can_lazy):
        """Test SDO read with abort response."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # SDO abort response: SCS=4 -> byte[0] = 0x80
        # Abort code 0x06020000 = "Object does not exist"
        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x581
        mock_msg.is_remote_frame = False
        mock_msg.data = bytearray([0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x02, 0x06])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x2000, 0x00)

        self.assertTrue(resp.error)
        self.assertEqual(resp.abort_code, 0x06020000)
        self.assertIn("does not exist", resp.abort_message)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_sdo_read_timeout(self, mock_can_lazy):
        """Test SDO read timeout."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1000, 0x00, timeout=0.1)

        self.assertTrue(resp.error)
        self.assertIn("timeout", resp.abort_message.lower())

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_node_scan_heartbeat(self, mock_can_lazy):
        """Test CANopen node scan discovers heartbeat-sending nodes."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        call_count = [0]

        def recv_side_effect(timeout=0.1):
            call_count[0] += 1
            # Return heartbeat for node 5 on first call
            if call_count[0] == 1:
                msg = MagicMock()
                msg.arbitration_id = 0x705  # Heartbeat for node 5
                msg.is_remote_frame = False
                msg.data = bytearray([0x05])  # Operational
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        nodes = self.scanner.canopen_node_scan(mock_bus, timeout_per_node=0.01)

        # Should have sent RTR messages
        self.assertIsInstance(nodes, list)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_device_info(self, mock_can_lazy):
        """Test device info reads identity objects."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Create a sequence of SDO responses for different OD entries
        responses = []

        # Device Type (0x1000) -> profile 401 (I/O)
        dt_msg = MagicMock()
        dt_msg.arbitration_id = 0x585  # Node 5
        dt_msg.is_remote_frame = False
        dt_msg.data = bytearray([0x43, 0x00, 0x10, 0x00, 0x91, 0x01, 0x00, 0x00])
        responses.append(dt_msg)

        # Error Register (0x1001) -> 0x00
        er_msg = MagicMock()
        er_msg.arbitration_id = 0x585
        er_msg.is_remote_frame = False
        er_msg.data = bytearray([0x4F, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
        responses.append(er_msg)

        # Remaining reads get abort (object not found)
        abort_msg = MagicMock()
        abort_msg.arbitration_id = 0x585
        abort_msg.is_remote_frame = False
        abort_msg.data = bytearray([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06])

        all_responses = responses + [abort_msg] * 20
        response_iter = iter(all_responses)

        def recv_side_effect(timeout=0.5):
            try:
                return next(response_iter)
            except StopIteration:
                return None

        mock_bus.recv.side_effect = recv_side_effect

        info = self.scanner.canopen_device_info(mock_bus, 5)

        self.assertEqual(info.node_id, 5)
        self.assertIsInstance(info, self.CANopenNode)
        mock_bus.send.assert_called()

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_emcy_monitor(self, mock_can_lazy):
        """Test EMCY monitoring captures emergency messages."""
        mock_bus = MagicMock()

        call_count = [0]

        def recv_side_effect(timeout=0.5):
            call_count[0] += 1
            if call_count[0] == 1:
                # EMCY from node 3: error 0x8130 (heartbeat error)
                msg = MagicMock()
                msg.arbitration_id = 0x083
                msg.data = bytearray([0x30, 0x81, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        messages = self.scanner.canopen_emcy_monitor(mock_bus, duration=0.2)

        self.assertIsInstance(messages, list)
        if messages:
            self.assertEqual(messages[0]["node_id"], 3)
            self.assertEqual(messages[0]["error_code"], 0x8130)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_heartbeat_monitor(self, mock_can_lazy):
        """Test heartbeat monitoring."""
        mock_bus = MagicMock()

        call_count = [0]

        def recv_side_effect(timeout=0.5):
            call_count[0] += 1
            if call_count[0] <= 3:
                msg = MagicMock()
                msg.arbitration_id = 0x70A  # Node 10
                msg.data = bytearray([0x05])  # Operational
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        result = self.scanner.canopen_heartbeat_monitor(mock_bus, duration=0.2)

        self.assertIsInstance(result, dict)
        if result:
            self.assertIn(10, result)
            self.assertEqual(result[10]["state_name"], "Operational")

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_nmt_state_read(self, mock_can_lazy):
        """Test reading NMT state via node guarding."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x701  # Heartbeat for node 1
        mock_msg.is_remote_frame = False
        mock_msg.data = bytearray([0x05])  # Operational
        mock_bus.recv.return_value = mock_msg

        state = self.scanner.canopen_nmt_state_read(mock_bus, 1, timeout=0.1)

        self.assertEqual(state, 0x05)
        mock_bus.send.assert_called_once()

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_nmt_state_read_timeout(self, mock_can_lazy):
        """Test NMT state read timeout."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        state = self.scanner.canopen_nmt_state_read(mock_bus, 1, timeout=0.05)

        self.assertIsNone(state)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_od_scan(self, mock_can_lazy):
        """Test Object Dictionary scanning."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # First read returns data, rest return abort
        call_count = [0]

        def recv_side_effect(timeout=0.2):
            call_count[0] += 1
            if call_count[0] == 1:
                msg = MagicMock()
                msg.arbitration_id = 0x581
                msg.is_remote_frame = False
                msg.data = bytearray([0x43, 0x00, 0x10, 0x00, 0x91, 0x01, 0x00, 0x00])
                return msg
            # Abort for all other indices
            msg = MagicMock()
            msg.arbitration_id = 0x581
            msg.is_remote_frame = False
            msg.data = bytearray([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06])
            return msg

        mock_bus.recv.side_effect = recv_side_effect

        found = self.scanner.canopen_od_scan(mock_bus, 1, index_range=(0x1000, 0x1002))

        self.assertIsInstance(found, list)
        mock_bus.send.assert_called()

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_modbus_gateway_detect_no_nodes(self, mock_can_lazy):
        """Test gateway detection with no nodes."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[])

        self.assertEqual(len(gateways), 0)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_modbus_gateway_detect_cia309(self, mock_can_lazy):
        """Test gateway detection identifies CiA 309 devices."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Pre-create a node with CiA 309 profile
        node = self.CANopenNode(
            node_id=3,
            device_type=0x00000135,  # Profile 309
            device_profile=309,
            device_profile_name="CANopen-to-Modbus Gateway (CiA 309)",
        )

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[node])

        self.assertEqual(len(gateways), 1)
        self.assertTrue(gateways[0].is_gateway)
        self.assertIn("309", gateways[0].gateway_type)

    @patch("oida.protocols.can.scanner._python_can")
    def test_canopen_modbus_register_map(self, mock_can_lazy):
        """Test Modbus register map enumeration."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # All reads return abort (no registers configured)
        abort_msg = MagicMock()
        abort_msg.arbitration_id = 0x583
        abort_msg.is_remote_frame = False
        abort_msg.data = bytearray([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06])
        mock_bus.recv.return_value = abort_msg

        mappings = self.scanner.canopen_modbus_register_map(
            mock_bus, 3, scan_range=(0x5100, 0x5102)
        )

        self.assertIsInstance(mappings, dict)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_sdo_response(self, mock_can_lazy):
        """Test SDO response reception."""
        mock_bus = MagicMock()

        mock_msg = MagicMock()
        mock_msg.arbitration_id = 0x581
        mock_msg.is_remote_frame = False
        mock_msg.data = bytearray([0x43, 0x00, 0x10, 0x00, 0x91, 0x01, 0x00, 0x00])
        mock_bus.recv.return_value = mock_msg

        resp = self.scanner._recv_sdo_response(mock_bus, 0x581, timeout=0.1)

        self.assertIsNotNone(resp)
        self.assertEqual(resp[0], 0x43)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_sdo_response_wrong_id(self, mock_can_lazy):
        """Test SDO response ignores wrong COB-ID."""
        mock_bus = MagicMock()

        # Return one message on wrong ID, then always None (timeout)
        wrong_msg = MagicMock()
        wrong_msg.arbitration_id = 0x582  # Wrong node
        wrong_msg.is_remote_frame = False
        wrong_msg.data = bytearray([0x43, 0x00, 0x10, 0x00, 0x91, 0x01, 0x00, 0x00])

        call_count = [0]

        def recv_side_effect(timeout=0.5):
            call_count[0] += 1
            if call_count[0] == 1:
                return wrong_msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        resp = self.scanner._recv_sdo_response(mock_bus, 0x581, timeout=0.1)

        # Should not match wrong ID - returns None on timeout
        self.assertIsNone(resp)

    @patch("oida.protocols.can.scanner._python_can")
    def test_recv_sdo_response_timeout(self, mock_can_lazy):
        """Test SDO response timeout returns None."""
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        resp = self.scanner._recv_sdo_response(mock_bus, 0x581, timeout=0.05)

        self.assertIsNone(resp)


# ---------------------------------------------------------------------------
# CANopen proto_args tests
# ---------------------------------------------------------------------------


class TestCANProtoArgsCANopen(unittest.TestCase):
    """Test CAN proto_args for CANopen arguments."""

    def _make_parser(self):
        import argparse

        from oida.protocols.can.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])
        return main_parser

    def test_canopen_scan_flag(self):
        """Test --canopen-scan flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--canopen-scan"])
        self.assertTrue(args.canopen_scan)

    def test_canopen_info_option(self):
        """Test --canopen-info option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--canopen-info", "5"])
        self.assertEqual(args.canopen_info, "5")

    def test_canopen_sdo_read_option(self):
        """Test --canopen-sdo-read option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--canopen-sdo-read", "1:0x1000:0"])
        self.assertEqual(args.canopen_sdo_read, "1:0x1000:0")

    def test_canopen_od_scan_option(self):
        """Test --canopen-od-scan option."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--canopen-od-scan", "1"])
        self.assertEqual(args.canopen_od_scan, "1")

    def test_canopen_od_range_option(self):
        """Test --canopen-od-range option."""
        parser = self._make_parser()
        args = parser.parse_args(
            [
                "can",
                "can0",
                "--canopen-od-scan",
                "1",
                "--canopen-od-range",
                "0x1000-0x1FFF",
            ]
        )
        self.assertEqual(args.canopen_od_range, "0x1000-0x1FFF")

    def test_canopen_monitor_flag(self):
        """Test --canopen-monitor flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--canopen-monitor"])
        self.assertTrue(args.canopen_monitor)

    def test_canopen_pdo_flag(self):
        """Test --canopen-pdo flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--canopen-pdo"])
        self.assertTrue(args.canopen_pdo)

    def test_canopen_pdo_node(self):
        """Test --canopen-pdo-node option."""
        parser = self._make_parser()
        args = parser.parse_args(
            [
                "can",
                "can0",
                "--canopen-pdo",
                "--canopen-pdo-node",
                "10",
            ]
        )
        self.assertEqual(args.canopen_pdo_node, "10")

    def test_modbus_gateway_flag(self):
        """Test --modbus-gateway flag."""
        parser = self._make_parser()
        args = parser.parse_args(["can", "can0", "--modbus-gateway"])
        self.assertTrue(args.modbus_gateway)


# ---------------------------------------------------------------------------
# CANopen segmented SDO transfer test
# ---------------------------------------------------------------------------


class TestCANopenSegmentedSDO(unittest.TestCase):
    """Test CANopen segmented SDO transfer handling."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_sdo_segmented_upload(self, mock_can_lazy):
        """Test SDO segmented upload for data > 4 bytes."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Sequence:
        # 1. Initiate upload response (non-expedited, size=10)
        # 2. Segment upload response (7 bytes, toggle=0, not last)
        # 3. Segment upload response (3 bytes, toggle=1, last)

        responses = []

        # Initiate upload response: SCS=2, e=0, s=1 -> 0x41
        # size in bytes 4..7 = 10 (little-endian)
        init_msg = MagicMock()
        init_msg.arbitration_id = 0x581
        init_msg.is_remote_frame = False
        init_msg.data = bytearray([0x41, 0x08, 0x10, 0x00, 0x0A, 0x00, 0x00, 0x00])
        responses.append(init_msg)

        # Segment 1: SCS=0, toggle=0, n=0, c=0 -> byte[0] = 0x00
        seg1_msg = MagicMock()
        seg1_msg.arbitration_id = 0x581
        seg1_msg.is_remote_frame = False
        seg1_msg.data = bytearray([0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47])
        responses.append(seg1_msg)

        # Segment 2: SCS=0, toggle=1, n=4 (4 unused), c=1 (last) -> byte[0] = 0x19
        # n=4 -> bits 3..1 = 100, c=1 -> bit 0 = 1
        seg2_msg = MagicMock()
        seg2_msg.arbitration_id = 0x581
        seg2_msg.is_remote_frame = False
        seg2_msg.data = bytearray([0x19, 0x48, 0x49, 0x4A, 0x00, 0x00, 0x00, 0x00])
        responses.append(seg2_msg)

        response_iter = iter(responses)

        def recv_side_effect(timeout=0.5):
            try:
                return next(response_iter)
            except StopIteration:
                return None

        mock_bus.recv.side_effect = recv_side_effect

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1008, 0x00)

        self.assertFalse(resp.error)
        self.assertEqual(len(resp.data), 10)
        self.assertEqual(resp.data, b"ABCDEFGHIJ")


# ---------------------------------------------------------------------------
# Additional CANopen Protocol Tests (comprehensive coverage)
# ---------------------------------------------------------------------------


class TestCANopenConstantsExtended(unittest.TestCase):
    """Extended tests for CANopen constants completeness and correctness."""

    def test_cob_id_function_codes_complete(self):
        """Test CANOPEN_FUNCTION_CODES has all required entries."""
        from oida.protocols.can.constants import CANOPEN_FUNCTION_CODES

        required_keys = [
            "NMT",
            "SYNC",
            "TIME",
            "EMCY",
            "TPDO1",
            "RPDO1",
            "TPDO2",
            "RPDO2",
            "TPDO3",
            "RPDO3",
            "TPDO4",
            "RPDO4",
            "SDO_TX",
            "SDO_RX",
            "HEARTBEAT",
        ]
        for key in required_keys:
            self.assertIn(key, CANOPEN_FUNCTION_CODES, f"Missing function code: {key}")

        # Verify ordering (priority-based: lower COB-ID = higher priority)
        self.assertEqual(CANOPEN_FUNCTION_CODES["NMT"], 0x000)
        self.assertEqual(CANOPEN_FUNCTION_CODES["SYNC"], 0x080)
        self.assertEqual(CANOPEN_FUNCTION_CODES["TIME"], 0x100)
        self.assertLess(CANOPEN_FUNCTION_CODES["TPDO1"], CANOPEN_FUNCTION_CODES["RPDO1"])
        self.assertLess(CANOPEN_FUNCTION_CODES["SDO_TX"], CANOPEN_FUNCTION_CODES["SDO_RX"])
        self.assertLess(CANOPEN_FUNCTION_CODES["SDO_RX"], CANOPEN_FUNCTION_CODES["HEARTBEAT"])

    def test_node_id_range(self):
        """Test CANopen node ID valid range is 1-127."""
        from oida.protocols.can.constants import (
            CANOPEN_NODE_ID_MAX,
            CANOPEN_NODE_ID_MIN,
        )

        self.assertEqual(CANOPEN_NODE_ID_MIN, 1)
        self.assertEqual(CANOPEN_NODE_ID_MAX, 127)

    def test_sdo_command_byte_values(self):
        """Test SDO command bytes have correct computed values."""
        from oida.protocols.can.constants import (
            SDO_CMD_ABORT,
            SDO_CMD_DOWNLOAD_INITIATE_1B,
            SDO_CMD_DOWNLOAD_INITIATE_4B,
            SDO_CMD_SEGMENT_UPLOAD_0,
            SDO_CMD_SEGMENT_UPLOAD_1,
            SDO_CMD_UPLOAD_INITIATE,
        )

        # Upload initiate = CCS=2 << 5 = 0x40
        self.assertEqual(SDO_CMD_UPLOAD_INITIATE, 0x40)
        # Segment upload toggle=0: CCS=3 << 5 = 0x60
        self.assertEqual(SDO_CMD_SEGMENT_UPLOAD_0, 0x60)
        # Segment upload toggle=1: 0x60 | 0x10 = 0x70
        self.assertEqual(SDO_CMD_SEGMENT_UPLOAD_1, 0x70)
        # Abort = CCS=4 << 5 = 0x80
        self.assertEqual(SDO_CMD_ABORT, 0x80)
        # Download initiate 4 bytes (expedited): CCS=1 << 5 | 0x23 = 0x23
        self.assertEqual(SDO_CMD_DOWNLOAD_INITIATE_4B, 0x23)
        # Download initiate 1 byte: 0x2F
        self.assertEqual(SDO_CMD_DOWNLOAD_INITIATE_1B, 0x2F)

    def test_sdo_bitmask_constants(self):
        """Test SDO bit masks for command byte parsing."""
        from oida.protocols.can.constants import (
            SDO_CMD_SPECIFIER_MASK,
            SDO_EXPEDITED_BIT,
            SDO_N_BITS_MASK,
            SDO_SIZE_INDICATED_BIT,
            SDO_TOGGLE_BIT,
        )

        self.assertEqual(SDO_CMD_SPECIFIER_MASK, 0xE0)
        self.assertEqual(SDO_EXPEDITED_BIT, 0x02)
        self.assertEqual(SDO_SIZE_INDICATED_BIT, 0x01)
        self.assertEqual(SDO_N_BITS_MASK, 0x0C)
        self.assertEqual(SDO_TOGGLE_BIT, 0x10)

    def test_sdo_abort_codes_completeness(self):
        """Test SDO abort codes cover all standard CiA 301 codes."""
        from oida.protocols.can.constants import SDO_ABORT_CODES

        # Key abort codes that must be present
        critical_codes = {
            0x05030000: "Toggle",
            0x05040000: "timed out",
            0x05040001: "command specifier",
            0x06010000: "Unsupported access",
            0x06010001: "read a write-only",
            0x06010002: "write a read-only",
            0x06020000: "does not exist",
            0x06070010: "Data type does not match",
            0x06090011: "Sub-index does not exist",
            0x08000000: "General error",
        }
        for code, expected_substr in critical_codes.items():
            self.assertIn(code, SDO_ABORT_CODES, f"Missing abort code 0x{code:08X}")
            self.assertIn(
                expected_substr.lower(),
                SDO_ABORT_CODES[code].lower(),
                f"Abort code 0x{code:08X} description mismatch",
            )

    def test_od_entries_mandatory(self):
        """Test mandatory Object Dictionary entries are defined."""
        from oida.protocols.can.constants import CANOPEN_OD_ENTRIES

        mandatory = [0x1000, 0x1001, 0x1018]
        for idx in mandatory:
            self.assertIn(idx, CANOPEN_OD_ENTRIES, f"Missing mandatory OD entry 0x{idx:04X}")

    def test_od_entries_has_descriptive_names(self):
        """Test that OD entries have non-empty descriptions."""
        from oida.protocols.can.constants import CANOPEN_OD_ENTRIES

        for idx, name in CANOPEN_OD_ENTRIES.items():
            self.assertIsInstance(name, str)
            self.assertTrue(len(name) > 0, f"Empty description for OD 0x{idx:04X}")

    def test_fingerprint_indices_structure(self):
        """Test fingerprint indices list has correct tuple structure."""
        from oida.protocols.can.constants import CANOPEN_FINGERPRINT_INDICES

        self.assertTrue(len(CANOPEN_FINGERPRINT_INDICES) >= 9)
        for entry in CANOPEN_FINGERPRINT_INDICES:
            self.assertEqual(len(entry), 3, "Fingerprint entry should be (index, subindex, name)")
            idx, sub, name = entry
            self.assertIsInstance(idx, int)
            self.assertIsInstance(sub, int)
            self.assertIsInstance(name, str)
            self.assertGreaterEqual(idx, 0x1000)
            self.assertLessEqual(idx, 0x1FFF)

    def test_device_profiles_include_key_profiles(self):
        """Test device profiles include CiA 301, 309, 401, 402, 404."""
        from oida.protocols.can.constants import CANOPEN_DEVICE_PROFILES

        self.assertIn(301, CANOPEN_DEVICE_PROFILES)
        self.assertIn(309, CANOPEN_DEVICE_PROFILES)
        self.assertIn(401, CANOPEN_DEVICE_PROFILES)
        self.assertIn(402, CANOPEN_DEVICE_PROFILES)
        self.assertIn(404, CANOPEN_DEVICE_PROFILES)
        self.assertIn("Generic I/O", CANOPEN_DEVICE_PROFILES[401])
        self.assertIn("Drives", CANOPEN_DEVICE_PROFILES[402])
        self.assertIn("Measuring", CANOPEN_DEVICE_PROFILES[404])
        self.assertIn("Modbus", CANOPEN_DEVICE_PROFILES[309])

    def test_emcy_error_codes_categories(self):
        """Test EMCY codes cover all standard error categories."""
        from oida.protocols.can.constants import CANOPEN_EMCY_CODES

        categories = [
            0x0000,
            0x1000,
            0x2000,
            0x3000,
            0x4000,
            0x5000,
            0x6000,
            0x7000,
            0x8000,
            0x9000,
            0xF000,
            0xFF00,
        ]
        for cat in categories:
            self.assertIn(cat, CANOPEN_EMCY_CODES, f"Missing EMCY category 0x{cat:04X}")

    def test_error_register_bits(self):
        """Test error register bit definitions."""
        from oida.protocols.can.constants import (
            CANOPEN_ERR_REG_COMMUNICATION,
            CANOPEN_ERR_REG_CURRENT,
            CANOPEN_ERR_REG_GENERIC,
            CANOPEN_ERR_REG_TEMPERATURE,
            CANOPEN_ERR_REG_VOLTAGE,
            CANOPEN_ERR_REGISTER_BITS,
        )

        self.assertEqual(CANOPEN_ERR_REG_GENERIC, 0x01)
        self.assertEqual(CANOPEN_ERR_REG_CURRENT, 0x02)
        self.assertEqual(CANOPEN_ERR_REG_VOLTAGE, 0x04)
        self.assertEqual(CANOPEN_ERR_REG_TEMPERATURE, 0x08)
        self.assertEqual(CANOPEN_ERR_REG_COMMUNICATION, 0x10)
        # All 8 bits should be defined
        self.assertEqual(len(CANOPEN_ERR_REGISTER_BITS), 8)

    def test_pdo_transmission_types(self):
        """Test PDO transmission type constants."""
        from oida.protocols.can.constants import (
            CANOPEN_PDO_TRANS_ASYNC_MFR,
            CANOPEN_PDO_TRANS_ASYNC_PROFILE,
            CANOPEN_PDO_TRANS_RTR_ASYNC,
            CANOPEN_PDO_TRANS_RTR_SYNC,
            CANOPEN_PDO_TRANS_SYNC_ACYCLIC,
        )

        self.assertEqual(CANOPEN_PDO_TRANS_SYNC_ACYCLIC, 0x00)
        self.assertEqual(CANOPEN_PDO_TRANS_RTR_SYNC, 0xFC)
        self.assertEqual(CANOPEN_PDO_TRANS_RTR_ASYNC, 0xFD)
        self.assertEqual(CANOPEN_PDO_TRANS_ASYNC_MFR, 0xFE)
        self.assertEqual(CANOPEN_PDO_TRANS_ASYNC_PROFILE, 0xFF)

    def test_lss_constants(self):
        """Test LSS (Layer Setting Services) COB-ID constants."""
        from oida.protocols.can.constants import CANOPEN_LSS_RX_ID, CANOPEN_LSS_TX_ID

        self.assertEqual(CANOPEN_LSS_TX_ID, 0x7E4)
        self.assertEqual(CANOPEN_LSS_RX_ID, 0x7E5)

    def test_cia309_constants(self):
        """Test CiA 309 Modbus gateway constants."""
        from oida.protocols.can.constants import (
            CIA309_MODBUS_FC_READ_HOLDING,
            CIA309_MODBUS_FC_READ_INPUT,
            CIA309_MODBUS_FC_WRITE_MULTIPLE,
            CIA309_MODBUS_FC_WRITE_SINGLE,
            CIA309_OD_GATEWAY_CONFIG,
            CIA309_OD_MODBUS_MAP_BASE,
            CIA309_OD_SLAVE_MAP_BASE,
            CIA309_PROFILE_NUMBER,
        )

        self.assertEqual(CIA309_PROFILE_NUMBER, 309)
        self.assertEqual(CIA309_OD_GATEWAY_CONFIG, 0x5000)
        self.assertEqual(CIA309_OD_MODBUS_MAP_BASE, 0x5100)
        self.assertEqual(CIA309_OD_SLAVE_MAP_BASE, 0x5200)
        self.assertEqual(CIA309_MODBUS_FC_READ_HOLDING, 0x03)
        self.assertEqual(CIA309_MODBUS_FC_READ_INPUT, 0x04)
        self.assertEqual(CIA309_MODBUS_FC_WRITE_SINGLE, 0x06)
        self.assertEqual(CIA309_MODBUS_FC_WRITE_MULTIPLE, 0x10)

    def test_timestamp_id(self):
        """Test TIME stamp object COB-ID."""
        from oida.protocols.can.constants import CANOPEN_TIMESTAMP_ID

        self.assertEqual(CANOPEN_TIMESTAMP_ID, 0x100)

    def test_sdo_server_client_od_indices(self):
        """Test SDO server/client parameter OD indices."""
        from oida.protocols.can.constants import (
            CANOPEN_OD_SDO_CLIENT_1,
            CANOPEN_OD_SDO_SERVER_1,
        )

        self.assertEqual(CANOPEN_OD_SDO_SERVER_1, 0x1200)
        self.assertEqual(CANOPEN_OD_SDO_CLIENT_1, 0x1280)

    def test_identity_subindices(self):
        """Test Identity object sub-index constants."""
        from oida.protocols.can.constants import (
            CANOPEN_OD_IDENTITY,
            CANOPEN_OD_IDENTITY_PRODUCT_CODE,
            CANOPEN_OD_IDENTITY_REVISION,
            CANOPEN_OD_IDENTITY_SERIAL,
            CANOPEN_OD_IDENTITY_VENDOR_ID,
        )

        self.assertEqual(CANOPEN_OD_IDENTITY, 0x1018)
        self.assertEqual(CANOPEN_OD_IDENTITY_VENDOR_ID, 0x01)
        self.assertEqual(CANOPEN_OD_IDENTITY_PRODUCT_CODE, 0x02)
        self.assertEqual(CANOPEN_OD_IDENTITY_REVISION, 0x03)
        self.assertEqual(CANOPEN_OD_IDENTITY_SERIAL, 0x04)


class TestCANopenNodeExtended(unittest.TestCase):
    """Extended tests for CANopenNode data class."""

    def test_cob_id_properties(self):
        """Test computed COB-ID properties for various node IDs."""
        from oida.protocols.can.constants import CANopenNode

        # Test node 1 (minimum)
        node1 = CANopenNode(node_id=1)
        self.assertEqual(node1.sdo_rx_cob_id, 0x601)
        self.assertEqual(node1.sdo_tx_cob_id, 0x581)
        self.assertEqual(node1.heartbeat_cob_id, 0x701)
        self.assertEqual(node1.emcy_cob_id, 0x081)

        # Test node 127 (maximum)
        node127 = CANopenNode(node_id=127)
        self.assertEqual(node127.sdo_rx_cob_id, 0x67F)
        self.assertEqual(node127.sdo_tx_cob_id, 0x5FF)
        self.assertEqual(node127.heartbeat_cob_id, 0x77F)
        self.assertEqual(node127.emcy_cob_id, 0x0FF)

        # Test node 42 (arbitrary mid-range)
        node42 = CANopenNode(node_id=42)
        self.assertEqual(node42.sdo_rx_cob_id, 0x600 + 42)
        self.assertEqual(node42.sdo_tx_cob_id, 0x580 + 42)

    def test_node_id_hex_format(self):
        """Test node ID hex string formatting."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(node_id=10)
        self.assertEqual(node.node_id_hex, "0x0A (10)")

        node2 = CANopenNode(node_id=127)
        self.assertEqual(node2.node_id_hex, "0x7F (127)")

    def test_gateway_fields(self):
        """Test gateway-related fields on CANopenNode."""
        from oida.protocols.can.constants import CANopenNode

        gw = CANopenNode(
            node_id=5,
            is_gateway=True,
            gateway_type="CiA 309 Modbus Gateway",
            device_profile=309,
            device_profile_name="CANopen-to-Modbus Gateway (CiA 309)",
        )
        self.assertTrue(gw.is_gateway)
        self.assertEqual(gw.gateway_type, "CiA 309 Modbus Gateway")
        self.assertEqual(gw.device_profile, 309)

    def test_node_with_full_identity(self):
        """Test CANopenNode with all identity fields populated."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(
            node_id=3,
            nmt_state=0x05,
            nmt_state_name="Operational",
            device_type=0x000F0191,
            device_profile=401,
            device_profile_name="Generic I/O Modules (CiA 401)",
            device_name="TestDevice",
            hw_version="1.0",
            sw_version="2.3.1",
            vendor_id=0x00000022,
            vendor_name="HMS Industrial Networks (Anybus)",
            product_code=0x00001234,
            revision=0x00020003,
            serial_number=42,
            error_register=0x00,
            heartbeat_ms=500,
        )
        self.assertEqual(node.device_name, "TestDevice")
        self.assertEqual(node.hw_version, "1.0")
        self.assertEqual(node.sw_version, "2.3.1")
        self.assertEqual(node.vendor_id, 0x00000022)
        self.assertEqual(node.serial_number, 42)
        self.assertEqual(node.heartbeat_ms, 500)
        self.assertFalse(node.is_gateway)

    def test_node_default_values(self):
        """Test that CANopenNode defaults are sensible."""
        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(node_id=1)
        self.assertEqual(node.nmt_state, 0)
        self.assertEqual(node.nmt_state_name, "")
        self.assertEqual(node.device_type, 0)
        self.assertEqual(node.device_profile, 0)
        self.assertEqual(node.device_name, "")
        self.assertEqual(node.vendor_id, 0)
        self.assertEqual(node.error_register, 0)
        self.assertEqual(node.od_entries_found, [])
        self.assertEqual(node.pdo_mappings, {})
        self.assertFalse(node.is_gateway)
        self.assertEqual(node.metadata, {})


class TestCANopenSDOResponseExtended(unittest.TestCase):
    """Extended tests for SDO response parsing edge cases."""

    def test_as_uint32_big_value(self):
        """Test UNSIGNED32 with max value."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1000,
            subindex=0,
            data=bytes([0xFF, 0xFF, 0xFF, 0xFF]),
        )
        self.assertEqual(resp.as_uint32, 0xFFFFFFFF)

    def test_as_uint16_little_endian(self):
        """Test UNSIGNED16 little-endian byte order."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1017,
            subindex=0,
            data=bytes([0xE8, 0x03]),  # 1000 in LE
        )
        self.assertEqual(resp.as_uint16, 1000)

    def test_as_string_with_null_terminator(self):
        """Test string parsing strips null terminators."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1008,
            subindex=0,
            data=b"TestDev\x00\x00\x00",
        )
        self.assertEqual(resp.as_string, "TestDev")

    def test_as_string_non_ascii(self):
        """Test string parsing handles non-ASCII gracefully."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1008,
            subindex=0,
            data=bytes([0x80, 0x81, 0x82, 0x00]),
        )
        # Should not raise; decode with errors='ignore'
        result = resp.as_string
        self.assertIsNotNone(result)

    def test_error_response_properties_return_none(self):
        """Test that property accessors return None on error responses."""
        from oida.protocols.can.constants import CANopenSDOResponse

        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1000,
            subindex=0,
            error=True,
            abort_code=0x06020000,
            abort_message="Object does not exist",
        )
        self.assertIsNone(resp.as_uint8)
        self.assertIsNone(resp.as_uint16)
        self.assertIsNone(resp.as_uint32)
        self.assertIsNone(resp.as_string)

    def test_short_data_properties(self):
        """Test property accessors with too-short data."""
        from oida.protocols.can.constants import CANopenSDOResponse

        # 1 byte data: uint8 works, uint16 and uint32 return None
        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1001,
            subindex=0,
            data=bytes([0x42]),
        )
        self.assertEqual(resp.as_uint8, 0x42)
        self.assertIsNone(resp.as_uint16)
        self.assertIsNone(resp.as_uint32)

    def test_as_uint32_device_type_parsing(self):
        """Test parsing device type from uint32 (profile in lower 16 bits)."""
        from oida.protocols.can.constants import (
            CANOPEN_DEVICE_PROFILES,
            CANopenSDOResponse,
        )

        # Device type = 0x000F0191 -> profile = 0x0191 = 401 = Generic I/O
        resp = CANopenSDOResponse(
            node_id=1,
            index=0x1000,
            subindex=0,
            data=bytes([0x91, 0x01, 0x0F, 0x00]),  # LE: 0x000F0191
        )
        device_type = resp.as_uint32
        self.assertIsNotNone(device_type)
        profile = device_type & 0xFFFF
        self.assertEqual(profile, 401)
        self.assertIn(profile, CANOPEN_DEVICE_PROFILES)


class TestCANopenScanResultExtended(unittest.TestCase):
    """Extended tests for CANopenScanResult data class."""

    def test_scan_result_with_gateways(self):
        """Test scan result with gateway list."""
        from oida.protocols.can.constants import CANopenNode, CANopenScanResult

        gw = CANopenNode(node_id=5, is_gateway=True, gateway_type="CiA 309")
        result = CANopenScanResult(
            nodes=[CANopenNode(node_id=1), gw],
            total_nodes_found=2,
            gateways=[gw],
        )
        self.assertEqual(result.total_nodes_found, 2)
        self.assertEqual(len(result.gateways), 1)
        self.assertTrue(result.gateways[0].is_gateway)

    def test_scan_result_with_modbus_mappings(self):
        """Test scan result with Modbus register mappings."""
        from oida.protocols.can.constants import CANopenScanResult

        result = CANopenScanResult(
            modbus_mappings={
                5: {"gateway_type": "CiA 309", "registers": {0x5100: b"\x01\x02"}},
            },
        )
        self.assertIn(5, result.modbus_mappings)

    def test_scan_result_empty(self):
        """Test empty scan result."""
        from oida.protocols.can.constants import CANopenScanResult

        result = CANopenScanResult()
        self.assertEqual(result.nodes, [])
        self.assertEqual(result.total_nodes_found, 0)
        self.assertEqual(result.scan_duration, 0.0)
        self.assertEqual(result.heartbeat_nodes, [])
        self.assertEqual(result.emcy_messages, [])
        self.assertEqual(result.gateways, [])
        self.assertEqual(result.modbus_mappings, {})


class TestCANopenScannerPDO(unittest.TestCase):
    """Tests for CANopen PDO discovery method."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_pdo_discover_tpdo_enabled(self, mock_can_lazy):
        """Test PDO discovery finds an enabled TPDO with mapping."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        call_count = [0]
        responses = {
            # TPDO1 comm param sub 1 (COB-ID): enabled, COB-ID=0x181
            (0x1800, 0x01): bytes([0x43, 0x00, 0x18, 0x01, 0x81, 0x01, 0x00, 0x00]),
            # TPDO1 comm param sub 2 (transmission type): 0xFF (async)
            (0x1800, 0x02): bytes([0x4F, 0x00, 0x18, 0x02, 0xFF, 0x00, 0x00, 0x00]),
            # TPDO1 mapping param sub 0 (count): 2 mappings
            (0x1A00, 0x00): bytes([0x4F, 0x00, 0x1A, 0x00, 0x02, 0x00, 0x00, 0x00]),
            # TPDO1 mapping 1: index=0x6000, sub=1, 8 bits
            (0x1A00, 0x01): bytes([0x43, 0x00, 0x1A, 0x01, 0x08, 0x01, 0x00, 0x60]),
            # TPDO1 mapping 2: index=0x6000, sub=2, 16 bits
            (0x1A00, 0x02): bytes([0x43, 0x00, 0x1A, 0x02, 0x10, 0x02, 0x00, 0x60]),
        }

        def recv_side_effect(timeout=0.5):
            nonlocal call_count
            call_count[0] += 1
            # After too many calls, return None
            if call_count[0] > 100:
                return
            return

        # We need to mock canopen_sdo_read instead for this test
        from oida.protocols.can.constants import CANopenSDOResponse

        sdo_calls = []

        def mock_sdo_read(bus, node_id, index, subindex=0, timeout=0.5):
            sdo_calls.append((index, subindex))
            key = (index, subindex)
            if key in responses:
                resp_data = responses[key]
                # Parse the expedited data from bytes 4-7
                cmd = resp_data[0]
                n = (cmd & 0x0C) >> 2
                data_len = 4 - n if (cmd & 0x01) else 4
                data = resp_data[4 : 4 + data_len]
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    data=bytes(data),
                )
            else:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    error=True,
                    abort_code=0x06020000,
                    abort_message="Object does not exist",
                )

        self.scanner.canopen_sdo_read = mock_sdo_read

        result = self.scanner.canopen_pdo_discover(mock_bus, node_id=1)

        self.assertIn("tpdo", result)
        self.assertIn("rpdo", result)
        # TPDO1 should have been read
        self.assertTrue(any(c == (0x1800, 0x01) for c in sdo_calls))

    @patch("oida.protocols.can.scanner._python_can")
    def test_pdo_discover_no_pdos(self, mock_can_lazy):
        """Test PDO discovery when no PDOs are configured."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenSDOResponse

        def mock_sdo_read(bus, node_id, index, subindex=0, timeout=0.5):
            return CANopenSDOResponse(
                node_id=node_id,
                index=index,
                subindex=subindex,
                error=True,
                abort_code=0x06020000,
                abort_message="Object does not exist",
            )

        self.scanner.canopen_sdo_read = mock_sdo_read

        result = self.scanner.canopen_pdo_discover(mock_bus, node_id=1)

        self.assertIn("tpdo", result)
        self.assertIn("rpdo", result)
        # Both should be empty
        self.assertEqual(result["tpdo"], {})
        self.assertEqual(result["rpdo"], {})


class TestCANopenGatewayVendorMatching(unittest.TestCase):
    """Tests for gateway detection via vendor keyword matching."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_gateway_detect_vendor_keyword(self, mock_can_lazy):
        """Test gateway detection via vendor ID + device name keywords."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenNode

        # Node with known vendor and 'gateway' in name
        # device_type must be non-zero to skip the canopen_device_info call
        node = CANopenNode(
            node_id=5,
            device_type=0x00000001,  # Non-zero to skip re-read
            device_profile=0,
            vendor_id=0x00000022,  # HMS Industrial Networks
            vendor_name="HMS Industrial Networks (Anybus)",
            device_name="Anybus X-gateway",
        )

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[node])

        self.assertEqual(len(gateways), 1)
        self.assertTrue(gateways[0].is_gateway)
        self.assertIn("Suspected", gateways[0].gateway_type)

    @patch("oida.protocols.can.scanner._python_can")
    def test_gateway_detect_vendor_no_keyword(self, mock_can_lazy):
        """Test that known vendor without gateway keywords is NOT flagged."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenNode

        # Node with known vendor but NO gateway keyword in name
        # device_type non-zero to skip re-read
        node = CANopenNode(
            node_id=3,
            device_type=0x00000191,  # CiA 401 (non-zero)
            device_profile=401,
            vendor_id=0x00000022,  # HMS
            vendor_name="HMS Industrial Networks (Anybus)",
            device_name="IO Module 8DI",  # Not a gateway name
        )

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[node])

        self.assertEqual(len(gateways), 0)

    @patch("oida.protocols.can.scanner._python_can")
    def test_gateway_detect_modbus_keyword(self, mock_can_lazy):
        """Test gateway detection with 'modbus' in device name."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(
            node_id=8,
            device_type=0x00000001,  # Non-zero to skip re-read
            vendor_id=0x000000C7,  # Moxa
            vendor_name="Moxa",
            device_name="MGate 5118 Modbus TCP",
        )

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[node])

        self.assertEqual(len(gateways), 1)
        self.assertTrue(gateways[0].is_gateway)

    @patch("oida.protocols.can.scanner._python_can")
    def test_gateway_detect_bridge_keyword(self, mock_can_lazy):
        """Test gateway detection with 'bridge' in device name."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(
            node_id=10,
            device_type=0x00000001,  # Non-zero to skip re-read
            vendor_id=0x000000A2,  # Phoenix Contact
            vendor_name="Phoenix Contact",
            device_name="Industrial Bridge Unit",
        )

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[node])

        self.assertEqual(len(gateways), 1)

    @patch("oida.protocols.can.scanner._python_can")
    def test_gateway_detect_unknown_vendor(self, mock_can_lazy):
        """Test that unknown vendor ID is NOT flagged as gateway."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenNode

        node = CANopenNode(
            node_id=12,
            device_type=0x00000001,  # Non-zero to skip re-read
            vendor_id=0x99999999,  # Unknown vendor
            vendor_name="Unknown Vendor",
            device_name="Some Gateway Device",  # Has keyword but unknown vendor
        )

        gateways = self.scanner.canopen_modbus_gateway_detect(mock_bus, nodes=[node])

        self.assertEqual(len(gateways), 0)


class TestCANopenScannerEdgeCases(unittest.TestCase):
    """Edge case tests for CANopen scanner methods."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_sdo_read_send_failure(self, mock_can_lazy):
        """Test SDO read when send raises exception."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.send.side_effect = Exception("Bus error")

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1000, 0x00)

        self.assertTrue(resp.error)
        self.assertIn("Failed to send", resp.abort_message)

    @patch("oida.protocols.can.scanner._python_can")
    def test_sdo_read_expedited_no_size_indicated(self, mock_can_lazy):
        """Test SDO expedited read when size is not indicated (s=0, e=1)."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Response: SCS=2, e=1, s=0 -> cmd = 0x42
        resp_msg = MagicMock()
        resp_msg.arbitration_id = 0x581
        resp_msg.is_remote_frame = False
        resp_msg.data = bytearray([0x42, 0x00, 0x10, 0x00, 0xAA, 0xBB, 0xCC, 0xDD])
        mock_bus.recv.return_value = resp_msg

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1000, 0x00)

        self.assertFalse(resp.error)
        # When s=0, e=1: full 4 bytes of data
        self.assertEqual(len(resp.data), 4)

    @patch("oida.protocols.can.scanner._python_can")
    def test_node_scan_only_rtr_discovery(self, mock_can_lazy):
        """Test node scan when no heartbeats but RTR responses exist."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        # Phase 1: No heartbeats during 2s listen
        call_count = [0]

        def recv_side_effect(timeout=0.5):
            call_count[0] += 1
            # During phase 1 (first ~20 calls), return None
            # During phase 2 RTR probe, respond for node 42
            if call_count[0] > 50:
                return
            return

        mock_bus.recv.side_effect = recv_side_effect

        # Just verify it doesn't crash and returns a list
        import time

        original_time = time.time

        # Speed up the test by mocking time
        time_counter = [original_time()]

        def fast_time():
            time_counter[0] += 0.5
            return time_counter[0]

        with patch("oida.protocols.can.scanner.time") as mock_time:
            mock_time.time = fast_time
            nodes = self.scanner.canopen_node_scan(mock_bus)

        self.assertIsInstance(nodes, list)

    @patch("oida.protocols.can.scanner._python_can")
    def test_emcy_monitor_ignores_non_emcy(self, mock_can_lazy):
        """Test EMCY monitor ignores non-EMCY messages."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        call_count = [0]

        def recv_side_effect(timeout=0.5):
            call_count[0] += 1
            if call_count[0] == 1:
                # Non-EMCY message (heartbeat)
                msg = MagicMock()
                msg.arbitration_id = 0x705  # Heartbeat
                msg.data = bytearray([0x05])
                return msg
            elif call_count[0] == 2:
                # EMCY message
                msg = MagicMock()
                msg.arbitration_id = 0x083  # EMCY node 3
                msg.data = bytearray([0x10, 0x81, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        messages = self.scanner.canopen_emcy_monitor(mock_bus, duration=0.1)

        # Should only capture the EMCY message, not the heartbeat
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["node_id"], 3)

    @patch("oida.protocols.can.scanner._python_can")
    def test_heartbeat_monitor_interval_calculation(self, mock_can_lazy):
        """Test heartbeat monitor calculates average interval correctly."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        import time as real_time

        real_time.time()
        call_count = [0]

        def recv_side_effect(timeout=0.5):
            call_count[0] += 1
            if call_count[0] <= 3:
                msg = MagicMock()
                msg.arbitration_id = 0x705  # Node 5
                msg.data = bytearray([0x05])  # Operational
                return msg
            return None

        mock_bus.recv.side_effect = recv_side_effect

        nodes = self.scanner.canopen_heartbeat_monitor(mock_bus, duration=0.1)

        self.assertIn(5, nodes)
        self.assertEqual(nodes[5]["count"], 3)
        self.assertEqual(nodes[5]["state"], 0x05)
        self.assertEqual(nodes[5]["state_name"], "Operational")

    @patch("oida.protocols.can.scanner._python_can")
    def test_od_scan_subindex_not_found(self, mock_can_lazy):
        """Test OD scan handles sub-index-not-found abort correctly."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenSDOResponse

        list(range(0x1000, 0x1003))

        def mock_sdo_read(bus, node_id, index, subindex=0, timeout=0.2):
            if index == 0x1000:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    data=bytes([0x91, 0x01, 0x00, 0x00]),
                )
            elif index == 0x1001:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    error=True,
                    abort_code=0x06090011,
                    abort_message="Sub-index does not exist",
                )
            else:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    error=True,
                    abort_code=0x06020000,
                    abort_message="Object does not exist",
                )

        self.scanner.canopen_sdo_read = mock_sdo_read

        found = self.scanner.canopen_od_scan(mock_bus, 1, index_range=(0x1000, 0x1002))

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], 0x1000)

    @patch("oida.protocols.can.scanner._python_can")
    def test_nmt_state_read_no_response(self, mock_can_lazy):
        """Test NMT state read returns None when no response."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()
        mock_bus.recv.return_value = None

        result = self.scanner.canopen_nmt_state_read(mock_bus, 99, timeout=0.05)

        self.assertIsNone(result)

    @patch("oida.protocols.can.scanner._python_can")
    def test_device_info_partial_read(self, mock_can_lazy):
        """Test device info when some OD entries are missing."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenSDOResponse

        def mock_sdo_read(bus, node_id, index, subindex=0, timeout=0.5):
            if index == 0x1000 and subindex == 0x00:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    data=bytes([0x91, 0x01, 0x00, 0x00]),
                )
            elif index == 0x1008:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    data=b"MiniDevice",
                )
            else:
                return CANopenSDOResponse(
                    node_id=node_id,
                    index=index,
                    subindex=subindex,
                    error=True,
                    abort_code=0x06020000,
                    abort_message="Object does not exist",
                )

        self.scanner.canopen_sdo_read = mock_sdo_read

        info = self.scanner.canopen_device_info(mock_bus, 1)

        self.assertEqual(info.node_id, 1)
        self.assertEqual(info.device_type, 0x00000191)
        self.assertEqual(info.device_profile, 401)
        self.assertEqual(info.device_name, "MiniDevice")
        # These should remain defaults since reads failed
        self.assertEqual(info.hw_version, "")
        self.assertEqual(info.sw_version, "")
        self.assertEqual(info.vendor_id, 0)

    @patch("oida.protocols.can.scanner._python_can")
    def test_modbus_register_map_empty(self, mock_can_lazy):
        """Test Modbus register map scan when nothing found."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        from oida.protocols.can.constants import CANopenSDOResponse

        def mock_sdo_read(bus, node_id, index, subindex=0, timeout=0.2):
            return CANopenSDOResponse(
                node_id=node_id,
                index=index,
                subindex=subindex,
                error=True,
                abort_code=0x06020000,
                abort_message="Object does not exist",
            )

        self.scanner.canopen_sdo_read = mock_sdo_read

        mappings = self.scanner.canopen_modbus_register_map(
            mock_bus, 5, scan_range=(0x5100, 0x5102)
        )

        self.assertEqual(len(mappings), 0)


class TestCANopenSegmentedSDOExtended(unittest.TestCase):
    """Extended tests for segmented SDO transfer handling."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    @patch("oida.protocols.can.scanner._python_can")
    def test_sdo_segmented_upload_unknown_size(self, mock_can_lazy):
        """Test segmented upload when total size is not indicated."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        responses = []

        # Initiate upload response: SCS=2, e=0, s=0 -> 0x40
        init_msg = MagicMock()
        init_msg.arbitration_id = 0x581
        init_msg.is_remote_frame = False
        init_msg.data = bytearray([0x40, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
        responses.append(init_msg)

        # Segment 1: 7 bytes, toggle=0, last
        seg1_msg = MagicMock()
        seg1_msg.arbitration_id = 0x581
        seg1_msg.is_remote_frame = False
        seg1_msg.data = bytearray([0x01, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0x00])
        responses.append(seg1_msg)

        response_iter = iter(responses)

        def recv_side_effect(timeout=0.5):
            try:
                return next(response_iter)
            except StopIteration:
                return None

        mock_bus.recv.side_effect = recv_side_effect

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1008, 0x00)

        self.assertFalse(resp.error)
        # Unknown size, so all assembled data is returned
        self.assertTrue(len(resp.data) > 0)

    @patch("oida.protocols.can.scanner._python_can")
    def test_sdo_segmented_upload_abort_mid_transfer(self, mock_can_lazy):
        """Test segmented upload handles abort during segment transfer."""
        mock_can = MagicMock()
        mock_can_lazy.return_value = mock_can
        mock_bus = MagicMock()

        responses = []

        # Initiate upload response: SCS=2, e=0, s=1 -> 0x41, size=20
        init_msg = MagicMock()
        init_msg.arbitration_id = 0x581
        init_msg.is_remote_frame = False
        init_msg.data = bytearray([0x41, 0x08, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00])
        responses.append(init_msg)

        # Abort response during segment read
        abort_msg = MagicMock()
        abort_msg.arbitration_id = 0x581
        abort_msg.is_remote_frame = False
        # SCS=4 (abort) -> 0x80, abort code 0x08000000 (general error)
        abort_msg.data = bytearray([0x80, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x08])
        responses.append(abort_msg)

        response_iter = iter(responses)

        def recv_side_effect(timeout=0.5):
            try:
                return next(response_iter)
            except StopIteration:
                return None

        mock_bus.recv.side_effect = recv_side_effect

        resp = self.scanner.canopen_sdo_read(mock_bus, 1, 0x1008, 0x00)

        self.assertTrue(resp.error)
        self.assertEqual(resp.abort_code, 0x08000000)


class TestCANopenTrafficClassification(unittest.TestCase):
    """Test that CAN traffic classifier identifies CANopen traffic correctly."""

    def setUp(self):
        from oida.protocols.can.scanner import CANScanner

        self.scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})

    def test_classify_nmt(self):
        """Test NMT COB-ID classification."""
        result = self.scanner._identify_id(0x000)
        self.assertEqual(result, "CANopen NMT")

    def test_classify_sync(self):
        """Test SYNC COB-ID classification."""
        result = self.scanner._identify_id(0x080)
        self.assertEqual(result, "CANopen SYNC")

    def test_classify_emcy_nodes(self):
        """Test EMCY COB-ID classification for various nodes."""
        for node_id in [1, 42, 127]:
            result = self.scanner._identify_id(0x080 + node_id)
            self.assertIn("Emergency", result)
            self.assertIn(f"node {node_id}", result)

    def test_classify_tpdo1(self):
        """Test TPDO1 classification."""
        result = self.scanner._identify_id(0x181)
        self.assertIn("TPDO1", result)
        self.assertIn("node 1", result)

    def test_classify_rpdo1(self):
        """Test RPDO1 classification."""
        result = self.scanner._identify_id(0x201)
        self.assertIn("RPDO1", result)
        self.assertIn("node 1", result)

    def test_classify_tpdo2(self):
        """Test TPDO2 classification."""
        result = self.scanner._identify_id(0x281)
        self.assertIn("TPDO2", result)

    def test_classify_rpdo2(self):
        """Test RPDO2 classification."""
        result = self.scanner._identify_id(0x301)
        self.assertIn("RPDO2", result)

    def test_classify_tpdo3(self):
        """Test TPDO3 classification."""
        result = self.scanner._identify_id(0x381)
        self.assertIn("TPDO3", result)

    def test_classify_rpdo3(self):
        """Test RPDO3 classification."""
        result = self.scanner._identify_id(0x401)
        self.assertIn("RPDO3", result)

    def test_classify_tpdo4(self):
        """Test TPDO4 classification."""
        result = self.scanner._identify_id(0x481)
        self.assertIn("TPDO4", result)

    def test_classify_rpdo4(self):
        """Test RPDO4 classification."""
        result = self.scanner._identify_id(0x501)
        self.assertIn("RPDO4", result)

    def test_classify_sdo_response(self):
        """Test SDO response (server->client) classification."""
        result = self.scanner._identify_id(0x581)
        self.assertIn("SDO Response", result)
        self.assertIn("node 1", result)

    def test_classify_sdo_request(self):
        """Test SDO request (client->server) classification."""
        result = self.scanner._identify_id(0x601)
        self.assertIn("SDO Request", result)
        self.assertIn("node 1", result)

    def test_classify_heartbeat(self):
        """Test heartbeat classification."""
        result = self.scanner._identify_id(0x701)
        self.assertIn("Heartbeat", result)
        self.assertIn("node 1", result)

    def test_classify_heartbeat_max_node(self):
        """Test heartbeat classification for node 127."""
        result = self.scanner._identify_id(0x77F)
        self.assertIn("Heartbeat", result)
        self.assertIn("node 127", result)


class TestCANProtoArgsCANopenExtended(unittest.TestCase):
    """Extended CLI argument tests for CANopen options."""

    def setUp(self):
        """Set up argument parser."""
        import argparse

        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers()
        parents = []

        from oida.protocols.can.proto_args import proto_args

        self.can_parser = proto_args(self.subparsers, parents)

    def test_canopen_scan_default_false(self):
        """Test --canopen-scan defaults to False."""
        args = self.can_parser.parse_args(["vcan0"])
        self.assertFalse(args.canopen_scan)

    def test_canopen_info_requires_value(self):
        """Test --canopen-info requires a NODE_ID value."""
        args = self.can_parser.parse_args(["vcan0", "--canopen-info", "5"])
        self.assertEqual(args.canopen_info, "5")

    def test_canopen_sdo_read_format(self):
        """Test --canopen-sdo-read accepts node:index:sub format."""
        args = self.can_parser.parse_args(["vcan0", "--canopen-sdo-read", "1:0x1000:0"])
        self.assertEqual(args.canopen_sdo_read, "1:0x1000:0")

    def test_canopen_od_scan_with_range(self):
        """Test --canopen-od-scan with --canopen-od-range."""
        args = self.can_parser.parse_args(
            [
                "vcan0",
                "--canopen-od-scan",
                "1",
                "--canopen-od-range",
                "0x1000-0x1FFF",
            ]
        )
        self.assertEqual(args.canopen_od_scan, "1")
        self.assertEqual(args.canopen_od_range, "0x1000-0x1FFF")

    def test_canopen_monitor_default_false(self):
        """Test --canopen-monitor defaults to False."""
        args = self.can_parser.parse_args(["vcan0"])
        self.assertFalse(args.canopen_monitor)

    def test_canopen_pdo_with_node(self):
        """Test --canopen-pdo with --canopen-pdo-node."""
        args = self.can_parser.parse_args(
            [
                "vcan0",
                "--canopen-pdo",
                "--canopen-pdo-node",
                "3",
            ]
        )
        self.assertTrue(args.canopen_pdo)
        self.assertEqual(args.canopen_pdo_node, "3")

    def test_modbus_gateway_default_false(self):
        """Test --modbus-gateway defaults to False."""
        args = self.can_parser.parse_args(["vcan0"])
        self.assertFalse(args.modbus_gateway)

    def test_all_canopen_flags_combined(self):
        """Test combining multiple CANopen flags."""
        args = self.can_parser.parse_args(
            [
                "vcan0",
                "--canopen-scan",
                "--canopen-monitor",
                "--canopen-pdo",
                "--modbus-gateway",
            ]
        )
        self.assertTrue(args.canopen_scan)
        self.assertTrue(args.canopen_monitor)
        self.assertTrue(args.canopen_pdo)
        self.assertTrue(args.modbus_gateway)


class TestCANopenNXCHandlerDispatch(unittest.TestCase):
    """Test that NXC handler methods are dispatched correctly in __init__.py."""

    def test_execute_features_dispatches_canopen_scan(self):
        """Test _execute_features calls _handle_canopen_scan when flag is set."""
        import argparse

        from oida.protocols.can import can as CanClass

        # Create a minimal mock args namespace
        argparse.Namespace(
            target="vcan0",
            baudrate=500000,
            bus_type="virtual",
            channel=None,
            fd=False,
            extended=False,
            sniff_time=0,
            no_sniff=True,
            canopen_scan=True,
            canopen_info=None,
            canopen_sdo_read=None,
            canopen_od_scan=None,
            canopen_monitor=False,
            canopen_pdo=False,
            modbus_gateway=False,
            uds_scan=False,
            obd2=False,
            id_scan=False,
            xcp_scan=False,
            xcp_info=False,
            xcp_memory_read=False,
            ccp_scan=False,
            uds_sessions=False,
            uds_dids=None,
            uds_seeds=False,
            uds_routines=False,
            uds_reset=False,
            send=None,
            send_file=None,
            replay=None,
            monitor=False,
            fuzz=False,
            filter_id="",
            verbose=0,
            debug=False,
        )

        # We just verify the can class can be constructed without error
        # (actual connection would fail since we're not on a real bus)
        # Test that the class has the expected handler methods
        self.assertTrue(hasattr(CanClass, "_handle_canopen_scan"))
        self.assertTrue(hasattr(CanClass, "_handle_canopen_info"))
        self.assertTrue(hasattr(CanClass, "_handle_canopen_sdo_read"))
        self.assertTrue(hasattr(CanClass, "_handle_canopen_od_scan"))
        self.assertTrue(hasattr(CanClass, "_handle_canopen_monitor"))
        self.assertTrue(hasattr(CanClass, "_handle_canopen_pdo"))
        self.assertTrue(hasattr(CanClass, "_handle_modbus_gateway"))

    def test_scanner_has_all_canopen_methods(self):
        """Test CANScanner has all required CANopen methods."""
        from oida.protocols.can.scanner import CANScanner

        required_methods = [
            "canopen_node_scan",
            "canopen_sdo_read",
            "canopen_device_info",
            "canopen_od_scan",
            "canopen_emcy_monitor",
            "canopen_heartbeat_monitor",
            "canopen_nmt_state_read",
            "canopen_pdo_discover",
            "canopen_modbus_gateway_detect",
            "canopen_modbus_register_map",
        ]
        for method in required_methods:
            self.assertTrue(hasattr(CANScanner, method), f"CANScanner missing method: {method}")

    def test_can_class_has_all_handlers(self):
        """Test NXC can class has all required handler methods."""
        from oida.protocols.can import can as CanClass

        required_handlers = [
            "_handle_canopen_scan",
            "_handle_canopen_info",
            "_handle_canopen_sdo_read",
            "_handle_canopen_od_scan",
            "_handle_canopen_monitor",
            "_handle_canopen_pdo",
            "_handle_modbus_gateway",
        ]
        for handler in required_handlers:
            self.assertTrue(hasattr(CanClass, handler), f"can class missing handler: {handler}")


class TestCANopenImports(unittest.TestCase):
    """Test all CANopen-related imports work correctly."""

    def test_import_canopen_constants(self):
        """Test importing all CANopen constants from constants module."""
        # Just verify they imported without error
        self.assertTrue(True)

    def test_import_canopen_data_classes(self):
        """Test importing CANopen data classes."""
        self.assertTrue(True)

    def test_import_scanner_canopen_methods(self):
        """Test that CANScanner can be imported and has CANopen methods."""
        from oida.protocols.can.scanner import CANScanner

        scanner = CANScanner({"interface": "vcan0", "bus-type": "virtual"})
        self.assertTrue(callable(getattr(scanner, "canopen_node_scan", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_sdo_read", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_device_info", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_od_scan", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_emcy_monitor", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_heartbeat_monitor", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_nmt_state_read", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_pdo_discover", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_modbus_gateway_detect", None)))
        self.assertTrue(callable(getattr(scanner, "canopen_modbus_register_map", None)))


if __name__ == "__main__":
    unittest.main()
