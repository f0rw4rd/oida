#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for IEC 104 NXC-style connection (nxc_connection.py).

Tests class structure, dependency checks, connection creation, enumeration,
scan execution, cleanup, and error handling paths.
"""

import unittest
from unittest.mock import Mock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers for building a mock iec104() instance without triggering proto_flow
# ---------------------------------------------------------------------------


def _make_iec104_instance(**overrides):
    """Build an iec104 NXC instance with proto_flow disabled.

    Since iec104.__init__ calls super().__init__ which calls proto_flow()
    automatically, we patch proto_flow and NetworkConnection.__init__
    to avoid any real initialization.
    """
    with patch("oida.protocols.iec104.nxc_connection.iec104.proto_flow"):
        with patch(
            "oida.protocols.iec104.nxc_connection.NetworkConnection.__init__",
            return_value=None,
        ):
            from oida.protocols.iec104.nxc_connection import iec104 as IEC104Class

            obj = IEC104Class.__new__(IEC104Class)
            obj.protocol_name = "IEC 104"
            obj.default_port = 2404
            obj.conn = None
            obj.args = Mock()
            obj.args.tls = False
            obj.args.port = 2404
            obj.args.timeout = 5
            obj.db = None
            obj.host = "192.168.1.100"
            obj.ip = "192.168.1.100"
            obj.logger = Mock()
            obj.results = {"data": {}, "success": False}
            obj.scanner = Mock()
            obj.scanner.common_address = 1

            for key, val in overrides.items():
                setattr(obj, key, val)
            return obj


class TestIEC104ClassStructure(unittest.TestCase):
    """Verify the iec104 NXC class has required methods and attributes."""

    def setUp(self):
        from oida.protocols.iec104.nxc_connection import iec104 as IEC104Class

        self.cls = IEC104Class

    def test_inherits_network_connection(self):
        from oida.connection import NetworkConnection

        self.assertTrue(issubclass(self.cls, NetworkConnection))

    def test_has_proto_flow(self):
        self.assertTrue(hasattr(self.cls, "proto_flow"))

    def test_has_create_conn_obj(self):
        self.assertTrue(hasattr(self.cls, "create_conn_obj"))

    def test_has_enum_host_info(self):
        self.assertTrue(hasattr(self.cls, "enum_host_info"))

    def test_has_print_host_info(self):
        self.assertTrue(hasattr(self.cls, "print_host_info"))

    def test_has_cleanup(self):
        self.assertTrue(hasattr(self.cls, "cleanup"))

    def test_has_check_dependencies(self):
        self.assertTrue(hasattr(self.cls, "check_dependencies"))

    def test_has_execute_scan(self):
        self.assertTrue(hasattr(self.cls, "_execute_scan"))

    def test_check_dependencies_is_static(self):
        """check_dependencies should be a staticmethod."""
        self.assertIsInstance(self.cls.__dict__["check_dependencies"], staticmethod)


class TestIEC104InitAttributes(unittest.TestCase):
    """Verify initial attribute defaults set in __init__."""

    def test_protocol_name(self):
        obj = _make_iec104_instance()
        self.assertEqual(obj.protocol_name, "IEC 104")

    def test_default_port(self):
        obj = _make_iec104_instance()
        self.assertEqual(obj.default_port, 2404)


class TestCheckDependencies(unittest.TestCase):
    """Tests for iec104.check_dependencies()"""

    def test_available(self):
        """When c104 is available, check_dependencies returns True."""
        with patch("oida.protocols.iec104.nxc_connection._c104") as mock_lazy:
            type(mock_lazy).is_available = PropertyMock(return_value=True)
            from oida.protocols.iec104.nxc_connection import iec104 as IEC104Class

            self.assertTrue(IEC104Class.check_dependencies())

    def test_unavailable(self):
        """When c104 is not available, check_dependencies returns False."""
        with patch("oida.protocols.iec104.nxc_connection._c104") as mock_lazy:
            type(mock_lazy).is_available = PropertyMock(return_value=False)
            from oida.protocols.iec104.nxc_connection import iec104 as IEC104Class

            self.assertFalse(IEC104Class.check_dependencies())


class TestCreateConnObj(unittest.TestCase):
    """Tests for create_conn_obj()"""

    def test_successful_connection_tcp(self):
        """When scanner.connect() succeeds via TCP, conn is set and success logged."""
        obj = _make_iec104_instance()
        obj.args.tls = False
        mock_conn = Mock()
        obj.scanner.connect.return_value = mock_conn

        obj.create_conn_obj()

        self.assertIs(obj.conn, mock_conn)
        obj.logger.success.assert_called_once()
        call_str = str(obj.logger.success.call_args)
        self.assertIn("TCP", call_str)
        self.assertIn("CA=1", call_str)

    def test_successful_connection_tls(self):
        """When TLS is enabled, success message should mention TLS."""
        obj = _make_iec104_instance()
        obj.args.tls = True
        mock_conn = Mock()
        obj.scanner.connect.return_value = mock_conn

        obj.create_conn_obj()

        self.assertIs(obj.conn, mock_conn)
        obj.logger.success.assert_called_once()
        call_str = str(obj.logger.success.call_args)
        self.assertIn("TLS", call_str)

    def test_failed_connection(self):
        """When scanner.connect() returns None, conn stays None and failure logged."""
        obj = _make_iec104_instance()
        obj.scanner.connect.return_value = None

        obj.create_conn_obj()

        self.assertIsNone(obj.conn)
        obj.logger.fail.assert_called_once()

    def test_tls_detection_via_getattr_default(self):
        """When args has no tls attribute, should default to TCP (no exception)."""
        obj = _make_iec104_instance()
        del obj.args.tls  # Remove tls attr so getattr falls back to False
        mock_conn = Mock()
        obj.scanner.connect.return_value = mock_conn

        obj.create_conn_obj()

        call_str = str(obj.logger.success.call_args)
        self.assertIn("TCP", call_str)


class TestEnumHostInfo(unittest.TestCase):
    """Tests for enum_host_info()"""

    def test_no_conn_returns_early(self):
        """When conn is None, should return without doing anything."""
        obj = _make_iec104_instance()
        obj.conn = None

        obj.enum_host_info()

        self.assertEqual(obj.results["data"], {})
        obj.scanner.get_server_info.assert_not_called()

    def test_successful_enum(self):
        """When _get_server_info succeeds, results should be populated."""
        obj = _make_iec104_instance()
        mock_conn = Mock()
        obj.conn = mock_conn
        server_info = {
            "connected": True,
            "stations": [{"common_address": 1, "type_ids": [1, 3, 13]}],
        }
        obj.scanner.get_server_info.return_value = server_info

        obj.enum_host_info()

        self.assertEqual(obj.results["data"]["device_info"], server_info)
        obj.scanner.get_server_info.assert_called_once_with(mock_conn)

    def test_enum_exception_handled(self):
        """When _get_server_info raises, should log warning and store error info."""
        obj = _make_iec104_instance()
        mock_conn = Mock()
        obj.conn = mock_conn
        obj.scanner.get_server_info.side_effect = Exception("Connection reset")

        obj.enum_host_info()

        obj.logger.warning.assert_called_once()
        device_info = obj.results["data"]["device_info"]
        self.assertTrue(device_info["connected"])
        self.assertEqual(device_info["enum_error"], "Connection reset")


class TestPrintHostInfo(unittest.TestCase):
    """Tests for print_host_info()"""

    def test_displays_transport(self):
        """print_host_info should display transport type."""
        obj = _make_iec104_instance()
        obj.args.quiet = False
        obj.scanner.use_tls = False
        obj.scanner._lock = __import__("threading").Lock()
        obj.scanner._discovered_stations = set()
        obj.scanner._discovered_points = {}
        obj.scanner._raw_type_ids = set()
        obj.results["data"]["device_info"] = {"connected": True}

        obj.print_host_info()

        calls = [str(c) for c in obj.logger.display.call_args_list]
        self.assertTrue(any("Transport: TCP" in c for c in calls))

    def test_quiet_suppresses_output(self):
        """When quiet=True, print_host_info should not display anything."""
        obj = _make_iec104_instance()
        obj.args.quiet = True
        obj.results["data"]["device_info"] = {"connected": True}

        obj.print_host_info()

        obj.logger.display.assert_not_called()

    def test_shows_common_address(self):
        """print_host_info should show common address."""
        obj = _make_iec104_instance()
        obj.args.quiet = False
        obj.scanner.use_tls = False
        obj.scanner.common_address = 1
        obj.scanner._lock = __import__("threading").Lock()
        obj.scanner._discovered_stations = set()
        obj.scanner._discovered_points = {}
        obj.scanner._raw_type_ids = set()
        obj.results["data"]["device_info"] = {}

        obj.print_host_info()

        calls = [str(c) for c in obj.logger.display.call_args_list]
        self.assertTrue(any("Common Address: 1" in c for c in calls))


class TestExecuteScan(unittest.TestCase):
    """Tests for _execute_scan()"""

    def test_no_conn_returns_early(self):
        """When conn is None, should return without scanning."""
        obj = _make_iec104_instance()
        obj.conn = None

        obj._execute_scan()

        obj.scanner.discover.assert_not_called()
        self.assertNotIn("scan_results", obj.results["data"])

    def test_successful_scan(self):
        """When discover succeeds, results should be stored."""
        obj = _make_iec104_instance()
        mock_conn = Mock()
        obj.conn = mock_conn
        scan_results = {
            "type_ids": {1: "M_SP_NA_1", 13: "M_ME_NC_1"},
            "station_count": 1,
        }
        obj.scanner.discover.return_value = scan_results

        obj._execute_scan()

        obj.scanner.discover.assert_called_once_with(mock_conn)
        self.assertEqual(obj.results["data"]["scan_results"], scan_results)

    def test_scan_results_stored_in_results(self):
        """Scan results should be stored under results['data']['scan_results']."""
        obj = _make_iec104_instance()
        obj.conn = Mock()
        expected = {"type_ids": {30: "M_SP_TB_1"}}
        obj.scanner.discover.return_value = expected

        obj._execute_scan()

        self.assertIs(obj.results["data"]["scan_results"], expected)


class TestCleanup(unittest.TestCase):
    """Tests for cleanup()"""

    def test_disconnects_connection(self):
        """When conn exists, cleanup should call scanner.disconnect."""
        obj = _make_iec104_instance()
        mock_conn = Mock()
        obj.conn = mock_conn

        obj.cleanup()

        obj.scanner.disconnect.assert_called_once_with(mock_conn)
        obj.logger.debug.assert_called()

    def test_no_connection(self):
        """When conn is None, cleanup should not call disconnect."""
        obj = _make_iec104_instance()
        obj.conn = None

        obj.cleanup()

        obj.scanner.disconnect.assert_not_called()

    def test_disconnect_exception_handled(self):
        """Exception during disconnect should be caught and logged."""
        obj = _make_iec104_instance()
        obj.conn = Mock()
        obj.scanner.disconnect.side_effect = Exception("disconnect error")

        # Should not raise
        obj.cleanup()
        obj.logger.debug.assert_called()

    def test_stop_listen_signal(self):
        """When scanner has _stop_listen, cleanup should set it."""
        obj = _make_iec104_instance()
        obj.conn = Mock()
        mock_stop = Mock()
        obj.scanner._stop_listen = mock_stop

        obj.cleanup()

        mock_stop.set.assert_called_once()

    def test_no_stop_listen_attribute(self):
        """When scanner has no _stop_listen, cleanup should still work."""
        obj = _make_iec104_instance()
        obj.conn = Mock()
        # Remove _stop_listen from scanner mock
        del obj.scanner._stop_listen

        # Should not raise
        obj.cleanup()
        obj.scanner.disconnect.assert_called_once()

    def test_cleanup_without_scanner(self):
        """When scanner attribute doesn't exist, cleanup should not raise."""
        obj = _make_iec104_instance()
        obj.conn = Mock()
        del obj.scanner

        # Should not raise (hasattr checks protect both _stop_listen and disconnect)
        obj.cleanup()


class TestProtoFlow(unittest.TestCase):
    """Tests for proto_flow() integration."""

    def test_full_flow_success(self):
        """proto_flow should call all steps in order when connection succeeds."""
        obj = _make_iec104_instance()
        obj.proto_logger = Mock()
        obj._convert_args_to_dict = Mock(return_value={"rhost": "192.168.1.100"})

        mock_conn = Mock()
        mock_scanner_cls = Mock()
        mock_scanner_inst = Mock()
        mock_scanner_inst.connect.return_value = mock_conn
        mock_scanner_inst.common_address = 1
        mock_scanner_inst.get_server_info.return_value = {"connected": True}
        mock_scanner_inst.discover.return_value = {"type_ids": {}}
        mock_scanner_cls.return_value = mock_scanner_inst

        with patch("oida.protocols.iec104.nxc_connection.IEC104Scanner", mock_scanner_cls):
            obj.proto_flow()

        # proto_logger is now called by connection.__init__, not proto_flow.
        # Test only the proto_flow contract.
        obj._convert_args_to_dict.assert_called_once()
        mock_scanner_cls.assert_called_once_with({"rhost": "192.168.1.100"})
        # Connection should have been established
        self.assertIs(obj.conn, mock_conn)

    def test_flow_stops_on_connection_failure(self):
        """When create_conn_obj leaves conn=None, flow should set failure and return."""
        obj = _make_iec104_instance()
        obj.proto_logger = Mock()
        obj._convert_args_to_dict = Mock(return_value={"rhost": "192.168.1.100"})

        mock_scanner_inst = Mock()
        mock_scanner_inst.connect.return_value = None

        with patch(
            "oida.protocols.iec104.nxc_connection.IEC104Scanner",
            return_value=mock_scanner_inst,
        ):
            obj.proto_flow()

        self.assertFalse(obj.results["success"])
        self.assertEqual(obj.results["error"], "Connection failed")
        # enum_host_info should not be called since conn is None
        mock_scanner_inst.get_server_info.assert_not_called()

    def test_flow_creates_scanner_with_args_dict(self):
        """proto_flow should pass _convert_args_to_dict result to IEC104Scanner."""
        obj = _make_iec104_instance()
        obj.proto_logger = Mock()
        args_dict = {"rhost": "10.0.0.1", "rport": 2404, "timeout": 10}
        obj._convert_args_to_dict = Mock(return_value=args_dict)

        mock_scanner_inst = Mock()
        mock_scanner_inst.connect.return_value = None

        with patch(
            "oida.protocols.iec104.nxc_connection.IEC104Scanner",
            return_value=mock_scanner_inst,
        ) as mock_cls:
            obj.proto_flow()

        mock_cls.assert_called_once_with(args_dict)


class TestProtoFlowViaInit(unittest.TestCase):
    """Test that proto_flow is triggered via __init__ (NXC pattern)."""

    @patch("oida.protocols.iec104.nxc_connection.IEC104Scanner")
    @patch("oida.protocols.iec104.nxc_connection.NetworkConnection.__init__")
    def test_init_calls_super(self, mock_super_init, mock_scanner_cls):
        """__init__ should set attributes then call super().__init__."""
        mock_super_init.return_value = None

        from oida.protocols.iec104.nxc_connection import iec104 as IEC104Class

        args = Mock()
        db = Mock()
        host = "192.168.1.100"

        instance = IEC104Class(args, db, host)

        self.assertEqual(instance.protocol_name, "IEC 104")
        self.assertEqual(instance.default_port, 2404)
        mock_super_init.assert_called_once_with(args, db, host)


class TestConvertArgsToDict(unittest.TestCase):
    """Test _convert_args_to_dict integration with proto_flow."""

    def test_args_dict_includes_host(self):
        """_convert_args_to_dict should include rhost from self.ip."""
        obj = _make_iec104_instance()
        obj.ip = "10.0.0.5"
        obj.args.port = 2404
        obj.args.timeout = 10

        result = obj._convert_args_to_dict()

        self.assertEqual(result["rhost"], "10.0.0.5")
        self.assertEqual(result["rport"], 2404)


class TestEdgeCases(unittest.TestCase):
    """Edge cases and error boundary tests."""

    def test_enum_after_successful_connect(self):
        """Full enum_host_info -> _execute_scan sequence with valid conn."""
        obj = _make_iec104_instance()
        mock_conn = Mock()
        obj.conn = mock_conn

        server_info = {"connected": True, "stations": []}
        obj.scanner.get_server_info.return_value = server_info
        scan_results = {"type_ids": {1: "M_SP_NA_1"}, "station_count": 1}
        obj.scanner.discover.return_value = scan_results

        obj.enum_host_info()
        obj._execute_scan()

        self.assertEqual(obj.results["data"]["device_info"], server_info)
        self.assertEqual(obj.results["data"]["scan_results"], scan_results)

    def test_cleanup_idempotent(self):
        """Calling cleanup twice should not raise."""
        obj = _make_iec104_instance()
        obj.conn = Mock()

        obj.cleanup()
        # After first cleanup, conn is still set (cleanup doesn't clear it)
        obj.cleanup()

        self.assertEqual(obj.scanner.disconnect.call_count, 2)

    def test_create_conn_obj_debug_log_tcp(self):
        """create_conn_obj should log debug with transport type."""
        obj = _make_iec104_instance()
        obj.args.tls = False
        obj.scanner.connect.return_value = Mock()

        obj.create_conn_obj()

        debug_calls = [str(c) for c in obj.logger.debug.call_args_list]
        tcp_logged = any("TCP" in c for c in debug_calls)
        self.assertTrue(tcp_logged)

    def test_create_conn_obj_debug_log_tls(self):
        """create_conn_obj should log debug with TLS transport."""
        obj = _make_iec104_instance()
        obj.args.tls = True
        obj.scanner.connect.return_value = Mock()

        obj.create_conn_obj()

        debug_calls = [str(c) for c in obj.logger.debug.call_args_list]
        tls_logged = any("TLS" in c for c in debug_calls)
        self.assertTrue(tls_logged)


if __name__ == "__main__":
    unittest.main()
