#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for ADS NXC-style connection (cli_runner.py) and ADS constants.

Tests class structure, dependency checks, operation dispatch, individual
operation methods, cleanup, and constant data integrity.
"""

import unittest
from unittest.mock import Mock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers for building a mock ads() instance without triggering proto_flow
# ---------------------------------------------------------------------------


def _make_ads_instance(**overrides):
    """Build an ads NXC instance with proto_flow disabled.

    Since ads.__init__ calls super().__init__ which calls proto_flow()
    automatically, we patch proto_flow and NetworkConnection.__init__
    to avoid any real initialization.
    """
    with patch("oida.protocols.ads.cli_runner.ads.proto_flow"):
        with patch("oida.protocols.ads.cli_runner.NetworkConnection.__init__", return_value=None):
            from oida.protocols.ads.cli_runner import ads as AdsClass

            obj = AdsClass.__new__(AdsClass)
            obj.protocol_name = "ADS"
            obj.default_port = 48898
            obj.conn = None
            # create_conn_obj()'s GH #59 probe reads args.port/args.timeout as
            # numbers - a bare Mock() raises TypeError in int()/float().
            obj.args = Mock(port=48898, timeout=2)
            obj.db = None
            obj.host = "192.168.1.100"
            obj.ip = "192.168.1.100"
            obj.logger = Mock()
            obj.results = {"data": {}, "success": False, "port": 48898}
            obj.scanner = Mock()

            for key, val in overrides.items():
                setattr(obj, key, val)
            return obj


class TestAdsClassStructure(unittest.TestCase):
    """Verify the ads NXC class has required methods and attributes."""

    def setUp(self):
        from oida.protocols.ads.cli_runner import ads as AdsClass

        self.cls = AdsClass

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

    def test_has_execute_operations(self):
        self.assertTrue(hasattr(self.cls, "_execute_operations"))

    def test_has_default_summary(self):
        self.assertTrue(hasattr(self.cls, "_default_summary"))

    def test_has_show_state(self):
        self.assertTrue(hasattr(self.cls, "_show_state"))

    def test_has_list_symbols(self):
        self.assertTrue(hasattr(self.cls, "_list_symbols"))

    def test_has_scan_ports(self):
        self.assertTrue(hasattr(self.cls, "_scan_ports"))

    def test_check_dependencies_is_static(self):
        """check_dependencies should be a staticmethod."""
        self.assertIsInstance(self.cls.__dict__["check_dependencies"], staticmethod)


class TestCheckDependencies(unittest.TestCase):
    """Tests for ads.check_dependencies()"""

    def test_available(self):
        """When pyads is available, check_dependencies returns True."""
        with patch("oida.protocols.ads.cli_runner._pyads") as mock_lazy:
            type(mock_lazy).is_available = PropertyMock(return_value=True)
            from oida.protocols.ads.cli_runner import ads as AdsClass

            self.assertTrue(AdsClass.check_dependencies())

    def test_unavailable(self):
        """When pyads is not available, check_dependencies returns False."""
        with patch("oida.protocols.ads.cli_runner._pyads") as mock_lazy:
            type(mock_lazy).is_available = PropertyMock(return_value=False)
            from oida.protocols.ads.cli_runner import ads as AdsClass

            self.assertFalse(AdsClass.check_dependencies())


class TestCreateConnObj(unittest.TestCase):
    """Tests for create_conn_obj()"""

    def test_successful_connection(self):
        obj = _make_ads_instance()
        obj.scanner.connect.return_value = Mock()

        obj.create_conn_obj()

        self.assertIsNotNone(obj.conn)
        obj.logger.success.assert_called()

    def test_failed_connection(self):
        obj = _make_ads_instance()
        obj.scanner.connect.return_value = None

        obj.create_conn_obj()

        self.assertIsNone(obj.conn)
        obj.logger.fail.assert_called()


class TestEnumHostInfo(unittest.TestCase):
    """Tests for enum_host_info()"""

    def test_no_conn_returns_early(self):
        """When conn is None, should return without doing anything."""
        obj = _make_ads_instance()
        obj.conn = None
        obj.enum_host_info()
        # No exception, no data populated
        self.assertEqual(obj.results["data"], {})

    def test_successful_enum(self):
        """When device info and state succeed, results should be populated."""
        obj = _make_ads_instance()
        mock_conn = Mock()
        obj.conn = mock_conn

        mock_version = Mock()
        mock_version.version = 3
        mock_version.revision = 1
        mock_version.build = 4024
        mock_conn.read_device_info.return_value = ("TwinCAT PLC", mock_version)
        mock_conn.read_state.return_value = (5, 0)

        obj.enum_host_info()

        device_info = obj.results["data"]["device_info"]
        self.assertEqual(device_info["name"], "TwinCAT PLC")
        self.assertEqual(device_info["version"], "3.1.4024")

        state_info = obj.results["data"]["state"]
        self.assertEqual(state_info["ads_state"], 5)
        self.assertEqual(state_info["ads_state_name"], "RUN")

    def test_device_info_fails_gracefully(self):
        """If read_device_info raises, should log debug and continue."""
        obj = _make_ads_instance()
        mock_conn = Mock()
        obj.conn = mock_conn
        mock_conn.read_device_info.side_effect = Exception("ADS timeout")
        mock_conn.set_timeout = Mock()

        obj.enum_host_info()

        obj.logger.debug.assert_called()
        self.assertNotIn("device_info", obj.results["data"])


class TestPrintHostInfo(unittest.TestCase):
    """Tests for print_host_info()"""

    def test_displays_device_name(self):
        obj = _make_ads_instance()
        obj.args.quiet = False
        obj.results["data"]["device_info"] = {
            "name": "TestPLC",
            "version": "3.1.4024",
        }
        obj.results["data"]["state"] = {
            "ads_state": 5,
            "ads_state_name": "RUN",
        }

        obj.print_host_info()

        # Should have called display at least twice (device + state)
        self.assertGreaterEqual(obj.logger.display.call_count, 2)

    def test_quiet_mode_suppresses(self):
        obj = _make_ads_instance()
        obj.args.quiet = True
        obj.results["data"]["device_info"] = {"name": "TestPLC", "version": "1.0"}

        obj.print_host_info()

        obj.logger.display.assert_not_called()

    def test_no_device_info(self):
        """When no device info, display should not be called for device."""
        obj = _make_ads_instance()
        obj.args.quiet = False

        obj.print_host_info()

        obj.logger.display.assert_not_called()


class TestExecuteOperations(unittest.TestCase):
    """Tests for _execute_operations() dispatch."""

    def _setup_args(self, **flags):
        """Build an ads instance where all CLI flags default to False/None."""
        obj = _make_ads_instance()
        obj.conn = Mock()

        # Set all known flags to their default (False/None)
        all_flags = [
            "state",
            "set_state",
            "list_symbols",
            "enumerate_symbols",
            "read_symbol",
            "write_symbol",
            "memory_read",
            "memory_write",
            "test_memory",
            "scan_ports",
            "scan_ports_extended",
            "scan_routes",
            "target_desc",
            "check_secure",
            "udp_discovery",
            "license_info",
            "io_devices",
            "list_files",
            "read_file",
            "read_registry",
            "download_program",
            "scan_ethercat",
            "scan_coe",
            "scan_coe_access",
            "read_coe",
            "write_coe",
            "eeprom_dump",
            "fuzz_coe",
            "esc_registers",
            "foe_read",
            "scan_foe",
            "foe_list",
            "foe_write",
            "foe_delete",
            "scan_soe",
            "read_soe",
            "scan_fsoe",
            "add_route",
            "fuzz",
            "test_write",
            "task_info",
            "watch",
            "device_info",
            "confirm",
            "coe_range",
            "symbol_filter",
        ]
        for flag in all_flags:
            setattr(
                obj.args,
                flag,
                False
                if flag
                not in (
                    "set_state",
                    "read_symbol",
                    "write_symbol",
                    "memory_read",
                    "memory_write",
                    "list_files",
                    "read_file",
                    "read_registry",
                    "read_coe",
                    "write_coe",
                    "foe_read",
                    "foe_list",
                    "foe_write",
                    "foe_delete",
                    "read_soe",
                    "add_route",
                    "fuzz",
                    "watch",
                    "coe_range",
                    "symbol_filter",
                )
                else None,
            )

        for key, val in flags.items():
            setattr(obj.args, key, val)

        return obj

    def test_no_flags_calls_default_summary(self):
        obj = self._setup_args()
        obj._default_summary = Mock()
        obj._execute_operations()
        obj._default_summary.assert_called_once()

    def test_state_flag_calls_show_state(self):
        obj = self._setup_args(state=True)
        obj._show_state = Mock()
        obj._default_summary = Mock()
        obj._execute_operations()
        obj._show_state.assert_called_once()

    def test_list_symbols_flag(self):
        obj = self._setup_args(list_symbols=True)
        obj._list_symbols = Mock()
        obj._default_summary = Mock()
        obj._execute_operations()
        obj._list_symbols.assert_called_once()

    def test_scan_ports_flag(self):
        obj = self._setup_args(scan_ports=True)
        obj._scan_ports = Mock()
        obj._default_summary = Mock()
        obj._execute_operations()
        obj._scan_ports.assert_called_once_with(extended=False)

    def test_scan_ports_extended_flag(self):
        obj = self._setup_args(scan_ports_extended=True)
        obj._scan_ports = Mock()
        obj._default_summary = Mock()
        obj._execute_operations()
        obj._scan_ports.assert_called_once_with(extended=True)

    def test_no_conn_returns_early(self):
        obj = self._setup_args(state=True)
        obj.conn = None
        obj._show_state = Mock()
        obj._execute_operations()
        obj._show_state.assert_not_called()

    def test_coe_range_warning_without_coe_op(self):
        """--coe-range without a CoE operation should trigger a warning."""
        obj = self._setup_args(coe_range="0x1000-0x1FFF")
        obj._default_summary = Mock()
        obj._execute_operations()
        obj.logger.warning.assert_called()

    def test_write_coe_requires_confirm(self):
        """--write-coe without --confirm should fail."""
        obj = self._setup_args(write_coe="0x1008:0:0x42", confirm=False)
        obj._write_coe_nxc = Mock()
        obj._default_summary = Mock()
        obj._execute_operations()
        obj.logger.fail.assert_called()
        obj._write_coe_nxc.assert_not_called()


class TestShowState(unittest.TestCase):
    """Tests for _show_state()"""

    def test_plc_state_success(self):
        """When read_state succeeds, display PLC state."""
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.conn.read_state.return_value = (5, 0)

        obj._show_state()

        # Should display PLC state info
        self.assertTrue(obj.logger.display.called)
        display_calls = [str(c) for c in obj.logger.display.call_args_list]
        state_shown = any("RUN" in c for c in display_calls)
        self.assertTrue(state_shown)

    @patch("oida.protocols.ads.cli_runner._get_pyads")
    @patch("oida.protocols.ads.cli_runner._read_raw")
    def test_ethercat_fallback(self, mock_read_raw, mock_get_pyads):
        """When read_state fails, fall back to EtherCAT master state."""
        import struct

        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.conn.read_state.side_effect = Exception("ADS timeout")

        mock_pyads = Mock()
        mock_get_pyads.return_value = mock_pyads
        mock_master_conn = Mock()
        mock_pyads.Connection.return_value = mock_master_conn

        # Return AL state data (2 bytes, LE uint16 = 8 = OP)
        mock_read_raw.return_value = struct.pack("<H", 8)

        obj._show_state()

        # EtherCAT state should be displayed
        self.assertTrue(obj.logger.display.called)


class TestListSymbols(unittest.TestCase):
    """Tests for _list_symbols()"""

    def test_lists_symbols(self):
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.args.symbol_filter = None
        obj.scanner.max_symbols = 100

        sym1 = Mock()
        sym1.name = "MAIN.Var1"
        sym1.symbol_type = "INT"
        sym2 = Mock()
        sym2.name = "MAIN.Var2"
        sym2.symbol_type = "BOOL"
        obj.conn.get_all_symbols.return_value = [sym1, sym2]

        obj._list_symbols()

        self.assertTrue(obj.logger.display.called)
        display_text = " ".join(str(c) for c in obj.logger.display.call_args_list)
        self.assertIn("MAIN.Var1", display_text)
        self.assertIn("MAIN.Var2", display_text)

    def test_exception_handling(self):
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.conn.get_all_symbols.side_effect = Exception("Symbol table error")
        obj.args.symbol_filter = None

        obj._list_symbols()

        obj.logger.fail.assert_called()


class TestScanPorts(unittest.TestCase):
    """Tests for _scan_ports()"""

    @patch("oida.protocols.ads.cli_runner._get_pyads")
    @patch("oida.protocols.ads.cli_runner._probe_netid")
    @patch("oida.protocols.ads.cli_runner.ProgressTracker")
    def test_basic_scan_uses_port_map(self, mock_progress, mock_probe, mock_get_pyads):
        """Non-extended scan should use ADS_PORT_MAP (fewer ports)."""

        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.args.output = None
        obj.args.format = "console"

        mock_probe.return_value = {"active": False, "type": "none", "detail": "timeout"}

        obj._scan_ports(extended=False)

        # display should be called for the header
        self.assertTrue(obj.logger.display.called)
        header_call = str(obj.logger.display.call_args_list[0])
        self.assertIn("common", header_call)

    @patch("oida.protocols.ads.cli_runner._get_pyads")
    @patch("oida.protocols.ads.cli_runner._probe_netid")
    @patch("oida.protocols.ads.cli_runner.ProgressTracker")
    def test_extended_scan_uses_service_ports(self, mock_progress, mock_probe, mock_get_pyads):
        """Extended scan should use AMS_SERVICE_PORTS (all ports)."""
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.args.output = None
        obj.args.format = "console"

        mock_probe.return_value = {"active": False, "type": "none", "detail": "timeout"}

        obj._scan_ports(extended=True)

        header_call = str(obj.logger.display.call_args_list[0])
        self.assertIn("extended", header_call)


class TestCleanup(unittest.TestCase):
    """Tests for cleanup()"""

    def test_disconnects_connection(self):
        obj = _make_ads_instance()
        mock_conn = Mock()
        obj.conn = mock_conn

        obj.cleanup()

        obj.scanner.disconnect.assert_called_once_with(mock_conn)

    def test_no_connection(self):
        """When no connection exists, cleanup should not raise."""
        obj = _make_ads_instance()
        obj.conn = None

        obj.cleanup()

        obj.scanner.disconnect.assert_not_called()

    def test_disconnect_exception_handled(self):
        """Exception during disconnect should be caught."""
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.scanner.disconnect.side_effect = Exception("disconnect error")

        # Should not raise
        obj.cleanup()
        obj.logger.debug.assert_called()


class TestDefaultSummary(unittest.TestCase):
    """Tests for _default_summary()"""

    @patch("oida.protocols.ads.cli_runner._probe_netid")
    @patch("oida.protocols.ads.cli_runner._get_pyads")
    @patch("oida.protocols.ads.cli_runner._read_raw")
    def test_active_probe_when_no_device_info(self, mock_read_raw, mock_get_pyads, mock_probe):
        """When device_info is empty, should run _probe_netid."""
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.results["data"] = {}  # No device_info

        mock_probe.return_value = {
            "active": True,
            "type": "ethercat",
            "detail": "CoE SDO accessible",
        }
        # Symbol count probe
        mock_read_raw.side_effect = Exception("not available")
        # Suppress UDP discovery
        obj.scanner._udp_discovery.side_effect = Exception("no UDP")
        obj.scanner._check_secure_ads.side_effect = Exception("no TLS")

        obj._default_summary()

        mock_probe.assert_called_once()
        obj.logger.display.assert_called()

    @patch("oida.protocols.ads.cli_runner._probe_netid")
    @patch("oida.protocols.ads.cli_runner._get_pyads")
    @patch("oida.protocols.ads.cli_runner._read_raw")
    def test_inactive_probe_shows_failure(self, mock_read_raw, mock_get_pyads, mock_probe):
        """When probe is inactive, show fail message."""
        obj = _make_ads_instance()
        obj.conn = Mock()
        obj.results["data"] = {}

        mock_probe.return_value = {
            "active": False,
            "type": "none",
            "detail": "timeout",
        }

        obj._default_summary()

        obj.logger.fail.assert_called()


# ---------------------------------------------------------------------------
# Constants validation
# ---------------------------------------------------------------------------


class TestADSConstants(unittest.TestCase):
    """Validate ADS constant data structures."""

    def test_ads_commands_is_dict(self):
        from oida.protocols.ads.constants import ADS_COMMANDS

        self.assertIsInstance(ADS_COMMANDS, dict)
        self.assertGreater(len(ADS_COMMANDS), 0)

    def test_ads_commands_keys_are_int(self):
        from oida.protocols.ads.constants import ADS_COMMANDS

        for key in ADS_COMMANDS:
            self.assertIsInstance(key, int)

    def test_ads_commands_values_are_str(self):
        from oida.protocols.ads.constants import ADS_COMMANDS

        for val in ADS_COMMANDS.values():
            self.assertIsInstance(val, str)

    def test_write_command_ids_is_frozenset(self):
        from oida.protocols.ads.constants import WRITE_COMMAND_IDS

        self.assertIsInstance(WRITE_COMMAND_IDS, frozenset)
        self.assertIn(0x0003, WRITE_COMMAND_IDS)  # Write
        self.assertIn(0x0005, WRITE_COMMAND_IDS)  # WriteControl
        self.assertIn(0x0009, WRITE_COMMAND_IDS)  # ReadWrite

    def test_read_command_ids_is_frozenset(self):
        from oida.protocols.ads.constants import READ_COMMAND_IDS

        self.assertIsInstance(READ_COMMAND_IDS, frozenset)
        self.assertIn(0x0001, READ_COMMAND_IDS)  # ReadDeviceInfo
        self.assertIn(0x0002, READ_COMMAND_IDS)  # Read
        self.assertIn(0x0004, READ_COMMAND_IDS)  # ReadState

    def test_write_and_read_disjoint(self):
        """Write and read command sets should not overlap."""
        from oida.protocols.ads.constants import WRITE_COMMAND_IDS, READ_COMMAND_IDS

        self.assertEqual(len(WRITE_COMMAND_IDS & READ_COMMAND_IDS), 0)

    def test_ads_idx_grp_keys_are_strings(self):
        from oida.protocols.ads.constants import ADS_IDX_GRP

        self.assertIsInstance(ADS_IDX_GRP, dict)
        for key in ADS_IDX_GRP:
            self.assertIsInstance(key, str)

    def test_ads_idx_grp_values_are_int(self):
        from oida.protocols.ads.constants import ADS_IDX_GRP

        for val in ADS_IDX_GRP.values():
            self.assertIsInstance(val, int)

    def test_ads_idx_grp_has_essential_keys(self):
        from oida.protocols.ads.constants import ADS_IDX_GRP

        essential = [
            "FILE_OPEN",
            "FILE_CLOSE",
            "FILE_READ",
            "FILE_WRITE",
            "SYM_TABLE",
            "SYM_NAME",
            "SYM_VALUE",
            "COE_SDO",
            "ECAT_SLAVE_COUNT",
        ]
        for key in essential:
            self.assertIn(key, ADS_IDX_GRP, f"Missing key: {key}")

    def test_ads_idx_grp_names_reverse_lookup(self):
        """Each code in ADS_IDX_GRP_NAMES should map back to a valid key name.

        DEV_DATA_* entries are index *offsets* used together with the
        DEV_DATA index *group* (0xF100), not index groups themselves, so
        they live in ADS_DEV_DATA_OFFSETS and are excluded from ADS_IDX_GRP
        / its reverse map. That keeps HW_ACCESS (0x05) unambiguous instead
        of colliding with DEV_DATA_ADSVERSIONCHECK (also 0x05).
        """
        from oida.protocols.ads.constants import ADS_IDX_GRP, ADS_IDX_GRP_NAMES

        self.assertNotIn("DEV_DATA_ADSSTATE", ADS_IDX_GRP)
        self.assertEqual(ADS_IDX_GRP_NAMES.get(0x05), "HW_ACCESS")

        for code, name in ADS_IDX_GRP_NAMES.items():
            self.assertIn(name, ADS_IDX_GRP)
            self.assertEqual(ADS_IDX_GRP[name], code)

    def test_ads_error_codes_is_dict(self):
        from oida.protocols.ads.constants import ADS_ERROR_CODES

        self.assertIsInstance(ADS_ERROR_CODES, dict)
        self.assertGreater(len(ADS_ERROR_CODES), 50)

    def test_ads_error_codes_has_zero(self):
        from oida.protocols.ads.constants import ADS_ERROR_CODES

        self.assertEqual(ADS_ERROR_CODES[0x0000], "OK")

    def test_ads_error_codes_has_timeout(self):
        from oida.protocols.ads.constants import ADS_ERROR_CODES

        self.assertEqual(ADS_ERROR_CODES[0x0719], "Timeout")

    def test_ads_state_map_is_dict(self):
        from oida.protocols.ads.constants import ADS_STATE_MAP

        self.assertIsInstance(ADS_STATE_MAP, dict)
        self.assertEqual(ADS_STATE_MAP[0], "INVALID")
        self.assertEqual(ADS_STATE_MAP[5], "RUN")
        self.assertEqual(ADS_STATE_MAP[6], "STOP")

    def test_ads_state_map_covers_range(self):
        from oida.protocols.ads.constants import ADS_STATE_MAP

        for i in range(20):
            self.assertIn(i, ADS_STATE_MAP)

    def test_ams_service_ports_is_dict(self):
        from oida.protocols.ads.constants import AMS_SERVICE_PORTS

        self.assertIsInstance(AMS_SERVICE_PORTS, dict)
        self.assertGreater(len(AMS_SERVICE_PORTS), 30)

    def test_ams_service_ports_has_router(self):
        from oida.protocols.ads.constants import AMS_SERVICE_PORTS

        self.assertEqual(AMS_SERVICE_PORTS["ROUTER"], 1)
        self.assertEqual(AMS_SERVICE_PORTS["ECAT_MASTER"], 65535)

    def test_ams_port_names_reverse_lookup(self):
        from oida.protocols.ads.constants import AMS_SERVICE_PORTS, AMS_PORT_NAMES

        for name, port in AMS_SERVICE_PORTS.items():
            self.assertEqual(AMS_PORT_NAMES.get(port), name)

    def test_ads_port_map_is_dict_of_str_int(self):
        """ADS_PORT_MAP should be a dict mapping str names to int ports."""
        from oida.protocols.ads.constants import ADS_PORT_MAP

        self.assertIsInstance(ADS_PORT_MAP, dict)
        self.assertGreater(len(ADS_PORT_MAP), 5)
        for name, port in ADS_PORT_MAP.items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(port, int)

    def test_ads_transport_has_tcp_udp(self):
        from oida.protocols.ads.constants import ADS_TRANSPORT

        self.assertEqual(ADS_TRANSPORT["TCP"], 48898)
        self.assertEqual(ADS_TRANSPORT["UDP"], 48899)
        self.assertIn("TLS", ADS_TRANSPORT)

    def test_ads_udp_magic_is_int(self):
        from oida.protocols.ads.constants import ADS_UDP_MAGIC

        self.assertIsInstance(ADS_UDP_MAGIC, int)
        self.assertEqual(ADS_UDP_MAGIC, 0x71146603)

    def test_ads_udp_tag_has_expected_keys(self):
        from oida.protocols.ads.constants import ADS_UDP_TAG

        expected = ["STATUS", "PASSWORD", "TC_VERSION", "OS_VERSION", "HOSTNAME", "NETID"]
        for key in expected:
            self.assertIn(key, ADS_UDP_TAG)

    def test_ads_file_flag_has_rw(self):
        from oida.protocols.ads.constants import ADS_FILE_FLAG

        self.assertEqual(ADS_FILE_FLAG["READ"], 0x01)
        self.assertEqual(ADS_FILE_FLAG["WRITE"], 0x02)
        self.assertIn("BINARY", ADS_FILE_FLAG)
        self.assertIn("TEXT", ADS_FILE_FLAG)

    def test_io_image_constants(self):
        from oida.protocols.ads.constants import INDEXGROUP_IOIMAGE_RWIB, INDEXGROUP_IOIMAGE_RWOB

        self.assertEqual(INDEXGROUP_IOIMAGE_RWIB, 0xF020)
        self.assertEqual(INDEXGROUP_IOIMAGE_RWOB, 0xF030)

    def test_timeout_constants(self):
        from oida.protocols.ads.constants import (
            ADS_TIMEOUT_MS,
            ADS_TLS_TIMEOUT,
            ADS_UDP_TIMEOUT,
            ADS_FUZZ_DELAY,
            ADS_FUZZ_SYMBOL_DELAY,
        )

        self.assertEqual(ADS_TIMEOUT_MS, 500)
        self.assertIsInstance(ADS_TLS_TIMEOUT, int)
        self.assertIsInstance(ADS_UDP_TIMEOUT, float)
        self.assertIsInstance(ADS_FUZZ_DELAY, float)
        self.assertIsInstance(ADS_FUZZ_SYMBOL_DELAY, float)

    def test_ads_commands_known_entries(self):
        from oida.protocols.ads.constants import ADS_COMMANDS

        self.assertEqual(ADS_COMMANDS[0x0001], "ReadDeviceInfo")
        self.assertEqual(ADS_COMMANDS[0x0002], "Read")
        self.assertEqual(ADS_COMMANDS[0x0003], "Write")
        self.assertEqual(ADS_COMMANDS[0x0009], "ReadWrite")


class TestAdsInitAttributes(unittest.TestCase):
    """Verify initial attribute defaults set in __init__."""

    def test_protocol_name(self):
        obj = _make_ads_instance()
        self.assertEqual(obj.protocol_name, "ADS")

    def test_default_port(self):
        obj = _make_ads_instance()
        self.assertEqual(obj.default_port, 48898)

    def test_initial_connection_none(self):
        obj = _make_ads_instance()
        self.assertIsNone(obj.conn)


if __name__ == "__main__":
    unittest.main()
