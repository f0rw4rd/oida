#!/usr/bin/env python3
"""
Comprehensive unit tests for GOOSE (IEC 61850) protocol scanner.

Tests both the Layer 1 GOOSEScanner and the Layer 2 NXC-style goose class.
All external dependencies (pyiec61850-ng) are mocked.
"""

import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class MockGooseMessage:
    """Mock GooseMessage returned by GooseSubscriber callbacks."""

    def __init__(
        self,
        go_cb_ref="testLD/LLN0$GO$gcb01",
        go_id="goose_id_01",
        data_set="testLD/LLN0$dsGOOSE",
        app_id=0x1000,
        st_num=1,
        sq_num=0,
        conf_rev=1,
        is_valid=True,
        needs_commissioning=False,
        time_allowed_to_live=2000,
        num_data_set_entries=4,
        values=None,
        timestamp=None,
        src_mac=None,
    ):
        self.go_cb_ref = go_cb_ref
        self.go_id = go_id
        self.data_set = data_set
        self.app_id = app_id
        self.st_num = st_num
        self.sq_num = sq_num
        self.conf_rev = conf_rev
        self.is_valid = is_valid
        self.needs_commissioning = needs_commissioning
        self.time_allowed_to_live = time_allowed_to_live
        self.num_data_set_entries = num_data_set_entries
        self.values = values
        self.timestamp = timestamp
        if src_mac is not None:
            self.src_mac = src_mac


class MockGoCBInfo:
    """Mock GoCBInfo returned by GoCBClient.enumerate()."""

    def __init__(
        self,
        gocb_ref="testLD/LLN0$GO$gcb01",
        goose_id="goose_id_01",
        dataset="testLD/LLN0$dsGOOSE",
        enabled=True,
        conf_rev=1,
        min_time=4,
        max_time=1000,
        fixed_offs=False,
        nds_comm=False,
        appid=0x1000,
        vlan_id=None,
        vlan_priority=None,
        dst_mac="",
    ):
        self.gocb_ref = gocb_ref
        self.goose_id = goose_id
        self.dataset = dataset
        self.enabled = enabled
        self.conf_rev = conf_rev
        self.min_time = min_time
        self.max_time = max_time
        self.fixed_offs = fixed_offs
        self.nds_comm = nds_comm
        self.appid = appid
        self.vlan_id = vlan_id
        self.vlan_priority = vlan_priority
        self.dst_mac = dst_mac


def _make_scanner(args_override=None):
    """Create a GOOSEScanner with sensible defaults and mocked logger."""
    from oida.protocols.goose import GOOSEScanner

    args = {"interface": "eth0"}
    if args_override:
        args.update(args_override)
    scanner = GOOSEScanner(args)
    # Replace logger with a mock so tests don't produce output
    scanner.logger = MagicMock()
    return scanner


# ===========================================================================
# Constants
# ===========================================================================


class TestGOOSEConstants(unittest.TestCase):
    """Test GOOSE module-level constants."""

    def test_goose_ethertype(self):
        """Test GOOSE EtherType is 0x88B8."""
        from oida.protocols.goose import GOOSE_ETHERTYPE

        self.assertEqual(GOOSE_ETHERTYPE, 0x88B8)

    def test_goose_multicast_prefix(self):
        """Test GOOSE multicast MAC prefix bytes."""
        from oida.protocols.goose import GOOSE_MULTICAST_PREFIX

        self.assertEqual(GOOSE_MULTICAST_PREFIX, bytes([0x01, 0x0C, 0xCD, 0x01]))
        self.assertIsInstance(GOOSE_MULTICAST_PREFIX, bytes)
        self.assertEqual(len(GOOSE_MULTICAST_PREFIX), 4)

    def test_protocol_options_dict_structure(self):
        """Test protocol_options contains expected keys and types."""
        from oida.protocols.goose import protocol_options

        self.assertIsInstance(protocol_options, dict)
        expected_keys = {
            "timeout",
            "gocb-ref",
            "appid",
            "rgoose",
            "rgoose-port",
            "rgoose-auth",
            "rgoose-key",
            "mms-enum",
            "mms-port",
        }
        self.assertEqual(set(protocol_options.keys()), expected_keys)

    def test_protocol_options_defaults(self):
        """Test protocol_options default values."""
        from oida.protocols.goose import protocol_options

        self.assertEqual(protocol_options["timeout"]["default"], 10)
        self.assertEqual(protocol_options["gocb-ref"]["default"], "")
        self.assertIsNone(protocol_options["appid"]["default"])
        self.assertFalse(protocol_options["rgoose"]["default"])
        self.assertIsNone(protocol_options["rgoose-port"]["default"])
        self.assertFalse(protocol_options["rgoose-auth"]["default"])
        self.assertIsNone(protocol_options["rgoose-key"]["default"])
        self.assertEqual(protocol_options["mms-enum"]["default"], "")
        self.assertEqual(protocol_options["mms-port"]["default"], 102)


# ===========================================================================
# Imports
# ===========================================================================


class TestGOOSEImports(unittest.TestCase):
    """Test that GOOSE module components can be imported."""

    def test_import_goose_module(self):
        """Test importing the GOOSE protocol module."""
        from oida.protocols import goose

        self.assertIsNotNone(goose)

    def test_import_goose_scanner_class(self):
        """Test importing the GOOSEScanner class."""
        from oida.protocols.goose import GOOSEScanner

        self.assertIsNotNone(GOOSEScanner)

    def test_import_goose_nxc_class(self):
        """Test importing the NXC-style goose class."""
        from oida.protocols.goose import goose as GooseConnection

        self.assertIsNotNone(GooseConnection)

    def test_import_metadata_and_run(self):
        """Test importing metadata and run function."""
        from oida.protocols.goose import metadata, run

        self.assertIsNotNone(metadata)
        self.assertIsNotNone(run)
        self.assertIsInstance(metadata, dict)
        self.assertTrue(callable(run))


# ===========================================================================
# GOOSEScanner.__init__
# ===========================================================================


class TestGOOSEScannerInit(unittest.TestCase):
    """Test GOOSEScanner initialization and parameter parsing."""

    def test_defaults(self):
        """Test default parameter values."""
        scanner = _make_scanner()

        self.assertEqual(scanner.capture_timeout, 10)
        self.assertEqual(scanner.gocb_ref, "")
        self.assertIsNone(scanner.appid_filter)
        self.assertFalse(scanner.rgoose_mode)
        self.assertIsNone(scanner.rgoose_port)
        self.assertFalse(scanner.rgoose_auth)
        self.assertIsNone(scanner.rgoose_key)
        self.assertEqual(scanner.mms_enum_target, "")
        self.assertEqual(scanner.mms_port, 102)
        self.assertEqual(scanner.interface, "eth0")
        self.assertEqual(scanner.goose_sources, {})
        self.assertIsNone(scanner._goose_subscriber)

    def test_custom_timeout(self):
        """Test custom capture timeout."""
        scanner = _make_scanner({"timeout": 30})
        self.assertEqual(scanner.capture_timeout, 30)

    def test_custom_gocb_ref(self):
        """Test custom GoCB reference."""
        scanner = _make_scanner({"gocb-ref": "myLD/LLN0$GO$gcb01"})
        self.assertEqual(scanner.gocb_ref, "myLD/LLN0$GO$gcb01")

    def test_appid_filter_integer(self):
        """Test appid filter is converted to integer."""
        scanner = _make_scanner({"appid": "4096"})
        self.assertEqual(scanner.appid_filter, 4096)

    def test_appid_filter_none(self):
        """Test appid filter remains None when not provided."""
        scanner = _make_scanner()
        self.assertIsNone(scanner.appid_filter)

    def test_rgoose_mode_enabled(self):
        """Test R-GOOSE mode flag."""
        scanner = _make_scanner({"rgoose": True})
        self.assertTrue(scanner.rgoose_mode)

    def test_rgoose_port(self):
        """Test R-GOOSE port setting."""
        scanner = _make_scanner({"rgoose-port": 1234})
        self.assertEqual(scanner.rgoose_port, 1234)

    def test_rgoose_auth(self):
        """Test R-GOOSE auth flag."""
        scanner = _make_scanner({"rgoose-auth": True})
        self.assertTrue(scanner.rgoose_auth)

    def test_rgoose_key(self):
        """Test R-GOOSE key path."""
        scanner = _make_scanner({"rgoose-key": "/path/to/key"})
        self.assertEqual(scanner.rgoose_key, "/path/to/key")

    def test_mms_enum_target(self):
        """Test MMS enumeration target IP."""
        scanner = _make_scanner({"mms-enum": "192.168.1.100"})
        self.assertEqual(scanner.mms_enum_target, "192.168.1.100")

    def test_mms_port(self):
        """Test custom MMS port."""
        scanner = _make_scanner({"mms-port": 8102})
        self.assertEqual(scanner.mms_port, 8102)

    def test_interface_from_rhost(self):
        """Test interface defaults to rhost when interface not given."""
        from oida.protocols.goose import GOOSEScanner

        args = {"rhost": "ens192"}
        scanner = GOOSEScanner(args)
        self.assertEqual(scanner.interface, "ens192")

    def test_interface_from_host(self):
        """Test interface defaults to host when interface and rhost not given."""
        from oida.protocols.goose import GOOSEScanner

        args = {"host": "br0"}
        scanner = GOOSEScanner(args)
        self.assertEqual(scanner.interface, "br0")

    def test_interface_default_eth0(self):
        """Test interface defaults to eth0 when nothing is given."""
        from oida.protocols.goose import GOOSEScanner

        args = {}
        scanner = GOOSEScanner(args)
        self.assertEqual(scanner.interface, "eth0")


# ===========================================================================
# get_protocol_name / get_default_port
# ===========================================================================


class TestGOOSEScannerProtocolInfo(unittest.TestCase):
    """Test basic protocol identification methods."""

    def test_get_protocol_name(self):
        """Test protocol name is IEC 61850 GOOSE."""
        scanner = _make_scanner()
        self.assertEqual(scanner.get_protocol_name(), "IEC 61850 GOOSE")

    def test_get_default_port(self):
        """Test default port is 0 (Layer 2 protocol)."""
        scanner = _make_scanner()
        self.assertEqual(scanner.get_default_port(), 0)


# ===========================================================================
# check_dependencies
# ===========================================================================


class TestGOOSECheckDependencies(unittest.TestCase):
    """Test dependency checking."""

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_dependencies_available(self, mock_dep):
        """Test returns True when pyiec61850-ng is available."""
        mock_dep.is_available = True
        scanner = _make_scanner()
        self.assertTrue(scanner.check_dependencies())

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_dependencies_missing(self, mock_dep):
        """Test returns False when pyiec61850-ng is missing."""
        mock_dep.is_available = False
        scanner = _make_scanner()
        self.assertFalse(scanner.check_dependencies())


# ===========================================================================
# connect
# ===========================================================================


class TestGOOSEScannerConnect(unittest.TestCase):
    """Test connect() method - three operating modes."""

    @patch("oida.protocols.goose._pyiec61850_goose")
    @patch("oida.protocols.goose._pyiec61850_mms")
    def test_connect_mms_mode(self, mock_mms, mock_goose):
        """Test connect dispatches to _connect_mms when mms_enum_target is set."""
        mock_client = MagicMock()
        mock_client.connect.return_value = True
        mock_mms.MMSClient.return_value = mock_client

        scanner = _make_scanner({"mms-enum": "192.168.1.100"})
        result = scanner.connect()

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "mms_connection")
        self.assertEqual(result["host"], "192.168.1.100")
        self.assertEqual(result["port"], 102)
        self.assertIs(result["client"], mock_client)

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_connect_rgoose_mode_returns_none(self, mock_goose):
        """Test connect returns None for R-GOOSE mode (not yet supported)."""
        scanner = _make_scanner({"rgoose": True})
        result = scanner.connect()

        self.assertIsNone(result)
        scanner.logger.fail.assert_called()

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_connect_goose_capture_with_gocb_ref(self, mock_goose):
        """Test connect creates goose_receiver config when gocb_ref set."""
        scanner = _make_scanner({"gocb-ref": "myLD/LLN0$GO$gcb01"})
        result = scanner.connect()

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "goose_receiver")
        self.assertEqual(result["interface"], "eth0")
        self.assertEqual(result["gocb_ref"], "myLD/LLN0$GO$gcb01")

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_connect_goose_capture_without_gocb_ref(self, mock_goose):
        """Test connect returns None when no gocb_ref for GOOSE capture."""
        scanner = _make_scanner()
        result = scanner.connect()

        self.assertIsNone(result)
        scanner.logger.fail.assert_called()


# ===========================================================================
# _create_goose_connection
# ===========================================================================


class TestCreateGooseConnection(unittest.TestCase):
    """Test _create_goose_connection method."""

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_missing_gocb_ref_returns_none(self, mock_goose):
        """Test returns None when gocb_ref is empty."""
        scanner = _make_scanner()
        result = scanner._create_goose_connection()

        self.assertIsNone(result)
        scanner.logger.fail.assert_called()

    @patch("oida.protocols.goose._pyiec61850_goose")
    def test_valid_gocb_ref_returns_config(self, mock_goose):
        """Test returns config dict when gocb_ref is set."""
        scanner = _make_scanner({"gocb-ref": "testLD/LLN0$GO$gcb01"})
        result = scanner._create_goose_connection()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["type"], "goose_receiver")
        self.assertEqual(result["interface"], "eth0")
        self.assertEqual(result["gocb_ref"], "testLD/LLN0$GO$gcb01")


# ===========================================================================
# _connect_mms
# ===========================================================================


class TestConnectMMS(unittest.TestCase):
    """Test _connect_mms method."""

    @patch("oida.protocols.goose._pyiec61850_mms")
    def test_mms_connect_success(self, mock_mms):
        """Test successful MMS connection."""
        mock_client = MagicMock()
        mock_client.connect.return_value = True
        mock_mms.MMSClient.return_value = mock_client

        scanner = _make_scanner()
        result = scanner._connect_mms("192.168.1.100", 102)

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "mms_connection")
        self.assertEqual(result["host"], "192.168.1.100")
        self.assertEqual(result["port"], 102)
        self.assertIs(result["client"], mock_client)
        mock_client.connect.assert_called_once_with("192.168.1.100", 102)

    @patch("oida.protocols.goose._pyiec61850_mms")
    def test_mms_connect_returns_false(self, mock_mms):
        """Test MMS connect returning False."""
        mock_client = MagicMock()
        mock_client.connect.return_value = False
        mock_mms.MMSClient.return_value = mock_client

        scanner = _make_scanner()
        result = scanner._connect_mms("192.168.1.100", 102)

        self.assertIsNone(result)
        scanner.logger.fail.assert_called()

    @patch("oida.protocols.goose._pyiec61850_mms")
    def test_mms_connect_exception(self, mock_mms):
        """Test MMS connect raising exception."""
        mock_mms.MMSClient.side_effect = Exception("Connection refused")

        scanner = _make_scanner()
        result = scanner._connect_mms("192.168.1.100", 102)

        self.assertIsNone(result)
        scanner.logger.fail.assert_called()

    @patch("oida.protocols.goose._pyiec61850_mms")
    def test_mms_connect_custom_port(self, mock_mms):
        """Test MMS connection with custom port."""
        mock_client = MagicMock()
        mock_client.connect.return_value = True
        mock_mms.MMSClient.return_value = mock_client

        scanner = _make_scanner()
        result = scanner._connect_mms("10.0.0.1", 8102)

        self.assertEqual(result["port"], 8102)
        mock_client.connect.assert_called_once_with("10.0.0.1", 8102)


# ===========================================================================
# disconnect
# ===========================================================================


class TestGOOSEScannerDisconnect(unittest.TestCase):
    """Test disconnect method."""

    def test_disconnect_none_connection(self):
        """Test disconnect with None connection does nothing."""
        scanner = _make_scanner()
        scanner.disconnect(None)
        # Should not raise

    def test_disconnect_goose_receiver(self):
        """Test disconnect stops GooseSubscriber."""
        scanner = _make_scanner()
        mock_subscriber = MagicMock()
        scanner._goose_subscriber = mock_subscriber

        connection = {"type": "goose_receiver"}
        scanner.disconnect(connection)

        mock_subscriber.stop.assert_called_once()
        self.assertIsNone(scanner._goose_subscriber)

    def test_disconnect_goose_receiver_no_subscriber(self):
        """Test disconnect goose_receiver when subscriber is None."""
        scanner = _make_scanner()
        scanner._goose_subscriber = None

        connection = {"type": "goose_receiver"}
        scanner.disconnect(connection)
        # Should not raise

    def test_disconnect_goose_receiver_stop_exception(self):
        """Test disconnect handles subscriber stop exception gracefully."""
        scanner = _make_scanner()
        mock_subscriber = MagicMock()
        mock_subscriber.stop.side_effect = Exception("Stop failed")
        scanner._goose_subscriber = mock_subscriber

        connection = {"type": "goose_receiver"}
        scanner.disconnect(connection)

        self.assertIsNone(scanner._goose_subscriber)
        scanner.logger.debug.assert_called()

    def test_disconnect_mms_connection(self):
        """Test disconnect closes MMS client."""
        scanner = _make_scanner()
        mock_client = MagicMock()

        connection = {"type": "mms_connection", "client": mock_client}
        scanner.disconnect(connection)

        mock_client.disconnect.assert_called_once()

    def test_disconnect_mms_no_client(self):
        """Test disconnect MMS with missing client key."""
        scanner = _make_scanner()
        connection = {"type": "mms_connection"}
        scanner.disconnect(connection)
        # Should not raise

    def test_disconnect_mms_exception(self):
        """Test disconnect handles MMS disconnect exception gracefully."""
        scanner = _make_scanner()
        mock_client = MagicMock()
        mock_client.disconnect.side_effect = Exception("Disconnect error")

        connection = {"type": "mms_connection", "client": mock_client}
        scanner.disconnect(connection)

        scanner.logger.debug.assert_called()

    def test_disconnect_unknown_type(self):
        """Test disconnect with unknown connection type does nothing harmful."""
        scanner = _make_scanner()
        connection = {"type": "unknown"}
        scanner.disconnect(connection)
        # Should not raise


# ===========================================================================
# discover
# ===========================================================================


class TestGOOSEScannerDiscover(unittest.TestCase):
    """Test discover method dispatching."""

    def test_discover_goose_receiver(self):
        """Test discover dispatches to _capture_goose for goose_receiver."""
        scanner = _make_scanner({"gocb-ref": "myLD/LLN0$GO$gcb01"})
        scanner._capture_goose = MagicMock(return_value=[{"gocb_ref": "test"}])
        scanner._analyze_security = MagicMock(return_value={"concerns": []})
        scanner._report_findings = MagicMock()

        connection = {"type": "goose_receiver", "interface": "eth0", "gocb_ref": "test"}
        results = scanner.discover(connection)

        scanner._capture_goose.assert_called_once_with(connection)
        self.assertEqual(results["goose_messages"], [{"gocb_ref": "test"}])

    def test_discover_mms_connection(self):
        """Test discover dispatches to _enumerate_gocbs for mms_connection."""
        scanner = _make_scanner({"mms-enum": "192.168.1.100"})
        scanner._enumerate_gocbs = MagicMock(return_value=[{"gocb_ref": "test"}])
        scanner._analyze_security = MagicMock(return_value={"concerns": []})
        scanner._report_findings = MagicMock()

        connection = {"type": "mms_connection", "client": MagicMock()}
        results = scanner.discover(connection)

        scanner._enumerate_gocbs.assert_called_once_with(connection)
        self.assertEqual(results["gocb_info"], [{"gocb_ref": "test"}])

    def test_discover_calls_security_analysis(self):
        """Test discover invokes _analyze_security."""
        scanner = _make_scanner()
        scanner._capture_goose = MagicMock(return_value=[])
        scanner._analyze_security = MagicMock(return_value={"concerns": ["test"]})
        scanner._report_findings = MagicMock()

        connection = {"type": "goose_receiver"}
        results = scanner.discover(connection)

        scanner._analyze_security.assert_called_once()
        self.assertEqual(results["security_analysis"]["concerns"], ["test"])

    def test_discover_exception_handling(self):
        """Test discover handles exceptions gracefully."""
        scanner = _make_scanner()

        # connection.get() will raise if connection is a non-dict
        connection = {"type": "goose_receiver"}
        scanner._capture_goose = MagicMock(side_effect=Exception("Capture error"))
        scanner._analyze_security = MagicMock(return_value={"concerns": []})
        scanner._report_findings = MagicMock()

        results = scanner.discover(connection)

        self.assertIn("error", results)
        self.assertIn("Capture error", results["error"])

    def test_discover_result_structure(self):
        """Test discover returns properly structured dict."""
        scanner = _make_scanner()
        scanner._capture_goose = MagicMock(return_value=[])
        scanner._analyze_security = MagicMock(return_value={})
        scanner._report_findings = MagicMock()

        connection = {"type": "goose_receiver"}
        results = scanner.discover(connection)

        self.assertIn("goose_messages", results)
        self.assertIn("goose_sources", results)
        self.assertIn("gocb_info", results)
        self.assertIn("security_analysis", results)


# ===========================================================================
# _goose_message_to_dict
# ===========================================================================


class TestGooseMessageToDict(unittest.TestCase):
    """Test _goose_message_to_dict conversion."""

    def test_full_message(self):
        """Test converting a complete GooseMessage."""
        scanner = _make_scanner()
        msg = MockGooseMessage()
        msg.src_mac = b"\x01\x0c\xcd\x01\x00\x01"

        result = scanner._goose_message_to_dict(msg)

        self.assertEqual(result["gocb_ref"], "testLD/LLN0$GO$gcb01")
        self.assertEqual(result["goose_id"], "goose_id_01")
        self.assertEqual(result["dataset_name"], "testLD/LLN0$dsGOOSE")
        self.assertEqual(result["appid"], 0x1000)
        self.assertEqual(result["st_num"], 1)
        self.assertEqual(result["sq_num"], 0)
        self.assertEqual(result["conf_rev"], 1)
        self.assertTrue(result["valid"])
        self.assertFalse(result["needs_commission"])
        self.assertEqual(result["time_allowed_to_live"], 2000)
        self.assertEqual(result["dataset_size"], 4)
        self.assertEqual(result["src_mac"], "01:0C:CD:01:00:01")
        self.assertEqual(result["transport"], "GOOSE/L2")
        self.assertIn("timestamp", result)

    def test_message_without_optional_fields(self):
        """Test converting message with empty optional fields."""
        scanner = _make_scanner()
        msg = MockGooseMessage(
            go_cb_ref="",
            go_id="",
            data_set="",
            values=None,
            timestamp=None,
        )

        result = scanner._goose_message_to_dict(msg)

        self.assertNotIn("gocb_ref", result)
        self.assertNotIn("goose_id", result)
        self.assertNotIn("dataset_name", result)
        self.assertNotIn("dataset_values", result)
        self.assertNotIn("goose_timestamp", result)

    def test_message_with_values(self):
        """Test converting message that has dataset values."""
        scanner = _make_scanner()
        test_values = [True, False, 42, 3.14]
        msg = MockGooseMessage(values=test_values)

        result = scanner._goose_message_to_dict(msg)

        self.assertEqual(result["dataset_values"], test_values)

    def test_message_with_timestamp(self):
        """Test converting message with goose timestamp."""
        scanner = _make_scanner()
        ts = datetime(2025, 1, 15, 12, 30, 0)
        msg = MockGooseMessage(timestamp=ts)

        result = scanner._goose_message_to_dict(msg)

        self.assertEqual(result["goose_timestamp"], ts.isoformat())

    def test_message_without_src_mac(self):
        """Test converting message without src_mac attribute."""
        scanner = _make_scanner()
        msg = MockGooseMessage()
        # No src_mac attribute set on this mock (no attribute at all)

        result = scanner._goose_message_to_dict(msg)

        self.assertNotIn("src_mac", result)


# ===========================================================================
# _gocb_info_to_dict
# ===========================================================================


class TestGoCBInfoToDict(unittest.TestCase):
    """Test _gocb_info_to_dict conversion."""

    def test_full_gocb_info(self):
        """Test converting a complete GoCBInfo."""
        scanner = _make_scanner()
        info = MockGoCBInfo(
            appid=0x2000,
            vlan_id=100,
            vlan_priority=4,
            dst_mac="01:0C:CD:01:00:02",
        )

        result = scanner._gocb_info_to_dict(info)

        self.assertEqual(result["gocb_ref"], "testLD/LLN0$GO$gcb01")
        self.assertEqual(result["goose_id"], "goose_id_01")
        self.assertEqual(result["dataset"], "testLD/LLN0$dsGOOSE")
        self.assertTrue(result["enabled"])
        self.assertEqual(result["conf_rev"], 1)
        self.assertEqual(result["min_time"], 4)
        self.assertEqual(result["max_time"], 1000)
        self.assertFalse(result["fixed_offs"])
        self.assertFalse(result["nds_comm"])
        self.assertEqual(result["appid"], 0x2000)
        self.assertEqual(result["vlan_id"], 100)
        self.assertEqual(result["vlan_priority"], 4)
        self.assertEqual(result["dst_mac"], "01:0C:CD:01:00:02")

    def test_gocb_info_without_optional_fields(self):
        """Test converting GoCBInfo with None optional fields."""
        scanner = _make_scanner()
        info = MockGoCBInfo(
            goose_id="",
            dataset="",
            appid=None,
            vlan_id=None,
            vlan_priority=None,
            dst_mac="",
        )

        result = scanner._gocb_info_to_dict(info)

        self.assertNotIn("goose_id", result)
        self.assertNotIn("dataset", result)
        self.assertNotIn("appid", result)
        self.assertNotIn("vlan_id", result)
        self.assertNotIn("vlan_priority", result)
        self.assertNotIn("dst_mac", result)

    def test_gocb_info_disabled(self):
        """Test GoCB with enabled=False."""
        scanner = _make_scanner()
        info = MockGoCBInfo(enabled=False)

        result = scanner._gocb_info_to_dict(info)
        self.assertFalse(result["enabled"])

    def test_gocb_info_nds_comm_set(self):
        """Test GoCB with nds_comm flag set."""
        scanner = _make_scanner()
        info = MockGoCBInfo(nds_comm=True)

        result = scanner._gocb_info_to_dict(info)
        self.assertTrue(result["nds_comm"])


# ===========================================================================
# _format_mac
# ===========================================================================


class TestFormatMac(unittest.TestCase):
    """Test _format_mac MAC address formatting."""

    def test_format_bytes(self):
        """Test formatting bytes MAC address."""
        scanner = _make_scanner()
        mac = b"\x01\x0c\xcd\x01\x00\x01"
        result = scanner._format_mac(mac)
        self.assertEqual(result, "01:0C:CD:01:00:01")

    def test_format_bytearray(self):
        """Test formatting bytearray MAC address."""
        scanner = _make_scanner()
        mac = bytearray([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        result = scanner._format_mac(mac)
        self.assertEqual(result, "AA:BB:CC:DD:EE:FF")

    def test_format_string_passthrough(self):
        """Test string MAC is returned as-is."""
        scanner = _make_scanner()
        mac = "01:0C:CD:01:00:01"
        result = scanner._format_mac(mac)
        self.assertEqual(result, "01:0C:CD:01:00:01")

    def test_format_non_bytes_fallback(self):
        """Test non-bytes input falls back to str() (caller always passes bytes)."""
        scanner = _make_scanner()
        mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        result = scanner._format_mac(mac)
        self.assertEqual(result, str(mac))

    def test_format_short_bytes(self):
        """Test formatting bytes shorter than 6 (truncated)."""
        scanner = _make_scanner()
        mac = b"\x01\x02\x03"
        result = scanner._format_mac(mac)
        # Should format the bytes it has
        self.assertEqual(result, "01:02:03")

    def test_format_error_fallback(self):
        """Test fallback to str() on error."""
        scanner = _make_scanner()
        # An object whose __len__ raises or is < 6 and not bytes/str
        mac = 12345
        result = scanner._format_mac(mac)
        self.assertEqual(result, "12345")

    def test_format_none_fallback(self):
        """Test formatting None falls back to str()."""
        scanner = _make_scanner()
        result = scanner._format_mac(None)
        self.assertEqual(result, "None")


# ===========================================================================
# _analyze_security
# ===========================================================================


class TestAnalyzeSecurity(unittest.TestCase):
    """Test _analyze_security method."""

    def test_empty_results(self):
        """Test analysis with no messages or GoCBs."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [],
            "gocb_info": [],
            "goose_sources": {},
        }

        analysis = scanner._analyze_security(results)

        self.assertIn("concerns", analysis)
        self.assertIn("security_score", analysis)
        # GOOSE has no built-in security, should be low
        self.assertEqual(analysis["security_level"], "low")

    def test_unprotected_messages(self):
        """Test detection of unprotected GOOSE traffic."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [{"gocb_ref": "test", "appid": 0x1000}] * 5,
            "gocb_info": [],
            "goose_sources": {},
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("Unprotected GOOSE traffic", concern_text)
        self.assertIn("5 messages", concern_text)

    def test_test_flag_messages(self):
        """Test detection of TEST/SIMULATION flag."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [
                {"is_test": True, "appid": 0x1000},
                {"is_test": True, "appid": 0x1001},
                {"is_test": False, "appid": 0x1002},
            ],
            "gocb_info": [],
            "goose_sources": {},
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("TEST/SIMULATION", concern_text)
        self.assertIn("2", concern_text)

    def test_default_appids(self):
        """Test detection of default AppIDs (0x0000, 0x0001)."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [
                {"appid": 0},
                {"appid": 1},
                {"appid": 0x1000},
            ],
            "gocb_info": [],
            "goose_sources": {},
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("default AppID", concern_text)
        self.assertIn("2", concern_text)

    def test_enabled_gocbs_concern(self):
        """Test detection of enabled GoCBs via MMS."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [],
            "gocb_info": [
                {"enabled": True, "gocb_ref": "a"},
                {"enabled": True, "gocb_ref": "b"},
                {"enabled": False, "gocb_ref": "c"},
            ],
            "goose_sources": {},
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("2 active GOOSE Control Blocks", concern_text)

    def test_nds_comm_gocbs(self):
        """Test detection of GoCBs needing commissioning."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [],
            "gocb_info": [
                {"nds_comm": True, "gocb_ref": "a"},
            ],
            "goose_sources": {},
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("NdsComm", concern_text)

    def test_multiple_sources(self):
        """Test detection of multiple GOOSE sources."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [],
            "gocb_info": [],
            "goose_sources": {
                "01:0C:CD:01:00:01": [],
                "01:0C:CD:01:00:02": [],
                "01:0C:CD:01:00:03": [],
            },
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("3 unique GOOSE sources", concern_text)

    def test_single_source_no_concern(self):
        """Test that single source does not raise concern."""
        scanner = _make_scanner()
        results = {
            "goose_messages": [],
            "gocb_info": [],
            "goose_sources": {"01:0C:CD:01:00:01": []},
        }

        analysis = scanner._analyze_security(results)

        concern_text = " ".join(analysis["concerns"])
        self.assertNotIn("unique GOOSE sources", concern_text)


# ===========================================================================
# _check_sequence_anomalies
# ===========================================================================


class TestCheckSequenceAnomalies(unittest.TestCase):
    """Test _check_sequence_anomalies method."""

    def test_decreasing_stnum_replay_detection(self):
        """Test detection of decreasing stNum (potential replay)."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 10, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 11, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 5, "sq_num": 0},  # replay
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("Decreasing stNum", concern_text)
        self.assertIn("possible replay", concern_text)

    def test_large_sqnum_gap(self):
        """Test detection of large sqNum gaps."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 200},  # gap=200
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("Large sqNum gap", concern_text)
        self.assertIn("gap=200", concern_text)

    def test_normal_sequences_no_concerns(self):
        """Test that normal sequences do not produce concerns."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 1},
            {"gocb_ref": "test/gcb01", "st_num": 2, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 2, "sq_num": 1},
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        self.assertEqual(analysis["concerns"], [])

    def test_empty_messages(self):
        """Test with empty message list."""
        scanner = _make_scanner()
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies([], analysis)

        self.assertEqual(analysis["concerns"], [])

    def test_single_message_per_gocb(self):
        """Test that single message per GoCB is skipped (needs >= 2)."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 10, "sq_num": 0},
            {"gocb_ref": "test/gcb02", "st_num": 5, "sq_num": 100},
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        self.assertEqual(analysis["concerns"], [])

    def test_messages_without_gocb_ref_ignored(self):
        """Test that messages without gocb_ref are ignored."""
        scanner = _make_scanner()
        messages = [
            {"st_num": 10, "sq_num": 0},
            {"gocb_ref": "", "st_num": 5, "sq_num": 0},
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        self.assertEqual(analysis["concerns"], [])

    def test_multiple_gocbs_independent(self):
        """Test anomaly detection is per-GoCB."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 10, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 11, "sq_num": 0},
            {"gocb_ref": "test/gcb02", "st_num": 20, "sq_num": 0},
            {"gocb_ref": "test/gcb02", "st_num": 5, "sq_num": 0},  # replay on gcb02
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        concern_text = " ".join(analysis["concerns"])
        self.assertIn("test/gcb02", concern_text)
        self.assertNotIn("test/gcb01", concern_text)

    def test_sqnum_gap_threshold_boundary(self):
        """Test sqNum gap exactly at threshold (100) does not trigger."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 100},  # gap=100, not > 100
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        self.assertEqual(analysis["concerns"], [])

    def test_sqnum_gap_just_over_threshold(self):
        """Test sqNum gap of 101 triggers concern."""
        scanner = _make_scanner()
        messages = [
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 0},
            {"gocb_ref": "test/gcb01", "st_num": 1, "sq_num": 101},
        ]
        analysis = {"concerns": []}

        scanner._check_sequence_anomalies(messages, analysis)

        self.assertEqual(len(analysis["concerns"]), 1)
        self.assertIn("Large sqNum gap", analysis["concerns"][0])


# ===========================================================================
# _display_goose_message
# ===========================================================================


class TestDisplayGooseMessage(unittest.TestCase):
    """Test _display_goose_message output logic."""

    def test_new_message_logs_success(self):
        """Test new message uses logger.success."""
        scanner = _make_scanner()
        msg = {
            "gocb_ref": "test/gcb01",
            "appid": 0x1000,
            "st_num": 1,
            "sq_num": 0,
            "src_mac": "01:0C:CD:01:00:01",
        }

        scanner._display_goose_message(msg, is_new=True)

        scanner.logger.success.assert_called_once()
        call_args = scanner.logger.success.call_args[0][0]
        self.assertIn("test/gcb01", call_args)
        self.assertIn("4096", call_args)

    def test_existing_message_logs_debug(self):
        """Test existing message uses logger.debug."""
        scanner = _make_scanner()
        msg = {
            "gocb_ref": "test/gcb01",
            "appid": 0x1000,
            "st_num": 5,
            "sq_num": 3,
            "src_mac": "01:0C:CD:01:00:01",
        }

        scanner._display_goose_message(msg, is_new=False)

        scanner.logger.debug.assert_called()
        call_args = scanner.logger.debug.call_args[0][0]
        self.assertIn("stNum=5", call_args)
        self.assertIn("sqNum=3", call_args)

    def test_new_message_with_goose_id(self):
        """Test new message displays GoID when present."""
        scanner = _make_scanner()
        msg = {
            "gocb_ref": "test/gcb01",
            "appid": 0x1000,
            "goose_id": "my_goose_id",
            "src_mac": "unknown",
        }

        scanner._display_goose_message(msg, is_new=True)

        # logger.display should be called with GoID
        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("my_goose_id", display_text)

    def test_new_message_with_test_flag(self):
        """Test new message with is_test flag logs warning."""
        scanner = _make_scanner()
        msg = {
            "gocb_ref": "test/gcb01",
            "appid": 0x1000,
            "is_test": True,
            "src_mac": "unknown",
        }

        scanner._display_goose_message(msg, is_new=True)

        scanner.logger.warning.assert_called_once()
        warning_text = scanner.logger.warning.call_args[0][0]
        self.assertIn("TEST/SIMULATION", warning_text)

    def test_new_message_with_dataset_size(self):
        """Test new message displays dataset size."""
        scanner = _make_scanner()
        msg = {
            "gocb_ref": "test/gcb01",
            "appid": 0x1000,
            "dataset_size": 8,
            "src_mac": "unknown",
        }

        scanner._display_goose_message(msg, is_new=True)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("8", display_text)

    def test_new_message_with_vlan(self):
        """Test new message displays VLAN info."""
        scanner = _make_scanner()
        msg = {
            "gocb_ref": "test/gcb01",
            "appid": 0x1000,
            "vlan_id": 100,
            "vlan_prio": 4,
            "src_mac": "unknown",
        }

        scanner._display_goose_message(msg, is_new=True)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("100", display_text)

    def test_message_missing_fields_uses_defaults(self):
        """Test message with missing keys uses safe defaults."""
        scanner = _make_scanner()
        msg = {}

        scanner._display_goose_message(msg, is_new=False)

        # Should use "unknown" for gocb_ref and "?" for appid/st_num/sq_num
        call_args = scanner.logger.debug.call_args[0][0]
        self.assertIn("unknown", call_args)


# ===========================================================================
# _display_gocb
# ===========================================================================


class TestDisplayGoCB(unittest.TestCase):
    """Test _display_gocb output logic."""

    def test_enabled_gocb(self):
        """Test display of enabled GoCB."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
        }

        scanner._display_gocb(gocb)

        scanner.logger.success.assert_called_once()
        call_args = scanner.logger.success.call_args[0][0]
        self.assertIn("ENABLED", call_args)
        self.assertIn("test/gcb01", call_args)

    def test_disabled_gocb(self):
        """Test display of disabled GoCB."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": False,
        }

        scanner._display_gocb(gocb)

        call_args = scanner.logger.success.call_args[0][0]
        self.assertIn("disabled", call_args)

    def test_gocb_with_goose_id(self):
        """Test GoCB display includes GoID."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "goose_id": "my_go_id",
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("my_go_id", display_text)

    def test_gocb_with_dataset(self):
        """Test GoCB display includes dataset."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "dataset": "testLD/LLN0$dsGOOSE",
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("testLD/LLN0$dsGOOSE", display_text)

    def test_gocb_with_appid(self):
        """Test GoCB display includes AppID in hex."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "appid": 0x2000,
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("0x2000", display_text.lower())

    def test_gocb_with_dst_mac(self):
        """Test GoCB display includes destination MAC."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "dst_mac": "01:0C:CD:01:00:02",
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("01:0C:CD:01:00:02", display_text)

    def test_gocb_with_vlan(self):
        """Test GoCB display includes VLAN info."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "vlan_id": 200,
            "vlan_priority": 6,
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("200", display_text)

    def test_gocb_with_timing(self):
        """Test GoCB display includes min/max timing."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "min_time": 4,
            "max_time": 1000,
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("4", display_text)
        self.assertIn("1000", display_text)

    def test_gocb_with_conf_rev(self):
        """Test GoCB display includes configuration revision."""
        scanner = _make_scanner()
        gocb = {
            "gocb_ref": "test/gcb01",
            "enabled": True,
            "conf_rev": 42,
        }

        scanner._display_gocb(gocb)

        display_calls = [str(c) for c in scanner.logger.display.call_args_list]
        display_text = " ".join(display_calls)
        self.assertIn("42", display_text)

    def test_gocb_minimal_fields(self):
        """Test GoCB display with only required fields."""
        scanner = _make_scanner()
        gocb = {"gocb_ref": "test/gcb01"}

        scanner._display_gocb(gocb)

        scanner.logger.success.assert_called_once()
        call_args = scanner.logger.success.call_args[0][0]
        self.assertIn("disabled", call_args)  # enabled defaults to False


# ===========================================================================
# _report_findings
# ===========================================================================


class TestReportFindings(unittest.TestCase):
    """Test _report_findings method."""

    def test_report_interface_mode(self):
        """Test report uses interface when not in MMS mode."""
        scanner = _make_scanner()
        scanner.report_host_info = MagicMock()
        scanner.report_vulnerability = MagicMock()

        results = {"security_analysis": {"concerns": ["test concern"]}}
        scanner._report_findings(results)

        scanner.report_host_info.assert_called_once_with("eth0")
        scanner.report_vulnerability.assert_called_once_with(
            "eth0", "goose_security", description="test concern"
        )

    def test_report_mms_mode(self):
        """Test report uses MMS target and reports service info."""
        scanner = _make_scanner({"mms-enum": "192.168.1.100"})
        scanner.report_host_info = MagicMock()
        scanner.report_service_info = MagicMock()
        scanner.report_vulnerability = MagicMock()

        results = {"security_analysis": {"concerns": []}}
        scanner._report_findings(results)

        scanner.report_host_info.assert_called_once_with("192.168.1.100")
        scanner.report_service_info.assert_called_once_with(
            "192.168.1.100",
            port=102,
            name="iec61850-goose-mms",
            proto="tcp",
        )

    def test_report_multiple_concerns(self):
        """Test report emits multiple vulnerability entries."""
        scanner = _make_scanner()
        scanner.report_host_info = MagicMock()
        scanner.report_vulnerability = MagicMock()

        results = {
            "security_analysis": {
                "concerns": ["concern_a", "concern_b", "concern_c"],
            }
        }
        scanner._report_findings(results)

        self.assertEqual(scanner.report_vulnerability.call_count, 3)

    def test_report_no_concerns(self):
        """Test report with no concerns does not call report_vulnerability."""
        scanner = _make_scanner()
        scanner.report_host_info = MagicMock()
        scanner.report_vulnerability = MagicMock()

        results = {"security_analysis": {"concerns": []}}
        scanner._report_findings(results)

        scanner.report_vulnerability.assert_not_called()

    def test_report_empty_security_analysis(self):
        """Test report with missing security_analysis key."""
        scanner = _make_scanner()
        scanner.report_host_info = MagicMock()
        scanner.report_vulnerability = MagicMock()

        results = {}
        scanner._report_findings(results)

        scanner.report_vulnerability.assert_not_called()


# ===========================================================================
# NXC class: goose
# ===========================================================================


class TestGooseNXCClass(unittest.TestCase):
    """Test the NXC-style goose callable class."""

    def test_class_exists(self):
        """Test goose NXC class can be imported."""
        from oida.protocols.goose import goose as GooseConnection

        self.assertIsNotNone(GooseConnection)

    def test_class_attributes(self):
        """Test goose NXC class has expected class-level attributes and methods."""
        from oida.protocols.goose import goose as GooseConnection

        self.assertTrue(hasattr(GooseConnection, "proto_flow"))
        self.assertTrue(hasattr(GooseConnection, "create_conn_obj"))
        self.assertTrue(hasattr(GooseConnection, "enum_host_info"))
        self.assertTrue(hasattr(GooseConnection, "print_host_info"))
        self.assertTrue(hasattr(GooseConnection, "cleanup"))
        self.assertTrue(hasattr(GooseConnection, "check_dependencies"))

    def test_check_dependencies_available(self):
        """Test static check_dependencies returns True when available."""
        from oida.protocols.goose import goose as GooseConnection

        with patch("importlib.import_module") as mock_import:
            mock_import.return_value = MagicMock()
            self.assertTrue(GooseConnection.check_dependencies())

    def test_check_dependencies_missing(self):
        """Test static check_dependencies returns False when missing."""
        from oida.protocols.goose import goose as GooseConnection

        with patch("importlib.import_module", side_effect=ImportError("not installed")):
            self.assertFalse(GooseConnection.check_dependencies())


# ===========================================================================
# Proto args
# ===========================================================================


class TestGooseProtoArgs(unittest.TestCase):
    """Test GOOSE proto_args CLI argument registration."""

    def test_proto_args_function_exists(self):
        """Test proto_args function can be imported."""
        from oida.protocols.goose.proto_args import proto_args

        self.assertTrue(callable(proto_args))

    def test_proto_args_registers_subparser(self):
        """Test proto_args registers goose subparser."""
        import argparse
        from oida.protocols.goose.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["goose", "eth0"])
        self.assertEqual(args.target, "eth0")

    def test_proto_args_timeout_default(self):
        """Test --timeout defaults to 10."""
        import argparse
        from oida.protocols.goose.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["goose", "eth0"])
        self.assertEqual(args.timeout, 10)

    def test_proto_args_timeout_custom(self):
        """Test --timeout with custom value."""
        import argparse
        from oida.protocols.goose.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["goose", "eth0", "--timeout", "60"])
        self.assertEqual(args.timeout, 60)

    def test_proto_args_rgoose_flag(self):
        """Test --rgoose store_true flag."""
        import argparse
        from oida.protocols.goose.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["goose", "eth0", "--rgoose"])
        self.assertTrue(args.rgoose)

    def test_proto_args_mms_enum(self):
        """Test --mms-enum option."""
        import argparse
        from oida.protocols.goose.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["goose", "eth0", "--mms-enum", "192.168.1.100"])
        self.assertEqual(args.mms_enum, "192.168.1.100")

    def test_proto_args_mms_port_default(self):
        """Test --mms-port defaults to 102."""
        import argparse
        from oida.protocols.goose.proto_args import proto_args

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        args = main_parser.parse_args(["goose", "eth0"])
        self.assertEqual(args.mms_port, 102)


# ===========================================================================
# Metadata / module factory
# ===========================================================================


class TestGOOSEMetadata(unittest.TestCase):
    """Test module-level metadata structure."""

    def test_metadata_has_required_keys(self):
        """Test metadata dict contains required fields."""
        from oida.protocols.goose import metadata

        self.assertIn("name", metadata)
        self.assertIn("description", metadata)
        self.assertIn("authors", metadata)

    def test_metadata_name(self):
        """Test metadata scanner name."""
        from oida.protocols.goose import metadata

        self.assertEqual(metadata["name"], "GOOSE Scanner")

    def test_run_is_callable(self):
        """Test run function is callable."""
        from oida.protocols.goose import run

        self.assertTrue(callable(run))


if __name__ == "__main__":
    unittest.main()
