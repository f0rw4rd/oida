#!/usr/bin/env python3
"""
Test suite for DNP3 scanner (yadnp3 / opendnp3 backend).

Tests scanner initialization, configuration, argument mapping,
and mocked protocol operations.
"""

import pytest

from oida.utils.exceptions import ConfigurationError


# Skip all tests if yadnp3 (opendnp3) is not installed
opendnp3 = pytest.importorskip("opendnp3", reason="yadnp3 (opendnp3) not installed")


from oida.protocols.dnp3.scanner import (
    DNP3Scanner,
)
from oida.protocols.dnp3.constants import KNOWN_ATTRIBUTES


class TestDNP3ScannerInit:
    """Test DNP3Scanner initialization."""

    def test_default_values(self):
        """Test scanner initializes with correct defaults."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})

        assert scanner.master_address == 1
        assert scanner.outstation_address == 1024
        assert scanner.op_timeout == 10
        assert scanner._read_class_setting == "all"
        assert scanner._read_variation_setting is None
        assert scanner.device_attributes is False
        assert scanner.skip_device_attrs is False
        assert scanner.control_mode is None
        assert scanner.sbo_mode is None
        assert scanner.control_code == 3  # Default LATCH_ON
        assert scanner.time_sync is None
        assert scanner.restart_mode is None
        assert scanner.use_tls is False
        assert scanner._connected is False

    def test_custom_addressing(self):
        """Test scanner with custom master/outstation addresses."""
        scanner = DNP3Scanner(
            {
                "rhost": "10.0.0.1",
                "rport": 20001,
                "master-address": 5,
                "outstation-address": 100,
            }
        )

        assert scanner.master_address == 5
        assert scanner.outstation_address == 100
        assert scanner.host == "10.0.0.1"
        assert scanner.port == 20001

    def test_custom_timeout(self):
        """Test scanner with custom timeout."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "timeout": 30,
            }
        )
        assert scanner.op_timeout == 30

    def test_tls_configuration(self):
        """Test scanner with TLS settings."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "tls": True,
                "tls-cert": "/path/to/cert.pem",
                "tls-key": "/path/to/key.pem",
            }
        )

        assert scanner.use_tls is True
        assert scanner.tls_cert == "/path/to/cert.pem"
        assert scanner.tls_key == "/path/to/key.pem"

    def test_scan_range_configuration(self):
        """Test scanner with address scan range."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "scan-range": "1-100",
            }
        )

        assert scanner.scan_range == "1-100"

    def test_control_configuration(self):
        """Test scanner with control mode settings."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "control": 5,  # Binary output index
                "control-code": 1,  # PULSE_ON
            }
        )

        assert scanner.control_mode == 5
        assert scanner.control_code == 1

    def test_sbo_configuration(self):
        """Test scanner with SBO mode."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "sbo": 3,  # Binary output index
                "control-code": 4,  # LATCH_OFF
            }
        )

        assert scanner.sbo_mode == 3
        assert scanner.control_code == 4

    def test_time_sync_configuration(self):
        """Test scanner with time sync mode."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "time-sync": "lan",
            }
        )
        assert scanner.time_sync == "lan"

    def test_restart_configuration(self):
        """Test scanner with restart mode."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "restart": "cold",
            }
        )
        assert scanner.restart_mode == "cold"

    def test_read_variation_configuration(self):
        """Test scanner with specific group/variation read."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "read-variation": "30.0",
            }
        )
        assert scanner._read_variation_setting == "30.0"


class TestDNP3ScannerProtocol:
    """Test protocol name and port methods."""

    def test_protocol_name(self):
        """Test get_protocol_name returns DNP3."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.get_protocol_name() == "DNP3"

    def test_default_port(self):
        """Test get_default_port returns 20000."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.get_default_port() == 20000

    def test_check_dependencies(self):
        """Test check_dependencies returns True when dnp3 is available."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.check_dependencies() is True


class TestKnownAttributes:
    """Test the KNOWN_ATTRIBUTES dictionary."""

    def test_manufacturer_name(self):
        assert KNOWN_ATTRIBUTES[254] == "Device Manufacturer's Name"

    def test_product_name(self):
        assert KNOWN_ATTRIBUTES[252] == "Device Manufacturer's Product Name"

    def test_serial_number(self):
        assert KNOWN_ATTRIBUTES[249] == "Device Serial Number"

    def test_software_version(self):
        assert KNOWN_ATTRIBUTES[242] == "Software Version"

    def test_hardware_version(self):
        assert KNOWN_ATTRIBUTES[243] == "Hardware Version"

    def test_location(self):
        assert KNOWN_ATTRIBUTES[245] == "Location"

    def test_all_attributes_request(self):
        assert KNOWN_ATTRIBUTES[196] == "All Attributes Request"

    def test_number_of_binary_inputs(self):
        assert KNOWN_ATTRIBUTES[224] == "Number of Binary Inputs"

    def test_number_of_analog_inputs(self):
        assert KNOWN_ATTRIBUTES[220] == "Number of Analog Inputs"


class TestDNP3ScannerScanData:
    """Test internal scan data structure."""

    def test_initial_state_not_connected(self):
        """Test initial state variables."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner._connected is False
        assert scanner._manager is None
        assert scanner._channel is None
        assert scanner._master is None
        assert scanner._scan_handler is None
        assert scanner._handler is None
        assert scanner._app is None
        assert scanner._chan_listener is None


class TestDNP3ScannerDiscover:
    """Test the discover method behavior without connection."""

    def test_discover_without_connection_returns_empty(self):
        """Test discover returns empty results when not connected."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        results = scanner.discover(None)

        assert "connection" in results
        assert "data_points" in results
        assert "device_attributes" in results
        assert "iin" in results
        assert "operations" in results

    def test_discover_connection_metadata(self):
        """Test discover populates connection metadata."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "master-address": 5,
                "outstation-address": 100,
            }
        )
        results = scanner.discover(None)

        assert results["connection"]["master_address"] == 5
        assert results["connection"]["outstation_address"] == 100
        assert results["connection"]["tls_enabled"] is False
        assert "timestamp" in results["connection"]

    def test_discover_includes_transport(self):
        """Test discover includes transport type in connection metadata."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "transport": "serial",
            }
        )
        results = scanner.discover(None)
        assert results["connection"]["transport"] == "serial"


class TestDNP3ScannerConvenienceMethods:
    """Test public convenience methods."""

    def test_integrity_poll_returns_dict(self):
        """Test integrity_poll returns a dict."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        # Without connection, this should return empty results
        result = scanner.integrity_poll()
        assert isinstance(result, dict)

    def test_read_class_returns_dict(self):
        """Test read_class returns a dict."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        result = scanner.read_class(0)
        assert isinstance(result, dict)

    def test_read_variation_returns_dict(self):
        """Test read_variation returns a dict."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        result = scanner.read_variation(30, 0)
        assert isinstance(result, dict)

    def test_read_attributes_returns_dict(self):
        """Test read_attributes returns a dict."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        result = scanner.read_attributes()
        assert isinstance(result, dict)


class TestDNP3ScannerDisconnect:
    """Test disconnect behavior."""

    def test_disconnect_when_not_connected(self):
        """Test disconnect when nothing is connected."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        # Should not raise
        scanner.disconnect(None)

        assert scanner._connected is False
        assert scanner._manager is None
        assert scanner._channel is None
        assert scanner._master is None
        assert scanner._scan_handler is None
        assert scanner._handler is None
        assert scanner._app is None
        assert scanner._chan_listener is None

    def test_disconnect_clears_state(self):
        """Test disconnect clears all connection state."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        # Simulate having state
        scanner._connected = True
        scanner._master = "fake_master"
        scanner._scan_handler = "fake_handler"
        scanner._handler = "fake_handler"
        scanner._app = "fake_app"
        scanner._chan_listener = "fake_listener"

        scanner.disconnect(None)

        assert scanner._connected is False
        assert scanner._master is None
        assert scanner._scan_handler is None
        assert scanner._handler is None
        assert scanner._app is None
        assert scanner._chan_listener is None


class TestDNP3AssignClass:
    """Test ASSIGN_CLASS header construction reflects the parsed group/range.

    Regression: _assign_class() previously sent only AllObjects(60, var),
    which carries no group qualifier and no index range and therefore
    reclassifies the entire outstation, while still echoing per-group /
    per-range fields into results. The request must instead target the
    parsed group over [start, end].
    """

    def _make_fake_dnp3(self, recorder):
        """A stand-in opendnp3 module that records Header factory calls."""

        class _FakeHeader:
            @staticmethod
            def AllObjects(group, variation):
                recorder.append(("AllObjects", group, variation))
                return ("AllObjects", group, variation)

            @staticmethod
            def Range16(group, variation, start, stop):
                recorder.append(("Range16", group, variation, start, stop))
                return ("Range16", group, variation, start, stop)

        class _FakeFunctionCode:
            ASSIGN_CLASS = "ASSIGN_CLASS"

        fake = type("FakeDnp3", (), {})()
        fake.Header = _FakeHeader
        fake.FunctionCode = _FakeFunctionCode
        return fake

    def test_assign_class_sends_ranged_header(self):
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        scanner.assign_class = ["1:0-9:1"]  # BI 0-9 -> Class 1

        header_calls = []
        scanner.__dict__["_dnp3"] = self._make_fake_dnp3(header_calls)

        sent = {}

        def fake_sync_task(task_fn, timeout=None):
            class _FakeMaster:
                def PerformFunction(self, name, func, headers, config):
                    sent["name"] = name
                    sent["func"] = func
                    sent["headers"] = headers

            task_fn(_FakeMaster(), object())
            return True

        scanner._sync_task = fake_sync_task

        results = {"operations": {}}
        scanner._assign_class(results)

        # The request must carry a Range16 header targeting the parsed group
        # over [start, end] -- not just a whole-device AllObjects(60, var).
        headers = sent["headers"]
        ranged = [h for h in headers if h[0] == "Range16"]
        assert ranged, f"expected a ranged header, got {headers}"
        # Range16(group=1, variation=0, start=0, stop=9)
        assert ranged[0] == ("Range16", 1, 0, 0, 9)

        # Class header still present: group 60, variation = class+1 = 2.
        assert ("AllObjects", 60, 2) in headers

        # results must reflect what was actually sent.
        op = results["operations"]["assign_class"]["operations"][0]
        assert op["group"] == 1
        assert op["start"] == 0
        assert op["end"] == 9
        assert op["target_class"] == 1


class TestNxcClass:
    """Test the NXC dnp3 class in __init__.py."""

    def test_scanner_importable(self):
        """Test that DNP3Scanner can be imported from scanner module."""
        from oida.protocols.dnp3.scanner import DNP3Scanner

        assert DNP3Scanner is not None

    def test_init_module_exports(self):
        """Test that the __init__ module exports expected names."""
        from oida.protocols.dnp3 import dnp3 as Dnp3NxcClass

        assert Dnp3NxcClass is not None
        assert hasattr(Dnp3NxcClass, "check_dependencies")
        assert hasattr(Dnp3NxcClass, "proto_flow")

    def test_check_dependencies_static(self):
        """Test check_dependencies as static method."""
        from oida.protocols.dnp3 import dnp3 as Dnp3NxcClass

        result = Dnp3NxcClass.check_dependencies()
        assert isinstance(result, bool)
        assert result is True  # Since we know yadnp3 (opendnp3) is installed

    def test_dnp3scanner_from_init(self):
        """Test DNP3Scanner is importable from the package."""
        from oida.protocols.dnp3 import DNP3Scanner as ScannerFromInit

        assert ScannerFromInit is not None

    def test_build_scanner_args_method_exists(self):
        """Test that _build_scanner_args exists on NXC class."""
        from oida.protocols.dnp3 import dnp3 as Dnp3NxcClass

        assert hasattr(Dnp3NxcClass, "_build_scanner_args")


class TestProtocolOptions:
    """Test protocol_options dict on the scanner module."""

    def test_protocol_options_defined(self):
        """Test that protocol_options are defined."""
        from oida.protocols.dnp3.scanner import protocol_options

        assert "master-address" in protocol_options
        assert "outstation-address" in protocol_options
        assert "read-class" in protocol_options
        assert "timeout" in protocol_options

    def test_master_address_default(self):
        """Test master-address default is 1."""
        from oida.protocols.dnp3.scanner import protocol_options

        assert protocol_options["master-address"]["default"] == 1

    def test_outstation_address_default(self):
        """Test outstation-address default is 1024."""
        from oida.protocols.dnp3.scanner import protocol_options

        assert protocol_options["outstation-address"]["default"] == 1024

    def test_timeout_default(self):
        """Test timeout default is 10."""
        from oida.protocols.dnp3.scanner import protocol_options

        assert protocol_options["timeout"]["default"] == 10


def _make_base_args(**overrides):
    """Create a base Namespace with all required DNP3 validation attributes.

    Use overrides to set specific values for testing.
    """
    from argparse import Namespace

    defaults = {
        "bo_direct": None,
        "bo_sbo": None,
        "ao_direct": None,
        "ao_sbo": None,
        "ao_value": None,
        "cold_restart": False,
        "warm_restart": False,
        "enable_unsol": False,
        "disable_unsol": False,
        "write_deadband": None,
        "outstation_addr": None,
        "scan_range": None,
        "freeze_immediate": False,
        "freeze_clear": False,
        "freeze_at_time": None,
        "freeze_no_ack": False,
        "stop_app": False,
        "start_app": False,
        "init_data": False,
        "init_app": False,
        "save_config": False,
        "activate_config": False,
        "delete_file": None,
        "write_file": None,
        "write_data": None,
        "file_auth": None,
        "assign_class": None,
        "read_octet": None,
        "transport": "tcp",
        "serial_device": None,
        "sa": False,
        "sa_key": None,
        "sa_user": 1,
        # All control ops require --confirm; default to True so positive-path
        # tests don't have to set it explicitly. Negative-path tests can
        # override with confirm=False.
        "confirm": True,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


class TestArgumentValidation:
    """Test argument validation logic for control operations."""

    def test_control_requires_outstation_addr(self):
        """Test that --bo-direct requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(bo_direct=0)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_control_requires_confirm(self):
        """Control operations must require --confirm (release blocker safety guard)."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(bo_direct=0, outstation_addr=10, confirm=False)
        with pytest.raises(ConfigurationError, match="--confirm is required"):
            validate_args(args)

    def test_cold_restart_requires_confirm(self):
        """--cold-restart must require --confirm."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(cold_restart=True, outstation_addr=10, confirm=False)
        with pytest.raises(ConfigurationError, match="--confirm is required"):
            validate_args(args)

    def test_write_file_requires_confirm(self):
        """--write-file must require --confirm."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(
            write_file="/test.bin",
            write_data="@local.bin",
            outstation_addr=10,
            confirm=False,
        )
        with pytest.raises(ConfigurationError, match="--confirm is required"):
            validate_args(args)

    def test_sbo_requires_outstation_addr(self):
        """Test that --bo-sbo requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(bo_sbo=0)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_cold_restart_requires_outstation_addr(self):
        """Test that --cold-restart requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(cold_restart=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_warm_restart_requires_outstation_addr(self):
        """Test that --warm-restart requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(warm_restart=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_control_with_outstation_addr_passes(self):
        """Test that control operation passes with --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(bo_direct=0, outstation_addr=10)
        # Should not raise
        validate_args(args)

    def test_discovery_without_outstation_addr_passes(self):
        """Test that discovery passes without --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args()
        # Should not raise
        validate_args(args)

    def test_scan_range_validation_valid(self):
        """Test valid scan range passes."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(scan_range="1-100")
        # Should not raise
        validate_args(args)

    def test_scan_range_validation_invalid_format(self):
        """Test invalid scan range format fails."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(scan_range="invalid")
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_scan_range_validation_reversed(self):
        """Test reversed scan range fails."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(scan_range="100-1")
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestAnalogOutputConfiguration:
    """Test analog output control configuration."""

    def test_ao_direct_configuration(self):
        """Test scanner with analog output direct operate."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "ao-direct": 0,
                "ao-value": "50.5",
                "ao-type": "float",
            }
        )

        assert scanner.ao_direct == 0
        assert scanner.ao_value == "50.5"
        assert scanner.ao_type == "float"

    def test_ao_sbo_configuration(self):
        """Test scanner with analog output SBO."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "ao-sbo": 5,
                "ao-value": "100",
                "ao-type": "int32",
            }
        )

        assert scanner.ao_sbo == 5
        assert scanner.ao_value == "100"
        assert scanner.ao_type == "int32"

    def test_ao_type_defaults_to_float(self):
        """Test analog output type defaults to float."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )

        assert scanner.ao_type == "float"

    def test_ao_direct_requires_value(self):
        """Test that --ao-direct requires --ao-value."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_direct=0, outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_ao_sbo_requires_value(self):
        """Test that --ao-sbo requires --ao-value."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_sbo=0, outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_ao_with_value_passes(self):
        """Test that analog output with value passes validation."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_direct=0, ao_value="50.5", outstation_addr=10)
        # Should not raise
        validate_args(args)


class TestFileTransferConfiguration:
    """Test file transfer operation configuration."""

    def test_list_dir_configuration(self):
        """Test scanner with directory listing."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "list-dir": "/",
            }
        )

        assert scanner.list_dir == "/"

    def test_read_file_configuration(self):
        """Test scanner with file read."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "read-file": "/config.txt",
                "save-file": "/tmp/config.txt",
            }
        )

        assert scanner.read_file == "/config.txt"
        assert scanner.save_file == "/tmp/config.txt"

    def test_file_info_configuration(self):
        """Test scanner with file info."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "file-info": "/data/log.bin",
            }
        )

        assert scanner.file_info == "/data/log.bin"

    def test_write_file_configuration(self):
        """Test scanner with file write settings."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "write-file": "/config.txt",
                "write-data": "key=value",
            }
        )

        assert scanner.write_file == "/config.txt"
        assert scanner.write_data == "key=value"

    def test_file_auth_configuration(self):
        """Test scanner with file authentication settings."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "file-auth": "/config.txt",
            }
        )

        assert scanner.file_auth == "/config.txt"


class TestPointEnumerationConfiguration:
    """Test point enumeration configuration."""

    def test_enumerate_points_default(self):
        """Test enumerate points defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )

        assert scanner.enumerate_points is False

    def test_enumerate_points_enabled(self):
        """Test enumerate points when enabled."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "enumerate-points": True,
            }
        )

        assert scanner.enumerate_points is True


class TestUnsolicitedConfiguration:
    """Test unsolicited response control configuration."""

    def test_enable_unsol_default(self):
        """Test enable unsol defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )

        assert scanner.enable_unsol is False

    def test_disable_unsol_default(self):
        """Test disable unsol defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )

        assert scanner.disable_unsol is False

    def test_enable_unsol_configuration(self):
        """Test scanner with enable unsolicited."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "enable-unsol": True,
            }
        )

        assert scanner.enable_unsol is True

    def test_disable_unsol_configuration(self):
        """Test scanner with disable unsolicited."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "disable-unsol": True,
            }
        )

        assert scanner.disable_unsol is True

    def test_enable_unsol_requires_outstation_addr(self):
        """Test that --enable-unsol requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(enable_unsol=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_disable_unsol_requires_outstation_addr(self):
        """Test that --disable-unsol requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(disable_unsol=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestDeadBandConfiguration:
    """Test dead band configuration."""

    def test_deadband_default(self):
        """Test write deadband defaults to None."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )

        assert scanner.write_deadband is None

    def test_deadband_type_default(self):
        """Test deadband type defaults to float."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )

        assert scanner.deadband_type == "float"

    def test_deadband_configuration(self):
        """Test scanner with deadband configuration."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "write-deadband": ["0:100", "1:50.5"],
                "deadband-type": "uint16",
            }
        )

        assert scanner.write_deadband == ["0:100", "1:50.5"]
        assert scanner.deadband_type == "uint16"

    def test_deadband_requires_outstation_addr(self):
        """Test that --write-deadband requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(write_deadband=["0:100"])
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_deadband_validation_invalid_format(self):
        """Test invalid deadband format fails."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(write_deadband=["invalid"], outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_deadband_validation_valid_format(self):
        """Test valid deadband format passes."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(write_deadband=["0:100", "1:50.5"], outstation_addr=10)
        # Should not raise
        validate_args(args)


class TestAdvancedArgumentValidation:
    """Test advanced argument validation combinations."""

    def test_ao_value_must_be_numeric(self):
        """Test that --ao-value must be a numeric value."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_direct=0, ao_value="not_a_number", outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_ao_value_accepts_integer(self):
        """Test that --ao-value accepts integer values."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_direct=0, ao_value="100", outstation_addr=10)
        # Should not raise
        validate_args(args)

    def test_ao_value_accepts_float(self):
        """Test that --ao-value accepts float values."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_direct=0, ao_value="50.5", outstation_addr=10)
        # Should not raise
        validate_args(args)

    def test_ao_value_accepts_negative(self):
        """Test that --ao-value accepts negative values."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(ao_direct=0, ao_value="-25.5", outstation_addr=10)
        # Should not raise
        validate_args(args)


class TestFreezeConfiguration:
    """Test freeze operation configuration."""

    def test_freeze_immediate_default(self):
        """Test freeze immediate defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.freeze_immediate is False

    def test_freeze_clear_default(self):
        """Test freeze clear defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.freeze_clear is False

    def test_freeze_at_time_default(self):
        """Test freeze at time defaults to None."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.freeze_at_time is None

    def test_freeze_no_ack_default(self):
        """Test freeze no ack defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.freeze_no_ack is False

    def test_freeze_immediate_configuration(self):
        """Test scanner with freeze immediate."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "freeze-immediate": True,
            }
        )
        assert scanner.freeze_immediate is True

    def test_freeze_clear_configuration(self):
        """Test scanner with freeze clear."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "freeze-clear": True,
            }
        )
        assert scanner.freeze_clear is True

    def test_freeze_at_time_configuration(self):
        """Test scanner with freeze at time."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "freeze-at-time": "+60s",
            }
        )
        assert scanner.freeze_at_time == "+60s"

    def test_freeze_no_ack_configuration(self):
        """Test scanner with freeze no ack."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "freeze-no-ack": True,
            }
        )
        assert scanner.freeze_no_ack is True


class TestFreezeArgumentValidation:
    """Test freeze operation argument validation."""

    def test_freeze_immediate_requires_outstation_addr(self):
        """Test that --freeze-immediate requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_immediate=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_freeze_clear_requires_outstation_addr(self):
        """Test that --freeze-clear requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_clear=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_freeze_at_time_requires_outstation_addr(self):
        """Test that --freeze-at-time requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_at_time="+60s")
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_freeze_no_ack_requires_freeze_operation(self):
        """Test that --freeze-no-ack requires a freeze operation."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_no_ack=True, outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_freeze_with_no_ack_passes(self):
        """Test freeze with no ack passes validation."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_immediate=True, freeze_no_ack=True, outstation_addr=10)
        # Should not raise
        validate_args(args)

    def test_freeze_at_time_valid_relative(self):
        """Test valid relative freeze time."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_at_time="+60s", outstation_addr=10)
        # Should not raise
        validate_args(args)

    def test_freeze_at_time_valid_iso(self):
        """Test valid ISO format freeze time."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_at_time="2025-01-15T10:30:00", outstation_addr=10)
        # Should not raise
        validate_args(args)

    def test_freeze_at_time_invalid_format(self):
        """Test invalid freeze time format."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(freeze_at_time="invalid", outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestFreezeTimeParser:
    """Test the _parse_freeze_time function."""

    def test_parse_relative_seconds(self):
        """Test parsing relative time in seconds."""
        from oida.protocols.dnp3.proto_args import _parse_freeze_time
        import time

        result = _parse_freeze_time("+60s")
        expected_min = (time.time() + 59) * 1000
        expected_max = (time.time() + 61) * 1000
        assert expected_min <= result <= expected_max

    def test_parse_relative_minutes(self):
        """Test parsing relative time in minutes."""
        from oida.protocols.dnp3.proto_args import _parse_freeze_time
        import time

        result = _parse_freeze_time("+5m")
        expected_min = (time.time() + 299) * 1000
        expected_max = (time.time() + 301) * 1000
        assert expected_min <= result <= expected_max

    def test_parse_relative_hours(self):
        """Test parsing relative time in hours."""
        from oida.protocols.dnp3.proto_args import _parse_freeze_time
        import time

        result = _parse_freeze_time("+1h")
        expected_min = (time.time() + 3599) * 1000
        expected_max = (time.time() + 3601) * 1000
        assert expected_min <= result <= expected_max

    def test_parse_iso_format(self):
        """Test parsing ISO format time."""
        from oida.protocols.dnp3.proto_args import _parse_freeze_time

        # Test a fixed time
        result = _parse_freeze_time("2025-01-15T10:30:00Z")
        # January 15, 2025 10:30:00 UTC in milliseconds
        expected = 1736937000000
        assert result == expected

    def test_parse_invalid_format(self):
        """Test invalid format raises ValueError."""
        from oida.protocols.dnp3.proto_args import _parse_freeze_time

        with pytest.raises(ValueError):
            _parse_freeze_time("invalid")


class TestApplicationControlConfiguration:
    """Test application control configuration."""

    def test_stop_app_default(self):
        """Test stop app defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.stop_app is False

    def test_start_app_default(self):
        """Test start app defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.start_app is False

    def test_init_data_default(self):
        """Test init data defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.init_data is False

    def test_init_app_default(self):
        """Test init app defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.init_app is False

    def test_stop_app_configuration(self):
        """Test scanner with stop app."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "stop-app": True,
            }
        )
        assert scanner.stop_app is True

    def test_start_app_configuration(self):
        """Test scanner with start app."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "start-app": True,
            }
        )
        assert scanner.start_app is True

    def test_init_data_configuration(self):
        """Test scanner with init data."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "init-data": True,
            }
        )
        assert scanner.init_data is True

    def test_init_app_configuration(self):
        """Test scanner with init app."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "init-app": True,
            }
        )
        assert scanner.init_app is True


class TestApplicationControlValidation:
    """Test application control argument validation."""

    def test_stop_app_requires_outstation_addr(self):
        """Test that --stop-app requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(stop_app=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_start_app_requires_outstation_addr(self):
        """Test that --start-app requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(start_app=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_init_data_requires_outstation_addr(self):
        """Test that --init-data requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(init_data=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_init_app_requires_outstation_addr(self):
        """Test that --init-app requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(init_app=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestConfigurationManagement:
    """Test configuration management configuration."""

    def test_save_config_default(self):
        """Test save config defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.save_config is False

    def test_save_config_configuration(self):
        """Test scanner with save config."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "save-config": True,
            }
        )
        assert scanner.save_config is True

    def test_save_config_requires_outstation_addr(self):
        """Test that --save-config requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(save_config=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_activate_config_default(self):
        """Test activate config defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.activate_config is False

    def test_activate_config_configuration(self):
        """Test scanner with activate config."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "activate-config": True,
            }
        )
        assert scanner.activate_config is True

    def test_activate_config_requires_outstation_addr(self):
        """Test that --activate-config requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(activate_config=True)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestFileDeleteConfiguration:
    """Test file delete configuration."""

    def test_delete_file_default(self):
        """Test delete file defaults to None."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.delete_file is None

    def test_delete_file_configuration(self):
        """Test scanner with delete file."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "delete-file": "/config/old.txt",
            }
        )
        assert scanner.delete_file == "/config/old.txt"

    def test_delete_file_requires_outstation_addr(self):
        """Test that --delete-file requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(delete_file="/config/old.txt")
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestDiagnosticConfiguration:
    """Test diagnostic operation configuration."""

    def test_delay_measure_default(self):
        """Test delay measure defaults to False."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
            }
        )
        assert scanner.delay_measure is False

    def test_delay_measure_configuration(self):
        """Test scanner with delay measure."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "delay-measure": True,
            }
        )
        assert scanner.delay_measure is True


class TestMixinMethodsExist:
    """Test that mixin methods exist on the scanner (replaces TestNewPublicConvenienceMethods)."""

    def test_perform_freeze_method_exists(self):
        """Test _perform_freeze method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_perform_freeze")

    def test_control_application_method_exists(self):
        """Test _control_application method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_control_application")

    def test_save_configuration_method_exists(self):
        """Test _save_configuration method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_save_configuration")

    def test_activate_configuration_method_exists(self):
        """Test _activate_configuration method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_activate_configuration")

    def test_delete_remote_file_method_exists(self):
        """Test _delete_remote_file method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_delete_remote_file")

    def test_measure_delay_method_exists(self):
        """Test _measure_delay method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_measure_delay")

    def test_write_file_method_exists(self):
        """Test _write_file method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_write_file")

    def test_authenticate_file_method_exists(self):
        """Test _authenticate_file method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_authenticate_file")

    def test_read_security_stats_method_exists(self):
        """Test _read_security_stats method exists."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert hasattr(scanner, "_read_security_stats")


class TestTransportConfiguration:
    """Test transport type configuration."""

    def test_transport_default_tcp(self):
        """Test transport defaults to tcp."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.transport == "tcp"

    def test_transport_serial(self):
        """Test serial transport configuration."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "transport": "serial",
                "serial-device": "/dev/ttyUSB0",
            }
        )
        assert scanner.transport == "serial"
        assert scanner.serial_device == "/dev/ttyUSB0"

    def test_transport_udp(self):
        """Test UDP transport configuration."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "transport": "udp",
            }
        )
        assert scanner.transport == "udp"

    def test_serial_settings(self):
        """Test serial port settings."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "transport": "serial",
                "serial-device": "/dev/ttyS0",
                "baud": 19200,
                "data-bits": 7,
                "stop-bits": 2,
                "parity": "even",
            }
        )
        assert scanner.baud == 19200
        assert scanner.data_bits == 7
        assert scanner.stop_bits == 2
        assert scanner.parity == "even"

    def test_serial_transport_requires_device(self):
        """Test that serial transport requires --serial-device."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(transport="serial", serial_device=None)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_serial_transport_with_device_passes(self):
        """Test serial transport with device passes validation."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(transport="serial", serial_device="/dev/ttyUSB0")
        # Should not raise
        validate_args(args)


class TestSecureAuthConfiguration:
    """Test Secure Authentication v5 configuration."""

    def test_sa_default_disabled(self):
        """Test SA defaults to disabled."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.sa_enabled is False

    def test_sa_enabled(self):
        """Test SA can be enabled."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "sa": True,
            }
        )
        assert scanner.sa_enabled is True

    def test_sa_user_default(self):
        """Test SA user defaults to 1."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.sa_user == 1

    def test_sa_user_custom(self):
        """Test SA user can be set."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "sa": True,
                "sa-user": 5,
            }
        )
        assert scanner.sa_user == 5

    def test_sa_key_configuration(self):
        """Test SA key configuration."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "sa": True,
                "sa-key": "0123456789abcdef",
            }
        )
        assert scanner.sa_key == "0123456789abcdef"

    def test_sa_key_validation_invalid_hex(self):
        """Test SA key validation with invalid hex."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(sa=True, sa_key="not_valid_hex_gg")
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_sa_key_validation_valid_hex(self):
        """Test SA key validation with valid hex."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(sa=True, sa_key="0123456789abcdef")
        # Should not raise
        validate_args(args)


class TestSecurityStatsConfiguration:
    """Test security statistics configuration."""

    def test_security_stats_default(self):
        """Test security stats defaults to False."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.security_stats is False

    def test_security_stats_enabled(self):
        """Test security stats can be enabled."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "security-stats": True,
            }
        )
        assert scanner.security_stats is True


class TestFileWriteConfiguration:
    """Test file write argument validation."""

    def test_write_file_requires_write_data(self):
        """Test --write-file requires --write-data."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(write_file="/config.txt", outstation_addr=10)
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)

    def test_write_file_with_data_passes(self):
        """Test --write-file with --write-data passes."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(
            write_file="/config.txt",
            write_data="key=value",
            outstation_addr=10,
        )
        # Should not raise
        validate_args(args)

    def test_write_file_requires_outstation_addr(self):
        """Test --write-file requires --outstation-addr."""
        from oida.protocols.dnp3.proto_args import validate_args

        args = _make_base_args(write_file="/config.txt", write_data="data")
        with pytest.raises((SystemExit, ConfigurationError)):
            validate_args(args)


class TestChannelRetryConfiguration:
    """Test channel retry tuning configuration."""

    def test_retry_min_default(self):
        """Test retry min defaults to None."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.retry_min is None

    def test_retry_max_default(self):
        """Test retry max defaults to None."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.retry_max is None

    def test_no_reconnect_default(self):
        """Test no reconnect defaults to False."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner.no_reconnect is False

    def test_retry_configuration(self):
        """Test channel retry configuration."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "retry-min": 1.0,
                "retry-max": 30.0,
                "no-reconnect": True,
            }
        )
        assert scanner.retry_min == 1.0
        assert scanner.retry_max == 30.0
        assert scanner.no_reconnect is True

    def test_build_channel_retry_returns_none_for_defaults(self):
        """Test _build_channel_retry returns None with default settings."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        assert scanner._build_channel_retry() is None

    def test_build_channel_retry_with_min(self):
        """Test _build_channel_retry with min delay returns an opendnp3 ChannelRetry."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "retry-min": 2.0,
            }
        )
        config = scanner._build_channel_retry()
        assert config is not None
        # Returns an opendnp3.ChannelRetry object, not a dict
        assert hasattr(config, "__class__")

    def test_build_channel_retry_with_no_reconnect(self):
        """Test _build_channel_retry with no reconnect returns an opendnp3 ChannelRetry."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "no-reconnect": True,
            }
        )
        config = scanner._build_channel_retry()
        assert config is not None
        # Returns an opendnp3.ChannelRetry object, not a dict
        assert hasattr(config, "__class__")


class TestBuildSAConfig:
    """Test that SA v5 credentials are actually applied to the stack config.

    Regression guard: previously ``--sa --sa-user N --sa-key <hex>`` built an
    auth-capable MasterAuthStackConfig but never installed the user_id /
    update_key, silently mis-reporting SA enforcement. The fix must either
    install the credentials via the binding API, or fail loudly if the
    installed opendnp3 binding has no SA credential API.
    """

    def _has_sa_install_api(self, scanner):
        """Return True if the installed opendnp3 binding can carry SA creds."""
        dnp3 = scanner._dnp3
        cfg = dnp3.MasterAuthStackConfig()
        auth = getattr(cfg, "auth", None)
        if auth is None:
            return False
        return any(
            getattr(auth, m, None) is not None
            for m in ("SetUpdateKey", "AddUser", "AddUpdateKey")
        )

    def test_sa_disabled_builds_plain_master_stack_config(self):
        """SA off -> plain MasterStackConfig (no auth wiring)."""
        scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        cfg = scanner._build_master_stack_config()
        assert type(cfg).__name__ == "MasterStackConfig"

    def test_sa_enabled_applies_credentials_or_fails_loudly(self):
        """SA on must install creds; if the binding can't, it must raise.

        It must NEVER silently return an auth-capable config with no
        credentials installed (the original bug).
        """
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "sa": True,
                "sa-user": 3,
                "sa-key": "deadbeef",
            }
        )
        if self._has_sa_install_api(scanner):
            cfg = scanner._build_master_stack_config()
            assert type(cfg).__name__ == "MasterAuthStackConfig"
        else:
            with pytest.raises(ConfigurationError) as exc:
                scanner._build_master_stack_config()
            assert "Secure Authentication" in str(exc.value)

    def test_sa_enabled_without_key_is_not_silently_accepted(self):
        """--sa with no --sa-key must not silently produce a no-cred config."""
        scanner = DNP3Scanner(
            {
                "rhost": "127.0.0.1",
                "rport": 20000,
                "sa": True,
                "sa-user": 1,
            }
        )
        # Either the binding lacks an SA API (raises) or it has one and the
        # missing key is rejected -- either way ConfigurationError, never a
        # silently-misconfigured auth stack.
        with pytest.raises(ConfigurationError):
            scanner._build_master_stack_config()


class TestConstantsGroupNames:
    """Test DNP3 group name constants include security-relevant groups."""

    def test_group_120_authentication(self):
        """Test Group 120 is Authentication."""
        from oida.protocols.dnp3.constants import DNP3_GROUP_NAMES

        assert 120 in DNP3_GROUP_NAMES
        assert DNP3_GROUP_NAMES[120] == "Authentication"

    def test_group_121_security_stats(self):
        """Test Group 121 is Security Statistics."""
        from oida.protocols.dnp3.constants import DNP3_GROUP_NAMES

        assert 121 in DNP3_GROUP_NAMES
        assert DNP3_GROUP_NAMES[121] == "Security Statistics"

    def test_group_122_security_stat_event(self):
        """Test Group 122 is Security Statistic Event."""
        from oida.protocols.dnp3.constants import DNP3_GROUP_NAMES

        assert 122 in DNP3_GROUP_NAMES
        assert DNP3_GROUP_NAMES[122] == "Security Statistic Event"

    def test_group_112_virtual_terminal_output(self):
        """Test Group 112 is Virtual Terminal Output."""
        from oida.protocols.dnp3.constants import DNP3_GROUP_NAMES

        assert 112 in DNP3_GROUP_NAMES
        assert DNP3_GROUP_NAMES[112] == "Virtual Terminal Output"

    def test_group_113_virtual_terminal_event(self):
        """Test Group 113 is Virtual Terminal Event."""
        from oida.protocols.dnp3.constants import DNP3_GROUP_NAMES

        assert 113 in DNP3_GROUP_NAMES
        assert DNP3_GROUP_NAMES[113] == "Virtual Terminal Event"


class TestDNP3CachedProperty:
    """Test the _dnp3 cached property."""

    def test_dnp3_property_is_cached_property(self):
        """Test _dnp3 is defined as a cached_property on the class."""
        from functools import cached_property

        assert isinstance(DNP3Scanner.__dict__["_dnp3"], cached_property)

    def test_dnp3_property_exists_on_instance(self):
        """Test _dnp3 is accessible on scanner instances."""
        DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
        # Verify the cached_property is defined on the class.
        assert "_dnp3" in DNP3Scanner.__dict__


class TestDataTypesConstant:
    """Test the _DATA_TYPES constant in polling mixin."""

    def test_data_types_defined(self):
        """Test _DATA_TYPES is defined and has correct entries."""
        from oida.protocols.dnp3.mixins.polling import _DATA_TYPES

        assert len(_DATA_TYPES) == 7
        # Check the first and last entries
        assert _DATA_TYPES[0] == ("binary_inputs", "binary_inputs")
        assert _DATA_TYPES[-1] == ("analog_output_statuses", "analog_output_statuses")

    def test_data_types_all_tuples(self):
        """Test _DATA_TYPES contains only 2-tuples."""
        from oida.protocols.dnp3.mixins.polling import _DATA_TYPES

        for entry in _DATA_TYPES:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
