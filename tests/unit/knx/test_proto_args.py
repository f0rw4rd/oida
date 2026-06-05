"""
Unit tests for KNX protocol argument parser.

Tests the proto_args module that defines CLI argument parsing for the KNX protocol.
"""

import argparse
import sys
from pathlib import Path
import pytest

# Add the project root to sys.path to allow direct import of proto_args
# without triggering the full knx package __init__.py which has scanner imports
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def get_proto_args():
    """Import proto_args function directly, bypassing package __init__.py."""
    import importlib.util

    proto_args_path = PROJECT_ROOT / "src" / "oida" / "protocols" / "knx" / "proto_args.py"

    # Load proto_args directly (no external dependencies after removing add_common_args)
    spec = importlib.util.spec_from_file_location("oida.protocols.knx.proto_args", proto_args_path)
    proto_args_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proto_args_mod)

    return proto_args_mod.proto_args


@pytest.fixture
def parser_setup():
    """Set up argparse parser with KNX subparser."""
    proto_args = get_proto_args()

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="protocol")
    std_parser = argparse.ArgumentParser(add_help=False)

    knx_parser = proto_args(subparsers, [std_parser])
    return parser, knx_parser


class TestProtoArgsRegistration:
    """Test argument parser creation and registration."""

    def test_proto_args_returns_parser(self, parser_setup):
        """Test that proto_args returns a valid parser."""
        parser, knx_parser = parser_setup
        assert knx_parser is not None

    def test_parser_name(self, parser_setup):
        """Test that parser is registered as 'knx'."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.protocol == "knx"

    def test_parser_help_text(self, parser_setup):
        """Test that parser has help and description."""
        _, knx_parser = parser_setup
        assert "KNX" in knx_parser.description or "knx" in knx_parser.description.lower()


class TestNetworkOptionsGroup:
    """Test Network Options argument group."""

    def test_port_default(self, parser_setup):
        """Test default port is 3671."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.port == 3671

    def test_port_custom(self, parser_setup):
        """Test custom port value."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--port", "3672"])
        assert args.port == 3672

    def test_timeout_default(self, parser_setup):
        """Test default timeout is 5.0 seconds."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.timeout == 5.0

    def test_timeout_custom(self, parser_setup):
        """Test custom timeout value."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--timeout", "10.0"])
        assert args.timeout == 10.0

    def test_nat_default(self, parser_setup):
        """Test NAT mode is enabled by default."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.nat is True

    def test_no_nat_flag(self, parser_setup):
        """Test --no-nat flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--no-nat"])
        assert args.no_nat is True


class TestTargetDefault:
    """Test target argument defaults and parsing."""

    def test_target_default_multicast(self, parser_setup):
        """Test default target is KNX multicast address 224.0.23.12."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.target == "224.0.23.12"

    def test_target_custom_unicast(self, parser_setup):
        """Test custom unicast target."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "192.168.1.100"])
        assert args.target == "192.168.1.100"

    def test_target_optional(self, parser_setup):
        """Test target is optional (nargs='?')."""
        parser, _ = parser_setup
        # Should not raise error when target is omitted
        args = parser.parse_args(["knx"])
        assert args.target is not None


class TestKNXOptionsGroup:
    """Test KNX Options argument group."""

    def test_interface_default(self, parser_setup):
        """Test interface default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.interface is None

    def test_interface_custom(self, parser_setup):
        """Test custom interface."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--interface", "eth0"])
        assert args.interface == "eth0"

    def test_tcp_flag(self, parser_setup):
        """Test --tcp flag for TCP tunneling."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--tcp"])
        assert args.tcp is True

    def test_tcp_default_false(self, parser_setup):
        """Test TCP flag is false by default."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.tcp is False

    def test_individual_address_short(self, parser_setup):
        """Test -i short form for individual address."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "-i", "1.1.1"])
        assert args.individual_address == "1.1.1"

    def test_individual_address_long(self, parser_setup):
        """Test --individual-address long form."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--individual-address", "2.2.5"])
        assert args.individual_address == "2.2.5"

    def test_group_address_short(self, parser_setup):
        """Test -g short form for group address."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "-g", "1/2/3"])
        assert args.group_address == "1/2/3"

    def test_group_address_long(self, parser_setup):
        """Test --group-address long form."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--group-address", "0/0/1"])
        assert args.group_address == "0/0/1"


class TestDeviceOperationsGroup:
    """Test Device Operations argument group."""

    def test_device_info_flag(self, parser_setup):
        """Test --device-info flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--device-info"])
        assert args.device_info is True

    def test_enumerate_objects_flag(self, parser_setup):
        """Test --enumerate-objects flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--enumerate-objects"])
        assert args.enumerate_objects is True

    def test_prog_mode_flag(self, parser_setup):
        """Test --prog-mode flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--prog-mode"])
        assert args.prog_mode is True

    def test_firmware_info_flag(self, parser_setup):
        """Test --firmware-info flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--firmware-info"])
        assert args.firmware_info is True

    def test_vendor_objects_flag(self, parser_setup):
        """Test --vendor-objects flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--vendor-objects"])
        assert args.vendor_objects is True

    def test_prop_dump_flag(self, parser_setup):
        """Test --prop-dump flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--prop-dump"])
        assert args.prop_dump is True

    def test_memory_dump(self, parser_setup):
        """Test --memory-dump argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--memory-dump", "0x0100:256"])
        assert args.memory_dump == "0x0100:256"

    def test_memory_ext(self, parser_setup):
        """Test --memory-ext argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--memory-ext", "0x010000:256"])
        assert args.memory_ext == "0x010000:256"

    def test_memory_user(self, parser_setup):
        """Test --memory-user argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--memory-user", "0x0100:128"])
        assert args.memory_user == "0x0100:128"

    def test_memory_write(self, parser_setup):
        """Test --memory-write argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--memory-write", "0x0116:00"])
        assert args.memory_write == "0x0116:00"

    def test_property_read(self, parser_setup):
        """Test --property-read argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--property-read", "0:78"])
        assert args.property_read == "0:78"

    def test_property_write(self, parser_setup):
        """Test --property-write argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--property-write", "0:78:00FA12"])
        assert args.property_write == "0:78:00FA12"

    def test_fuzz_property(self, parser_setup):
        """Test --fuzz-property argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--fuzz-property", "0:19"])
        assert args.fuzz_property == "0:19"

    def test_fuzz_iterations_default(self, parser_setup):
        """Test --fuzz-iterations default is 10."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.fuzz_iterations == 10

    def test_fuzz_iterations_custom(self, parser_setup):
        """Test custom --fuzz-iterations."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--fuzz-iterations", "100"])
        assert args.fuzz_iterations == 100

    def test_adc_read(self, parser_setup):
        """Test --adc-read argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--adc-read", "5"])
        assert args.adc_read == 5

    def test_group_write(self, parser_setup):
        """Test --group-write argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--group-write", "1/0/1:01"])
        assert args.group_write == "1/0/1:01"

    def test_restart_flag(self, parser_setup):
        """Test --restart flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--restart"])
        assert args.restart is True

    def test_confirm_flag(self, parser_setup):
        """Test --confirm flag for dangerous operations."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--confirm"])
        assert args.confirm is True

    def test_prop_desc(self, parser_setup):
        """Test --prop-desc argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--prop-desc", "0:78"])
        assert args.prop_desc == "0:78"


class TestReconnaissanceGroup:
    """Test Reconnaissance argument group."""

    def test_gateway_scan_flag(self, parser_setup):
        """Test --gateway-scan flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--gateway-scan"])
        assert args.gateway_scan is True

    def test_bus_scan_flag(self, parser_setup):
        """Test --bus-scan flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--bus-scan"])
        assert args.bus_scan is True

    def test_listen_flag(self, parser_setup):
        """Test --listen flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--listen"])
        assert args.listen is True

    def test_listen_time_short(self, parser_setup):
        """Test -L short form for listen time."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "-L", "60"])
        assert args.listen_time == 60

    def test_listen_time_long(self, parser_setup):
        """Test --listen-time long form."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--listen-time", "120"])
        assert args.listen_time == 120

    def test_listen_time_default(self, parser_setup):
        """Test --listen-time default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.listen_time is None

    def test_slow_scan_flag(self, parser_setup):
        """Test --slow-scan flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--slow-scan"])
        assert args.slow_scan is True

    def test_serial_scan(self, parser_setup):
        """Test --serial-scan argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--serial-scan", "00FA12345678"])
        assert args.serial_scan == "00FA12345678"

    def test_scan_range_short(self, parser_setup):
        """Test -r short form for scan range."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "-r", "1.1.1-1.1.255"])
        assert args.scan_range == "1.1.1-1.1.255"

    def test_scan_range_long(self, parser_setup):
        """Test --scan-range long form."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--scan-range", "2.1.1-2.1.10"])
        assert args.scan_range == "2.1.1-2.1.10"

    def test_scan_range_all(self, parser_setup):
        """Test --scan-range with '-' for all."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--scan-range", "-"])
        assert args.scan_range == "-"

    def test_scan_range_multiple(self, parser_setup):
        """Test --scan-range with multiple ranges."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--scan-range", "1.1.1-1.1.5,2.2.1-2.2.10"])
        assert args.scan_range == "1.1.1-1.1.5,2.2.1-2.2.10"


class TestAuthenticationGroup:
    """Test Authentication argument group."""

    def test_auth_test_default_key(self, parser_setup):
        """Test --auth-test with default factory key."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--auth-test"])
        assert args.auth_test == "FFFFFFFF"

    def test_auth_test_custom_key(self, parser_setup):
        """Test --auth-test with custom key."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--auth-test", "12345678"])
        assert args.auth_test == "12345678"

    def test_key_file(self, parser_setup):
        """Test --key-file argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--key-file", "/path/to/keys.txt"])
        assert args.key_file == "/path/to/keys.txt"

    def test_key_range(self, parser_setup):
        """Test --key-range argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--key-range", "00000000-000000FF"])
        assert args.key_range == "00000000-000000FF"

    def test_brute_delay_default(self, parser_setup):
        """Test --brute-delay default is 100ms."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.brute_delay == 100

    def test_brute_delay_custom(self, parser_setup):
        """Test custom --brute-delay."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--brute-delay", "50"])
        assert args.brute_delay == 50

    def test_continue_on_success_default(self, parser_setup):
        """Test --continue-on-success is default False (stop on first success)."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.continue_on_success is False

    def test_continue_on_success_flag(self, parser_setup):
        """Test --continue-on-success flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--continue-on-success"])
        assert args.continue_on_success is True

    def test_key_write(self, parser_setup):
        """Test --key-write argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--key-write", "FFFFFFFF:0"])
        assert args.key_write == "FFFFFFFF:0"


class TestETSProjectGroup:
    """Test ETS Project Operations argument group."""

    def test_knxproj(self, parser_setup):
        """Test --knxproj argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj", "/path/to/project.knxproj"])
        assert args.knxproj == "/path/to/project.knxproj"

    def test_knxproj_password(self, parser_setup):
        """Test --knxproj-password argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj-password", "secret123"])
        assert args.knxproj_password == "secret123"

    def test_knxproj_wordlist(self, parser_setup):
        """Test --knxproj-wordlist argument."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj-wordlist", "/path/to/wordlist.txt"])
        assert args.knxproj_wordlist == "/path/to/wordlist.txt"

    def test_knxproj_threads_default(self, parser_setup):
        """Test --knxproj-threads default is 16."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj_threads == 16

    def test_knxproj_threads_custom(self, parser_setup):
        """Test custom --knxproj-threads."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj-threads", "32"])
        assert args.knxproj_threads == 32

    def test_knxproj_info_flag(self, parser_setup):
        """Test --knxproj-info flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj-info"])
        assert args.knxproj_info is True

    def test_knxproj_hash_flag(self, parser_setup):
        """Test --knxproj-hash flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj-hash"])
        assert args.knxproj_hash is True

    def test_knxproj_fast_flag(self, parser_setup):
        """Test --knxproj-fast flag."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--knxproj-fast"])
        assert args.knxproj_fast is True


class TestCommonArgs:
    """Test common arguments - these are now on the main parser, not subparser.

    The flags --output, --verbose, --debug, --format are provided by the
    main CLI parser (cli.py) and inherited by all protocol subparsers.
    KNX proto_args no longer calls add_common_args() directly.
    """

    def test_common_args_not_on_subparser(self, parser_setup):
        """Verify common args are NOT duplicated on the KNX subparser."""
        _, knx_parser = parser_setup
        subparser_dests = {a.dest for a in knx_parser._actions}
        # These should NOT be on the subparser (they're on the main parser)
        assert "output" not in subparser_dests
        assert "format" not in subparser_dests
        assert "verbose" not in subparser_dests
        assert "debug" not in subparser_dests


class TestBooleanFlagsDefaults:
    """Test default values for all boolean flags are False."""

    def test_tcp_default_false(self, parser_setup):
        """Test --tcp default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.tcp is False

    def test_device_info_default_false(self, parser_setup):
        """Test --device-info default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.device_info is False

    def test_enumerate_objects_default_false(self, parser_setup):
        """Test --enumerate-objects default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.enumerate_objects is False

    def test_prog_mode_default_false(self, parser_setup):
        """Test --prog-mode default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.prog_mode is False

    def test_firmware_info_default_false(self, parser_setup):
        """Test --firmware-info default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.firmware_info is False

    def test_vendor_objects_default_false(self, parser_setup):
        """Test --vendor-objects default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.vendor_objects is False

    def test_prop_dump_default_false(self, parser_setup):
        """Test --prop-dump default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.prop_dump is False

    def test_restart_default_false(self, parser_setup):
        """Test --restart default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.restart is False

    def test_confirm_default_false(self, parser_setup):
        """Test --confirm default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.confirm is False

    def test_gateway_scan_default_false(self, parser_setup):
        """Test --gateway-scan default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.gateway_scan is False

    def test_bus_scan_default_false(self, parser_setup):
        """Test --bus-scan default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.bus_scan is False

    def test_listen_default_false(self, parser_setup):
        """Test --listen default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.listen is False

    def test_slow_scan_default_false(self, parser_setup):
        """Test --slow-scan default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.slow_scan is False

    def test_continue_on_success_default_false(self, parser_setup):
        """Test --continue-on-success default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.continue_on_success is False

    def test_knxproj_info_default_false(self, parser_setup):
        """Test --knxproj-info default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj_info is False

    def test_knxproj_hash_default_false(self, parser_setup):
        """Test --knxproj-hash default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj_hash is False

    def test_knxproj_fast_default_false(self, parser_setup):
        """Test --knxproj-fast default is False."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj_fast is False


class TestValueArgumentsDefaults:
    """Test default values for value arguments."""

    def test_interface_default_none(self, parser_setup):
        """Test --interface default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.interface is None

    def test_individual_address_default_none(self, parser_setup):
        """Test --individual-address default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.individual_address is None

    def test_group_address_default_none(self, parser_setup):
        """Test --group-address default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.group_address is None

    def test_memory_dump_default_none(self, parser_setup):
        """Test --memory-dump default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.memory_dump is None

    def test_memory_ext_default_none(self, parser_setup):
        """Test --memory-ext default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.memory_ext is None

    def test_memory_user_default_none(self, parser_setup):
        """Test --memory-user default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.memory_user is None

    def test_memory_write_default_none(self, parser_setup):
        """Test --memory-write default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.memory_write is None

    def test_property_read_default_none(self, parser_setup):
        """Test --property-read default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.property_read is None

    def test_property_write_default_none(self, parser_setup):
        """Test --property-write default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.property_write is None

    def test_fuzz_property_default_none(self, parser_setup):
        """Test --fuzz-property default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.fuzz_property is None

    def test_adc_read_default_none(self, parser_setup):
        """Test --adc-read default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.adc_read is None

    def test_group_write_default_none(self, parser_setup):
        """Test --group-write default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.group_write is None

    def test_serial_scan_default_none(self, parser_setup):
        """Test --serial-scan default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.serial_scan is None

    def test_scan_range_default_none(self, parser_setup):
        """Test --scan-range default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.scan_range is None

    def test_key_file_default_none(self, parser_setup):
        """Test --key-file default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.key_file is None

    def test_key_range_default_none(self, parser_setup):
        """Test --key-range default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.key_range is None

    def test_key_write_default_none(self, parser_setup):
        """Test --key-write default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.key_write is None

    def test_knxproj_default_none(self, parser_setup):
        """Test --knxproj default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj is None

    def test_knxproj_password_default_none(self, parser_setup):
        """Test --knxproj-password default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj_password is None

    def test_knxproj_wordlist_default_none(self, parser_setup):
        """Test --knxproj-wordlist default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.knxproj_wordlist is None

    def test_prop_desc_default_none(self, parser_setup):
        """Test --prop-desc default is None."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx"])
        assert args.prop_desc is None


class TestHelpTextPresence:
    """Test that all arguments have help text."""

    def test_all_arguments_have_help(self, parser_setup):
        """Test all registered arguments have help text."""
        _, knx_parser = parser_setup

        # Get all actions (arguments) from the parser
        for action in knx_parser._actions:
            # Skip help action itself
            if action.dest == "help":
                continue
            # All arguments should have non-empty help
            assert action.help is not None, f"Argument {action.dest} has no help text"
            assert len(action.help) > 0, f"Argument {action.dest} has empty help text"


class TestArgumentGroups:
    """Test that all argument groups are created."""

    def test_argument_groups_exist(self, parser_setup):
        """Test that expected argument groups are created."""
        _, knx_parser = parser_setup

        # Get all group titles
        group_titles = [group.title for group in knx_parser._action_groups]

        # Check for expected groups
        assert "Network Options" in group_titles
        assert "KNX Options" in group_titles
        assert "Device Operations" in group_titles
        assert "Reconnaissance" in group_titles
        assert "Authentication" in group_titles
        assert "ETS Project Operations" in group_titles


class TestComplexUsageScenarios:
    """Test complex command-line usage scenarios."""

    def test_gateway_discovery_mode(self, parser_setup):
        """Test gateway discovery command."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "--gateway-scan", "--timeout", "10"])
        assert args.gateway_scan is True
        assert args.timeout == 10.0
        assert args.target == "224.0.23.12"

    def test_bus_scan_with_range(self, parser_setup):
        """Test bus scan with custom range."""
        parser, _ = parser_setup
        args = parser.parse_args(
            ["knx", "192.168.1.100", "--bus-scan", "--scan-range", "1.1.1-1.1.50"]
        )
        assert args.target == "192.168.1.100"
        assert args.bus_scan is True
        assert args.scan_range == "1.1.1-1.1.50"

    def test_device_info_collection(self, parser_setup):
        """Test device info collection command."""
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "knx",
                "192.168.1.100",
                "-i",
                "1.1.1",
                "--device-info",
                "--firmware-info",
                "--enumerate-objects",
            ]
        )
        assert args.target == "192.168.1.100"
        assert args.individual_address == "1.1.1"
        assert args.device_info is True
        assert args.firmware_info is True
        assert args.enumerate_objects is True

    def test_memory_dump_scenario(self, parser_setup):
        """Test memory dump command."""
        parser, _ = parser_setup
        args = parser.parse_args(
            ["knx", "192.168.1.100", "-i", "1.1.1", "--memory-dump", "0x0100:512"]
        )
        assert args.individual_address == "1.1.1"
        assert args.memory_dump == "0x0100:512"

    def test_auth_testing_scenario(self, parser_setup):
        """Test authentication testing command."""
        parser, _ = parser_setup
        args = parser.parse_args(
            ["knx", "192.168.1.100", "-i", "1.1.1", "--auth-test", "--brute-delay", "50"]
        )
        assert args.auth_test == "FFFFFFFF"
        assert args.brute_delay == 50

    def test_key_bruteforce_scenario(self, parser_setup):
        """Test key bruteforce command."""
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "knx",
                "192.168.1.100",
                "-i",
                "1.1.1",
                "--key-range",
                "00000000-0000FFFF",
                "--brute-delay",
                "25",
                "--continue-on-success",
            ]
        )
        assert args.key_range == "00000000-0000FFFF"
        assert args.brute_delay == 25
        assert args.continue_on_success is True

    def test_passive_listen_mode(self, parser_setup):
        """Test passive listen mode command."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "192.168.1.100", "--listen", "--listen-time", "300"])
        assert args.listen is True
        assert args.listen_time == 300

    def test_ets_project_cracking(self, parser_setup):
        """Test ETS project cracking command."""
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "knx",
                "--knxproj",
                "/path/to/project.knxproj",
                "--knxproj-wordlist",
                "/path/to/wordlist.txt",
                "--knxproj-threads",
                "64",
            ]
        )
        assert args.knxproj == "/path/to/project.knxproj"
        assert args.knxproj_wordlist == "/path/to/wordlist.txt"
        assert args.knxproj_threads == 64

    def test_dangerous_operation_with_confirm(self, parser_setup):
        """Test dangerous operation requiring confirmation."""
        parser, _ = parser_setup
        args = parser.parse_args(
            ["knx", "192.168.1.100", "-i", "1.1.1", "--memory-write", "0x0116:00", "--confirm"]
        )
        assert args.memory_write == "0x0116:00"
        assert args.confirm is True

    def test_property_fuzzing_scenario(self, parser_setup):
        """Test property fuzzing command."""
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "knx",
                "192.168.1.100",
                "-i",
                "1.1.1",
                "--fuzz-property",
                "0:19",
                "--fuzz-iterations",
                "50",
                "--confirm",
            ]
        )
        assert args.fuzz_property == "0:19"
        assert args.fuzz_iterations == 50
        assert args.confirm is True

    def test_tcp_tunneling_with_no_nat(self, parser_setup):
        """Test TCP tunneling without NAT mode."""
        parser, _ = parser_setup
        args = parser.parse_args(["knx", "192.168.1.100", "--tcp", "--no-nat"])
        assert args.tcp is True
        assert args.no_nat is True

    def test_full_output_options(self, parser_setup):
        """Test gateway scan with target (output/format/verbose/debug are on main parser)."""
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "knx",
                "192.168.1.100",
                "--gateway-scan",
            ]
        )
        assert args.target == "192.168.1.100"
        assert args.gateway_scan is True
