"""
Unit tests for IEC 104 protocol argument parser.

Tests the proto_args module that defines CLI argument parsing for the IEC 104 protocol.
"""

import argparse
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Default target to use in tests (target is a required positional arg)
T = "192.168.1.100"


def get_proto_args():
    """Import proto_args function directly, bypassing package __init__.py."""
    import importlib.util

    proto_args_path = PROJECT_ROOT / "src" / "oida" / "protocols" / "iec104" / "proto_args.py"

    spec = importlib.util.spec_from_file_location(
        "oida.protocols.iec104.proto_args", proto_args_path
    )
    proto_args_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proto_args_mod)

    return proto_args_mod.proto_args


@pytest.fixture
def parser_setup():
    """Set up argparse parser with IEC 104 subparser."""
    proto_args = get_proto_args()

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="protocol")
    std_parser = argparse.ArgumentParser(add_help=False)

    iec104_parser = proto_args(subparsers, [std_parser])
    return parser, iec104_parser


class TestProtoArgsRegistration:
    """Test argument parser creation and registration."""

    def test_proto_args_returns_parser(self, parser_setup):
        parser, iec104_parser = parser_setup
        assert iec104_parser is not None

    def test_parser_name(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.protocol == "iec104"

    def test_parser_description(self, parser_setup):
        _, iec104_parser = parser_setup
        assert (
            "IEC 104" in iec104_parser.description or "iec104" in iec104_parser.description.lower()
        )


class TestNetworkOptions:
    """Test Network Options group."""

    def test_port_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.port == 2404

    def test_port_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--port", "19998"])
        assert args.port == 19998

    def test_timeout_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.timeout == 2  # Default from add_network_options

    def test_timeout_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--timeout", "30"])
        assert args.timeout == 30.0


class TestTargetArgument:
    """Test target positional argument."""

    def test_target_provided(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", "10.0.0.1"])
        assert args.target == "10.0.0.1"

    def test_target_required(self, parser_setup):
        """Test that target is required (not optional)."""
        parser, _ = parser_setup
        with pytest.raises(SystemExit):
            parser.parse_args(["iec104"])


class TestTLSOptions:
    """Test TLS argument group."""

    def test_tls_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--tls"])
        assert args.tls is True

    def test_tls_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.tls is False

    def test_tls_cert(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--tls-cert", "/path/to/cert.pem"])
        assert args.tls_cert == "/path/to/cert.pem"

    def test_tls_key(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--tls-key", "/path/to/key.pem"])
        assert args.tls_key == "/path/to/key.pem"


class TestIEC101SerialMode:
    """Test IEC 101 serial mode argument group."""

    def test_iec101_full_config(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--iec101", "/dev/ttyUSB0:9600:E:1"])
        assert args.iec101 == "/dev/ttyUSB0:9600:E:1"

    def test_iec101_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.iec101 is None

    def test_list_ports_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--list-ports"])
        assert args.list_ports is True

    def test_link_address_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.link_address == 1

    def test_link_address_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--link-address", "5"])
        assert args.link_address == 5

    def test_balanced_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--balanced"])
        assert args.balanced is True

    def test_balanced_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.balanced is False


class TestScanPhaseFlags:
    """Test scan phase flags."""

    def test_interrogate_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-I"])
        assert args.interrogate is True

    def test_interrogate_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--interrogate"])
        assert args.interrogate is True

    def test_interrogate_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.interrogate is False


class TestIEC104Options:
    """Test IEC 104 options group."""

    def test_asdu_address_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-a", "10"])
        assert args.asdu_address == 10

    def test_asdu_address_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--asdu-address", "10"])
        assert args.asdu_address == 10

    def test_asdu_address_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.asdu_address == -1  # -1 means auto-discover

    def test_ioa_range_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-r", "0-1000"])
        assert args.ioa_range == "0-1000"

    def test_ioa_range_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--ioa-range", "100-5000"])
        assert args.ioa_range == "100-5000"

    def test_common_address_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-c", "5"])
        assert args.common_address == 5

    def test_common_address_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--common-address", "10"])
        assert args.common_address == 10

    def test_max_commands_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.max_commands == 100

    def test_max_commands_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--max-commands", "50"])
        assert args.max_commands == 50

    def test_wait_time_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-w", "10"])
        assert args.wait_time == 10

    def test_wait_time_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.wait_time == 3

    def test_probe_custom_types_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-X"])
        assert args.probe_custom_types is True

    def test_probe_custom_types_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--probe-custom-types"])
        assert args.probe_custom_types is True


class TestFileTransferOptions:
    """Test file transfer argument group."""

    def test_probe_files_long_only(self, parser_setup):
        """Test --probe-files works (long flag only, no -P short flag — W5 fix)."""
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--probe-files"])
        assert args.probe_files is True

    def test_no_P_short_flag(self, parser_setup):
        """Verify -P is NOT a valid short flag (W5 fix)."""
        parser, _ = parser_setup
        with pytest.raises(SystemExit):
            parser.parse_args(["iec104", T, "-P"])

    def test_download_file(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-D", "1000"])
        assert args.download_file == 1000

    def test_download_file_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--download-file", "2000"])
        assert args.download_file == 2000

    def test_delete_file(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--delete-file", "500"])
        assert args.delete_file == 500

    def test_upload_file(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--upload-file", "/tmp/test.bin"])
        assert args.upload_file == "/tmp/test.bin"

    def test_upload_ioa(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--upload-ioa", "1000"])
        assert args.upload_ioa == 1000

    def test_upload_nof_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.upload_nof == 1

    def test_upload_nof_choices(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--upload-nof", "2"])
        assert args.upload_nof == 2

    def test_upload_nof_invalid(self, parser_setup):
        parser, _ = parser_setup
        with pytest.raises(SystemExit):
            parser.parse_args(["iec104", T, "--upload-nof", "3"])

    def test_query_log(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--query-log", "1000"])
        assert args.query_log == 1000

    def test_log_start(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--log-start", "2024-01-01T00:00:00"])
        assert args.log_start == "2024-01-01T00:00:00"

    def test_log_end(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--log-end", "now"])
        assert args.log_end == "now"

    def test_log_type_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.log_type == 2

    def test_log_type_choices(self, parser_setup):
        parser, _ = parser_setup
        for choice in [1, 2, 3, 4]:
            args = parser.parse_args(["iec104", T, "--log-type", str(choice)])
            assert args.log_type == choice

    def test_log_type_invalid(self, parser_setup):
        parser, _ = parser_setup
        with pytest.raises(SystemExit):
            parser.parse_args(["iec104", T, "--log-type", "5"])


class TestReadOperations:
    """Test read operation argument group."""

    def test_read_ioa_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-R", "100,200,300"])
        assert args.read_ioa == "100,200,300"

    def test_read_ioa_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--read-ioa", "1000"])
        assert args.read_ioa == "1000"

    def test_counter_interrogation_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-C"])
        assert args.counter_interrogation is True

    def test_counter_interrogation_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--counter-interrogation"])
        assert args.counter_interrogation is True

    def test_clock_read_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-K"])
        assert args.clock_read is True

    def test_clock_read_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--clock-read"])
        assert args.clock_read is True


class TestWriteOperations:
    """Test write operation argument group."""

    def test_write_single_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-W", "100"])
        assert args.write_single == "100"

    def test_write_single_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-single", "200"])
        assert args.write_single == "200"

    def test_write_single_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-W", "100:on"])
        assert args.write_single == "100:on"

    def test_write_double(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-double", "100"])
        assert args.write_double == "100"

    def test_write_double_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-double", "200:off"])
        assert args.write_double == "200:off"

    def test_write_float(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-float", "100"])
        assert args.write_float == "100"

    def test_write_float_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-float", "700:42.5"])
        assert args.write_float == "700:42.5"

    def test_write_scaled(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-scaled", "100"])
        assert args.write_scaled == "100"

    def test_write_scaled_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-scaled", "500:1234"])
        assert args.write_scaled == "500:1234"

    def test_write_normalized(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-normalized", "100"])
        assert args.write_normalized == "100"

    def test_write_normalized_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-normalized", "100:0.5"])
        assert args.write_normalized == "100:0.5"

    def test_write_step(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-step", "100"])
        assert args.write_step == "100"

    def test_write_step_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-step", "300:up"])
        assert args.write_step == "300:up"

    def test_value_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-V", "on"])
        assert args.value == "on"

    def test_value_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--value", "50.5"])
        assert args.value == "50.5"

    def test_select_execute(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--select-execute"])
        assert args.select_execute is True

    def test_write_type(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-type", "128"])
        assert args.write_type == 128

    def test_write_ioa(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--write-ioa", "100"])
        assert args.write_ioa == 100


class TestListenOptions:
    """Test listen mode argument group."""

    def test_listen_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--listen"])
        assert args.listen is True

    def test_listen_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.listen is False

    def test_listen_raw(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--listen-raw"])
        assert args.listen_raw is True


class TestDangerousOptions:
    """Test fuzzing and dangerous operation argument group."""

    def test_confirm_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--confirm"])
        assert args.confirm is True

    def test_confirm_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.confirm is False

    def test_fuzz_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--fuzz"])
        assert args.fuzz is True

    def test_fuzz_iterations_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.fuzz_iterations == 20

    def test_fuzz_iterations_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--fuzz-iterations", "100"])
        assert args.fuzz_iterations == 100

    def test_test_commands_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--test-commands"])
        assert args.test_commands is True

    def test_fuzz_ioa_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.fuzz_ioa == 1

    def test_fuzz_ioa_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--fuzz-ioa", "500"])
        assert args.fuzz_ioa == 500


class TestArgumentGroups:
    """Test that all expected argument groups exist."""

    def test_argument_groups_exist(self, parser_setup):
        _, iec104_parser = parser_setup
        group_titles = [group.title for group in iec104_parser._action_groups]

        assert "Network Options" in group_titles
        assert "IEC 101 Serial Mode" in group_titles
        assert "Scan Phase Flags" in group_titles
        assert "IEC 104 Options" in group_titles
        assert "Read Operations" in group_titles
        assert "Write Operations" in group_titles


class TestBooleanFlagsDefaults:
    """Test all boolean flags default to False."""

    def test_interrogate_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.interrogate is False

    def test_list_ports_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.list_ports is False

    def test_balanced_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.balanced is False

    def test_probe_custom_types_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.probe_custom_types is False

    def test_probe_files_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.probe_files is False

    def test_counter_interrogation_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.counter_interrogation is False

    def test_clock_read_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.clock_read is False

    def test_select_execute_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.select_execute is False

    def test_listen_raw_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.listen_raw is False

    def test_test_commands_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.test_commands is False

    def test_fuzz_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.fuzz is False


class TestValueArgumentsDefaults:
    """Test value arguments default to None."""

    def test_ioa_range_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.ioa_range is None

    def test_common_address_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.common_address is None

    def test_read_ioa_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.read_ioa is None

    def test_write_single_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_single is None

    def test_write_double_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_double is None

    def test_write_float_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_float is None

    def test_write_scaled_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_scaled is None

    def test_write_normalized_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_normalized is None

    def test_write_step_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_step is None

    def test_value_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.value is None

    def test_write_type_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_type is None

    def test_write_ioa_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.write_ioa is None

    def test_download_file_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.download_file is None

    def test_delete_file_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.delete_file is None

    def test_upload_file_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.upload_file is None

    def test_upload_ioa_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.upload_ioa is None

    def test_query_log_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.query_log is None

    def test_log_start_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.log_start is None

    def test_log_end_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.log_end is None

    def test_tls_cert_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.tls_cert is None

    def test_tls_key_default(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.tls_key is None


class TestHelpTextPresence:
    """Test that all arguments have help text."""

    def test_all_arguments_have_help(self, parser_setup):
        _, iec104_parser = parser_setup
        for action in iec104_parser._actions:
            if action.dest == "help":
                continue
            assert action.help is not None, f"Argument {action.dest} has no help text"
            assert len(action.help) > 0, f"Argument {action.dest} has empty help text"


class TestComplexUsageScenarios:
    """Test realistic command-line usage combinations."""

    def test_basic_discovery(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", "192.168.1.100"])
        assert args.target == "192.168.1.100"
        assert args.port == 2404

    def test_full_interrogation_scan(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-I", "-X", "--probe-files", "-w", "5"])
        assert args.interrogate is True
        assert args.probe_custom_types is True
        assert args.probe_files is True
        assert args.wait_time == 5

    def test_write_single_command(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-W", "100", "-V", "on", "--confirm"])
        assert args.write_single == "100"
        assert args.value == "on"
        assert args.confirm is True

    def test_write_single_combined_format(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-W", "100:on", "--confirm"])
        assert args.write_single == "100:on"
        assert args.confirm is True

    def test_write_float_setpoint(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            ["iec104", T, "--write-float", "200", "-V", "50.5", "--select-execute", "--confirm"]
        )
        assert args.write_float == "200"
        assert args.value == "50.5"
        assert args.select_execute is True

    def test_listen_mode(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--listen", "--listen-raw"])
        assert args.listen is True
        assert args.listen_raw is True

    def test_iec101_serial_mode(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "iec104",
                T,
                "--iec101",
                "/dev/ttyUSB0:9600:E:1",
                "--link-address",
                "5",
                "--balanced",
                "-I",
            ]
        )
        assert args.iec101 == "/dev/ttyUSB0:9600:E:1"
        assert args.link_address == 5
        assert args.balanced is True
        assert args.interrogate is True

    def test_file_download(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-D", "1000"])
        assert args.download_file == 1000

    def test_file_upload_with_confirm(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "iec104",
                T,
                "--upload-file",
                "/tmp/fw.bin",
                "--upload-ioa",
                "1000",
                "--upload-nof",
                "1",
                "--confirm",
            ]
        )
        assert args.upload_file == "/tmp/fw.bin"
        assert args.upload_ioa == 1000
        assert args.upload_nof == 1
        assert args.confirm is True

    def test_fuzzing_scenario(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            ["iec104", T, "--fuzz", "--fuzz-ioa", "100", "--fuzz-iterations", "50", "--confirm"]
        )
        assert args.fuzz is True
        assert args.fuzz_ioa == 100
        assert args.fuzz_iterations == 50
        assert args.confirm is True

    def test_tls_mode(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            ["iec104", T, "--tls", "--tls-cert", "/path/cert.pem", "--tls-key", "/path/key.pem"]
        )
        assert args.tls is True
        assert args.tls_cert == "/path/cert.pem"
        assert args.tls_key == "/path/key.pem"

    def test_read_operations_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-R", "100,200", "-C", "-K"])
        assert args.read_ioa == "100,200"
        assert args.counter_interrogation is True
        assert args.clock_read is True

    def test_custom_type_write(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            ["iec104", T, "--write-type", "128", "--write-ioa", "500", "-V", "42", "--confirm"]
        )
        assert args.write_type == 128
        assert args.write_ioa == 500
        assert args.value == "42"

    def test_log_query(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(
            [
                "iec104",
                T,
                "--query-log",
                "1000",
                "--log-start",
                "now-1h",
                "--log-end",
                "now",
                "--log-type",
                "3",
            ]
        )
        assert args.query_log == 1000
        assert args.log_start == "now-1h"
        assert args.log_end == "now"
        assert args.log_type == 3


class TestInterrogateGroupsFlag:
    """Test --interrogate-groups / -G flag."""

    def test_interrogate_groups_short(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-G"])
        assert args.interrogate_groups is True

    def test_interrogate_groups_long(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--interrogate-groups"])
        assert args.interrogate_groups is True

    def test_interrogate_groups_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.interrogate_groups is False

    def test_interrogate_and_groups_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "-I", "-G"])
        assert args.interrogate is True
        assert args.interrogate_groups is True


class TestProtocolParameterTuning:
    """Test --t1, --t3, --originator flags."""

    def test_t1_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--t1", "30"])
        assert args.t1 == 30

    def test_t1_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.t1 is None

    def test_t3_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--t3", "10"])
        assert args.t3 == 10

    def test_t3_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.t3 is None

    def test_originator_custom(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--originator", "42"])
        assert args.originator == 42

    def test_originator_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.originator is None

    def test_combined_protocol_params(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--t1", "20", "--t3", "5", "--originator", "10"])
        assert args.t1 == 20
        assert args.t3 == 5
        assert args.originator == 10


class TestResetProcessFlag:
    """Test --reset-process flag."""

    def test_reset_process_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--reset-process"])
        assert args.reset_process is True

    def test_reset_process_default_false(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.reset_process is False

    def test_reset_process_with_confirm(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--reset-process", "--confirm"])
        assert args.reset_process is True
        assert args.confirm is True


class TestParameterCommands:
    """Test --param-normalized, --param-scaled, --param-float, --param-activate flags."""

    def test_param_normalized(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-normalized", "100"])
        assert args.param_normalized == "100"

    def test_param_normalized_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-normalized", "100:0.5"])
        assert args.param_normalized == "100:0.5"

    def test_param_normalized_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.param_normalized is None

    def test_param_scaled(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-scaled", "200"])
        assert args.param_scaled == "200"

    def test_param_scaled_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-scaled", "200:1234"])
        assert args.param_scaled == "200:1234"

    def test_param_scaled_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.param_scaled is None

    def test_param_float(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-float", "300"])
        assert args.param_float == "300"

    def test_param_float_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-float", "300:3.14"])
        assert args.param_float == "300:3.14"

    def test_param_float_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.param_float is None

    def test_param_activate(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-activate", "0"])
        assert args.param_activate == "0"

    def test_param_activate_combined(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-activate", "0:1"])
        assert args.param_activate == "0:1"

    def test_param_activate_default_none(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T])
        assert args.param_activate is None

    def test_param_float_with_confirm_and_value(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-float", "100:3.14", "--confirm"])
        assert args.param_float == "100:3.14"
        assert args.confirm is True

    def test_param_activate_with_value_flag(self, parser_setup):
        parser, _ = parser_setup
        args = parser.parse_args(["iec104", T, "--param-activate", "0", "-V", "1", "--confirm"])
        assert args.param_activate == "0"
        assert args.value == "1"
        assert args.confirm is True
