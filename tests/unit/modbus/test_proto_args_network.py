#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus proto_args network, TLS, and advanced options.

Tests argument parsing for network, TLS, modbus core, write operations,
diagnostics, device identification, and other advanced options.
"""

import pytest
import argparse


def create_parser():
    """Create a minimal argument parser for testing all options."""
    from oida.protocols.modbus.proto_args import proto_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="protocol")

    # Create parent parser with common args
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("-v", "--verbose", action="count", default=0)
    common_parser.add_argument("--format", type=str, default=None)
    common_parser.add_argument("-o", "--output", type=str, default=None)

    # Register modbus protocol
    proto_args(subparsers, [common_parser])

    return parser


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def parser():
    """Create argument parser."""
    return create_parser()


# =============================================================================
# Test Network Options
# =============================================================================


class TestNetworkOptions:
    """Tests for network options (--port, --timeout, --udp)."""

    def test_port_default(self, parser):
        """Test default port is 502."""
        args = parser.parse_args(["modbus", "192.168.1.100"])
        assert args.port == 502

    def test_port_custom(self, parser):
        """Test custom port."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--port", "1502"])
        assert args.port == 1502

    def test_port_short_flag(self, parser):
        """Test -p short flag for port."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-p", "5020"])
        assert args.port == 5020

    def test_timeout_default(self, parser):
        """Test default timeout."""
        args = parser.parse_args(["modbus", "192.168.1.100"])
        # Default is typically 5 or 10 seconds
        assert hasattr(args, "timeout")

    def test_timeout_custom(self, parser):
        """Test custom timeout."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--timeout", "30"])
        assert args.timeout == 30

    def test_udp_flag(self, parser):
        """Test --udp flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--udp"])
        assert args.udp is True

    def test_udp_default_false(self, parser):
        """Test UDP defaults to False."""
        args = parser.parse_args(["modbus", "192.168.1.100"])
        assert args.udp is False

    def test_rtu_over_tcp_flag(self, parser):
        """Test --rtu-over-tcp flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--rtu-over-tcp"])
        assert args.rtu_over_tcp is True

    def test_ascii_over_tcp_flag(self, parser):
        """Test --ascii-over-tcp flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--ascii-over-tcp"])
        assert args.ascii_over_tcp is True


# =============================================================================
# Test TLS Options
# =============================================================================


class TestTLSOptions:
    """Tests for TLS options (--tls, --tls-cert, --tls-key)."""

    def test_tls_flag(self, parser):
        """Test --tls flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--tls"])
        assert args.tls is True

    def test_tls_default_false(self, parser):
        """Test TLS defaults to False."""
        args = parser.parse_args(["modbus", "192.168.1.100"])
        assert args.tls is False

    def test_tls_cert_path(self, parser):
        """Test --tls-cert path."""
        args = parser.parse_args(
            ["modbus", "192.168.1.100", "--tls", "--tls-cert", "/path/to/cert.pem"]
        )
        assert args.tls_cert == "/path/to/cert.pem"

    def test_tls_key_path(self, parser):
        """Test --tls-key path."""
        args = parser.parse_args(
            ["modbus", "192.168.1.100", "--tls", "--tls-key", "/path/to/key.pem"]
        )
        assert args.tls_key == "/path/to/key.pem"

    def test_tls_with_cert_and_key(self, parser):
        """Test --tls with both cert and key."""
        args = parser.parse_args(
            [
                "modbus",
                "192.168.1.100",
                "--tls",
                "--tls-cert",
                "/path/to/cert.pem",
                "--tls-key",
                "/path/to/key.pem",
            ]
        )
        assert args.tls is True
        assert args.tls_cert == "/path/to/cert.pem"
        assert args.tls_key == "/path/to/key.pem"


# =============================================================================
# Test Modbus Core Options
# =============================================================================


class TestModbusCoreOptions:
    """Tests for Modbus core options (--unit-id, --scan-range, --register-type)."""

    def test_unit_id_default(self, parser):
        """Test default unit ID (None means scan all unit IDs)."""
        args = parser.parse_args(["modbus", "192.168.1.100"])
        assert args.unit_id is None

    def test_unit_id_custom(self, parser):
        """Test custom unit ID."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--unit-id", "5"])
        assert args.unit_id == 5

    def test_unit_id_short_flag(self, parser):
        """Test -u short flag for unit ID."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-u", "10"])
        assert args.unit_id == 10

    def test_unit_id_broadcast(self, parser):
        """Test unit ID 0 (broadcast)."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-u", "0"])
        assert args.unit_id == 0

    def test_unit_id_max(self, parser):
        """Test maximum unit ID (247)."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-u", "247"])
        assert args.unit_id == 247

    def test_scan_range(self, parser):
        """Test --scan-range option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--scan-range", "0-100"])
        assert args.scan_range == "0-100"

    def test_scan_range_short_flag(self, parser):
        """Test -r short flag for scan range."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-r", "1000-1050"])
        assert args.scan_range == "1000-1050"

    def test_register_type_holding(self, parser):
        """Test --register-type holding."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--register-type", "holding"])
        assert args.register_type == "holding"

    def test_register_type_input(self, parser):
        """Test --register-type input."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--register-type", "input"])
        assert args.register_type == "input"

    def test_register_type_coil(self, parser):
        """Test --register-type coil."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--register-type", "coil"])
        assert args.register_type == "coil"

    def test_register_type_discrete(self, parser):
        """Test --register-type discrete."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--register-type", "discrete"])
        assert args.register_type == "discrete"

    def test_register_type_all(self, parser):
        """Test --register-type all."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--register-type", "all"])
        assert args.register_type == "all"

    def test_register_type_short_flag(self, parser):
        """Test -R short flag for register type."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-R", "coil"])
        assert args.register_type == "coil"

    def test_discover_units_flag(self, parser):
        """Test --discover-units flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--discover-units"])
        assert args.discover_units is True

    def test_unit_range(self, parser):
        """Test --unit-range option."""
        args = parser.parse_args(
            ["modbus", "192.168.1.100", "--discover-units", "--unit-range", "1-10"]
        )
        assert args.unit_range == "1-10"

    def test_scan_fc_flag(self, parser):
        """Test --scan-fc flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--scan-fc"])
        assert args.scan_fc is True

    def test_fc_all_flag(self, parser):
        """Test --fc-all flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--fc-all"])
        assert args.fc_all is True

    def test_fc_range(self, parser):
        """Test --fc-range option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--fc-range", "1-16"])
        assert args.fc_range == "1-16"


# =============================================================================
# Test Write Operations Options
# =============================================================================


class TestWriteOperationOptions:
    """Tests for write operation options."""

    def test_write_option(self, parser):
        """Test --write option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--write", "100=1234"])
        assert args.write == "100=1234"

    def test_write_short_flag(self, parser):
        """Test -w short flag for write."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-w", "50=5678"])
        assert args.write == "50=5678"

    def test_write_coil_option(self, parser):
        """Test --write-coil option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--write-coil", "10=1"])
        assert args.write_coil == "10=1"

    def test_write_multiple_option(self, parser):
        """Test --write-multiple option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--write-multiple", "100=10,20,30"])
        assert args.write_multiple == "100=10,20,30"

    def test_write_multiple_coils_option(self, parser):
        """Test --write-multiple-coils option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--write-multiple-coils", "0=1,0,1,1"])
        assert args.write_multiple_coils == "0=1,0,1,1"

    def test_test_write_flag(self, parser):
        """Test --test-write flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--test-write"])
        assert args.test_write is True

    def test_test_write_thorough_flag(self, parser):
        """Test --test-write-thorough flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--test-write-thorough"])
        assert args.test_write_thorough is True

    def test_restore_on_exit_flag(self, parser):
        """Test --restore-on-exit flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--restore-on-exit"])
        assert args.restore_on_exit is True


# =============================================================================
# Test Diagnostics Options
# =============================================================================


class TestDiagnosticsOptions:
    """Tests for diagnostics options (FC 8)."""

    def test_diag_option_all(self, parser):
        """Test --diag all."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--diag", "all"])
        assert args.diag == "all"

    def test_diag_option_echo(self, parser):
        """Test --diag echo."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--diag", "echo"])
        assert args.diag == "echo"

    def test_diag_option_counters(self, parser):
        """Test --diag counters."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--diag", "counters"])
        assert args.diag == "counters"

    def test_diag_option_clear(self, parser):
        """Test --diag clear."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--diag", "clear"])
        assert args.diag == "clear"

    def test_diag_option_default(self, parser):
        """Test --diag with no argument defaults to 'all'."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--diag"])
        assert args.diag == "all"

    def test_diag_data_option(self, parser):
        """Test --diag-data option."""
        args = parser.parse_args(
            ["modbus", "192.168.1.100", "--diag", "echo", "--diag-data", "0x1234"]
        )
        assert args.diag_data == "0x1234"


# =============================================================================
# Test Device Identification Options
# =============================================================================


class TestDeviceIdentificationOptions:
    """Tests for device identification options (FC 43/14, FC 17)."""

    def test_identify_flag(self, parser):
        """Test --identify / -i flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-i"])
        assert args.identify is True

    def test_identify_long_flag(self, parser):
        """Test --identify long flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--identify"])
        assert args.identify is True

    def test_mei_object_basic(self, parser):
        """Test --mei-object basic."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--mei-object", "basic"])
        assert args.mei_object == "basic"

    def test_mei_object_regular(self, parser):
        """Test --mei-object regular."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--mei-object", "regular"])
        assert args.mei_object == "regular"

    def test_mei_object_extended(self, parser):
        """Test --mei-object extended."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--mei-object", "extended"])
        assert args.mei_object == "extended"

    def test_mei_object_specific(self, parser):
        """Test --mei-object specific."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--mei-object", "specific"])
        assert args.mei_object == "specific"

    def test_mei_object_all(self, parser):
        """Test --mei-object all."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--mei-object", "all"])
        assert args.mei_object == "all"

    def test_mei_object_id(self, parser):
        """Test --mei-object-id option."""
        args = parser.parse_args(
            ["modbus", "192.168.1.100", "--mei-object", "specific", "--mei-object-id", "0"]
        )
        assert args.mei_object_id == 0

    def test_server_id_flag(self, parser):
        """Test --server-id flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--server-id"])
        assert args.server_id is True

    def test_exception_status_flag(self, parser):
        """Test --exception-status flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--exception-status"])
        assert args.exception_status is True


# =============================================================================
# Test Communication Events Options
# =============================================================================


class TestCommunicationEventsOptions:
    """Tests for communication events options (FC 11/12)."""

    def test_events_flag(self, parser):
        """Test --events flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--events"])
        assert args.events is True


# =============================================================================
# Test File Records Options
# =============================================================================


class TestFileRecordsOptions:
    """Tests for file records options (FC 20/21)."""

    def test_file_read_option(self, parser):
        """Test --file-read option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--file-read", "1:0:5"])
        assert args.file_read == "1:0:5"

    def test_file_write_option(self, parser):
        """Test --file-write option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--file-write", "1:0:100,200,300"])
        assert args.file_write == "1:0:100,200,300"


# =============================================================================
# Test Atomic Operations Options
# =============================================================================


class TestAtomicOperationsOptions:
    """Tests for atomic operations options (FC 22/23)."""

    def test_mask_write_option(self, parser):
        """Test --mask-write option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--mask-write", "0:0xFF00:0x00FF"])
        assert args.mask_write == "0:0xFF00:0x00FF"

    def test_atomic_rw_option(self, parser):
        """Test --atomic-rw option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--atomic-rw", "0-5:10=100,200"])
        assert args.atomic_rw == "0-5:10=100,200"


# =============================================================================
# Test FIFO Queue Options
# =============================================================================


class TestFIFOQueueOptions:
    """Tests for FIFO queue options (FC 24)."""

    def test_fifo_option(self, parser):
        """Test --fifo option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--fifo", "100"])
        assert args.fifo == 100


# =============================================================================
# Test Data Decoding Options
# =============================================================================


class TestDataDecodingOptions:
    """Tests for data decoding options."""

    def test_decode_option(self, parser):
        """Test --decode / -d option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-d", "f32"])
        assert args.decode == "f32"

    def test_decode_various_types(self, parser):
        """Test --decode with various type values."""
        for dtype in ["f32", "f64", "i16", "i32", "u16", "u32", "str", "hex", "bits", "bcd"]:
            args = parser.parse_args(["modbus", "192.168.1.100", "-d", dtype])
            assert args.decode == dtype

    def test_endian_option(self, parser):
        """Test --endian / -e option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-e", "little"])
        assert args.endian == "little"

    def test_endian_choices(self, parser):
        """Test --endian valid choices."""
        for endian in ["big", "little", "big-swap", "little-swap"]:
            args = parser.parse_args(["modbus", "192.168.1.100", "--endian", endian])
            assert args.endian == endian

    def test_decode_all_flag(self, parser):
        """Test --decode-all flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--decode-all"])
        assert args.decode_all is True

    def test_decode_width_option(self, parser):
        """Test --decode-width / -W option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "-W", "4"])
        assert args.decode_width == 4

    def test_filter_zero_flag(self, parser):
        """Test --filter-zero flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--filter-zero"])
        assert args.filter_zero is True

    def test_register_map_option(self, parser):
        """Test --register-map option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--register-map", "schneider-m340"])
        assert args.register_map == "schneider-m340"

    def test_list_maps_flag(self, parser):
        """Test --list-maps flag."""
        args = parser.parse_args(["modbus", "--list-maps"])
        assert args.list_maps is True


# =============================================================================
# Test Monitor Mode Options
# =============================================================================


class TestMonitorModeOptions:
    """Tests for monitor mode options."""

    def test_monitor_flag(self, parser):
        """Test --monitor flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--monitor"])
        assert args.monitor is True

    def test_interval_option(self, parser):
        """Test --interval option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--monitor", "--interval", "2"])
        assert args.interval == 2

    def test_duration_option(self, parser):
        """Test --duration option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--monitor", "--duration", "60"])
        assert args.duration == 60

    def test_on_change_flag(self, parser):
        """Test --on-change flag."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--monitor", "--on-change"])
        assert args.on_change is True

    def test_log_file_option(self, parser):
        """Test --log-file option."""
        args = parser.parse_args(
            ["modbus", "192.168.1.100", "--monitor", "--log-file", "/tmp/modbus.log"]
        )
        assert args.log_file == "/tmp/modbus.log"


# =============================================================================
# Test Custom Function Code Options
# =============================================================================


class TestCustomFCOptions:
    """Tests for custom function code options."""

    def test_raw_fc_option(self, parser):
        """Test --raw-fc option."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--raw-fc", "65"])
        assert args.raw_fc == 65

    def test_raw_fc_alias(self, parser):
        """Test --custom-fc alias."""
        args = parser.parse_args(["modbus", "192.168.1.100", "--custom-fc", "90"])
        assert args.raw_fc == 90


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
