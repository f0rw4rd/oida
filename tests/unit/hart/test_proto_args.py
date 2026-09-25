"""Feature-flag coverage for HART proto_args."""

import argparse

import pytest

from oida.protocols.hart.proto_args import proto_args


def _parse(*flags):
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["hart", "127.0.0.1", *flags])


class TestHARTProtoArgs:
    def test_target_positional(self):
        assert _parse().target == "127.0.0.1"

    def test_tcp_flag(self):
        assert _parse("--tcp").tcp is True

    def test_probe_version_flag(self):
        assert _parse("--probe-version").probe_version is True

    def test_psk_identity(self):
        args = _parse("--psk-identity", "client01")
        assert args.psk_identity == "client01"

    def test_psk_key(self):
        args = _parse("--psk-key", "deadbeef")
        assert args.psk_key == "deadbeef"

    def test_cipher_suite(self):
        args = _parse("--cipher-suite", "PSK-AES128-CCM-8")
        assert args.cipher_suite == "PSK-AES128-CCM-8"

    def test_poll_addr_default(self):
        # poll-addr has a default; just verify the attr exists
        assert hasattr(_parse(), "poll_addr")

    def test_poll_addr_custom(self):
        args = _parse("--poll-addr", "5")
        assert int(args.poll_addr) == 5

    def test_read_id_flag(self):
        assert _parse("--read-id").read_id is True

    def test_read_pv_flag(self):
        assert _parse("--read-pv").read_pv is True

    def test_read_current_flag(self):
        assert _parse("--read-current").read_current is True

    def test_read_all_vars_flag(self):
        assert _parse("--read-all-vars").read_all_vars is True

    # Discovery shortcut flags drive scan_mode in proto_flow.
    def test_discover_flag(self):
        assert _parse("--discover").discover is True

    def test_full_flag(self):
        assert _parse("--full").full is True

    # --quick and --deep-scan are deliberately NOT registered: cli_runner only reads
    # discover/full, so both fell through to the plain enumeration path and changed
    # nothing. They are suppressed rather than advertised as no-ops.
    @pytest.mark.parametrize("flag", ["--quick", "--deep-scan"])
    def test_inert_scan_mode_flags_are_not_registered(self, flag):
        with pytest.raises(SystemExit):
            _parse(flag)

    # Previously-unregistered flags whose handlers were unreachable.
    def test_enumerate_device_specific_flag(self):
        assert _parse("--enumerate-device-specific").enumerate_device_specific is True

    def test_probe_calibration_flag(self):
        assert _parse("--probe-calibration").probe_calibration is True

    def test_probe_write_flag(self):
        assert _parse("--probe-write").probe_write is True

    def test_enumerate_device_specific_default_false(self):
        assert _parse().enumerate_device_specific is False

    def test_probe_flags_default_false(self):
        args = _parse()
        assert args.probe_calibration is False
        assert args.probe_write is False
