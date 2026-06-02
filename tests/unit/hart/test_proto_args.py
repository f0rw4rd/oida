"""Feature-flag coverage for HART proto_args."""

import argparse


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
