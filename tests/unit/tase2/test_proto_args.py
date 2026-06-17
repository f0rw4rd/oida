"""Feature-flag coverage for TASE.2 proto_args."""

import argparse


from oida.protocols.tase2.proto_args import proto_args


def _parse(*flags):
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["tase2", "127.0.0.1", *flags])


class TestTASE2ProtoArgs:
    def test_target_positional(self):
        assert _parse().target == "127.0.0.1"

    def test_local_ap_title(self):
        args = _parse("--local-ap-title", "1.1.999.1")
        assert args.local_ap_title == "1.1.999.1"

    def test_remote_ap_title(self):
        args = _parse("--remote-ap-title", "1.1.999.2")
        assert args.remote_ap_title == "1.1.999.2"

    def test_discover_vcc_default_and_disable(self):
        assert _parse().discover_vcc is True
        assert _parse("--no-discover-vcc").discover_vcc is False

    def test_discover_icc_default_and_disable(self):
        assert _parse().discover_icc is True
        assert _parse("--no-discover-icc").discover_icc is False

    def test_analyze_blt_default_and_disable(self):
        assert _parse().analyze_blt is True
        assert _parse("--no-analyze-blt").analyze_blt is False

    def test_enumerate_points_default_and_disable(self):
        assert _parse().enumerate_points is True
        assert _parse("--no-enumerate-points").enumerate_points is False

    def test_max_points_default(self):
        assert hasattr(_parse(), "max_points")

    def test_max_points_custom(self):
        args = _parse("--max-points", "50")
        assert int(args.max_points) == 50

    def test_test_rbe_flag(self):
        assert _parse("--test-rbe").test_rbe is True

    def test_test_control_flag(self):
        assert _parse("--test-control").test_control is True

    def test_test_write_flag(self):
        assert _parse("--test-write").test_write is True
