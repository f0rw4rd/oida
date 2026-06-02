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

    def test_discover_vcc_flag(self):
        assert _parse("--discover-vcc").discover_vcc is True

    def test_discover_icc_flag(self):
        assert _parse("--discover-icc").discover_icc is True

    def test_analyze_blt_flag(self):
        assert _parse("--analyze-blt").analyze_blt is True

    def test_enumerate_points_flag(self):
        assert _parse("--enumerate-points").enumerate_points is True

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
