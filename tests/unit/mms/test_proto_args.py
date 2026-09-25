"""Feature-flag coverage for MMS proto_args.

Verifies every advertised MMS CLI flag is parsed and reaches args with
the expected name and default value.  Mirrors the pattern in
``tests/unit/iec104/test_proto_args.py``.
"""

import argparse


from oida.protocols.mms.proto_args import proto_args


def _parse(*flags):
    """Build the same parser the CLI uses and return parsed args."""
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["mms", "127.0.0.1", *flags])


class TestMMSProtoArgs:
    """Each advertised flag must parse and bind a sensibly-named attribute."""

    def test_target_positional(self):
        args = _parse()
        assert args.target == "127.0.0.1"

    def test_default_port(self):
        assert _parse().port == 102

    def test_custom_port(self):
        assert _parse("--port", "10102").port == 10102

    def test_default_timeout(self):
        # add_network_options() default - verify there IS a timeout attr.
        assert hasattr(_parse(), "timeout")

    def test_read_values_flag(self):
        assert _parse("--read-values").read_values is True

    def test_test_write_flag(self):
        assert _parse("--test-write").test_write is True

    def test_max_objects_default(self):
        assert _parse().max_objects == 1000

    def test_max_objects_custom(self):
        assert _parse("--max-objects", "50").max_objects == 50

    def test_fuzz_flag(self):
        # add_dangerous_options(include_fuzz=True) provides --fuzz.
        args = _parse("--fuzz")
        assert args.fuzz is True

    def test_fuzz_reference(self):
        args = _parse("--fuzz-reference", "Domain/Obj")
        assert args.fuzz_reference == "Domain/Obj"

    def test_confirm_default_false(self):
        # add_dangerous_options provides --confirm gating for fuzz/write.
        assert _parse().confirm is False

    def test_confirm_flag(self):
        assert _parse("--confirm").confirm is True


class TestMMSFlagCombinations:
    """Real-world flag combos that should parse cleanly together."""

    def test_read_values_with_max_objects(self):
        args = _parse("--read-values", "--max-objects", "200")
        assert args.read_values is True
        assert args.max_objects == 200

    def test_fuzz_with_confirm(self):
        args = _parse("--fuzz", "--confirm")
        assert args.fuzz is True
        assert args.confirm is True
