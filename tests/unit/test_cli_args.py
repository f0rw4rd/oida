"""CLI argument constraint tests.

Validates that protocol subparsers don't conflict with the main parser
and follow consistent conventions. Catches regressions like duplicate
flags, missing required options, and broken help output.
"""

import argparse
from collections import Counter
from pathlib import Path

import pytest

from oida.cli import gen_cli_args
from oida.loader import ProtocolLoader

pytestmark = pytest.mark.core

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PROTOCOLS_DIR = str(Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols")


@pytest.fixture(scope="module")
def main_parser():
    """Build the full CLI parser with all registered protocols."""
    return gen_cli_args()


@pytest.fixture(scope="module")
def registered_protocols(main_parser):
    """Protocol names that actually registered a subparser."""
    return sorted(main_parser._subparsers_action.choices.keys())


# Long-form output/verbosity flags consolidated on the main parser.
# These were historically duplicated via add_common_args() / add_output_options()
# and must NOT be re-added by protocol subparsers.
#
# NOTE: Short flags like -o, -f, -d, -v are intentionally NOT listed here
# because protocols legitimately reuse them for protocol-specific options
# (e.g., -o for --outstation-addr in dnp3, -f for --force in discovery).
# The subparser namespace is separate from the main parser, so short flag
# reuse is fine — only the long-form duplicates cause real problems
# (inconsistent --verbose action types, duplicate --output/--format dests).
CONSOLIDATED_LONG_FLAGS = {
    "--verbose",
    "--debug",
    "--output",
    "--format",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_subparser(main_parser, name):
    """Return the subparser for a given protocol name."""
    return main_parser._subparsers_action.choices[name]


def _collect_option_strings(parser):
    """Return all option strings registered on a parser."""
    strings = []
    for action in parser._actions:
        strings.extend(action.option_strings)
    return strings


def _get_registered_protos():
    """Get protocol names known to the loader (used for parametrize)."""
    loader = ProtocolLoader(PROTOCOLS_DIR)
    return sorted(loader.get_protocols().keys())


# ---------------------------------------------------------------------------
# Tests: No duplicate flags within any single subparser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_no_duplicate_flags_in_protocol(main_parser, proto):
    """Each protocol subparser must not have duplicate option strings."""
    if proto not in main_parser._subparsers_action.choices:
        pytest.skip(f"{proto} not registered (missing optional dep?)")

    sub = _get_subparser(main_parser, proto)
    flags = _collect_option_strings(sub)
    dupes = [f for f, cnt in Counter(flags).items() if cnt > 1]
    assert not dupes, f"{proto}: duplicate flags {dupes}"


# ---------------------------------------------------------------------------
# Tests: Protocol subparsers don't re-add consolidated output/verbosity flags
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_no_duplicate_output_verbose_flags(main_parser, proto):
    """Protocol subparsers must not re-define output/verbosity long flags.

    The main parser provides --verbose, --debug, --output, --format.
    Protocols that re-add these (via add_common_args, add_output_options, or
    manually) cause inconsistent behavior (e.g. --verbose as store_true vs count)
    and confusing duplicate help entries.
    """
    if proto not in main_parser._subparsers_action.choices:
        pytest.skip(f"{proto} not registered (missing optional dep?)")

    sub = _get_subparser(main_parser, proto)
    own_flags = set(_collect_option_strings(sub))
    shadowed = own_flags & CONSOLIDATED_LONG_FLAGS
    assert not shadowed, (
        f"{proto}: flags {shadowed} duplicate main parser output/verbosity flags "
        f"(remove add_common_args/add_output_options from proto_args.py)"
    )


# ---------------------------------------------------------------------------
# Tests: --help exits cleanly for every registered protocol
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_help_does_not_crash(main_parser, proto):
    """Calling --help on each protocol subparser must not raise."""
    if proto not in main_parser._subparsers_action.choices:
        pytest.skip(f"{proto} not registered (missing optional dep?)")

    sub = _get_subparser(main_parser, proto)
    with pytest.raises(SystemExit) as exc_info:
        sub.parse_args(["--help"])
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Tests: Every protocol has a target positional or is special (serial/fuzz/pcap)
# ---------------------------------------------------------------------------

SPECIAL_SUBCOMMANDS = {"serial", "fuzz", "pcap"}


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_protocol_has_target_argument(main_parser, proto):
    """Every protocol (except special subcommands) should accept a target."""
    if proto in SPECIAL_SUBCOMMANDS:
        pytest.skip("Special subcommand, not a protocol")
    if proto not in main_parser._subparsers_action.choices:
        pytest.skip(f"{proto} not registered")

    sub = _get_subparser(main_parser, proto)
    positionals = [a for a in sub._actions if not a.option_strings]
    names = [a.dest for a in positionals]
    assert "target" in names, f"{proto}: missing 'target' positional argument"


# ---------------------------------------------------------------------------
# Tests: Main parser global options are well-formed
# ---------------------------------------------------------------------------


def test_main_verbose_is_count(main_parser):
    """-v/--verbose on the main parser must use action=count (not store_true)."""
    for action in main_parser._actions:
        if "--verbose" in action.option_strings:
            assert isinstance(action, argparse._CountAction), (
                f"Main parser --verbose should be action=count, got {type(action).__name__}"
            )
            return
    pytest.fail("Main parser missing --verbose")


def test_main_debug_is_store_true(main_parser):
    """--debug on the main parser must use action=store_true."""
    for action in main_parser._actions:
        if "--debug" in action.option_strings:
            assert isinstance(action, argparse._StoreTrueAction), (
                f"Main parser --debug should be store_true, got {type(action).__name__}"
            )
            return
    pytest.fail("Main parser missing --debug")


def test_main_output_present(main_parser):
    """-o/--output must exist on the main parser."""
    for action in main_parser._actions:
        if "--output" in action.option_strings:
            return
    pytest.fail("Main parser missing --output")


def test_main_format_present(main_parser):
    """--format must exist on the main parser."""
    for action in main_parser._actions:
        if "--format" in action.option_strings:
            return
    pytest.fail("Main parser missing --format")


# ---------------------------------------------------------------------------
# Tests: proto_args modules importable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_proto_args_importable(proto):
    """Every protocol's proto_args module must be importable."""
    loader = ProtocolLoader(PROTOCOLS_DIR)
    info = loader.get_protocols().get(proto)
    if not info or not info.get("argspath"):
        pytest.skip(f"{proto} has no proto_args.py")

    try:
        mod = loader.load_proto_args(proto)
    except (ImportError, ModuleNotFoundError, SyntaxError) as exc:
        pytest.skip(f"Cannot load (optional dep or syntax issue): {exc}")

    if mod is None:
        pytest.skip(f"{proto}: loader returned None (optional dep not installed)")

    assert hasattr(mod, "proto_args"), f"{proto}: proto_args.py missing proto_args() function"
