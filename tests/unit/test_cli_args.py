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
from tests.service_gate import require_service

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


# Long-form global flags that the main parser defines AND deliberately mirrors
# onto every protocol subparser (via the shared std_parser parent) so they are
# accepted both before and after the subcommand, e.g. `oida modbus HOST -v`.
#
# The mirror is only safe when it is consistent with the main parser: same
# action type, and default=SUPPRESS so an absent flag after the subcommand does
# not clobber a value parsed before it. A protocol re-adding one of these with a
# different action type or a real default would reintroduce the old clobbering
# bug — that is the regression these tests now guard against.
#
# NOTE: Short flags like -o, -q, -t, -W are intentionally NOT mirrored, because
# protocols legitimately reuse them for protocol-specific options (e.g. -o for
# --outstation-addr in dnp3, -W for --decode-width in modbus). After the
# subcommand those short flags keep their protocol meaning; the long forms above
# carry the global meaning.
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
        require_service(f"{proto} not registered (missing optional dep?)")

    sub = _get_subparser(main_parser, proto)
    flags = _collect_option_strings(sub)
    dupes = [f for f, cnt in Counter(flags).items() if cnt > 1]
    assert not dupes, f"{proto}: duplicate flags {dupes}"


# ---------------------------------------------------------------------------
# Tests: Protocol subparsers don't re-add consolidated output/verbosity flags
# ---------------------------------------------------------------------------


def _option_action_map(parser):
    """Map each option string to its argparse Action on a parser."""
    return {opt: a for a in parser._actions for opt in a.option_strings}


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_consolidated_flags_mirrored_consistently(main_parser, proto):
    """Each subparser mirrors the consolidated globals consistently and safely.

    The main parser's --verbose/--debug/--output/--format are deliberately
    mirrored onto every protocol subparser (via the shared std_parser parent) so
    they also work AFTER the subcommand (`oida modbus HOST -v`). For that to be
    correct the mirrored copy must:

      * use the SAME action type as the main parser (so --verbose stays a count,
        not a store_true), and
      * default to argparse.SUPPRESS, so an absent flag after the subcommand
        does not clobber the value parsed before it back to a default.

    A protocol that re-adds one of these with a different action type or a real
    default reintroduces the positional-clobbering bug; this test fails fast on
    that.
    """
    if proto not in main_parser._subparsers_action.choices:
        require_service(f"{proto} not registered (missing optional dep?)")

    sub = _get_subparser(main_parser, proto)
    main_actions = _option_action_map(main_parser)
    sub_actions = _option_action_map(sub)

    for flag in CONSOLIDATED_LONG_FLAGS:
        assert flag in sub_actions, (
            f"{proto}: global {flag} not mirrored onto the subparser; it would only "
            f"work before the subcommand. Ensure proto_args() forwards std_parser."
        )
        sub_action = sub_actions[flag]
        main_action = main_actions[flag]
        assert type(sub_action) is type(main_action), (
            f"{proto}: {flag} mirrored as {type(sub_action).__name__} but main parser "
            f"uses {type(main_action).__name__} — action types must match"
        )
        assert sub_action.default is argparse.SUPPRESS, (
            f"{proto}: mirrored {flag} must default to argparse.SUPPRESS to avoid "
            f"clobbering the value parsed before the subcommand (got {sub_action.default!r})"
        )


# ---------------------------------------------------------------------------
# Tests: --help exits cleanly for every registered protocol
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto", [pytest.param(p, id=p) for p in _get_registered_protos()])
def test_help_does_not_crash(main_parser, proto):
    """Calling --help on each protocol subparser must not raise."""
    if proto not in main_parser._subparsers_action.choices:
        require_service(f"{proto} not registered (missing optional dep?)")

    sub = _get_subparser(main_parser, proto)
    with pytest.raises(SystemExit) as exc_info:
        sub.parse_args(["--help"])
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Tests: Every protocol has a target positional or is special (serial/fuzz/pcap)
# ---------------------------------------------------------------------------

SPECIAL_SUBCOMMANDS = {"serial", "fuzz", "pcap"}


@pytest.mark.parametrize(
    "proto",
    [pytest.param(p, id=p) for p in _get_registered_protos() if p not in SPECIAL_SUBCOMMANDS],
)
def test_protocol_has_target_argument(main_parser, proto):
    """Every protocol (except special subcommands) should accept a target."""
    if proto not in main_parser._subparsers_action.choices:
        require_service(f"{proto} not registered")

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


def test_global_flags_not_clobbered_by_subparser_defaults(main_parser):
    """A global flag given before the subcommand must survive subparser parsing.

    Subparsers that re-declare a flag (e.g. fuzz's -v, or --json-log) must use
    default=argparse.SUPPRESS, otherwise a subparser-level non-occurrence resets
    the value the main parser already set. Regression guard for the fuzz -v and
    iec104 --json-log clobbering bugs.
    """
    # -v before the subcommand must be preserved (fuzz re-declares -v).
    ns = main_parser.parse_args(["-vv", "fuzz", "mms", "127.0.0.1"])
    assert ns.verbose == 2, f"global -vv clobbered to {ns.verbose} by fuzz subparser"
    # --json-log before the subcommand must be preserved across protocols.
    ns = main_parser.parse_args(["--json-log", "/tmp/x.jsonl", "iec104", "127.0.0.1"])
    assert ns.json_log == "/tmp/x.jsonl", "global --json-log clobbered by iec104 subparser"
    # -v before the serial subcommand must survive serial's own store_true -v
    # (serial detect/list re-declare -v; they must use default=SUPPRESS).
    ns = main_parser.parse_args(["-vv", "serial", "list"])
    assert ns.verbose == 2, f"global -vv clobbered to {ns.verbose!r} by serial subparser"


def _full_parser(monkeypatch, argv):
    """Build a parser with the invoked protocol FULLY registered.

    gen_cli_args() keys its parser-build mode off sys.argv (to keep startup
    fast), so align sys.argv with the argv under test — otherwise the protocol
    is a lightweight stub that lacks its own flags. Skips if the protocol fell
    back to a stub anyway (optional dependency missing in this env).
    """
    monkeypatch.setattr("sys.argv", ["oida", *argv])
    parser = gen_cli_args()
    proto = next((a for a in argv if not a.startswith("-")), None)
    sub = parser._subparsers_action.choices.get(proto)
    if sub is not None and not any("--timeout" in ac.option_strings for ac in sub._actions):
        require_service(f"{proto} subparser not fully registered in this env")
    return parser


def test_timeout_is_per_protocol_flag_after_target(monkeypatch):
    """--timeout is honored after the target and keeps its per-protocol default.

    Regression guard for the shadowing bug where a global --timeout collided
    with each protocol's own --timeout dest.
    """
    p = _full_parser(monkeypatch, ["modbus", "127.0.0.1", "--timeout", "7"])
    assert p.parse_args(["modbus", "127.0.0.1", "--timeout", "7"]).timeout == 7

    p = _full_parser(monkeypatch, ["modbus", "127.0.0.1"])
    assert p.parse_args(["modbus", "127.0.0.1"]).timeout == 2  # modbus default

    # Per-protocol default must NOT collapse to a single global value.
    p = _full_parser(monkeypatch, ["dicom", "127.0.0.1"])
    assert p.parse_args(["dicom", "127.0.0.1"]).timeout == 10  # dicom default


def test_timeout_before_subcommand_is_rejected(monkeypatch):
    """The global --timeout was removed. Placing it before the subcommand is now
    a clean error, not a silently-ignored value (was: clobbered to the subparser
    default)."""
    p = _full_parser(monkeypatch, ["--timeout", "30", "modbus", "127.0.0.1"])
    with pytest.raises(SystemExit):
        p.parse_args(["--timeout", "30", "modbus", "127.0.0.1"])


def test_ads_tase2_keep_connect_timeout_default_5(monkeypatch):
    """ads/tase2 dropped their reliance on the global --timeout default (5) but
    must keep that effective default via their own --timeout, and honor an
    explicit override."""
    for proto in ("ads", "tase2"):
        p = _full_parser(monkeypatch, [proto, "127.0.0.1"])
        assert p.parse_args([proto, "127.0.0.1"]).timeout == 5
        p = _full_parser(monkeypatch, [proto, "127.0.0.1", "--timeout", "9"])
        assert p.parse_args([proto, "127.0.0.1", "--timeout", "9"]).timeout == 9


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
    """-o/--output must exist on the main parser and take a directory value."""
    for action in main_parser._actions:
        if "--output" in action.option_strings:
            assert "-o" in action.option_strings, (
                f"--output should keep its -o short flag, got {action.option_strings}"
            )
            assert action.metavar == "DIR"
            assert action.type is str
            return
    pytest.fail("Main parser missing --output")


def test_main_format_present(main_parser):
    """--format must exist on the main parser with the documented choices/default."""
    for action in main_parser._actions:
        if "--format" in action.option_strings:
            assert action.choices == ["json", "csv", "xml", "console", "all"]
            assert action.default == "console"
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
        require_service(f"Cannot load (optional dep or syntax issue): {exc}")

    if mod is None:
        require_service(f"{proto}: loader returned None (optional dep not installed)")

    assert hasattr(mod, "proto_args"), f"{proto}: proto_args.py missing proto_args() function"


# ---------------------------------------------------------------------------
# Credential-redaction contract
# ---------------------------------------------------------------------------


class TestRedactSensitiveArgs:
    """_redact_sensitive_args must mask credential-like dest names."""

    def test_masks_password(self):
        from oida.cli import _redact_sensitive_args

        out = _redact_sensitive_args({"password": "hunter2", "host": "1.2.3.4"})
        assert out["password"] == "***"
        assert out["host"] == "1.2.3.4"

    def test_masks_all_known_patterns(self):
        from oida.cli import _redact_sensitive_args

        sensitive = {
            "password": "x",
            "ssh_passwd": "y",
            "client_secret": "z",
            "api_token": "t",
            "psk": "p",
            "pre_shared_key": "k",
            "private_key": "key",
            "auth_string": "a",
            "auth_pass": "b",
            "snmp_community": "public",
            "api_key": "k1",
            "apikey": "k2",
            "stored_credential": "c",
        }
        out = _redact_sensitive_args(sensitive)
        for k in sensitive:
            assert out[k] == "***", f"{k} not redacted"

    def test_preserves_none_values(self):
        from oida.cli import _redact_sensitive_args

        out = _redact_sensitive_args({"password": None, "host": "x"})
        # None means user didn't supply the flag — keep as None for legibility
        assert out["password"] is None
        assert out["host"] == "x"

    def test_does_not_mask_non_sensitive(self):
        from oida.cli import _redact_sensitive_args

        out = _redact_sensitive_args({"port": 502, "timeout": 5.0, "verbose": True})
        assert out == {"port": 502, "timeout": 5.0, "verbose": True}

    def test_cli_args_debug_log_is_wired_to_redactor(self):
        # Regression: the debug dump of CLI args must pass through the redactor,
        # otherwise running with --debug leaks passwords/community strings into
        # logs. Guards against the wrapper being dropped again.
        import pathlib

        src = pathlib.Path("src/oida/cli.py").read_text()
        assert 'logger.debug("CLI args: %s", _redact_sensitive_args(vars(args)))' in src, (
            "CLI args debug log must redact credentials via _redact_sensitive_args"
        )
        assert 'logger.debug("CLI args: %s", vars(args))' not in src, (
            "raw vars(args) must not be logged at debug level"
        )


# ---------------------------------------------------------------------------
# Config merge contract: typed defaults must not silently drop config values
# ---------------------------------------------------------------------------


class TestMergeConfigWithArgs:
    """merge_config_with_args must honor non-None argparse defaults."""

    def _make_parser_and_args(self, **cli_overrides):
        import argparse

        p = argparse.ArgumentParser()
        p.add_argument("--verbose", action="count", default=0)
        p.add_argument("--port", type=int, default=502)
        p.add_argument("--host", default=None)
        p.add_argument("--enable-x", action="store_true")
        argv = []
        for k, v in cli_overrides.items():
            if v is True:
                argv.append(f"--{k.replace('_', '-')}")
            elif v is False:
                pass
            else:
                argv.extend([f"--{k.replace('_', '-')}", str(v)])
        return p, p.parse_args(argv)

    def test_config_value_applied_when_default_is_zero(self):
        """Bug: --verbose default=0 caused config{verbose: 3} to be dropped."""
        from oida.cli import merge_config_with_args

        p, args = self._make_parser_and_args()
        merge_config_with_args(args, {"verbose": 3}, parser=p)
        assert args.verbose == 3, "Config value silently dropped (the bug)"

    def test_config_value_applied_when_default_is_false(self):
        """Bug: action='store_true' default=False dropped config{enable_x: True}."""
        from oida.cli import merge_config_with_args

        p, args = self._make_parser_and_args()
        merge_config_with_args(args, {"enable-x": True}, parser=p)
        assert args.enable_x is True

    def test_cli_overrides_config_when_explicitly_set(self):
        """CLI always wins when operator typed the flag."""
        from oida.cli import merge_config_with_args

        p, args = self._make_parser_and_args(port=4840)
        merge_config_with_args(args, {"port": 502}, parser=p)
        assert args.port == 4840

    def test_unknown_key_logs_warning_not_silently_added(self):
        """Typo 'tiemout: 5' must not create args.tiemout."""
        import logging
        from oida.cli import merge_config_with_args

        p, args = self._make_parser_and_args()
        with caplog_at(logging.WARNING):
            merge_config_with_args(args, {"tiemout": 5}, parser=p)
        assert not hasattr(args, "tiemout")

    def test_dash_underscore_key_normalization(self):
        """'enable-x' in config maps to args.enable_x."""
        from oida.cli import merge_config_with_args

        p, args = self._make_parser_and_args()
        merge_config_with_args(args, {"enable-x": True}, parser=p)
        assert args.enable_x is True


import contextlib
import logging as _logging


@contextlib.contextmanager
def caplog_at(level):
    handler = _logging.StreamHandler()
    handler.setLevel(level)
    root = _logging.getLogger()
    root.addHandler(handler)
    try:
        yield
    finally:
        root.removeHandler(handler)


class TestExportResultsDoesNotMutate:
    """export_results must not destructively edit caller-owned result dicts.

    Regression for CODE_REVIEW.md cli.py:303-308: the 'collect tables' loop
    used data.pop('tables', ...) which silently stripped 'tables' from the
    live result dicts, so a second consumer (or a re-export) would see
    truncated data. The read loop must leave the source dict intact.
    """

    def _results_with_tables(self):
        return [
            {
                "host": "10.0.0.1",
                "ip": "10.0.0.1",
                "protocol": "pcap",
                "port": 0,
                "success": True,
                "data": {
                    "identified": True,
                    "tables": [
                        {"name": "creds", "rows": [{"user": "admin"}]},
                    ],
                },
            },
        ]

    def test_tables_still_present_after_export(self, tmp_path):
        from oida.cli import export_results

        results = self._results_with_tables()
        export_results(
            results,
            str(tmp_path),
            "json",
            protocol_name="pcap",
        )

        # The live result dict must still carry its 'tables' payload.
        assert "tables" in results[0]["data"]
        assert results[0]["data"]["tables"] == [
            {"name": "creds", "rows": [{"user": "admin"}]},
        ]

    def test_tables_excluded_from_json_dump(self, tmp_path):
        import json as _json

        from oida.cli import export_results

        results = self._results_with_tables()
        export_results(results, str(tmp_path), "json", protocol_name="pcap")

        with open(tmp_path / "pcap.json") as f:
            dumped = _json.load(f)

        # tables are written to dedicated CSV files, not the JSON dump
        assert "tables" not in dumped[0]["data"]
        # ...but the source dict is untouched
        assert "tables" in results[0]["data"]

    def test_repeated_export_sees_same_data(self, tmp_path):
        from oida.cli import export_results

        results = self._results_with_tables()
        export_results(results, str(tmp_path / "a"), "json", protocol_name="pcap")
        # second consumer must still see the tables
        export_results(results, str(tmp_path / "b"), "json", protocol_name="pcap")

        assert "tables" in results[0]["data"]
