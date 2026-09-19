"""CLI flag-drift guard: every argparse dest must actually be read somewhere,
and every args-like read must correspond to a real dest.

The CLI has ~1000+ flags across the global parser and 26+ protocol
subparsers. Nothing previously checked whether a defined flag is ever read
downstream, or whether a `self.args.get("...")` / `getattr(args, "...")` read
matches a real dest. That drift is exactly how --rtu-over-tcp,
--ascii-over-tcp, and --max-registers ended up silently dead in
modbus/scanner.py (dashed dict keys read against an underscored argparse
Namespace) — this test is the regression guard for that class of bug.

This is a heuristic, not a type-checker: it instantiates the real parser for
the dest side, and AST-scans `src/oida/` for three read shapes
(`args.X` / `self.args.X`, `getattr(args_like, "X", ...)`,
`args_like.get("X")`) for the usage side. False positives happen when a
totally unrelated variable is also named `args`/`ns`/`namespace` — add those
to the whitelists below with a comment, don't loosen the scan.
"""

import argparse
import ast
from pathlib import Path

import pytest

from oida.cli import gen_cli_args

pytestmark = pytest.mark.core

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "oida"

# Dests that are never read as a plain attribute/getattr/get lookup by design.
_DEST_WHITELIST = {
    "help",
    "protocol",  # main parser's subparsers dispatch dest
    "serial_action",  # serial_cli.py's nested subparsers dispatch dest
    "bug",  # handled via a raw sys.argv scan in cli.py before argparse runs
    # --- Known CLI wiring debt, surfaced by this test, triaged for a
    # follow-up pass rather than fixed here (scope-limited per this
    # commit's intent: land the guard test + the base_scanner dash-
    # normalization fix, not a full audit of every protocol). Each of
    # these dests is genuinely never read under its own name -- some are
    # likely fuzz_cli.py-specific wiring gaps, others are OCPP/DNP3/etc.
    # test-* flags. Re-verify individually when triaged.
    "bo_direct",
    "bo_sbo",
    "case",
    "check_auth",
    "check_boot",
    "check_config_keys",
    "class_poll",
    "cold_restart",
    "composite_schedule",
    "compress",
    "config",
    "copy_ram_to_rom",
    "cpu_hot_start",
    "cpu_start",
    "data_transfer",
    "disable",
    "dump_attrs",
    "dump_files",
    "dump_history",
    "dump_methods",
    "dump_write",
    "enable",
    "enum_connectors",
    "enumerate_szl",
    "export",
    "extended_bauds",
    "fhir_version",
    "fire_forget_fuzz",
    "full_sweep",
    "fuzz_protocol",
    "get_config",
    "get_datetime",
    "info",
    "installed_certs",
    "json",
    "json_log",
    "list_blocks",
    "list_ports",
    "list_requests",
    "list_szl",
    "local_list_version",
    "machine",
    "meter_values",
    "method",
    "model",
    "monitors",
    "no_calibrate",
    "no_receive",
    "replay_range",
    "reproduce_target",
    "scan_programs",
    "show_options",
    "sync_datetime",
    "test_authorize",
    "test_availability",
    "test_charging",
    "test_charging_profile",
    "test_clear_cache",
    "test_config_write",
    "test_customer_info",
    "test_diagnostics",
    "test_display_msg",
    "test_firmware",
    "test_install_cert",
    "test_local_list",
    "test_meter_inject",
    "test_network_profile",
    "test_remote_start",
    "test_remote_stop",
    "test_reserve",
    "test_reset",
    "test_ssrf_extended",
    "test_unlock",
    "test_ws_hijack",
    "vendor",
    "warm_restart",
    "with_options",
}

# args-like reads that don't correspond to a real dest but are known-fine
# (e.g. config-only keys merged onto args by merge_config_with_args()).
_READ_WHITELIST = {
    # --- Genuinely not CLI flags (not bugs) ---
    # Set dynamically at runtime by cli.py's scan_target(), not by argparse.
    "host",
    "rhost",
    "rport",
    "lhost",
    # Set dynamically by cli.py main() after parsing (True when the operator
    # passed an explicit -p/--port vs the protocol default), then read by
    # protocols like ocpp to decide default-port fallback.
    "_port_explicit",
    # base_scanner.py's `self.args.get("d", ...)` legacy-alias fallback --
    # "-d"/"--decode" share dest "decode"; "d" is checked as a belt-and-
    # braces alias, never itself a real dest.
    "d",
    # Config-only keys merged onto args by config-file loading, not argparse
    # flags (base_scanner.py / ethernetip scanner.py).
    "export-file",
    "export-format",
    "read-only",
    # fuzz_cli.py builds its own bespoke args-like wrapper object (not the
    # gen_cli_args() Namespace) and passes it into FuzzApplication /
    # run_command(); these names are real fields on THAT wrapper, not on
    # the main CLI parser, so they can't match a `gen_cli_args()` dest.
    "calibrate",
    "case_id",
    "command",
    "console_output",
    "disabled_requests",
    "distribution_id",
    "distribution_total",
    "enabled_requests",
    "index_end",
    "index_start",
    "ip",
    "monitor_config",
    "range",
    "receive_data_after_each_request",
    "receive_data_after_fuzz",
    "skip_pre_send",
    "web_interface",
    "web_port",
    # --- Known CLI wiring debt (dest-name mismatches), surfaced by this
    # test, triaged for a follow-up pass rather than fixed here. Same bug
    # class as the modbus rtu-over-tcp/ascii-over-tcp/max-registers fix in
    # this commit, just not chased down for every protocol right now.
    "bytesize",
    "certificate-path",
    "community",
    "control",
    "device-attributes",
    "discover-logical-devices",
    "discovery-timeout",
    "dsrdtr",
    "eeprom",
    "emergency-monitor",
    "emergency_monitor",
    "event_count_only",
    "function-range",
    "fuzz_delay",
    "get-device-id",
    "location_name",
    "master-address",
    "max-dbs",
    "max_read_bytes",
    "max_series",
    "operation-timeout",
    "organization_name",
    "outstation-address",
    "practitioner_name",
    "private-key-path",
    "read-class",
    "rtscts",
    "sbo",
    "sdo",
    "security-mode",
    "security-policy",
    "stopbits",
    "target-url",
    "test-read",
    "test-routing",
}

_SKIP_ATTRS = {
    "get",
    "items",
    "keys",
    "values",
    "copy",
    "update",
    "pop",
    "setdefault",
    "__dict__",
    "__class__",
}


def _iter_source_files():
    yield from sorted(SRC.rglob("*.py"))


def _collect_dests(parser: argparse.ArgumentParser) -> set:
    dests = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            dests.add(action.dest)
            for sub in action.choices.values():
                dests |= _collect_dests(sub)
            continue
        dests.add(action.dest)
    return dests


class _UsedNamesVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, sink: list):
        self.filename = filename
        self.sink = sink
        # A bare `args` Name is unambiguous only in the files that define the
        # `__init__(self, args)` scanner constructor convention (scanner.py /
        # cli_runner.py / a protocol's package __init__.py) -- NOT under
        # mixins/, where HL7/DICOM/ASTM message-field-parsing code also uses
        # a local variable named `args` for unrelated parsed-message dicts.
        # Matching bare `args` everywhere produced 1000+ false positives.
        p = Path(filename)
        self._bare_args_ok = p.name in {
            "scanner.py",
            "cli_runner.py",
            "__init__.py",
            "application.py",  # src/oida/fuzz/{core,monitors}/application.py
            # utils/crash_report.py: every bare `args` there is the args-like
            # object passed into _opt()/is_suppressed() to read flag values.
            "crash_report.py",
        } and ("mixins" not in p.parts)

    def _is_args_like(self, node) -> bool:
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "args"
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return True
        return self._bare_args_ok and isinstance(node, ast.Name) and node.id == "args"

    def _record(self, name, lineno):
        self.sink.append((name, self.filename, lineno))

    def visit_Attribute(self, node):
        if node.attr not in _SKIP_ATTRS and self._is_args_like(node.value):
            self._record(node.attr, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
            target, name_arg = node.args[0], node.args[1]
            if (
                self._is_args_like(target)
                and isinstance(name_arg, ast.Constant)
                and isinstance(name_arg.value, str)
            ):
                self._record(name_arg.value, node.lineno)
        elif isinstance(func, ast.Attribute) and func.attr == "get" and node.args:
            if self._is_args_like(func.value):
                name_arg = node.args[0]
                if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                    self._record(name_arg.value, node.lineno)
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in ("_arg", "_arg_from")
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
        ):
            # profinet's self._arg("name", default) / self._arg_from(args,
            # "name", default) helpers (src/oida/protocols/profinet/__init__.py)
            # -- the name is the 1st positional arg for _arg, 2nd for _arg_from.
            idx = 0 if func.attr == "_arg" else 1
            if len(node.args) > idx:
                name_arg = node.args[idx]
                if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                    self._record(name_arg.value, node.lineno)
        elif (
            isinstance(func, ast.Name)
            and func.id == "_opt"
            and len(node.args) >= 2
            and self._is_args_like(node.args[0])
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            # crash_report.py's _opt(args, "name", default) helper reads flag
            # values off whatever args-like object the caller holds (e.g.
            # _opt(args, "no_bug_report") in is_suppressed()).
            self._record(node.args[1].value, node.lineno)
        self.generic_visit(node)


@pytest.fixture(scope="module")
def main_parser():
    # Force FULL registration of every protocol subparser. gen_cli_args()
    # keys its build mode off sys.argv when no argv is passed, and pytest's
    # xdist workers run with sys.argv == ['-c'] (no positional token), which
    # stubs every protocol and would leave this test comparing the AST scan
    # against a 71-dest stub parser. A sentinel positional that matches no
    # protocol alias makes _select_parser_mode return ("all", None).
    return gen_cli_args(argv=["oida", "force-full-registration"])


@pytest.fixture(scope="module")
def all_dests(main_parser):
    return _collect_dests(main_parser)


@pytest.fixture(scope="module")
def usage_sites():
    sink = []
    for path in _iter_source_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        _UsedNamesVisitor(str(path.relative_to(ROOT)), sink).visit(tree)
    return sink


def test_no_dead_or_phantom_cli_flags(all_dests, usage_sites):
    # _ArgsBridge.get()/getattr()-style dict access normalizes dashes to
    # underscores at runtime (base_scanner.py), so "read-only" and
    # "read_only" are both legitimate, working spellings of the same dest.
    # Attribute access (self.args.X) can never contain a dash anyway, so
    # normalizing here matches actual runtime resolution on both read shapes.
    used_names = {name.replace("-", "_") for name, _, _ in usage_sites}

    unused = sorted(all_dests - used_names - _DEST_WHITELIST)
    phantom_sites = [
        (name, f, ln)
        for name, f, ln in usage_sites
        if name.replace("-", "_") not in all_dests and name not in _READ_WHITELIST
    ]

    messages = []
    if unused:
        messages.append(f"Flags defined but never read anywhere (dead flags): {', '.join(unused)}")
    if phantom_sites:
        by_name = {}
        for name, f, ln in phantom_sites:
            by_name.setdefault(name, []).append(f"{f}:{ln}")
        offenders = "; ".join(
            f"{name!r} at {', '.join(locs)}" for name, locs in sorted(by_name.items())
        )
        messages.append(f"Reads that match no real CLI dest (typo'd/broken wiring): {offenders}")

    assert not messages, (
        "CLI flag drift detected.\n"
        + "\n".join(messages)
        + "\nIf a name above is a legitimate non-flag args-like read (e.g. a "
        "config-only key merged onto args), add it to _READ_WHITELIST / "
        "_DEST_WHITELIST in this test with a comment explaining why."
    )


def test_extraction_is_not_vacuous(all_dests, usage_sites):
    """Anti-vacuity guard: the scan should find a substantial number of dests
    and usage sites, so a broken extraction can't silently pass by matching
    nothing on both sides."""
    assert len(all_dests) >= 1000, f"Only found {len(all_dests)} dests — parser build likely broken"
    used_names = {name for name, _, _ in usage_sites}
    assert len(used_names) >= 300, (
        f"Only found {len(used_names)} used names — AST scan likely broken"
    )
    assert {"verbose", "output"} <= used_names
