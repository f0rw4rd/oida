"""
OIDA Command Line Interface

Main CLI entry point:
    oida <protocol> <target> [options]

Examples:
    oida modbus 192.168.1.100 --unit-id 1 -r 0-100
    oida opcua opc.tcp://192.168.1.100:4840 --auth Anonymous
    oida s7 192.168.1.10 --rack 0 --slot 2
"""

import os

# Suppress c104 warning about buffered mode
os.environ.setdefault("PYTHONUNBUFFERED", "1")

import sys
import copy
import argparse
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Any, Dict, Tuple
import time
import json
import csv

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from oida.loader import ProtocolLoader
from oida.targets import parse_targets
from oida.serial_cli import serial_args, handle_serial_command
from oida.fuzz_cli import fuzz_args, handle_fuzz_command
from oida.utils.ics_logger import get_logger
from oida.utils.export_utils import configure_from_args, _write_xml
from oida.utils.ics_logger import get_module_logger
from oida import __version__

try:
    from termcolor import colored as _colored
except ImportError:  # pragma: no cover - termcolor is a hard dependency

    def _colored(text, *args, **kwargs):  # type: ignore[misc]
        return text


def _supports_color() -> bool:
    """Color only on an interactive terminal, and honor NO_COLOR."""
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, *args, **kwargs) -> str:
    """termcolor wrapper that degrades to plain text when piped/redirected."""
    if not _supports_color():
        return text
    return _colored(text, *args, **kwargs)


# Configure logging - suppress noisy libraries
logging.basicConfig(level=logging.ERROR, format="%(message)s")
logger = get_module_logger(__name__)

# Suppress noisy third-party loggers
for noisy_logger in ["c104", "asyncua", "pymodbus", "pyads", "xknx", "paho"]:
    logging.getLogger(noisy_logger).setLevel(logging.CRITICAL)


def load_config_file(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML or JSON file.

    Args:
        config_path: Path to configuration file (.yaml, .yml, or .json)

    Returns:
        Dictionary with configuration values

    Raises:
        ValueError: If file format is unsupported or file cannot be parsed
    """
    path = Path(config_path)

    if not path.exists():
        raise ValueError(f"Config file not found: {config_path}")

    suffix = path.suffix.lower()

    yaml_error: tuple = (yaml.YAMLError,) if HAS_YAML else ()
    try:
        with open(path, "r") as f:
            if suffix in [".yaml", ".yml"]:
                if not HAS_YAML:
                    raise ValueError(
                        "YAML support requires PyYAML. Install with: pip install pyyaml"
                    )
                data = yaml.safe_load(f) or {}
            elif suffix == ".json":
                data = json.load(f)
            else:
                raise ValueError(
                    f"Unsupported config file format: {suffix} (use .yaml, .yml, or .json)"
                )
        # A syntactically valid but non-mapping top level (a YAML/JSON list or
        # scalar) would later crash merge_config_with_args's config.items().
        # Reject it here so it flows through the ValueError handler in main().
        if not isinstance(data, dict):
            raise ValueError(
                f"Config file must contain a mapping at the top level, got {type(data).__name__}"
            )
        return data
    except (json.JSONDecodeError, *yaml_error) as e:
        raise ValueError(f"Failed to parse config file: {e}")
    except (OSError, UnicodeDecodeError) as e:
        # PermissionError / IsADirectoryError (a directory named foo.json passes
        # the suffix check) / binary content etc. path.exists() doesn't prevent
        # these. Re-raise as ValueError so they flow through main()'s clean
        # "Config error:" / exit-1 handler instead of a raw traceback.
        raise ValueError(f"Could not read config file {path}: {e}")


def merge_config_with_args(
    args: argparse.Namespace,
    config: Dict[str, Any],
    parser: argparse.ArgumentParser,
) -> argparse.Namespace:
    """
    Merge config file values into parsed arguments.

    Command-line arguments take precedence over config file values.
    A config value is applied when the matching attribute is still at
    the argparse default (i.e. the operator did not set it on the
    command line). Per-dest defaults are computed from the parser so
    booleans / ints / lists are honored.

    Unknown keys (no matching dest, no matching subcommand action) are
    surfaced via a warning instead of being silently set — typos like
    `tiemout: 5` would otherwise create args.tiemout=5 that nothing reads.
    """
    # Walk the parser + every subparser so dests like 'unit_id' that
    # live under `oida modbus` are recognized. `-c/--config` is a
    # main-parser-only flag, so it must precede the subcommand
    # (`oida -c file.yaml modbus HOST`).
    defaults: Dict[str, Any] = {}
    for act in parser._actions:
        if act.dest != argparse.SUPPRESS:
            defaults[act.dest] = act.default
    for act in parser._actions:
        if isinstance(act, argparse._SubParsersAction):
            for sub in act.choices.values():
                for sub_act in sub._actions:
                    if sub_act.dest != argparse.SUPPRESS:
                        defaults.setdefault(sub_act.dest, sub_act.default)
    # A dest can live on both the main parser and a subparser (e.g. a
    # per-protocol flag whose default differs from the global one). The
    # sweeps above let the main parser / an arbitrary first subparser win
    # the baseline, which makes the "still-at-default?" test below compare
    # against the wrong value for the protocol actually being run. Override
    # with the ACTIVE subcommand's own defaults so the baseline matches what
    # argparse actually applied to `args`.
    active = getattr(args, "protocol", None)
    if active:
        for act in parser._actions:
            if isinstance(act, argparse._SubParsersAction) and active in act.choices:
                for sub_act in act.choices[active]._actions:
                    if (
                        sub_act.dest != argparse.SUPPRESS
                        and sub_act.default is not argparse.SUPPRESS
                    ):
                        defaults[sub_act.dest] = sub_act.default
    valid_dests = set(defaults.keys()) | {"config"}

    for key, value in config.items():
        attr_name = key.replace("-", "_")

        if attr_name not in valid_dests:
            logger.warning("Config key %r does not match any CLI argument — ignoring", key)
            continue

        if not hasattr(args, attr_name):
            setattr(args, attr_name, value)
            continue

        # Apply config value when the operator left the flag at its
        # argparse default. Identity-or-equality avoids weird edge
        # cases with mutable defaults (default=[] would compare True
        # for any empty list — fine here, the operator didn't set it).
        current = getattr(args, attr_name)
        if current == defaults.get(attr_name):
            setattr(args, attr_name, value)

    return args


_SENSITIVE_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "token",
    "psk",
    "shared_key",
    "private_key",
    "auth_string",
    "auth_pass",
    "community",
    "apikey",
    "api_key",
    "credential",
)


def _redact_sensitive_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of args with credential-like values replaced by '***'.

    None values are kept as-is so callers can distinguish 'not supplied'
    from 'supplied but hidden'.
    """
    result = {}
    for k, v in args.items():
        key_lower = k.lower()
        if v is not None and any(pat in key_lower for pat in _SENSITIVE_PATTERNS):
            result[k] = "***"
        else:
            result[k] = v
    return result


def _sanitize_table_filename(title: str) -> str:
    """Convert a table title to a safe filename stem.

    Preserves dots (for IP addresses) and uses ``--`` for flow arrows.

    Examples:
        "MODBUS 10.0.0.1:502 <-> 10.0.0.2:1234 (5 ops)" -> "modbus_10.0.0.1-502--10.0.0.2-1234"
        "OPCUA ::1:4840 <-> ::1:60012 (5 ops)" -> "opcua_loopback-4840--loopback-60012"
        "MMS Sessions" -> "mms_sessions"
        "NTLM Hashes" -> "ntlm_hashes"
    """
    import re

    name = title.lower()
    # Strip parenthesised suffixes like "(5 ops)"
    name = re.sub(r"\s*\(.*?\)\s*$", "", name)
    # Replace loopback addresses before colon-to-dash conversion.
    # IPv6 loopback ::1 (with optional port suffix) produces broken
    # filenames like "opcua--1-4840" after colon-to-dash conversion.
    name = re.sub(r"::1\b", "loopback", name)
    name = re.sub(r"\b127\.0\.0\.1\b", "loopback", name)
    # Normalise flow arrows to double-dash
    name = name.replace("<->", "--")
    # Colon -> dash (preserves IP:port readability)
    name = name.replace(":", "-")
    # Replace remaining non-alnum/dot/dash sequences with underscore
    name = re.sub(r"[^a-z0-9.\-]+", "_", name)
    # Collapse repeated separators
    name = re.sub(r"[_\-]{2,}", lambda m: "--" if "-" in m.group() else "_", name)
    return name.strip("_.-") or "table"


def _export_tables(
    tables: List[Dict[str, Any]],
    output_dir: str,
    formats: List[str],
    nxc_logger=None,
) -> None:
    """Write each harvest table to *output_dir*, one file per requested format.

    Only the formats the user selected (via ``--format``) are written, so
    ``--format json`` produces ``<table>.json`` and no ``.csv`` sibling, and
    vice versa.
    """
    _log = nxc_logger or get_logger("EXPORT", "", 0)
    want_csv = "csv" in formats
    want_json = "json" in formats
    want_xml = "xml" in formats
    if not (want_csv or want_json or want_xml):
        return
    os.makedirs(output_dir, exist_ok=True)
    seen: Dict[str, int] = {}
    exported = 0
    for table in tables:
        rows = table.get("rows")
        headers = table.get("headers")
        if not rows or not headers:
            continue

        stem = _sanitize_table_filename(table.get("title", "table"))
        # De-duplicate filenames by appending a counter
        if stem in seen:
            seen[stem] += 1
            stem = f"{stem}_{seen[stem]}"
        else:
            seen[stem] = 0

        written = []
        if want_csv:
            csv_path = os.path.join(output_dir, f"{stem}.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            written.append("csv")

        if want_json:
            # JSON (list of dicts) — use structured json_rows when available
            json_path = os.path.join(output_dir, f"{stem}.json")
            json_data = table.get("json_rows") or [dict(zip(headers, row)) for row in rows]
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, default=str)
            written.append("json")

        if want_xml:
            # Previously missing: `--format xml` hit the early return above and
            # every harvest table was silently discarded.
            xml_path = Path(output_dir) / f"{stem}.xml"
            if _write_xml(xml_path, headers, rows, stem):
                written.append("xml")

        _log.debug("Table exported: %s (%s)", stem, "/".join(written))
        exported += 1

    if exported:
        _log.success(f"{exported} tables exported to {output_dir}")


def _flatten_results_for_export(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten scan results into tabular rows (shared by CSV and XML export).

    ``data`` sub-fields are hoisted to ``data_<key>`` columns; the ``tables``
    key is skipped (it gets dedicated per-table files).
    """
    flat_results = []
    for r in results:
        flat = {
            "host": r.get("host", ""),
            "ip": r.get("ip", ""),
            "protocol": r.get("protocol", ""),
            "port": r.get("port", ""),
            "success": r.get("success", False),
            "error": r.get("error", ""),
        }
        data = r.get("data", {})
        if isinstance(data, dict):
            for key, value in data.items():
                # ``tables`` get their own dedicated files
                if key == "tables":
                    continue
                # Convert complex values to strings
                if isinstance(value, (dict, list)):
                    flat[f"data_{key}"] = json.dumps(value, default=str)
                else:
                    flat[f"data_{key}"] = value
        flat_results.append(flat)
    return flat_results


def export_results(
    results: List[Dict[str, Any]],
    output_path: str,
    output_format: str,
    protocol_name: str = "scan",
    nxc_logger=None,
) -> None:
    """
    Export scan results to file(s) in specified format(s).

    ``-o DIR`` is treated as a directory.  Files are written inside it,
    named after the protocol (e.g. ``pcap.json``, ``modbus.json``).

    Args:
        results: List of result dictionaries from scans
        output_path: Output directory
        output_format: Format option ("json", "csv", "xml", "console", "all")
        protocol_name: Protocol identifier used for the summary filename
        nxc_logger: Optional NXC-style logger for prefixed output
    """
    _log = nxc_logger or get_logger("EXPORT", "", 0)
    if not results:
        _log.warning("No results to export")
        return

    # Determine formats to export
    formats = []
    if output_format.lower() == "all":
        formats = ["json", "csv", "xml"]
    elif output_format.lower() in ["json", "csv", "xml"]:
        formats = [output_format.lower()]

    # Treat -o as a directory
    output_dir = output_path
    os.makedirs(output_dir, exist_ok=True)

    # Collect per-table data from pcap results for dedicated file export.
    # Read without mutating the caller-owned result dicts; ``tables`` are
    # written to dedicated CSV files below, so they are excluded from the
    # JSON/CSV dumps at export time rather than by deleting them in place.
    all_tables: List[Dict[str, Any]] = []
    for r in results:
        data = r.get("data", {})
        if isinstance(data, dict):
            tables = data.get("tables", [])
            if tables:
                all_tables.extend(tables)

    for fmt in formats:
        if fmt == "json":
            json_path = os.path.join(output_dir, f"{protocol_name}.json")
            export_results_json = [
                {
                    **r,
                    "data": {k: v for k, v in r["data"].items() if k != "tables"},
                }
                if isinstance(r.get("data"), dict) and "tables" in r["data"]
                else r
                for r in results
            ]
            with open(json_path, "w") as f:
                json.dump(export_results_json, f, indent=2, default=str)
            _log.debug("Results exported to %s", json_path)

        elif fmt == "csv":
            csv_path = os.path.join(output_dir, f"{protocol_name}.csv")
            flat_results = _flatten_results_for_export(results)
            if flat_results:
                # Get all unique keys
                all_keys = set()
                for r in flat_results:
                    all_keys.update(r.keys())
                fieldnames = sorted(all_keys)

                with open(csv_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(flat_results)
                _log.debug("Results exported to %s", csv_path)

        elif fmt == "xml":
            xml_path = Path(output_dir) / f"{protocol_name}.xml"
            flat_results = _flatten_results_for_export(results)
            if flat_results:
                headers = sorted({k for r in flat_results for k in r})
                rows = [[r.get(h, "") for h in headers] for r in flat_results]
                if _write_xml(xml_path, headers, rows, protocol_name):
                    _log.debug("Results exported to %s", xml_path)

    # Write each harvest table as dedicated file(s), honouring --format
    if all_tables:
        _export_tables(all_tables, output_dir, formats, nxc_logger=nxc_logger)


def _select_parser_mode(argv, known_names):
    """Decide how much of the protocol CLI parser to build.

    Building every protocol's subparser imports every protocol package
    (scapy / pydicom / c104 / snap7 / ...), which made even ``oida --help`` slow
    to boot -- badly so in the frozen standalone binary. Returns ``(mode, name)``:

      ("one", <proto>) -> fully register only <proto>, stub the rest  (fast)
      ("stub", None)   -> stub every protocol: help / version / fuzz / serial /
                          no subcommand -- none of those need a scanner  (fast)
      ("all", None)    -> fully register everything: safe fallback for anything
                          ambiguous (e.g. a global option value before the
                          subcommand)  (same cost as before -- no regression)

    It only narrows when the invoked subcommand is unambiguously a known protocol
    (resolving aliases like ``s7`` -> ``snap7``, ``discover`` -> ``discovery``),
    so it can only make common invocations faster, never break or slow an odd one.
    """
    positional = [t for t in argv[1:] if not t.startswith("-")]
    if not positional:
        return ("stub", None)
    first = positional[0]
    canonical = PROTOCOL_ALIASES.get(first, first)
    if canonical in known_names:
        return ("one", canonical)
    if first in ("fuzz", "serial", "help"):
        return ("stub", None)
    return ("all", None)


def gen_cli_args(argv=None):
    """
    Generate argument parser with dynamic protocol loading

    Scans the protocols directory and registers each protocol's
    arguments dynamically.

    Args:
        argv: The argument list this parser will be asked to parse — the
            caller's ``main(argv)`` view, defaulting to ``sys.argv``. The
            selective-registration fast path inspects THIS list (not the
            process argv) to decide which protocol subparser to fully
            build: reading the process argv instead made programmatic /
            embedded ``main(argv=[...])`` calls build stub parsers that
            reject protocol aliases (``oida s7``) and per-protocol flags.

    Returns:
        argparse.ArgumentParser: Configured argument parser
    """

    # Custom parser class that shows subcommand help on errors
    class SubcommandHelpParser(argparse.ArgumentParser):
        """Parser that shows subcommand-specific help on errors.

        On the *main* parser (``_is_main``) ``-h`` reuses the same colored,
        domain-grouped protocol listing as the no-arg screen, instead of
        argparse's flat ``{serial,fuzz,ads,...}`` dump. Subparsers created
        from this class inherit the type but keep ``_is_main`` False, so
        per-protocol ``oida <proto> -h`` renders normally.
        """

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._subparsers_action = None
            self._is_main = False

        def error(self, message):
            """Show subcommand help when an error occurs in a subcommand."""
            # Check if we're in a subcommand context
            if hasattr(self, "_active_subparser") and self._active_subparser:
                self._active_subparser.print_usage(sys.stderr)
                self.exit(2, f"{self._active_subparser.prog}: error: {message}\n")
            else:
                super().error(message)

        def format_help(self):
            """Render global options via argparse, then append the grouped,
            colored protocol sections — keeping ``oida -h`` consistent with
            the no-arg screen and free of the giant subparser-choices blob.
            """
            if not self._is_main:
                return super().format_help()

            formatter = self._get_formatter()
            formatter.add_usage(self.usage, self._actions, self._mutually_exclusive_groups)
            formatter.add_text(self.description)

            # Render every argument group EXCEPT the subparsers group (the flat
            # protocol dump) — that is replaced by the grouped sections below.
            for action_group in self._action_groups:
                if any(
                    isinstance(a, argparse._SubParsersAction) for a in action_group._group_actions
                ):
                    continue
                formatter.start_section(action_group.title)
                formatter.add_text(action_group.description)
                formatter.add_arguments(action_group._group_actions)
                formatter.end_section()

            parts = [_banner_str(), formatter.format_help()]
            sections = _format_protocol_sections(self)
            if sections is not None:
                parts.append(sections)
            parts.append(
                f"Run {_c('oida <protocol> -h', 'yellow')} for protocol-specific options\n"
            )
            return "\n".join(parts)

    # Create main parser
    parser = SubcommandHelpParser(
        prog="oida",
        description="O.I.D.A. = OT / ICS Dynamic Assessment framework",
        epilog="For protocol-specific help: oida <protocol> --help",
    )
    # Only the top-level parser gets the grouped/colored -h treatment; the
    # dynamically created subparsers stay False (set in __init__).
    parser._is_main = True

    # Global options
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--bug", action="store_true", help="Print diagnostic info for bug reports")

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        metavar="FILE",
        help="Load scan configuration from YAML or JSON file",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")

    output_group.add_argument(
        "-o", "--output", type=str, help="Output file path (without extension)"
    )

    output_group.add_argument(
        "--format",
        choices=["json", "csv", "xml", "console", "all"],
        default="console",
        help="Output format (default: console)",
    )

    output_group.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")

    output_group.add_argument(
        "-W",
        "--full-width",
        action="store_true",
        default=False,
        help="Show full-width tables without truncating to terminal width",
    )

    output_group.add_argument(
        "--json-log",
        type=str,
        metavar="FILE",
        help="Write structured JSON log events to FILE (NDJSON format, one object per line)",
    )

    # Create subparsers for protocols
    subparsers = parser.add_subparsers(
        title="Available Protocols",
        dest="protocol",
        required=True,
        metavar="<protocol>",
        help="Protocol to use for scanning",
    )

    # Register serial utilities subcommand
    serial_args(subparsers, [])

    # Register fuzz subcommand
    fuzz_args(subparsers, [])

    # Standard parser (inherited by all protocols)
    std_parser = argparse.ArgumentParser(add_help=False)

    # Mirror the most-used global flags onto every protocol subparser so they
    # are also accepted *after* the subcommand and target -- e.g.
    # `oida modbus HOST -v` -- not only before it. argparse only lets a
    # parser's own optionals appear ahead of its subcommand, so without this
    # `oida modbus HOST -v` is rejected with a confusing usage error.
    #
    # default=SUPPRESS is essential: when a flag is absent after the
    # subcommand, the subparser must NOT write its dest, otherwise it would
    # clobber the value already parsed before the subcommand back to a default.
    # The pre-subcommand definitions on the main parser supply the real
    # defaults, so each attribute is always present on the namespace either way.
    #
    # Short aliases that individual protocols reuse for their own options
    # (-o, -q, -t, -W) are deliberately mirrored by long form only; after the
    # subcommand those short flags keep their protocol-specific meaning.
    post_cmd = std_parser.add_argument_group("Global Options (also valid after the target)")
    post_cmd.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="Increase verbosity (-v, -vv, -vvv)",
    )
    post_cmd.add_argument(
        "--debug", action="store_true", default=argparse.SUPPRESS, help="Enable debug output"
    )
    post_cmd.add_argument(
        "--quiet", action="store_true", default=argparse.SUPPRESS, help="Suppress console output"
    )
    post_cmd.add_argument(
        "--output", type=str, default=argparse.SUPPRESS, help="Output file path (without extension)"
    )
    post_cmd.add_argument(
        "--format",
        choices=["json", "csv", "xml", "console", "all"],
        default=argparse.SUPPRESS,
        help="Output format",
    )
    post_cmd.add_argument(
        "--threads", type=int, default=argparse.SUPPRESS, help="Number of concurrent threads"
    )
    post_cmd.add_argument(
        "--full-width",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show full-width tables without truncating to terminal width",
    )
    post_cmd.add_argument(
        "--json-log",
        type=str,
        metavar="FILE",
        default=argparse.SUPPRESS,
        help="Write structured JSON log events to FILE (NDJSON format)",
    )

    # Load protocols dynamically
    protocols_dir = Path(__file__).parent / "protocols"
    p_loader = ProtocolLoader(str(protocols_dir))
    protocols = p_loader.get_protocols()

    # Only fully build the subparser for the subcommand actually being invoked;
    # stub the rest. Fully registering a protocol imports its (heavy) package, so
    # doing it for all 26+ protocols on every launch made the CLI -- and the
    # frozen binary especially -- slow to boot. See _select_parser_mode.
    _mode, _selected = _select_parser_mode(
        sys.argv if argv is None else argv, set(protocols.keys())
    )

    protocols_registered = 0

    def _add_stub_subparser(name):
        """A lightweight placeholder subparser (no protocol import), enough to
        list the command in --help and dispatch when it is actually selected."""
        stub = subparsers.add_parser(
            name,
            help=f"{name} protocol (run 'oida {name} -h' for options)",
            parents=[std_parser],
        )
        stub.add_argument(
            "target",
            nargs="?",
            default="127.0.0.1",
            help="Target IP, hostname, CIDR, range, or file",
        )
        stub.add_argument(
            "--port",
            type=int,
            help="Target port (protocol default if not specified)",
        )

    # Register each protocol's arguments
    for protocol_name in sorted(protocols.keys()):
        protocol_info = protocols[protocol_name]
        full = (_mode == "all") or (_mode == "one" and protocol_name == _selected)

        registered = False
        if full and protocol_info.get("argspath"):
            try:
                # Load proto_args module using dedicated method (imports the
                # protocol package -- only for the selected subcommand).
                proto_args_module = p_loader.load_proto_args(protocol_name)
                if proto_args_module and hasattr(proto_args_module, "proto_args"):
                    proto_args_module.proto_args(subparsers, [std_parser])
                    registered = True
                    logger.debug(f"Registered protocol: {protocol_name}")
                elif proto_args_module:
                    logger.warning(
                        "Protocol '%s': proto_args.py has no proto_args() function",
                        protocol_name,
                    )
            except Exception as e:
                logger.warning("Protocol '%s' not available: %s", protocol_name, e)

        if not registered:
            logger.debug(f"Creating stub subparser for {protocol_name}")
            _add_stub_subparser(protocol_name)

        protocols_registered += 1

    logger.debug(f"Registered {protocols_registered} protocols")

    # Store the subparsers action for later access to subparser choices
    parser._subparsers_action = subparsers

    # Persist the loader so main() can reuse it (R7: avoid double instantiation)
    parser._protocol_loader = p_loader

    return parser


def setup_logging(args):
    """
    Configure logging based on verbosity flags

    Args:
        args: Parsed command-line arguments
    """
    if args.debug or args.verbose >= 1:
        level = logging.DEBUG
    else:
        level = logging.ERROR

    # Set level on oida namespace logger (not root) to avoid duplicate
    # output from root's basicConfig handler + LogHandler propagation.
    logging.getLogger("oida").setLevel(level)
    logger.setLevel(level)

    # Enable ICSLogger verbose mode for debug output with [D] sigil
    if args.verbose >= 1 or args.debug:
        from oida.utils.ics_logger import set_verbose

        set_verbose(True)


def _banner_str() -> str:
    """Return the colored OIDA banner block (no trailing newline collapse)."""
    art = _c(
        "     ██████╗ ██╗██████╗  █████╗\n"
        "    ██╔═══██╗██║██╔══██╗██╔══██╗\n"
        "    ██║   ██║██║██║  ██║███████║\n"
        "    ██║   ██║██║██║  ██║██╔══██║\n"
        "    ╚██████╔╝██║██████╔╝██║  ██║\n"
        "     ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝",
        "cyan",
        attrs=["bold"],
    )
    version = _c(f"v{__version__}", "dark_grey")
    tagline = _c("Scan. Fuzz. Assess. Responsibly in OT.", "white", attrs=["bold"])
    url = _c("https://getoida.dev", "blue")
    return f"\n{art}  {version}\n\n    {tagline}\n    {url}\n"


def print_banner():
    """Print OIDA banner"""
    print(_banner_str())


# Subcommands that are utilities, not scannable wire protocols. These are
# surfaced under "Discovery & tooling" rather than mixed into the protocol
# list, since they don't take a single <target> the way a scanner does.
_NON_PROTOCOL_SUBCOMMANDS = {"serial", "fuzz"}

# Passive/active modules that read traffic or sweep a network rather than
# scan one wire protocol — grouped with the tooling, not the scanners.
_CORE_TOOLING = {"discovery", "pcap"}

# Display grouping for the no-arg usage screen, keyed on canonical names.
# Anything registered but unlisted here falls into "Other protocols", so a
# newly added scanner still shows up — it just lands in the catch-all until
# it's slotted into a section. (title, color, {canonical names})
_PROTOCOL_CATEGORIES: List[Tuple[str, str, set]] = [
    (
        "OT / industrial",
        "cyan",
        {
            "modbus",
            "opcua",
            "snap7",
            "iec104",
            "ads",
            "ethernetip",
            "dnp3",
            "mms",
            "tase2",
            "goose",
            "ethercat",
            "profinet",
            "hart",
            "knx",
            "bacnet",
            "can",
        },
    ),
    ("IoT / application", "green", {"mqtt", "coap", "ocpp", "snmp"}),
    ("Healthcare", "magenta", {"hl7", "fhir", "dicom", "astm"}),
]


def _subcommand_help(parser) -> Dict[str, Tuple[str, str]]:
    """Map every registered subcommand to (display_name, help_text).

    Reads the help strings argparse already stores on each registered
    subparser, so the no-arg usage screen can never drift from the actual
    set of dynamically loaded protocols. display_name folds in aliases
    (e.g. ``snap7 (s7)``); the dict key stays the canonical name.
    """
    action = getattr(parser, "_subparsers_action", None)
    if action is None:
        return {}

    # canonical name -> aliases (reverse of PROTOCOL_ALIASES)
    aliases: Dict[str, List[str]] = {}
    for alias, canonical in PROTOCOL_ALIASES.items():
        aliases.setdefault(canonical, []).append(alias)

    result: Dict[str, Tuple[str, str]] = {}
    for pseudo in action._choices_actions:
        name = pseudo.dest
        display = name
        if name in aliases:
            display = f"{name} ({', '.join(sorted(aliases[name]))})"
        result[name] = (display, pseudo.help or "")
    return result


def _section_str(title: str, color: str, rows: List[Tuple[str, str]], width: int) -> str:
    """Build one colored section header followed by its name/help rows."""
    if not rows:
        return ""
    lines = [_c(title, color, attrs=["bold"])]
    for display, help_text in sorted(rows):
        lines.append(f"  {_c(display.ljust(width), color)}  {help_text}")
    lines.append("")
    return "\n".join(lines)


def _format_protocol_sections(parser=None) -> Optional[str]:
    """Build the grouped, colored protocol listing shared by the no-arg
    screen and ``oida -h``.

    Returns None when the protocol set cannot be enumerated, so callers can
    fall back to a plain hint.
    """
    subcommands = _subcommand_help(parser) if parser is not None else {}
    if not subcommands:
        return None

    # Consistent column width across every section so help text lines up.
    width = max((len(display) for display, _ in subcommands.values()), default=0)
    categorized: set = set()
    blocks: List[str] = []

    # Scannable protocols, grouped by domain.
    for title, color, names in _PROTOCOL_CATEGORIES:
        rows = [subcommands[n] for n in names if n in subcommands]
        categorized.update(n for n in names if n in subcommands)
        blocks.append(_section_str(title, color, rows, width))

    # Anything registered but not slotted into a category above (excluding
    # the tooling subcommands handled separately) — keeps new protocols visible.
    other = [
        info
        for name, info in subcommands.items()
        if name not in categorized
        and name not in _CORE_TOOLING
        and name not in _NON_PROTOCOL_SUBCOMMANDS
    ]
    blocks.append(_section_str("Other protocols", "white", other, width))

    # Discovery / passive / fuzzing — not single-target wire scanners.
    tooling = [
        subcommands[n]
        for n in (*sorted(_CORE_TOOLING), *sorted(_NON_PROTOCOL_SUBCOMMANDS))
        if n in subcommands
    ]
    blocks.append(_section_str("Discovery & tooling", "blue", tooling, width))

    return "\n".join(b for b in blocks if b)


def _show_usage_and_exit(parser=None) -> int:
    """Show grouped, colored usage information when no arguments provided."""
    print_banner()
    print(f"{_c('Usage:', 'yellow', attrs=['bold'])} oida <protocol> <target> [options]\n")

    sections = _format_protocol_sections(parser)
    if sections is None:
        print("  (unable to enumerate protocols; run 'oida <protocol> -h')")
        print("\nRun 'oida <protocol> -h' for protocol-specific options")
        return 0

    print(sections)
    print(f"Run {_c('oida <protocol> -h', 'yellow')} for protocol-specific options")
    return 0


def _list_serial_ports(for_iec101: bool = False) -> int:
    """List available serial ports"""
    try:
        import serial.tools.list_ports

        ports = list(serial.tools.list_ports.comports())
        if not ports:
            print("No serial ports found")
        else:
            header = (
                "Available serial ports (for --iec101 mode):"
                if for_iec101
                else "Available serial ports:"
            )
            print(header)
            for port in ports:
                desc = port.description or ""
                hwid = port.hwid or ""
                print(f"  {port.device}  - {desc} ({hwid})")
        return 0
    except ImportError:
        logger.error("pyserial not available. Install with: pip install oida-ics[serial]")
        return 1


def _resolve_targets(args, protocol_name: str, is_serial_protocol: bool) -> Optional[List[str]]:
    """
    Parse and resolve targets from arguments.

    Returns:
        List of targets, or None on error (error already logged)
    """
    target_input = getattr(args, "target", None)
    list_maps = getattr(args, "list_maps", False)

    if list_maps and not target_input:
        return ["list-maps"]

    if is_serial_protocol:
        logger.info(f"Serial port target: {target_input}")
        return [target_input]

    # File-path protocols (e.g. pcap) pass the path through directly
    if protocol_name in FILE_TARGET_PROTOCOLS:
        return [target_input]

    # Parse targets from input
    try:
        targets = parse_targets(target_input)
        logger.info(f"Parsed {len(targets)} targets from '{target_input}'")
        return targets
    except Exception as e:
        logger.error(f"Failed to parse targets '{target_input}': {e}")
        return None


def _execute_scans(protocol_class, args, targets: List[str], protocol_name: str) -> tuple:
    """
    Execute scans concurrently against all targets.

    Returns:
        (results_list, successful_count, failed_count)
    """
    results = []
    failed = 0
    successful = 0

    # Create progress logger for NXC-style output.
    # protocol_class.default_port is almost never set at class scope (Layer-2
    # protocols set self.default_port in __init__; Layer-1 uses
    # get_default_port(), an instance method) — args.port already carries the
    # protocol's real default via add_network_options(..., default_port=N),
    # so prefer it and only fall back to the (usually absent) class attribute.
    default_port = getattr(args, "port", None) or getattr(protocol_class, "default_port", 0)
    progress_logger = get_logger(protocol_name.upper(), "*", default_port)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all scan tasks
        future_to_target = {
            executor.submit(scan_target, protocol_class, args, target): target for target in targets
        }

        # Process completed scans
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                if result and result.get("success"):
                    successful += 1
                else:
                    failed += 1
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning {target}: {e}")
                failed += 1

            # Progress indicator (NXC-style)
            if not args.quiet and len(targets) > 1:
                completed = successful + failed
                progress_logger.progress(completed, len(targets), successful, failed)

    # Clear progress line
    if not args.quiet and len(targets) > 1:
        print()

    return results, successful, failed


# Protocol name aliases (CLI name -> loader name)
PROTOCOL_ALIASES = {
    "s7": "snap7",  # oida s7 -> snap7.py
    "discover": "discovery",  # oida discover -> discovery (verb form)
}

# Serial protocols (use serial port as target instead of IP)
SERIAL_PROTOCOLS: set = set()

# Protocols whose target is a file path (bypass IP/CIDR target parsing)
FILE_TARGET_PROTOCOLS = {"pcap"}


def print_bug_report() -> None:
    """Print diagnostic information useful for filing bug reports."""
    import platform
    import socket
    import sys
    import importlib

    lines = []
    lines.append("OIDA Bug Report Info")
    lines.append("====================")

    # Version
    lines.append(f"Version:      {__version__}")

    # Python
    py_impl = platform.python_implementation()
    py_ver = platform.python_version()
    lines.append(f"Python:       {py_ver} ({py_impl})")
    lines.append(f"Python Path:  {sys.executable}")

    # Virtualenv
    in_venv = sys.prefix != sys.base_prefix
    venv_info = "Yes" if in_venv else "No"
    if in_venv:
        venv_info += f" ({sys.prefix})"
    lines.append(f"Virtualenv:   {venv_info}")

    # Install mode
    frozen = getattr(sys, "frozen", False)
    if frozen:
        bundler = getattr(sys, "_MEIPASS", None)
        if bundler:
            lines.append("Install:      PyInstaller bundle")
        else:
            lines.append("Install:      frozen binary")
    else:
        try:
            from importlib.metadata import distribution

            dist = distribution("oida")
            direct_url = dist.read_text("direct_url.json")
            if direct_url and "dir_info" in direct_url:
                lines.append("Install:      editable (pip install -e)")
            else:
                lines.append("Install:      pip")
        except Exception:
            lines.append("Install:      unknown")

    # Pip version
    try:
        from importlib.metadata import version as pkg_version

        pip_ver = pkg_version("pip")
        lines.append(f"pip:          {pip_ver}")
    except Exception as e:
        logger.debug(f"Optional import pkg_version not available: {e}")

    # Platform and architecture
    arch = platform.machine() or "unknown"
    kernel = platform.release() or "unknown"
    system = platform.system() or "unknown"
    lines.append(f"Platform:     {system} {kernel} {arch}")

    # OS distribution (Linux-specific, falls back gracefully)
    os_name = ""
    if system == "Linux":
        try:
            import distro

            os_name = distro.name(pretty=True)
        except ImportError as e:
            logger.debug(f"Optional import distro not available: {e}")
        if not os_name:
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            os_name = line.split("=", 1)[1].strip().strip('"')
                            break
            except (OSError, IOError) as e:
                logger.debug(f"with open(etcos-release) as f:: {e}")
    elif system == "Darwin":
        mac_ver = platform.mac_ver()[0]
        os_name = f"macOS {mac_ver}" if mac_ver else "macOS"
    elif system == "Windows":
        os_name = platform.platform()

    if os_name:
        lines.append(f"OS:           {os_name}")

    # Root check
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    lines.append(f"Root:         {'Yes' if is_root else 'No'}")

    # Raw socket test
    raw_socket_msg = ""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
        raw_socket_msg = "Yes"
    except AttributeError:
        raw_socket_msg = "No (AF_PACKET not available on this platform)"
    except PermissionError:
        raw_socket_msg = "No (needs root or CAP_NET_RAW)"
    except OSError as e:
        raw_socket_msg = f"No ({e})"
    lines.append(f"Raw Sockets:  {raw_socket_msg}")

    # Linux capabilities (CAP_NET_RAW specifically)
    if system == "Linux" and not is_root:
        cap_msg = "unknown"
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_hex = int(line.split(":")[1].strip(), 16)
                        has_net_raw = bool(cap_hex & (1 << 13))  # CAP_NET_RAW = 13
                        cap_msg = "Yes" if has_net_raw else "No"
                        break
        except (OSError, ValueError) as e:
            logger.debug(f"with open(procselfstatus) as f:: {e}")
        lines.append(f"CAP_NET_RAW:  {cap_msg}")

    # Locale
    import locale

    lines.append(f"Locale:       {locale.getlocale()[0] or 'C'} / {locale.getpreferredencoding()}")

    # tshark
    import shutil
    import subprocess

    tshark_path = shutil.which("tshark")
    if tshark_path:
        try:
            result = subprocess.run(
                [tshark_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            first_line = result.stdout.split("\n", 1)[0] if result.stdout else "?"
            lines.append(f"tshark:       {first_line}")
        except Exception:
            lines.append(f"tshark:       {tshark_path} (version unknown)")
    else:
        lines.append("tshark:       not found")

    # Protocol dependencies — derived directly from installed metadata
    lines.append("")
    lines.append("Protocol Dependencies:")

    def _fmt_exc(e: BaseException, limit: int = 140) -> str:
        # Surface the real cause: "ValueError" alone is useless, but
        # "ValueError: numpy.dtype size changed ..." points straight at an
        # ABI mismatch. Keep it to the first line and cap the length so the
        # report stays readable.
        msg = str(e).strip().splitlines()[0] if str(e).strip() else ""
        if len(msg) > limit:
            msg = msg[: limit - 1] + "…"
        return f"{type(e).__name__}: {msg}" if msg else type(e).__name__

    import re

    try:
        from importlib.metadata import requires as _requires
    except ImportError:
        from importlib_metadata import requires as _requires  # type: ignore[no-redef]

    from oida.utils.lazy_import import _IMPORT_OVERRIDES, _SKIP_EXTRAS

    _extra_re = re.compile(r'extra\s*==\s*"([^"]+)"')
    _seen_pkgs: set = set()
    dep_packages = []
    for line in _requires("oida") or []:
        m = _extra_re.search(line)
        if not m:
            continue
        extra_name = m.group(1)
        if extra_name in _SKIP_EXTRAS:
            continue
        # Strip the PEP 508 URL form first ("pyshark @ git+https://…") so the
        # display/import name is the bare distribution, then version specifiers
        # and extras.
        pip_name = line.split(";")[0].split("@")[0]
        for _sep in (">", "<", "=", "!", "~", "["):
            pip_name = pip_name.split(_sep)[0]
        pip_name = pip_name.strip()
        if pip_name in _seen_pkgs:
            continue
        _seen_pkgs.add(pip_name)
        import_name = _IMPORT_OVERRIDES.get(pip_name.lower(), pip_name)
        dep_packages.append((pip_name, import_name, extra_name))

    # Suppress noisy library warnings (e.g. c104 buffered mode) during imports
    import logging

    _devnull = open(os.devnull, "w")
    _saved_stderr = sys.stderr
    _saved_stdout = sys.stdout
    _saved_log_level = logging.root.level
    sys.stderr = _devnull
    sys.stdout = _devnull
    logging.root.setLevel(logging.CRITICAL)

    try:
        for display_name, import_name, proto in dep_packages:
            try:
                mod = importlib.import_module(import_name)
                ver = getattr(mod, "__version__", None)
                if ver is not None and not isinstance(ver, str):
                    ver = None
                if ver is None:
                    ver = getattr(mod, "VERSION", None)
                    if ver is not None and not isinstance(ver, str):
                        ver = None
                if ver is None:
                    try:
                        from importlib.metadata import version as pkg_version

                        ver = pkg_version(display_name)
                    except Exception:
                        ver = "?"
                lines.append(f"  {display_name:<20s}{ver:<12s}({proto})")
            except ImportError:
                lines.append(f"  {display_name:<20s}{'--':<12s}({proto}) NOT INSTALLED")
            except Exception as e:
                # Installed but failed to load — e.g. a native lib (adslib.so,
                # libsnap7) missing from a frozen build, or a transitive ABI
                # mismatch (numpy/pandas). A diagnostic probe must never crash
                # on this; report it with the message and move on. The message
                # is the whole point of the probe — a bare type name like
                # "ValueError" hides the actual cause.
                lines.append(
                    f"  {display_name:<20s}{'--':<12s}({proto}) UNAVAILABLE ({_fmt_exc(e)})"
                )

        # Protocol load test
        lines.append("")
        lines.append("Protocol Modules:")
        try:
            protocols_dir = os.path.join(os.path.dirname(__file__), "protocols")
            loader = ProtocolLoader(protocols_dir)
            available = loader.get_protocols()
            for name in sorted(available.keys()):
                try:
                    importlib.import_module(f"oida.protocols.{name}")
                    lines.append(f"  {name:<20s}OK")
                except Exception as e:
                    lines.append(f"  {name:<20s}FAIL ({_fmt_exc(e)})")
        except Exception:
            lines.append("  (could not enumerate protocols)")
        # All installed packages
        lines.append("")
        lines.append("Installed Packages:")
        try:
            from importlib.metadata import distributions

            pkgs = sorted(
                ((d.metadata["Name"], d.metadata["Version"]) for d in distributions()),
                key=lambda x: x[0].lower(),
            )
            for name, ver in pkgs:
                lines.append(f"  {name:<30s}{ver}")
        except Exception:
            lines.append("  (could not list packages)")
    finally:
        sys.stderr = _saved_stderr
        sys.stdout = _saved_stdout
        logging.root.setLevel(_saved_log_level)
        _devnull.close()

    report = "\n".join(lines)
    print(f"```\n{report}\n```")


def main(argv: Optional[List[str]] = None):
    """
    Main CLI entry point

    Args:
        argv: Command-line arguments (uses sys.argv if None)

    Returns:
        int: Exit code (0 for success, non-zero for error)
    """
    # Windows consoles default to a legacy code page (e.g. cp1252) that can't
    # encode the Unicode in help/output text, which crashes a frozen binary
    # with "charmap codec can't encode character". Force UTF-8 on the standard
    # streams so output is encoding-safe on every platform.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args_to_parse = argv if argv is not None else sys.argv[1:]

    # Handle --bug before argparse (no protocol subcommand required)
    if "--bug" in args_to_parse:
        print_bug_report()
        return 0

    # Show banner when no arguments provided
    if not args_to_parse:
        try:
            parser = gen_cli_args(sys.argv)
        except Exception as e:
            logger.debug(f"parser build failed for banner: {e}")
            parser = None
        return _show_usage_and_exit(parser)

    # Generate parser. Pass the args we are ABOUT to parse, not the process
    # argv: gen_cli_args() keys selective registration off this list, and an
    # embedding process can have a very different sys.argv (e.g. a wrapper
    # whose own first positional is another protocol name).
    try:
        parser = gen_cli_args(["oida", *args_to_parse])
    except Exception as e:
        logger.error(f"Failed to initialize CLI: {e}")
        return 1

    # Detect subcommand for better error messages
    if args_to_parse and parser._subparsers_action:
        for arg in args_to_parse:
            if not arg.startswith("-"):
                choices = parser._subparsers_action.choices
                if arg in choices:
                    parser._active_subparser = choices[arg]
                break

    # Parse arguments
    args = parser.parse_args(argv)

    # Load config file if specified
    if args.config:
        try:
            config = load_config_file(args.config)
            args = merge_config_with_args(args, config, parser=parser)
            logger.info(f"Loaded configuration from {args.config}")
        except ValueError as e:
            logger.error(f"Config error: {e}")
            return 1

    # Setup logging and exports
    setup_logging(args)
    configure_from_args(args)

    logger.debug("CLI args: %s", _redact_sensitive_args(vars(args)))

    # Enable structured JSON logging if requested
    json_log_path = getattr(args, "json_log", None)
    if json_log_path:
        from oida.utils.ics_logger import set_json_log_path

        set_json_log_path(json_log_path)

    # Handle special subcommands (not protocols)
    if args.protocol == "serial":
        return handle_serial_command(args)
    if args.protocol == "fuzz":
        return handle_fuzz_command(args)

    # Handle --list-ports for IEC 104 (IEC 101 serial mode)
    if args.protocol == "iec104" and getattr(args, "list_ports", False):
        return _list_serial_ports(for_iec101=True)

    # Resolve protocol alias
    protocol_name = PROTOCOL_ALIASES.get(args.protocol, args.protocol)
    is_serial_protocol = protocol_name in SERIAL_PROTOCOLS

    # Handle --list-ports for serial protocols
    if is_serial_protocol and getattr(args, "list_ports", False):
        return _list_serial_ports(for_iec101=False)

    # Reuse the ProtocolLoader from gen_cli_args() (its cache is already warm)
    p_loader = parser._protocol_loader
    try:
        protocol_class = p_loader.get_protocol_class(protocol_name)
        logger.debug(f"Loaded protocol class: {protocol_class.__name__}")
    except Exception as e:
        logger.error(f"Failed to load protocol {args.protocol}: {e}")
        return 1

    # Validate target is provided (unless in special modes)
    target_input = getattr(args, "target", None)
    list_maps = getattr(args, "list_maps", False)

    # GOOSE has two modes that carry their own target instead of the
    # positional: MMS GoCB enumeration (--mms-enum <ip>) and the R-GOOSE
    # listener (--rgoose). When the positional interface is absent, derive
    # the run target from --mms-enum so the documented
    # `oida goose --mms-enum <ip>` invocation works; the GOOSEScanner reads
    # --mms-enum directly and ignores the interface in that branch.
    if protocol_name == "goose" and not target_input:
        mms_enum = getattr(args, "mms_enum", None)
        if mms_enum:
            target_input = mms_enum
            args.target = mms_enum
        elif getattr(args, "rgoose", False):
            # R-GOOSE is unimplemented; pass through so the scanner can emit
            # its own "not yet supported" message instead of an argparse error.
            target_input = "rgoose"
            args.target = "rgoose"

    if not target_input and not list_maps:
        if is_serial_protocol:
            logger.error("No serial port specified. Usage: oida iec101 /dev/ttyUSB0")
            logger.error("Use --list-ports to see available serial ports")
        elif protocol_name == "discovery":
            logger.error("No interface specified. Usage: oida discovery <interface>")
            logger.error("Example: oida discovery eth0")
        else:
            logger.error("No target specified. Usage: oida <protocol> <target>")
            logger.error("Example: oida s7 192.168.1.100")
        return 1

    # Resolve targets
    targets = _resolve_targets(args, protocol_name, is_serial_protocol)
    if targets is None or not targets:
        if targets is not None:  # Empty list case
            logger.error(f"No valid targets found in: {target_input}")
        return 1

    # Execute scans
    start_time = time.time()
    try:
        results, successful, failed = _execute_scans(protocol_class, args, targets, protocol_name)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        return 130  # Standard exit code for Ctrl+C

    # Print summary (only for multiple targets)
    elapsed = time.time() - start_time
    if not args.quiet and len(targets) > 1:
        print(
            f"\nCompleted {len(targets)} targets in {elapsed:.2f}s ({successful} ok, {failed} failed)"
        )

    # Export results if requested
    if args.output:
        fmt = args.format if args.format != "console" else "json"
        default_port = getattr(args, "port", None) or getattr(protocol_class, "default_port", 0)
        export_logger = get_logger(protocol_name.upper(), "", default_port)
        try:
            export_results(results, args.output, fmt, protocol_name, nxc_logger=export_logger)
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return 1

    return 0 if failed == 0 else 1


def scan_target(protocol_class, args, target: str):
    """
    Scan a single target with the protocol.

    Args:
        protocol_class: Protocol scanner class
        args: Command-line arguments (argparse Namespace)
        target: Target IP/hostname

    Returns:
        dict: Scan results
    """
    try:
        # Build a per-target copy with host/rhost set.
        # BaseScanner._normalize_args() handles dict-vs-attribute adaptation
        # internally, so we just pass a plain Namespace here. Deep-copy so
        # mutable attributes (lists/dicts/sets) are not shared across the
        # concurrent per-target scans run by the ThreadPoolExecutor below —
        # a shallow vars() copy aliased them, making an in-place mutation in
        # one target's scan a data race visible to every other target.
        target_args = copy.deepcopy(args)
        target_args.host = target
        target_args.rhost = target

        # Detect Layer 1 (BaseScanner) vs Layer 2 (NetworkConnection) classes.
        # Layer 2 classes accept (args, db, host) and auto-scan via proto_flow.
        # Layer 1 classes accept (args) only and require explicit run_scan().
        from oida.utils.base_scanner import BaseScanner

        if issubclass(protocol_class, BaseScanner):
            scanner = protocol_class(target_args)
            result = scanner.run_scan()
            result["host"] = target
            result["success"] = "error" not in result
            return result

        # Layer 2: instantiate with (args, db, host) — triggers scan via proto_flow
        scanner = protocol_class(target_args, None, target)

        # Get results
        if hasattr(scanner, "get_results"):
            return scanner.get_results()
        else:
            return {
                "host": target,
                "protocol": getattr(args, "protocol", "unknown"),
                "success": True,
            }

    except Exception as e:
        # Reached only for failures that escape the scanner's own error
        # handling (e.g. constructor/get_results bugs) — normal scan
        # failures are already caught and logged non-debug inside
        # BaseScanner.run_scan() / NetworkConnection's proto_flow wrapper.
        # Log visibly here too, so unexpected crashes aren't silently
        # swallowed unless -v/--debug is passed.
        logger.error(f"Error scanning {target}: {e}")
        return {
            "host": target,
            "protocol": getattr(args, "protocol", "unknown"),
            "success": False,
            "error": str(e),
        }


if __name__ == "__main__":
    sys.exit(main())
