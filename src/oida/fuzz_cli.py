"""
OIDA Fuzzing CLI

CLI integration for the fuzzing framework.

Usage:
    oida fuzz <protocol> <target> [options]
    oida fuzz list [--category <cat>]
    oida fuzz replay <session> [--range N-M]

Examples:
    oida fuzz modbus 192.168.1.100
    oida fuzz http 192.168.1.100 -p 8080
    oida fuzz list --category ics
"""

import argparse
import logging
import random

from oida.targets import split_host_port
from oida.utils.ics_logger import get_logger, get_module_logger

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


# Module logger
logger = get_module_logger(__name__)

# Noisy loggers to suppress
NOISY_LOGGERS = [
    "boofuzz",
    "boofuzz.sessions",
    "boofuzz.monitors",
    "sulley",
    "urllib3",
    "asyncio",
]

# Default ports for protocols (used when --port not specified)
WELL_KNOWN_PORTS = {
    "modbus": 502,
    "http": 80,
    "mqtt": 1883,
    "mqtts": 8883,
    "dnp3": 20000,
    "iec104": 2404,
    "bacnet": 47808,
    "opcua": 4840,
    "ethernetip": 44818,
    "fins": 9600,
    "mms": 102,
    "coap": 5683,
    "ftp": 21,
    "smtp": 25,
    "smtps": 465,
    "tftp": 69,
    "snmpv1": 161,
    "snmpv2c": 161,
    "snmpv3": 161,
    "ntp": 123,
    "dns": 53,
    "dhcp": 67,
    "memcached": 11211,
    "vnc": 5900,
    "ads": 48898,
    "hartip": 5094,
    "hl7": 2575,
    "dicom": 104,
    "tase2": 102,
    "iccp": 102,
    "http2": 443,
}


# The host:port splitter is shared with the scanner CLI (oida.targets); the
# private alias is kept so existing callers/tests keep resolving.
_split_target_port = split_host_port


def setup_fuzz_logging(verbose: bool = False):
    """
    Configure logging for fuzz CLI based on verbosity.

    Args:
        verbose: Enable debug level logging
    """
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add handler - use ICSLogger via set_context for output
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(handler)

    # Configure module logger
    logger.setLevel(level)

    # Suppress noisy third-party loggers
    for noisy in NOISY_LOGGERS:
        logging.getLogger(noisy).setLevel(logging.CRITICAL)


def fuzz_args(subparsers, parents):
    """Register fuzz subcommand with NXC-style help"""

    # Main fuzz parser
    fuzz_parser = subparsers.add_parser(
        "fuzz",
        help="Protocol fuzzing (boofuzz-based)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=parents,
        description="Protocol fuzzing framework using boofuzz for ICS/OT security testing",
        epilog="""
examples:
  oida fuzz modbus 192.168.1.100           Fuzz Modbus on default port
  oida fuzz http 192.168.1.100 -p 8080     Fuzz HTTP on custom port
  oida fuzz mqtt 192.168.1.100 -v          Fuzz MQTT with debug logging

  oida fuzz list                           List all available fuzzers
  oida fuzz list -c ics                    List ICS protocol fuzzers
  oida fuzz modbus --show-options          Show Modbus-specific options
  oida fuzz modbus --list-requests         Show fuzzable requests

  oida fuzz replay mysession               View session statistics
  oida fuzz replay mysession -r 1-100      Replay test case range
  oida fuzz crashes mysession              Report crashes grouped by signature
  oida fuzz crashes mysession --case 42    Dump one crash payload
  oida fuzz reproduce mysession            Re-send stored crashes, verify a repro
  oida fuzz narrow mysession               Bisect the crash window to the culprit case

For protocol-specific options: oida fuzz <protocol> --show-options
        """,
    )

    # First positional: could be 'list', 'replay', or a protocol name
    fuzz_parser.add_argument(
        "fuzz_protocol",
        nargs="?",
        help="Protocol to fuzz (e.g., modbus) or command (list, replay)",
    )

    # Second positional: target for fuzzing, or session for replay
    fuzz_parser.add_argument(
        "target", nargs="?", help="Target IP address or session name (for replay)"
    )

    # List options
    fuzz_parser.add_argument(
        "--category", "-c", type=str, help="Filter by category (for list command)"
    )
    fuzz_parser.add_argument(
        "--with-options",
        "-w",
        action="store_true",
        help="Show protocols with custom options (for list command)",
    )

    # Replay options
    fuzz_parser.add_argument(
        "--range",
        "-r",
        type=str,
        dest="replay_range",
        help="Test case range to replay (e.g., 1-100 or 42)",
    )
    fuzz_parser.add_argument("--case", "-C", type=int, help="Single test case ID to replay")
    fuzz_parser.add_argument(
        "--detail", "-d", action="store_true", help="Show detailed output (for replay)"
    )
    fuzz_parser.add_argument(
        "--check-response", action="store_true", help="Validate responses (for replay)"
    )
    fuzz_parser.add_argument(
        "--export",
        type=str,
        metavar="PATH",
        help="Write a crash payload to PATH (with 'crashes <session> --case <id>')",
    )
    fuzz_parser.add_argument(
        "--target",
        type=str,
        dest="reproduce_target",
        metavar="HOST",
        help="Override the recorded target host (for 'reproduce <session>')",
    )

    # Connection parameters
    fuzz_parser.add_argument(
        "--port", "-p", type=int, help="Target port (protocol default if not specified)"
    )

    # Session parameters
    fuzz_parser.add_argument(
        "--session",
        "-s",
        type=str,
        default="oida_fuzz_session",
        help="Session name for database storage (default: oida_fuzz_session)",
    )
    fuzz_parser.add_argument(
        "--nolog",
        "-n",
        action="store_true",
        help="Disable session logging for better performance",
    )
    fuzz_parser.add_argument(
        "--store-all-payloads",
        action="store_true",
        help="Store all payloads (larger DB). Default: lightweight mode",
    )
    fuzz_parser.add_argument(
        "--boofuzz-db",
        action="store_true",
        help="Enable boofuzz-results database (disabled by default)",
    )
    fuzz_parser.add_argument(
        "--fuzz-db-keep-pass-cases",
        type=int,
        default=500,
        metavar="N",
        dest="fuzz_db_keep_pass_cases",
        help="Cap passing test cases kept in boofuzz's results DB (default: 500). "
        "0 = keep all (boofuzz default; unbounded RAM on long runs). Failing cases "
        "are always retained.",
    )

    # Output control. Also accept -v/--verbose on the subparser (not just the
    # global parser) so `oida fuzz <proto> <target> -v` works as the help
    # advertises; the dispatcher reads args.verbose either way.
    fuzz_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        # SUPPRESS so a subparser-level non-occurrence doesn't clobber a global
        # `-v` given before the subcommand (the global parser supplies default=0).
        default=argparse.SUPPRESS,
        dest="verbose",
        help="Increase verbosity (-v, -vv, -vvv)",
    )

    # Fuzzing control
    fuzz_parser.add_argument("--seed", "-S", type=int, help="Random seed for reproducible fuzzing")

    # Combinatorial-depth control (mutually exclusive). boofuzz fuzzes depth 1
    # (each field alone), then depth 2 (field pairs), then triples, ...
    depth_grp = fuzz_parser.add_mutually_exclusive_group()
    depth_grp.add_argument(
        "--max-depth",
        type=int,
        metavar="N",
        help="Cap combinatorial depth: fuzz depths 1..N then stop (default: all depths)",
    )
    depth_grp.add_argument(
        "--only-depth",
        "--depth",
        "-D",
        type=int,
        metavar="N",
        dest="only_depth",
        help="Fuzz ONLY depth N, skipping lower depths (N=1 single fields, "
        "N=2 field pairs, N=3 triples); starts sending immediately",
    )

    # Multi-machine distribution
    fuzz_parser.add_argument(
        "--machine",
        "-m",
        type=str,
        metavar="TOTAL,ID",
        help="Distribute across machines (e.g., --machine 3,2 for machine 2 of 3)",
    )

    # Monitor parameters
    fuzz_parser.add_argument(
        "--check-interval",
        "-I",
        type=int,
        default=100,
        help="Monitor check interval (default: 100)",
    )
    # The monitor registry pulls in boofuzz (the optional 'fuzz' extra). Only
    # the monitor *names* are needed here for help text, so a missing extra must
    # not break CLI init for every other protocol (e.g. `oida modbus`). Degrade
    # gracefully: still register the fuzz subcommand; it errors with a clear
    # "install oida-ics[fuzz]" message at run time via check_dependencies.
    try:
        from oida.fuzz.monitors.registry import MONITOR_REGISTRY

        available_monitors = ", ".join(sorted(MONITOR_REGISTRY.keys()))
    except Exception:
        available_monitors = "requires the 'fuzz' extra (pip install oida-ics[fuzz])"
    fuzz_parser.add_argument(
        "--monitors",
        "-M",
        type=str,
        metavar="SPEC",
        help="Monitor specification (default: protocol-specific). "
        "Format: name[:interval],name[:interval],... "
        "Examples: ping,socket | ping:50,modbus:10 | none. "
        f"Available: {available_monitors}",
    )
    fuzz_parser.add_argument(
        "--monitor-logic",
        type=str,
        choices=["and", "or"],
        default="and",
        metavar="MODE",
        help="Monitor combination logic: and|or (default: and). "
        "and = ALL monitors must pass, or = ANY monitor must pass",
    )
    fuzz_parser.add_argument(
        "--pause-on-crash",
        "-P",
        action="store_true",
        default=False,
        dest="pause_on_crash",
        help="Pause fuzzing when crash is detected (wait for user input to continue)",
    )

    # Performance options
    fuzz_parser.add_argument(
        "--reuse-connection",
        "-R",
        action="store_true",
        default=False,
        dest="reuse_connection",
        help="Reuse TCP connection between test cases (faster, less stable). "
        "Recommended for long campaigns on hosts with tcp_tw_reuse=0, where a fresh "
        "connection per case can exhaust ephemeral ports (TIME_WAIT) and stall throughput.",
    )
    fuzz_parser.add_argument(
        "-X",
        "--no-receive",
        action="store_true",
        default=False,
        dest="no_receive",
        help="Do not wait for any responses (faster, may break state machines)",
    )
    fuzz_parser.add_argument(
        "-F",
        "--fire-forget-fuzz",
        action="store_true",
        default=False,
        dest="fire_forget_fuzz",
        help="Fire-forget fuzz payloads only (still receive setup/prereq responses)",
    )
    fuzz_parser.add_argument(
        "-z",
        "--sleep-time",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between test cases in seconds (default: 0.0)",
    )
    fuzz_parser.add_argument(
        "--script-monitor",
        type=str,
        metavar="CMD",
        dest="script_monitor",
        help="External health-check command run between test cases; exit 0 = healthy "
        "(e.g. --script-monitor \"ssh plc 'pidof runtime >/dev/null'\")",
    )
    fuzz_parser.add_argument(
        "--valid-case",
        type=str,
        metavar="HEX",
        dest="valid_case",
        help="Hex bytes of a known-good request; sent between test cases to verify the "
        "target still answers correctly (protocol-agnostic valid-case probe)",
    )
    fuzz_parser.add_argument(
        "--valid-case-expect",
        type=str,
        metavar="HEX",
        dest="valid_case_expect",
        help="Hex substring that must appear in the valid-case reply (default: strict "
        "baseline match). Use when replies vary, e.g. embedded timestamps",
    )
    fuzz_parser.add_argument(
        "--agent-monitor",
        type=str,
        metavar="HOST:PORT",
        dest="agent_monitor",
        help="Query an on-target oida-fuzzing-agent (separate repo) for real "
        "crash/exit/hang detection (e.g. --agent-monitor 10.0.0.5:5555)",
    )
    fuzz_parser.add_argument(
        "--agent-token",
        type=str,
        metavar="SECRET",
        dest="agent_token",
        help="Shared secret for the oida-fuzzing-agent handshake (--agent-monitor)",
    )
    fuzz_parser.add_argument(
        "--restart-command",
        type=str,
        metavar="CMD",
        dest="restart_command",
        help="Command run once per crash to bring the target back up, then resume "
        '(e.g. --restart-command "docker restart plc")',
    )
    fuzz_parser.add_argument(
        "--restart-delay",
        type=float,
        default=2.0,
        metavar="SECONDS",
        dest="restart_delay",
        help="Seconds to wait after the restart command before re-probing (default: 2.0)",
    )
    fuzz_parser.add_argument(
        "--recv-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Socket receive timeout for fuzz responses (default: per-protocol, usually 5.0s)",
    )
    fuzz_parser.add_argument(
        "--send-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Socket send timeout (default: per-protocol, usually 5.0s)",
    )
    fuzz_parser.add_argument(
        "--reconnect-delay",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Delay between reconnection attempts on connection reset (default: 0.5s)",
    )
    fuzz_parser.add_argument(
        "--max-reconnect-attempts",
        type=int,
        default=None,
        metavar="N",
        help="Maximum reconnection attempts on connection reset (default: 3)",
    )
    fuzz_parser.add_argument(
        "--no-calibrate",
        action="store_true",
        default=False,
        help="Disable automatic timeout calibration (keep per-protocol defaults)",
    )
    fuzz_parser.add_argument(
        "--calibration-probes",
        type=int,
        default=50,
        metavar="N",
        help="Probes sent during timeout calibration (default: 50, min 30 clean)",
    )
    fuzz_parser.add_argument(
        "--adaptive-timeout",
        action="store_true",
        default=False,
        help="Adapt the monitor timeout online from observed latency (default: off)",
    )
    fuzz_parser.add_argument(
        "--detect-drift",
        action="store_true",
        default=False,
        help="Recalibrate when sustained latency drift is detected (implies --adaptive-timeout)",
    )

    # Protocol-specific options
    fuzz_parser.add_argument(
        "--option",
        "-O",
        action="append",
        dest="protocol_options",
        metavar="KEY=VALUE",
        help="Protocol-specific option (can be used multiple times)",
    )

    # Request selection
    fuzz_parser.add_argument(
        "--show-options",
        "-o",
        action="store_true",
        help="Show available options for the protocol",
    )
    fuzz_parser.add_argument(
        "--list-requests",
        "-L",
        action="store_true",
        help="List available requests for the protocol",
    )
    fuzz_parser.add_argument(
        "--enable",
        "-e",
        type=str,
        metavar="REQUESTS",
        help="Comma-separated list of requests to enable",
    )
    fuzz_parser.add_argument(
        "--disable",
        "-x",
        type=str,
        metavar="REQUESTS",
        help="Comma-separated list of requests to disable",
    )

    # Node specification
    fuzz_parser.add_argument("--node", "-N", type=str, help="Specific node to fuzz")

    # TLS/SSL options
    fuzz_parser.add_argument(
        "--tls",
        "-T",
        action="store_true",
        dest="tls_enabled",
        help="Enable TLS/SSL encryption (HTTPS, FTPS, Modbus/TLS, etc.)",
    )

    # Capability enumeration
    fuzz_parser.add_argument(
        "--enumerate",
        "-E",
        action="store_true",
        default=True,
        dest="enumerate",
        help="Probe target capabilities before fuzzing (default: enabled)",
    )
    fuzz_parser.add_argument(
        "--no-enumerate",
        action="store_false",
        dest="enumerate",
        help="Skip capability enumeration, fuzz all methods",
    )

    return fuzz_parser


def handle_fuzz_command(args):
    """Handle the fuzz command with NXC-style output"""

    # Setup logging based on verbosity
    verbose = getattr(args, "verbose", False)
    setup_fuzz_logging(verbose)

    fuzz_protocol = getattr(args, "fuzz_protocol", None)
    target = getattr(args, "target", None)

    # Handle 'list' command
    if fuzz_protocol == "list":
        return handle_list_command(args)

    # Handle 'replay' command
    if fuzz_protocol == "replay":
        # Target becomes session name for replay
        args.session = target
        return handle_replay_command(args)

    # Handle 'crashes' command (read-only crash report grouped by signature)
    if fuzz_protocol == "crashes":
        args.session = target
        return handle_crashes_command(args)

    # Handle 'reproduce' command (re-send stored crash payloads, verify via monitor)
    if fuzz_protocol == "reproduce":
        args.session = target
        return handle_reproduce_command(args)

    # Handle 'narrow' command (bisect the recorded crash window to the real culprit)
    if fuzz_protocol == "narrow":
        args.session = target
        return handle_narrow_command(args)

    # Check if just requesting help for a protocol
    if fuzz_protocol and getattr(args, "show_options", False):
        return show_protocol_options(fuzz_protocol)

    if fuzz_protocol and getattr(args, "list_requests", False):
        return show_protocol_requests(fuzz_protocol)

    # Validate we have what we need for fuzzing
    if not fuzz_protocol:
        return show_fuzz_help()

    if not target:
        return show_protocol_usage(fuzz_protocol)

    return run_fuzzing(args, fuzz_protocol, target)


def show_fuzz_help():
    """Show comprehensive fuzz help with all protocols listed"""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS, PROTOCOL_CATEGORIES

    print()
    print(colored("[!]", "yellow", attrs=["bold"]) + " Protocol is required")
    print()
    print(colored("Usage:", "white", attrs=["bold"]))
    print("  oida fuzz <protocol> <target> [options]")
    print("  oida fuzz <protocol>                     # Show protocol help")
    print("  oida fuzz replay <session>               # View session / test cases")
    print("  oida fuzz crashes <session>              # Report crashes by signature")
    print("  oida fuzz reproduce <session>            # Verify crashes reproduce")
    print("  oida fuzz narrow <session>               # Pin the real culprit case")
    print()
    print(colored("Examples:", "white", attrs=["bold"]))
    print("  oida fuzz modbus 192.168.1.100           # Fuzz Modbus (port 502)")
    print("  oida fuzz http 10.0.0.1 -p 8080          # Fuzz HTTP on port 8080")
    print("  oida fuzz mqtt 10.0.0.1 -v               # Verbose output")
    print()
    print(colored("Available Protocols:", "white", attrs=["bold"]))

    # Group protocols by category for compact display
    for category, cat_info in sorted(PROTOCOL_CATEGORIES.items()):
        protocols = [p for p in cat_info["protocols"] if p in PROTOCOL_FUZZERS]
        if protocols:
            cat_label = colored(f"  [{category}]", "cyan")
            proto_list = ", ".join(protocols)
            print(f"{cat_label} {proto_list}")

    total = len(PROTOCOL_FUZZERS)
    print()
    print(colored("[*]", "blue", attrs=["bold"]) + f" {total} protocols available")
    print()
    print(colored("Common Options:", "white", attrs=["bold"]))
    print("  -p, --port PORT          Target port")
    print("  -v, --verbose            Increase verbosity (-v, -vv, -vvv)")
    print("  -s, --session NAME       Session name for database")
    print("  -O, --option KEY=VALUE   Protocol-specific option")
    print("  --seed SEED              Random seed for reproducibility")
    print("  --max-depth N            Cap combinatorial depth: fuzz depths 1..N then stop")
    print("  -D, --only-depth N       Fuzz ONLY depth N (skip lower depths)")
    print()
    print("Run 'oida fuzz <protocol>' for protocol-specific options")

    return 1


def handle_list_command(args):
    """List available protocol fuzzers with NXC-style output"""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS, PROTOCOL_CATEGORIES

    category_filter = getattr(args, "category", None)
    with_options = getattr(args, "with_options", False)

    print()
    print(colored("[*]", "blue", attrs=["bold"]) + " OIDA Protocol Fuzzers")

    if category_filter:
        # Show protocols in specific category
        if category_filter not in PROTOCOL_CATEGORIES:
            print(colored("[-]", "red", attrs=["bold"]) + f" Unknown category: {category_filter}")
            print(f"    Available: {', '.join(sorted(PROTOCOL_CATEGORIES.keys()))}")
            return 1

        cat_info = PROTOCOL_CATEGORIES[category_filter]
        print(colored("[+]", "green", attrs=["bold"]) + f" {cat_info['name']}")
        print(f"    {cat_info['description']}")
        print()
        for protocol in cat_info["protocols"]:
            print(f"    {protocol}")
    else:
        # Show all categories
        for category, cat_info in sorted(PROTOCOL_CATEGORIES.items()):
            cat_label = colored(f"[{category}]", "cyan")
            print(f"\n{cat_label} {cat_info['name']}")
            print(f"    {cat_info['description']}")
            protocols = cat_info["protocols"]
            if with_options:
                # Show which have custom options
                for p in protocols:
                    try:
                        fuzzer_class = PROTOCOL_FUZZERS[p]
                        has_opts = bool(fuzzer_class.get_protocol_options())
                        if has_opts:
                            opt_mark = colored(" [opts]", "yellow")
                        else:
                            opt_mark = ""
                        print(f"      {p}{opt_mark}")
                    except (KeyError, AttributeError):
                        print(f"      {p} " + colored("(unavailable)", "red"))
            else:
                print(f"    Protocols: {', '.join(protocols)}")

    total = len(list(PROTOCOL_FUZZERS.keys()))
    print()
    print(colored("[*]", "blue", attrs=["bold"]) + f" {total} protocols available")
    print()
    print("Run 'oida fuzz <protocol> --show-options' for protocol-specific options")

    return 0


def handle_replay_command(args):
    """Replay test cases from a session with NXC-style output"""
    session = getattr(args, "session", None)

    if not session:
        logger.error("Session name is required")
        print("Usage: oida fuzz replay <session> [--range N-M]")
        return 1

    # Replay reads a session file (no live target); set a logging context so the
    # global ICSLogger helpers used by the DB layer have one.
    from oida.utils.ics_logger import set_context

    set_context("FUZZ-REPLAY", session, 0)

    # Import database. The fuzzer writes via SQLAlchemyDatabase (ORM) - use
    # the same backend for reads so we never see schema drift. SQLiteDatabase
    # (raw SQL) is kept for backward compatibility but no longer the default.
    from oida.fuzz.core.database.orm import SQLAlchemyDatabase

    import os

    db_path = f"{session}.db"
    # SQLAlchemyDatabase(...).init_schema() creates the file if missing, which
    # would make a replay of a non-existent session silently "succeed" with 0
    # cases. Detect the missing file up front instead.
    if not os.path.exists(db_path):
        logger.error(f"Session database not found: {db_path}")
        return 1
    try:
        db = SQLAlchemyDatabase(db_path)
        db.init_schema()

        # Check if --range or --case specified
        test_range = getattr(args, "replay_range", None)
        test_case = getattr(args, "case", None)
        detail = getattr(args, "detail", False)

        if test_case:
            test_range = str(test_case)

        if not test_range:
            # List test cases - show session statistics
            print()
            print(colored("[*]", "blue", attrs=["bold"]) + f" Session: {session}")

            stats = db.get_stats()
            metadata = db.get_all_metadata()

            # Check if lightweight mode (test_cases table may be empty)
            lightweight = metadata.get("lightweight_mode", "False") == "True"
            if lightweight:
                # Read from metadata for lightweight sessions
                total = int(metadata.get("last_test_case", "0") or "0")
                crashed = int(metadata.get("crash_count", "0") or "0")
                print(colored("[+]", "green", attrs=["bold"]) + f" Total test cases: {total}")
                print("    Mode:    Lightweight (no individual test case storage)")
                print(f"    Crashed: {crashed}")
                print(f"    Size:    {stats['db_size_mb']} MB")
                print(f"    Seed:    {metadata.get('seed', 'unknown')}")
            else:
                print(
                    colored("[+]", "green", attrs=["bold"])
                    + f" Total test cases: {stats['total_test_cases']}"
                )
                print(f"    Passed:  {stats['passed']}")
                print(f"    Failed:  {stats['failed']}")
                print(f"    Crashed: {stats['crashed']}")
                print(f"    Size:    {stats['db_size_mb']} MB")

            if stats.get("crashed", 0) > 0 or (
                lightweight and int(metadata.get("crash_count", "0") or "0") > 0
            ):
                print()
                crash_cases = db.get_test_cases(result_filter="crash", limit=None)
                unique = len({c.crash_hash for c in db.get_all_crashes()})
                print(
                    colored("[!]", "yellow", attrs=["bold"])
                    + f" {len(crash_cases)} crash(es), {unique} unique signature(s)"
                )
                print(f"    Report:    oida fuzz crashes {session}")
                print(f"    Reproduce: oida fuzz reproduce {session} [--target HOST]")

            print()
            if lightweight:
                print("Note: Lightweight mode - use --store-all-payloads to enable replay")
            else:
                print("Use -r/--range or --case to replay specific test cases")
            return 0

        # Show test case details
        print()
        print(colored("[*]", "blue", attrs=["bold"]) + f" Replaying: {session}")
        print(f"    Range: {test_range}")

        # Parse range
        if "-" in test_range:
            start, end = map(int, test_range.split("-"))
            test_ids = list(range(start, end + 1))
        else:
            test_ids = [int(test_range)]

        for test_id in test_ids:
            case = db.get_test_case(test_id)
            if case:
                if case.result == "crash":
                    sigil = colored("[!]", "red", attrs=["bold"])
                elif case.result == "fail":
                    sigil = colored("[-]", "yellow", attrs=["bold"])
                else:
                    sigil = colored("[+]", "green", attrs=["bold"])

                print(f"\n{sigil} [{case.id}] {case.name}")
                print(f"    Result: {case.result}")
                print(f"    CRC32:  {case.crc32:08x}")

                crash = db.get_crash(test_id)
                if crash:
                    print(f"    Payload: {len(crash.payload)} bytes")
                    if detail and crash.crash_info:
                        print(f"    Info:    {crash.crash_info}")
            else:
                print(colored("[-]", "red", attrs=["bold"]) + f" Test case {test_id} not found")

        return 0

    except FileNotFoundError:
        logger.error(f"Session database not found: {db_path}")
        return 1
    except Exception as e:
        logger.error(f"Failed to read session: {e}")
        return 1


def _open_session_db(session):
    """Open a session's on-disk DB read-only-ish, or return None with an error.

    Shared by the replay/crashes/reproduce read paths: refuses to init a schema
    for a non-existent session (which would silently create an empty DB).
    """
    import os

    from oida.utils.ics_logger import set_context

    from oida.fuzz.core.database.orm import SQLAlchemyDatabase

    if not session:
        logger.error("Session name is required")
        return None
    set_context("FUZZ", session, 0)
    db_path = f"{session}.db"
    if not os.path.exists(db_path):
        logger.error(f"Session database not found: {db_path}")
        return None
    db = SQLAlchemyDatabase(db_path)
    db.init_schema()
    return db


def handle_crashes_command(args):
    """Report stored crashes for a session, grouped by crash signature."""
    import base64

    from oida.fuzz.core.config import hexdump

    session = getattr(args, "session", None)
    db = _open_session_db(session)
    if db is None:
        print("Usage: oida fuzz crashes <session> [--case <id>] [--export PATH]")
        return 1

    crashes = db.get_all_crashes()
    if not crashes:
        print()
        print(colored("[*]", "blue", attrs=["bold"]) + f" Session: {session}")
        print(colored("[+]", "green", attrs=["bold"]) + " No crashes recorded")
        return 0

    # --case: dump a single crash payload (hexdump + base64, optional export)
    case = getattr(args, "case", None)
    if case:
        crash = db.get_crash(case)
        if not crash:
            print(colored("[-]", "red", attrs=["bold"]) + f" No crash stored for test case {case}")
            return 1
        tc = db.get_test_case(case)
        print()
        print(colored("[!]", "red", attrs=["bold"]) + f" Crash for test case {case}")
        if tc:
            print(f"    Request: {tc.name}    Target: {tc.target_ip}:{tc.target_port}")
        print(f"    Signature: {crash.crash_hash or 'unknown'}")
        if crash.crash_info:
            print(f"    Info: {crash.crash_info}")
        print(f"    Payload: {len(crash.payload)} bytes")
        print()
        print(hexdump(crash.payload))
        print()
        print("Base64: " + base64.b64encode(crash.payload).decode("ascii"))
        export = getattr(args, "export", None)
        if export:
            with open(export, "wb") as fh:
                fh.write(crash.payload)
            print(
                colored("[+]", "green", attrs=["bold"])
                + f" Wrote {len(crash.payload)} bytes to {export}"
            )
        return 0

    # Group by signature (crash_hash); unknown hashes bucket under "unknown".
    buckets: dict = {}
    for c in crashes:
        buckets.setdefault(c.crash_hash or "unknown", []).append(c)

    print()
    print(colored("[*]", "blue", attrs=["bold"]) + f" Session: {session}")
    print(
        colored("[!]", "yellow", attrs=["bold"])
        + f" {len(crashes)} crash(es), {len(buckets)} unique signature(s)"
    )
    print()
    for sig, items in sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True):
        rep = items[0]
        tc = db.get_test_case(rep.test_case_id)
        name = tc.name if tc else "?"
        ids = ", ".join(str(c.test_case_id) for c in items[:8])
        if len(items) > 8:
            ids += f", ... (+{len(items) - 8})"
        print(colored(f"  [{sig}]", "cyan") + f"  x{len(items)}")
        print(f"    Representative: [{rep.test_case_id}] {name}  ({len(rep.payload)} bytes)")
        if rep.crash_info:
            info = rep.crash_info if len(rep.crash_info) <= 100 else rep.crash_info[:97] + "..."
            print(f"    Info: {info}")
        print(f"    Test cases: {ids}")
        print()
    print(f"Dump a payload:  oida fuzz crashes {session} --case <id> [--export out.bin]")
    print(f"Verify a crash:  oida fuzz reproduce {session} [--target HOST] [-p PORT]")
    return 0


def _probe_alive(combined_monitor) -> bool:
    """One raw health probe of every child monitor, combined by the monitor's logic.

    Uses each monitor's ``_check_alive_once`` (no retry, no recovery, never raises)
    so a reproduce verdict is a clean up/down read rather than the fuzz-loop's
    recovery machinery. A probe that raises counts as down. No child probes ->
    unknown, treated as up.
    """
    children = getattr(combined_monitor, "monitors", None) or []
    checks = []
    for m in children:
        probe = getattr(m, "_check_alive_once", None)
        if callable(probe):
            try:
                checks.append(bool(probe()))
            except Exception:
                checks.append(False)
    if not checks:
        return True
    logic = getattr(combined_monitor, "logic", "and")
    return any(checks) if logic == "or" else all(checks)


def handle_reproduce_command(args):
    """Re-send stored crash payloads to a live target and verify via the monitor.

    Uses the *stored* crash payload (no fragile regeneration) and, by default, the
    target host/port recorded with the crash. Reproduces one representative per
    unique crash signature (or a single ``--case``). Verdict per crash:
    REPRODUCED / NOT-REPRODUCED / TARGET-DOWN / ERROR.
    """
    import time

    from oida.fuzz.core.config import FuzzerConfig
    from oida.fuzz.core.connections import RealConnectionFactory
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    session = getattr(args, "session", None)
    db = _open_session_db(session)
    if db is None:
        print("Usage: oida fuzz reproduce <session> [--target HOST] [-p PORT] [--case <id>]")
        return 1

    metadata = db.get_all_metadata()
    default_protocol = metadata.get("protocol_name")

    # Select crashes: one per unique signature, or a single --case.
    case = getattr(args, "case", None)
    if case:
        c = db.get_crash(case)
        if not c:
            print(colored("[-]", "red", attrs=["bold"]) + f" No crash stored for test case {case}")
            return 1
        selected = [c]
    else:
        seen: set = set()
        selected = []
        for c in db.get_all_crashes():
            key = c.crash_hash or f"id{c.test_case_id}"
            if key not in seen:
                seen.add(key)
                selected.append(c)
    if not selected:
        print(colored("[+]", "green", attrs=["bold"]) + " No crashes to reproduce")
        return 0

    host_override = getattr(args, "reproduce_target", None)
    port_override = getattr(args, "port", None)
    verbose = getattr(args, "verbose", False)

    print()
    print(
        colored("[*]", "blue", attrs=["bold"])
        + f" Reproducing {len(selected)} crash(es) from {session}"
    )
    print()

    results = []
    for crash in selected:
        tc = db.get_test_case(crash.test_case_id)
        protocol = (tc.protocol if tc and tc.protocol else default_protocol) or "unknown"
        host = host_override or (tc.target_ip if tc else None)
        port = port_override or (tc.target_port if tc else None)

        label = f"[{crash.test_case_id}] {protocol} -> {host}:{port}"
        if protocol not in PROTOCOL_FUZZERS:
            print(
                colored("[-]", "red", attrs=["bold"])
                + f" {label}  ERROR (unknown protocol '{protocol}')"
            )
            results.append((crash.test_case_id, "ERROR"))
            continue
        if not host:
            print(
                colored("[-]", "red", attrs=["bold"]) + f" {label}  ERROR (no target; use --target)"
            )
            results.append((crash.test_case_id, "ERROR"))
            continue

        try:
            cfg = FuzzerConfig(
                target_ip=host,
                target_port=int(port) if port else 0,
                protocol=protocol,
                enumerate=False,
                log_session=False,
                console_output=verbose,
                calibrate=False,
            )
            fuzzer = PROTOCOL_FUZZERS[protocol](
                config=cfg, connection_factory=RealConnectionFactory()
            )

            # Baseline: the target must be up before we send.
            if not _probe_alive(fuzzer.monitor):
                print(
                    colored("[!]", "yellow", attrs=["bold"])
                    + f" {label}  TARGET-DOWN (unhealthy before send)"
                )
                results.append((crash.test_case_id, "TARGET-DOWN"))
                continue

            # Send the recorded crash payload.
            sock = fuzzer._create_socket()
            sock.open()
            try:
                sock.send(crash.payload)
            finally:
                sock.close()

            # Verify: give a delayed crash a moment to surface.
            reproduced = False
            for _ in range(3):
                time.sleep(0.5)
                if not _probe_alive(fuzzer.monitor):
                    reproduced = True
                    break

            if reproduced:
                print(colored("[+]", "green", attrs=["bold"]) + f" {label}  REPRODUCED")
                results.append((crash.test_case_id, "REPRODUCED"))
            else:
                print(
                    colored("[-]", "yellow", attrs=["bold"])
                    + f" {label}  NOT-REPRODUCED (target still up)"
                )
                results.append((crash.test_case_id, "NOT-REPRODUCED"))
        except Exception as e:
            print(colored("[-]", "red", attrs=["bold"]) + f" {label}  ERROR ({e})")
            results.append((crash.test_case_id, "ERROR"))

    # Summary
    print()
    repro = sum(1 for _, v in results if v == "REPRODUCED")
    print(colored("[*]", "blue", attrs=["bold"]) + " Reproduction summary")
    print(f"    Reproduced:     {repro}/{len(results)}")
    for status in ("NOT-REPRODUCED", "TARGET-DOWN", "ERROR"):
        n = sum(1 for _, v in results if v == status)
        if n:
            print(f"    {status}: {n}")
    return 0 if repro else 1


def _build_repro_fuzzer(protocol, host, port, verbose=False):
    """Construct a protocol fuzzer bound to a live target for repro/narrow.

    Returns the fuzzer (with monitors built via _setup_monitor) or None if the
    protocol is unknown. Does not fuzz or enumerate.
    """
    from oida.fuzz.core.config import FuzzerConfig
    from oida.fuzz.core.connections import RealConnectionFactory
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    if protocol not in PROTOCOL_FUZZERS:
        return None
    cfg = FuzzerConfig(
        target_ip=host,
        target_port=int(port) if port else 0,
        protocol=protocol,
        enumerate=False,
        log_session=False,
        console_output=verbose,
        calibrate=False,
    )
    return PROTOCOL_FUZZERS[protocol](config=cfg, connection_factory=RealConnectionFactory())


def _send_payload(fuzzer, payload):
    """Open a fresh connection, send one payload, close. Swallow socket errors
    (the target may already be down mid-replay; the monitor probe is the oracle)."""
    try:
        sock = fuzzer._create_socket()
        sock.open()
        try:
            sock.send(payload)
        finally:
            sock.close()
    except OSError:
        pass


def _bisect_min_crashing_prefix(n, oracle):
    """Return the minimal prefix length k in [1..n] for which oracle(k) is True.

    ``oracle(k)`` replays window[:k] and returns True if the target crashed, False
    if it survived, or None if inconclusive (abort -> returns None here too).
    Assumes monotonicity: once a prefix contains the culprit, every longer prefix
    also crashes. The culprit is window[k-1]. Returns None if inconclusive.
    """
    lo, hi = 1, n
    while lo < hi:
        mid = (lo + hi) // 2
        verdict = oracle(mid)
        if verdict is None:
            return None
        if verdict:
            hi = mid
        else:
            lo = mid + 1
    return lo


def handle_narrow_command(args):
    """Bisect a recorded crash window to the test case that actually breaks the target.

    A monitor flags a crash at *detection* time (up to check_interval cases after the
    culprit), so the stored crash id is only approximate. This replays the recorded
    pre-crash window (persisted with payloads as a CrashEvent) against a live target,
    restarting between trials, and prefix-bisects to the minimal prefix whose replay
    drops the target -- that prefix's last case is the culprit.

    Needs the target to return between trials: pass --restart-command, or point at a
    target that auto-respawns.
    """
    import shlex
    import subprocess
    import time

    from oida.fuzz.core.config import hexdump

    session = getattr(args, "session", None)
    db = _open_session_db(session)
    if db is None:
        print("Usage: oida fuzz narrow <session> [--target HOST] [-p PORT] [--restart-command CMD]")
        return 1

    events = db.get_crash_events()
    if not events:
        print(colored("[-]", "red", attrs=["bold"]) + " No crash context stored for this session.")
        print("    (Re-fuzz with a build that records crash context, then narrow.)")
        return 1

    # Pick the event: by --case (its detected_at_id) or the newest.
    case = getattr(args, "case", None)
    event_meta = None
    if case:
        event_meta = next((e for e in events if e["detected_at_id"] == case), None)
        if not event_meta:
            print(
                colored("[-]", "red", attrs=["bold"]) + f" No crash event detected at case {case}"
            )
            return 1
    else:
        event_meta = events[0]

    full = db.get_crash_event(event_meta["id"])
    context = sorted(full["context"], key=lambda c: c["test_case_id"])
    window = []
    for entry in context:
        payload = db.get_crash_context_payload(event_meta["id"], entry["test_case_id"])
        if payload is not None:
            window.append((entry["test_case_id"], entry["name"], payload))
    if not window:
        print(
            colored("[-]", "red", attrs=["bold"]) + " Crash event has no payload context to replay."
        )
        return 1

    protocol = event_meta.get("protocol") or db.get_all_metadata().get("protocol_name") or "unknown"
    host = getattr(args, "reproduce_target", None) or event_meta.get("target_ip")
    port = getattr(args, "port", None) or event_meta.get("target_port")
    verbose = getattr(args, "verbose", False)

    fuzzer = _build_repro_fuzzer(protocol, host, port, verbose)
    if fuzzer is None:
        print(colored("[-]", "red", attrs=["bold"]) + f" Unknown protocol '{protocol}'")
        return 1

    restart_cmd = getattr(args, "restart_command", None)
    restart_argv = shlex.split(restart_cmd) if restart_cmd else None
    restart_delay = getattr(args, "restart_delay", 2.0) or 2.0

    print()
    print(
        colored("[*]", "blue", attrs=["bold"])
        + f" Narrowing crash detected at case {event_meta['detected_at_id']}"
    )
    print(
        f"    Target: {protocol} -> {host}:{port}   window: {len(window)} cases "
        f"(ids {window[0][0]}..{window[-1][0]})"
    )
    if not restart_cmd:
        print("    No --restart-command: relying on the target to auto-respawn between trials.")
    print()

    def restore_target(timeout=12.0):
        """Bring the target back and wait until the monitor says it's up."""
        if restart_argv:
            try:
                subprocess.Popen(restart_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print(colored("[-]", "red", attrs=["bold"]) + f" restart-command failed: {e}")
        deadline = time.time() + timeout
        time.sleep(restart_delay if restart_argv else 0.3)
        while time.time() < deadline:
            if _probe_alive(fuzzer.monitor):
                return True
            time.sleep(0.3)
        return _probe_alive(fuzzer.monitor)

    def crashes_after_prefix(k):
        """Restore target, replay window[:k], report whether the target went down."""
        if not restore_target():
            return None  # cannot get a healthy target -> inconclusive
        for _, _, payload in window[:k]:
            _send_payload(fuzzer, payload)
        for _ in range(3):
            time.sleep(0.3)
            if not _probe_alive(fuzzer.monitor):
                return True
        return False

    n = len(window)
    print(colored("[*]", "blue", attrs=["bold"]) + " Verifying the full window reproduces...")
    full_crash = crashes_after_prefix(n)
    if full_crash is None:
        print(
            colored("[-]", "red", attrs=["bold"])
            + " Could not get a healthy target between trials."
        )
        print("    Provide --restart-command so narrow can restore the target each trial.")
        return 1
    if not full_crash:
        print(
            colored("[-]", "yellow", attrs=["bold"])
            + " Replaying the whole recorded window did NOT crash the target."
        )
        print(
            "    The crash may be non-deterministic, stateful beyond the buffer, or timing-dependent."
        )
        return 1

    # Prefix-bisection: minimal k in [1..n] whose prefix crashes; culprit = window[k-1].
    print(colored("[*]", "blue", attrs=["bold"]) + " Bisecting to the culprit case...")

    def traced_oracle(k):
        verdict = crashes_after_prefix(k)
        if verdict is not None:
            print(f"    prefix 1..{k} ({window[k - 1][0]}): {'crash' if verdict else 'ok'}")
        return verdict

    k = _bisect_min_crashing_prefix(n, traced_oracle)
    if k is None:
        print(colored("[-]", "red", attrs=["bold"]) + " Lost the target mid-bisection; aborting.")
        return 1

    cid, cname, cpayload = window[k - 1]
    print()
    print(colored("[+]", "green", attrs=["bold"]) + " Culprit identified:")
    print(f"    Test case: [{cid}] {cname}")
    print(
        f"    Detected-at (recorded) case: {event_meta['detected_at_id']}  (off by {event_meta['detected_at_id'] - cid})"
    )
    print(f"    Payload: {len(cpayload)} bytes")
    print()
    print(hexdump(cpayload[:256]))
    if len(cpayload) > 256:
        print(f"    ... (+{len(cpayload) - 256} more bytes)")
    return 0


def show_protocol_usage(protocol):
    """Show comprehensive usage help when target is missing"""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    try:
        fuzzer_class = PROTOCOL_FUZZERS[protocol]
    except KeyError:
        logger.error(f"Unknown protocol: {protocol}")
        print("Use 'oida fuzz list' to see available protocols")
        return 1

    # Get protocol info - check for default port in config or well-known ports
    default_port = getattr(fuzzer_class, "default_port", None) or WELL_KNOWN_PORTS.get(protocol, 0)

    print()
    print(
        colored("[!]", "yellow", attrs=["bold"]) + f" Target required for {protocol.upper()} fuzzer"
    )
    print()
    print(colored("Usage:", "white", attrs=["bold"]))
    print(f"  oida fuzz {protocol} <target> [options]")
    print()
    print(colored("Examples:", "white", attrs=["bold"]))
    if default_port:
        print(f"  oida fuzz {protocol} 192.168.1.100                 # Default port {default_port}")
        print(f"  oida fuzz {protocol} 192.168.1.100 -p {default_port}           # Explicit port")
    else:
        print(f"  oida fuzz {protocol} 192.168.1.100 -p <port>       # Specify port")
    print(f"  oida fuzz {protocol} 10.0.0.1 -v                   # Verbose output")
    print(f"  oida fuzz {protocol} 10.0.0.1 -s mysession         # Named session")
    print()
    print(colored("Common Options:", "white", attrs=["bold"]))
    print("  -p, --port PORT          Target port (default: protocol-specific)")
    print("  -v, --verbose            Increase verbosity (-v, -vv, -vvv)")
    print("  -s, --session NAME       Session name for results database")
    print("  -O, --option KEY=VALUE   Protocol-specific option")
    print("  --seed SEED              Random seed for reproducibility")
    print("  --max-depth N            Cap combinatorial depth: fuzz depths 1..N then stop")
    print("  -D, --only-depth N       Fuzz ONLY depth N (skip lower depths)")
    print("  --check-interval N       Monitor check interval (default: 100)")
    print("  -R, --reuse-connection   Reuse TCP connection (faster, less stable)")

    # Show full protocol-specific options
    try:
        options_help = fuzzer_class.format_options_help()
        if options_help and options_help.strip():
            print()
            print(options_help)
    except AttributeError as e:
        logger.debug(f"Failed to get options_help: {e}")

    # Show available requests if method exists
    try:
        requests_help = fuzzer_class.format_requests_help()
        if requests_help and requests_help.strip():
            print()
            print(requests_help)
    except AttributeError as e:
        logger.debug(f"Failed to get requests_help: {e}")

    print()
    print(colored("More Info:", "white", attrs=["bold"]))
    print(f"  oida fuzz {protocol} --list-requests   Show fuzzable requests")
    print("  oida fuzz --help                       Full command help")

    return 1


def show_protocol_options(protocol):
    """Show available options for a protocol with NXC-style output"""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    try:
        fuzzer_class = PROTOCOL_FUZZERS[protocol]
    except KeyError:
        logger.error(f"Unknown protocol: {protocol}")
        print("Use 'oida fuzz list' to see available protocols")
        return 1

    print()
    print(colored("[*]", "blue", attrs=["bold"]) + f" Protocol: {protocol.upper()}")
    print()
    try:
        print(fuzzer_class.format_options_help())
    except AttributeError:
        print("    No custom options available")
    print()
    print(f"Usage: oida fuzz {protocol} <target> -O key=value")
    return 0


def show_protocol_requests(protocol):
    """Show available requests for a protocol with NXC-style output"""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    try:
        fuzzer_class = PROTOCOL_FUZZERS[protocol]
    except KeyError:
        logger.error(f"Unknown protocol: {protocol}")
        print("Use 'oida fuzz list' to see available protocols")
        return 1

    print()
    print(
        colored("[*]", "blue", attrs=["bold"])
        + f" Protocol: {protocol.upper()} - Fuzzable Requests"
    )
    print()
    try:
        print(fuzzer_class.format_requests_help())
    except AttributeError:
        print("    No request listing available")
    print()
    print(f"Usage: oida fuzz {protocol} <target> --enable request1,request2")
    return 0


def run_fuzzing(args, protocol, target):
    """Run the actual fuzzing with NXC-style output"""
    try:
        from oida.fuzz.protocols import PROTOCOL_FUZZERS, PROTOCOL_IMPORT_ERRORS, install_hint
        from oida.fuzz import FuzzerApplication
    except ImportError as e:
        # The fuzzer core is built on boofuzz (the optional 'fuzz' extra). This
        # only fires if the fuzz subsystem itself cannot import (e.g. boofuzz is
        # absent). Individual protocol deps no longer break the whole package.
        logger.error(
            "Fuzzing requires the 'fuzz' extra (missing dependency: %s). "
            'Install it with: pip install "oida-ics[fuzz]"',
            e.name or e,
        )
        return 1

    # Validate protocol
    try:
        fuzzer_class = PROTOCOL_FUZZERS[protocol]
    except KeyError:
        # A protocol we know about but whose optional dependency failed to
        # import is recorded in PROTOCOL_IMPORT_ERRORS -- name the missing
        # module AND the exact extra that provides it, rather than pretending
        # the protocol does not exist.
        import_error = PROTOCOL_IMPORT_ERRORS.get(protocol)
        if import_error is not None:
            logger.error(
                "Protocol '%s' is unavailable (missing dependency: %s). Install it with: %s",
                protocol,
                import_error,
                install_hint(protocol),
            )
            return 1
        logger.error(f"Unknown protocol: {protocol}")
        print("Use 'oida fuzz list' to see available protocols")
        return 1

    # Auto-parse an embedded port from the target (e.g. 127.0.0.1:8080, [::1]:8080)
    target, embedded_port = _split_target_port(target)

    # Port precedence, matching the scanner CLI: the port embedded in the target
    # is the most specific spec, so it wins over --port, which wins over the
    # protocol default.
    user_port = getattr(args, "port", None)
    default_port = getattr(fuzzer_class, "default_port", None) or WELL_KNOWN_PORTS.get(protocol, 0)
    port = embedded_port or user_port or default_port

    # Create ICSLogger and set global context for consistent output
    verbose = getattr(args, "verbose", False)
    fuzz_logger = get_logger(f"FUZZ-{protocol.upper()}", target, port, verbose=verbose)

    # Set global context so internal modules can use ics_logger helper functions
    from oida.utils.ics_logger import set_context

    set_context(f"FUZZ-{protocol.upper()}", target, port, verbose=verbose)

    # Display banner (NXC-style)
    print()
    fuzz_logger.display(f"Fuzzer: {fuzzer_class.__name__}")
    if embedded_port:
        fuzz_logger.display(f"Parsed target: {target}:{embedded_port}")
        if user_port and user_port != embedded_port:
            fuzz_logger.display(f"Ignoring --port {user_port}: target port {embedded_port} wins")

    # Handle seed
    seed = getattr(args, "seed", None)
    if seed is None:
        seed = 0x01DA  # Default deterministic seed
    random.seed(seed)

    # ==================== STARTUP INFO ====================
    import os

    session_name = getattr(args, "session", "oida_fuzz_session")
    db_path = f"{session_name}.db"
    check_interval = getattr(args, "check_interval", 100)
    buffer_size = max(2 * check_interval, 100)  # Rolling buffer size

    # Log essential startup information
    fuzz_logger.display(f"Seed: {seed} (0x{seed:04X})")
    fuzz_logger.display(f"Session: {session_name}")

    # Get request info from fuzzer class
    try:
        requests = fuzzer_class.get_request_definitions()
        request_count = len(requests)
        categories = set(r.category for r in requests if hasattr(r, "category"))
        fuzz_logger.display(f"Requests: {request_count} ({', '.join(sorted(categories))})")
    except AttributeError as e:
        logger.debug(
            f"Failed to get requests: {e}"
        )  # Protocol doesn't implement get_request_definitions

    # Web interface info (runs locally, boofuzz default: 26000+)
    fuzz_logger.success("Web UI: http://localhost:26000 (boofuzz)")
    fuzz_logger.display(f"Buffer: {buffer_size} test cases (2 x {check_interval})")

    # Check for existing session data to determine resume point (filtered by target)
    # Note: The "RESUMING SESSION" message is displayed by base_fuzzer._display_session_info()
    resume_from = 1  # Default: start from beginning
    if os.path.exists(db_path):
        try:
            from oida.fuzz.core.database.orm import SQLAlchemyDatabase

            db = SQLAlchemyDatabase(db_path)
            db.init_schema()
            stats = db.get_target_stats(target, port)
            if stats["last_id"] and stats["last_id"] > 0:
                resume_from = stats["last_id"] + 1
        except ImportError as e:
            logger.debug(
                f"Optional import SQLAlchemyDatabase not available: {e}"
            )  # SQLAlchemy not installed, no resume support
        except Exception as e:
            fuzz_logger.warning(f"Could not resume from {db_path}: {e} - starting from beginning")
    fuzz_logger.debug(f"Database initialized: {db_path}")

    # Log special modes
    if getattr(args, "nolog", False):
        fuzz_logger.warning("Logging DISABLED (--nolog)")

    # Parse multi-machine distribution
    machine_str = getattr(args, "machine", None)
    distribution_total = None
    distribution_id = None

    if machine_str:
        try:
            parts = machine_str.split(",")
            if len(parts) != 2:
                logger.error("--machine format must be TOTAL,ID (e.g., 3,2)")
                return 1
            distribution_total = int(parts[0])
            distribution_id = int(parts[1])
            if distribution_id < 1 or distribution_id > distribution_total:
                logger.error(f"Machine ID must be between 1 and {distribution_total}")
                return 1
            fuzz_logger.display(f"Distribution: machine {distribution_id}/{distribution_total}")
        except ValueError:
            logger.error("Invalid --machine format")
            return 1

    # Parse protocol options
    protocol_options = {}
    raw_options = getattr(args, "protocol_options", None) or []
    for opt in raw_options:
        if "=" in opt:
            key, value = opt.split("=", 1)
            # Convert types
            if value.lower() == "true":
                protocol_options[key] = True
            elif value.lower() == "false":
                protocol_options[key] = False
            else:
                # Try integer conversion (handles negative numbers)
                try:
                    protocol_options[key] = int(value)
                except ValueError:
                    protocol_options[key] = value

    if protocol_options:
        logger.debug(f"Protocol options: {protocol_options}")

    # Parse request filters
    enabled_requests = None
    disabled_requests = None

    if getattr(args, "enable", None):
        enabled_requests = [r.strip() for r in args.enable.split(",")]
        fuzz_logger.display(f"Enabled: {', '.join(enabled_requests)}")

    if getattr(args, "disable", None):
        disabled_requests = [r.strip() for r in args.disable.split(",")]
        fuzz_logger.display(f"Disabled: {', '.join(disabled_requests)}")

    # Parse monitor configuration
    from oida.fuzz.core.config import MonitorConfig

    monitor_config = None
    monitor_logic = getattr(args, "monitor_logic", "and")

    monitors_str = getattr(args, "monitors", None)
    if monitors_str:
        monitor_config = MonitorConfig.parse(monitors_str, monitor_logic)
        fuzz_logger.display(f"Monitor: {monitor_config.format_display()}")
    else:
        # Will use protocol defaults - show what will be used
        try:
            default_monitors = fuzzer_class.get_default_monitors()
            default_config = MonitorConfig.parse(default_monitors, monitor_logic)
            fuzz_logger.display(f"Monitor: {default_config.format_display()} (protocol default)")
        except AttributeError:
            fuzz_logger.display("Monitor: ping, socket (default)")

    # Display TLS status
    if getattr(args, "tls_enabled", False):
        fuzz_logger.display("TLS: enabled (no verification)")

    # Build config wrapper
    class ArgsWrapper:
        """Wrapper for args to support application interface"""

        pass

    wrapped = ArgsWrapper()
    wrapped.ip = target
    wrapped.port = port or 0
    wrapped.protocol = protocol
    wrapped.session = getattr(args, "session", "oida_fuzz_session")
    wrapped.nolog = getattr(args, "nolog", False)
    wrapped.store_all_payloads = getattr(args, "store_all_payloads", False)
    wrapped.boofuzz_db = getattr(args, "boofuzz_db", False)
    wrapped.fuzz_db_keep_pass_cases = getattr(args, "fuzz_db_keep_pass_cases", 500)
    wrapped.skip_pre_send = True
    wrapped.check_interval = getattr(args, "check_interval", 100)
    # Console output based on verbosity
    wrapped.console_output = getattr(args, "verbose", False)
    wrapped.seed = seed
    wrapped.protocol_options = protocol_options
    wrapped.distribution_total = distribution_total
    wrapped.distribution_id = distribution_id
    wrapped.enabled_requests = enabled_requests
    wrapped.disabled_requests = disabled_requests
    wrapped.monitor_config = monitor_config
    wrapped.monitor_logic = monitor_logic
    wrapped.reuse_connection = getattr(args, "reuse_connection", False)
    # -X: skip ALL receives (may break state machines)
    wrapped.receive_data_after_fuzz = not getattr(args, "no_receive", False)
    # -F: fire-forget fuzz payloads only (still receive setup/prereq responses)
    if getattr(args, "fire_forget_fuzz", False):
        wrapped.receive_data_after_fuzz = False
        wrapped.receive_data_after_each_request = True
    else:
        wrapped.receive_data_after_each_request = wrapped.receive_data_after_fuzz
    wrapped.sleep_time = getattr(args, "sleep_time", 0.0)
    wrapped.recv_timeout = getattr(args, "recv_timeout", None)
    wrapped.send_timeout = getattr(args, "send_timeout", None)
    wrapped.reconnect_delay = getattr(args, "reconnect_delay", None)
    wrapped.max_reconnect_attempts = getattr(args, "max_reconnect_attempts", None)
    # Timeout calibration
    wrapped.calibrate = not getattr(args, "no_calibrate", False)
    wrapped.calibration_probes = getattr(args, "calibration_probes", 50)
    wrapped.detect_drift = getattr(args, "detect_drift", False)
    # Drift recalibration only makes sense with online adaptation enabled
    wrapped.adaptive_timeout = getattr(args, "adaptive_timeout", False) or wrapped.detect_drift
    wrapped.node = getattr(args, "node", None)
    wrapped.command = "fuzz"
    # Resume from last test case if session exists
    wrapped.index_start = resume_from
    # TLS configuration
    wrapped.tls_enabled = getattr(args, "tls_enabled", False)
    # Capability enumeration
    wrapped.enumerate = getattr(args, "enumerate", True)
    # Crash handling
    wrapped.pause_on_crash = getattr(args, "pause_on_crash", False)
    # Platform-feature monitors (script / valid-case) + auto-restart
    wrapped.script_monitor = getattr(args, "script_monitor", None)
    wrapped.valid_case = getattr(args, "valid_case", None)
    wrapped.valid_case_expect = getattr(args, "valid_case_expect", None)
    wrapped.restart_command = getattr(args, "restart_command", None)
    wrapped.restart_delay = getattr(args, "restart_delay", 2.0)
    wrapped.agent_monitor = getattr(args, "agent_monitor", None)
    wrapped.agent_token = getattr(args, "agent_token", None)

    # Run application (enumeration happens during fuzzer creation)
    print()
    app = FuzzerApplication()
    try:
        result = app.run_command(wrapped)
    except ConnectionError as e:
        fuzz_logger.fail(str(e))
        return 1

    # Show final session summary
    print()
    try:
        if os.path.exists(db_path):
            from oida.fuzz.core.database.orm import SQLAlchemyDatabase

            db = SQLAlchemyDatabase(db_path)
            db.init_schema()
            stats = db.get_stats()

            # boofuzz position = resume_base + sent + skipped:
            #   sent        = cases transmitted/recorded this run
            #   skipped     = mutations boofuzz jumped this run (crash-threshold fast-forward)
            #   resume_base = cases already covered by earlier sessions (resume offset)
            #   total       = boofuzz's mutation-space position (matches its UI "Total")
            sent = stats.get("total_processed", 0) or stats.get("total_test_cases", 0)
            total = stats.get("final_mutant_index", sent)
            resume_base = stats.get("resume_base", 0)
            skipped = max(0, total - sent - resume_base)
            final_crashes = stats.get("total_crashes", 0)
            db_size = stats.get("db_size_mb", 0)

            fuzz_logger.display(
                f"Test cases - sent: {sent:,} | skipped: {skipped:,} | total: {total:,}"
            )
            if resume_base:
                fuzz_logger.display(
                    f"Resumed past {resume_base:,} cases fuzzed in earlier sessions"
                )
            fuzz_logger.display(f"Total crashes: {final_crashes:,}")
            fuzz_logger.display(f"Database size: {db_size:.2f} MB")
    except Exception as e:
        logger.debug(f"Could not read final stats: {e}")

    if result == 0:
        fuzz_logger.success("Fuzzing completed")
    else:
        fuzz_logger.fail("Fuzzing terminated with errors")

    return result
