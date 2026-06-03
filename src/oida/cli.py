"""
OIDA Command Line Interface

Main CLI entry point:
    oida <protocol> <target> [options]

Examples:
    oida modbus 192.168.1.100 -u 1 -r 0-100
    oida opcua opc.tcp://192.168.1.100:4840 --auth Anonymous
    oida s7 192.168.1.10 --rack 0 --slot 2
"""

import os

# Suppress c104 warning about buffered mode
os.environ.setdefault("PYTHONUNBUFFERED", "1")

import sys
import argparse
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Any, Dict
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
from oida.utils.export_utils import configure_from_args
from oida.utils.ics_logger import get_module_logger
from oida import __version__


# Configure logging - suppress noisy libraries
logging.basicConfig(level=logging.ERROR, format="%(message)s")
logger = get_module_logger(__name__)

# Suppress noisy third-party loggers
for noisy_logger in ["c104", "asyncua", "pymodbus", "pyads", "xknx", "paho"]:
    logging.getLogger(noisy_logger).setLevel(logging.CRITICAL)


# Substring patterns matched against argparse dest names. Any dest containing
# one of these (case-insensitive) has its value replaced with '***' before
# args are logged, exported, or otherwise echoed back to the operator.
# Tested against vars(argparse.Namespace) which is shallow str→value.
_SENSITIVE_ARG_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "token",
    "psk",
    "pre_shared_key",
    "private_key",
    "privkey",
    "auth_string",
    "auth_pass",
    "community",  # SNMPv1/v2c community string is effectively a password
    "api_key",
    "apikey",
    "credential",
)


def _redact_sensitive_args(args_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of args_dict with credential-like values masked."""
    redacted: Dict[str, Any] = {}
    for k, v in args_dict.items():
        kl = str(k).lower()
        if v is not None and any(p in kl for p in _SENSITIVE_ARG_PATTERNS):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted


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
                return yaml.safe_load(f) or {}
            elif suffix == ".json":
                return json.load(f)
            else:
                raise ValueError(
                    f"Unsupported config file format: {suffix} (use .yaml, .yml, or .json)"
                )
    except (json.JSONDecodeError, *yaml_error) as e:
        raise ValueError(f"Failed to parse config file: {e}")


def merge_config_with_args(args: argparse.Namespace, config: Dict[str, Any]) -> argparse.Namespace:
    """
    Merge config file values into parsed arguments.

    Command-line arguments take precedence over config file values.
    Only values that weren't explicitly set on command line are overridden.

    Args:
        args: Parsed command-line arguments
        config: Configuration dictionary from file

    Returns:
        Updated argparse.Namespace with merged values
    """
    # Get defaults from parser for comparison
    # Values explicitly set on command line won't match defaults

    for key, value in config.items():
        # Convert dashes to underscores (CLI uses dashes, argparse uses underscores)
        attr_name = key.replace("-", "_")

        # Only set if attribute doesn't exist or is at default
        if not hasattr(args, attr_name):
            setattr(args, attr_name, value)
        elif getattr(args, attr_name) is None:
            # None typically means not set on command line
            setattr(args, attr_name, value)

    return args


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


def _export_tables(tables: List[Dict[str, Any]], output_dir: str, nxc_logger=None) -> None:
    """Write each harvest table as CSV + JSON in *output_dir*."""
    _log = nxc_logger or get_logger("EXPORT", "", 0)
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

        # CSV
        csv_path = os.path.join(output_dir, f"{stem}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

        # JSON (list of dicts) — use structured json_rows when available
        json_path = os.path.join(output_dir, f"{stem}.json")
        json_data = table.get("json_rows") or [dict(zip(headers, row)) for row in rows]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        _log.debug("Table exported: %s.csv / .json", stem)
        exported += 1

    if exported:
        _log.success(f"{exported} tables exported to {output_dir}")


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
        formats = ["json", "csv"]
    elif output_format.lower() in ["json", "csv", "xml"]:
        formats = [output_format.lower()]

    # Treat -o as a directory
    output_dir = output_path
    os.makedirs(output_dir, exist_ok=True)

    # Collect per-table data from pcap results for dedicated file export
    all_tables: List[Dict[str, Any]] = []
    for r in results:
        data = r.get("data", {})
        if isinstance(data, dict):
            tables = data.pop("tables", [])
            if tables:
                all_tables.extend(tables)

    for fmt in formats:
        if fmt == "json":
            json_path = os.path.join(output_dir, f"{protocol_name}.json")
            with open(json_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            _log.debug("Results exported to %s", json_path)

        elif fmt == "csv":
            csv_path = os.path.join(output_dir, f"{protocol_name}.csv")
            # Flatten results for CSV
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
                # Add flattened data fields if present
                data = r.get("data", {})
                if isinstance(data, dict):
                    for key, value in data.items():
                        # Convert complex values to strings
                        if isinstance(value, (dict, list)):
                            flat[f"data_{key}"] = json.dumps(value, default=str)
                        else:
                            flat[f"data_{key}"] = value
                flat_results.append(flat)

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
            _log.warning("XML export not yet implemented")

    # Write each harvest table as a dedicated CSV file
    if all_tables:
        _export_tables(all_tables, output_dir, nxc_logger=nxc_logger)


def gen_cli_args():
    """
    Generate argument parser with dynamic protocol loading

    Scans the protocols directory and registers each protocol's
    arguments dynamically.

    Returns:
        argparse.ArgumentParser: Configured argument parser
    """

    # Custom parser class that shows subcommand help on errors
    class SubcommandHelpParser(argparse.ArgumentParser):
        """Parser that shows subcommand-specific help on errors."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._subparsers_action = None

        def error(self, message):
            """Show subcommand help when an error occurs in a subcommand."""
            # Check if we're in a subcommand context
            if hasattr(self, "_active_subparser") and self._active_subparser:
                self._active_subparser.print_usage(sys.stderr)
                self.exit(2, f"{self._active_subparser.prog}: error: {message}\n")
            else:
                super().error(message)

    # Create main parser
    parser = SubcommandHelpParser(
        prog="oida",
        description="Industrial Control Systems Security Testing Framework",
        epilog="For protocol-specific help: oida <protocol> --help",
    )

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

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)",
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
        help="Protocol to use for scanning",
    )
    # Store subparsers reference for error handling
    parser._subparsers_map = {}

    # Register serial utilities subcommand
    serial_args(subparsers, [])

    # Register fuzz subcommand
    fuzz_args(subparsers, [])

    # Standard parser (inherited by all protocols)
    std_parser = argparse.ArgumentParser(add_help=False)

    # Load protocols dynamically
    protocols_dir = Path(__file__).parent / "protocols"
    p_loader = ProtocolLoader(str(protocols_dir))
    protocols = p_loader.get_protocols()

    # Track if any protocols were registered
    protocols_registered = 0

    # Register each protocol's arguments
    for protocol_name in sorted(protocols.keys()):
        protocol_info = protocols[protocol_name]

        # Check if protocol has proto_args.py
        if protocol_info.get("argspath"):
            try:
                # Load proto_args module using dedicated method
                proto_args_module = p_loader.load_proto_args(protocol_name)

                # Call proto_args() function to register arguments
                if proto_args_module and hasattr(proto_args_module, "proto_args"):
                    proto_args_module.proto_args(subparsers, [std_parser])
                    protocols_registered += 1
                    logger.debug(f"Registered protocol: {protocol_name}")
                elif proto_args_module:
                    print(
                        f"[!] Protocol '{protocol_name}': proto_args.py has no proto_args() function",
                        file=sys.stderr,
                    )
            except Exception as e:
                print(
                    f"[!] Protocol '{protocol_name}' not available: {e}",
                    file=sys.stderr,
                )
        else:
            # No proto_args.py - create basic subparser
            logger.debug(f"Creating default subparser for {protocol_name}")
            protocol_parser = subparsers.add_parser(
                protocol_name,
                help=f"{protocol_name.upper()} protocol scanner",
                parents=[std_parser],
            )
            protocol_parser.add_argument(
                "target",
                nargs="?",
                default="127.0.0.1",
                help="Target IP, hostname, CIDR, range, or file",
            )
            protocol_parser.add_argument(
                "--port",
                type=int,
                help="Target port (protocol default if not specified)",
            )
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


def print_banner():
    """Print OIDA banner (NXC style)"""
    print(f"""
     ╔═╗╦╔╦╗╔═╗
     ║ ║║ ║║╠═╣
     ╚═╝╩═╩╝╩ ╩  v{__version__}

    OT/ICS Dynamic Assessment Framework
    https://github.com/f0rw4rd/oida
""")


def _show_usage_and_exit() -> int:
    """Show usage information when no arguments provided"""
    print_banner()
    print("Usage: oida <protocol> <target> [options]")
    print("")
    print("Available protocols:")
    print("  ads        Beckhoff ADS/TwinCAT")
    print("  astm       ASTM/LIS laboratory")
    print("  bacnet     BACnet building automation")
    print("  can        Controller Area Network (CANopen/UDS/XCP)")
    print("  coap       CoAP (RFC 7252) constrained devices")
    print("  dicom      DICOM medical imaging")
    print("  discovery  Network discovery (passive/active)")
    print("  dnp3       DNP3 SCADA")
    print("  ethercat   EtherCAT fieldbus")
    print("  ethernetip EtherNet/IP CIP")
    print("  fhir       FHIR R4 REST healthcare")
    print("  goose      IEC 61850 GOOSE sniffer / R-GOOSE listener")
    print("  hart       HART-IP field devices")
    print("  hl7        HL7 healthcare messaging")
    print("  iec104     IEC 60870-5-104 telecontrol")
    print("  knx        KNX/EIB building automation")
    print("  mms        MMS/IEC 61850")
    print("  modbus     Modbus TCP/RTU/TLS")
    print("  mqtt       MQTT with Sparkplug B")
    print("  ocpp       OCPP EV charging stations")
    print("  opcua      OPC UA")
    print("  pcap       Passive capture analysis")
    print("  profinet   PROFINET DCP/RPC")
    print("  s7         Siemens S7 (Snap7)")
    print("  snmp       SNMP v1/v2c/v3")
    print("  tase2      TASE.2/ICCP (IEC 60870-6)")
    print("")
    print("Run 'oida <protocol> -h' for protocol-specific options")
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
        logger.error("pyserial not available. Install with: pip install pyserial")
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

    # Create progress logger for NXC-style output
    default_port = getattr(protocol_class, "default_port", 0)
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

    # pip version
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
        pip_name = line.split(";")[0].split(">")[0].split("<")[0].split("=")[0].split("!")[0]
        pip_name = pip_name.split("[")[0].strip()
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
                    err = type(e).__name__
                    lines.append(f"  {name:<20s}FAIL ({err})")
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
    args_to_parse = argv if argv is not None else sys.argv[1:]

    # Handle --bug before argparse (no protocol subcommand required)
    if "--bug" in args_to_parse:
        print_bug_report()
        return 0

    # Show banner when no arguments provided
    if not args_to_parse:
        return _show_usage_and_exit()

    # Generate parser
    try:
        parser = gen_cli_args()
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
            args = merge_config_with_args(args, config)
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
        default_port = getattr(protocol_class, "default_port", 0)
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
        # internally, so we just pass a plain Namespace here.
        target_args = argparse.Namespace(**vars(args), host=target, rhost=target)

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
        logger.debug(f"Error scanning {target}: {e}")
        return {
            "host": target,
            "protocol": getattr(args, "protocol", "unknown"),
            "success": False,
            "error": str(e),
        }


if __name__ == "__main__":
    sys.exit(main())
