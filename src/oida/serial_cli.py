"""
Serial port utilities CLI subcommand.

Provides commands for listing serial ports and auto-detecting parameters.
"""

import argparse
import sys

from oida.utils.serial_detection import (
    SerialDetector,
    DetectionMethod,
    check_serial_available,
)


def serial_args(subparsers: argparse._SubParsersAction, parents: list) -> argparse.ArgumentParser:
    """
    Register serial subcommand and its sub-actions.

    Args:
        subparsers: Parent subparser to add serial command to
        parents: Parent parsers for common arguments

    Returns:
        The serial argument parser
    """
    serial_parser = subparsers.add_parser(
        "serial",
        help="Serial port utilities (list ports, auto-detect parameters)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Serial port utilities for OIDA.

Commands:
  list     List available serial ports
  detect   Auto-detect serial port parameters (baud rate, parity, etc.)

Examples:
  oida serial list
  oida serial detect /dev/ttyUSB0 --method passive
  oida serial detect /dev/ttyUSB0 --method active --full-sweep
""",
    )

    serial_sub = serial_parser.add_subparsers(
        dest="serial_action", title="serial commands", metavar="<command>"
    )

    # oida serial list
    list_parser = serial_sub.add_parser(
        "list",
        help="List available serial ports",
        description="Enumerate all available serial ports on the system.",
    )
    list_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        # SUPPRESS so a subparser-level non-occurrence doesn't clobber a global
        # `-v` given before the subcommand (the main parser supplies default=0).
        default=argparse.SUPPRESS,
        help="Show detailed port information",
    )

    # oida serial detect <port> --method <passive|active>
    detect_parser = serial_sub.add_parser(
        "detect",
        help="Auto-detect serial port parameters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Auto-detect serial port parameters (baud rate, parity, stop bits).

Detection Methods:
  passive  Listen for incoming data and analyze character patterns.
           Best for devices that emit continuous output (boot logs, consoles).
           Requires the target device to be actively sending data.

  active   Send probe strings and analyze responses.
           Best for interactive devices that respond to commands.
           Sends: \\r\\n, AT\\r\\n

Examples:
  # Detect baud rate only (assumes 8N1)
  oida serial detect /dev/ttyUSB0 --method passive

  # Full parameter sweep (baud + parity + stopbits)
  oida serial detect /dev/ttyUSB0 --method passive --full-sweep

  # Active probing with longer timeout
  oida serial detect /dev/ttyUSB0 --method active --timeout 10
""",
    )
    detect_parser.add_argument("port", help="Serial port device (e.g., /dev/ttyUSB0, COM1)")
    detect_parser.add_argument(
        "--method",
        required=True,
        choices=["passive", "active"],
        help="Detection method: passive (listen) or active (probe)",
    )
    detect_parser.add_argument(
        "--full-sweep",
        action="store_true",
        help="Test all parity/stopbit combinations (slower but thorough)",
    )
    detect_parser.add_argument(
        "--extended-bauds", action="store_true", help="Test extended baud rate range (300-921600)"
    )
    detect_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECS",
        help="Timeout per test in seconds (default: 5.0)",
    )
    detect_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        # SUPPRESS so a subparser-level non-occurrence doesn't clobber a global
        # `-v` given before the subcommand (the main parser supplies default=0).
        default=argparse.SUPPRESS,
        help="Show verbose output during detection",
    )
    detect_parser.add_argument("--json", action="store_true", help="Output result as JSON")

    return serial_parser


def handle_serial_command(args: argparse.Namespace) -> int:
    """
    Handle serial subcommand execution.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    if not check_serial_available():
        print("Error: pyserial is not installed.", file=sys.stderr)
        print("Install with: pip install oida-ics[serial]", file=sys.stderr)
        return 1

    if not hasattr(args, "serial_action") or args.serial_action is None:
        print("Error: No serial command specified.", file=sys.stderr)
        print("Use 'oida serial --help' for available commands.", file=sys.stderr)
        return 1

    if args.serial_action == "list":
        return _handle_list(args)
    elif args.serial_action == "detect":
        return _handle_detect(args)
    else:
        print(f"Error: Unknown serial action: {args.serial_action}", file=sys.stderr)
        return 1


def _handle_list(args: argparse.Namespace) -> int:
    """Handle 'oida serial list' command."""
    detector = SerialDetector()
    ports = detector.list_ports()

    if not ports:
        print("No serial ports found.")
        return 0

    print("Available Serial Ports:")
    print()

    for port in ports:
        if args.verbose:
            print(f"  Device:       {port.device}")
            print(f"  Description:  {port.description}")
            print(f"  Hardware ID:  {port.hwid}")
            if port.manufacturer:
                print(f"  Manufacturer: {port.manufacturer}")
            print()
        else:
            print(f"  {port}")

    return 0


def _handle_detect(args: argparse.Namespace) -> int:
    """Handle 'oida serial detect' command."""
    import json

    method = DetectionMethod.PASSIVE if args.method == "passive" else DetectionMethod.ACTIVE

    detector = SerialDetector(verbose=args.verbose)

    if not args.verbose:
        print(f"Detecting serial parameters on {args.port}...")
        method_desc = "passive listening" if method == DetectionMethod.PASSIVE else "active probing"
        sweep_desc = " (full sweep)" if args.full_sweep else ""
        print(f"Method: {method_desc}{sweep_desc}")
        print()

    try:
        config = detector.detect(
            port=args.port,
            method=method,
            full_sweep=args.full_sweep,
            timeout=args.timeout,
            extended_bauds=args.extended_bauds,
        )
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if config is None:
        print("Detection failed: Could not determine serial parameters.")
        print()
        print("Suggestions:")
        print("  - Ensure the device is powered on and sending data (for passive mode)")
        print("  - Try the other detection method (--method active/passive)")
        print("  - Try --full-sweep to test all parameter combinations")
        print("  - Increase timeout with --timeout")
        return 1

    if args.json:
        print(json.dumps(config.as_dict(), indent=2))
    else:
        print("Detected Configuration:")
        print()
        for line in str(config).split("\n"):
            print(f"  {line}")
        print()

        # Show usage hint
        if config.confidence < 0.7:
            print(f"Note: Confidence is {config.confidence:.0%}. Results may need verification.")
        else:
            print(f"Confidence: {config.confidence:.0%}")

    return 0
