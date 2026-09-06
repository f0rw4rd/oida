"""
Argument parser definition for HART protocol

This module registers HART-specific command-line arguments using the
central proto_args_factory functions for standard option groups.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_dangerous_options,
    add_discovery_options,
)


def proto_args(parser, parents):
    """Register HART-specific arguments"""
    hart_parser = create_protocol_parser(
        parser,
        name="hart",
        help_text="HART-IP protocol scanner",
        description="Scan and interact with HART (Highway Addressable Remote Transducer) "
        "devices over HART-IP",
        parents=parents,
        epilog="""
Examples:
  # Basic device identification
  oida hart 192.168.1.100

  # Read all process variables
  oida hart 192.168.1.100 --read-all-vars

  # Scan for devices on multi-drop network
  oida hart 192.168.1.100 --scan-addresses 0-15

  # Enumerate supported commands
  oida hart 192.168.1.100 --enumerate-commands

  # Security analysis
  oida hart 192.168.1.100 --security-analysis -v

  # Fuzzing (requires --confirm)
  oida hart 192.168.1.100 --fuzz --fuzz-iterations 50 --confirm

  # Use TCP instead of UDP
  oida hart 192.168.1.100 --tcp --port 5095

  # Write operations (require --confirm)
  oida hart 192.168.1.100 --write-tag "SENSOR01" --confirm
        """,
    )

    # Standard target argument
    add_target_argument(hart_parser)

    # Standard network options (port + timeout)
    network = add_network_options(hart_parser, default_port=5094)
    network.add_argument(
        "--tcp",
        action="store_true",
        help="Use TCP instead of UDP (default: UDP)",
    )
    network.add_argument(
        "--probe-version",
        action="store_true",
        help="Probe HART-IP server version before connecting (detects v1/v2 TLS support)",
    )

    # HART-IP v2 TLS/PSK Options
    tls_group = hart_parser.add_argument_group("HART-IP v2 TLS/PSK Options")
    tls_group.add_argument(
        "--psk-identity",
        type=str,
        metavar="ID",
        help="Pre-shared key identity for HART-IP v2 TLS-PSK authentication",
    )
    tls_group.add_argument(
        "--psk-key",
        type=str,
        metavar="HEX",
        help="Pre-shared key (hex) for HART-IP v2 TLS-PSK authentication",
    )
    tls_group.add_argument(
        "--cipher-suite",
        type=str,
        metavar="CIPHER",
        help="TLS cipher suite for HART-IP v2 (default: library default)",
    )

    # HART Addressing
    addr_group = hart_parser.add_argument_group("HART Addressing")
    addr_group.add_argument(
        "--poll-addr",
        type=int,
        default=0,
        metavar="ADDR",
        help="Polling address for multi-drop (0-15, default: 0)",
    )

    # Read Operations
    read_group = hart_parser.add_argument_group("Read Operations")
    read_group.add_argument(
        "--read-id",
        action="store_true",
        help="Read device unique identifier (Command 0)",
    )
    read_group.add_argument(
        "--read-pv",
        action="store_true",
        help="Read primary variable (Command 1)",
    )
    read_group.add_argument(
        "--read-current",
        action="store_true",
        help="Read loop current and percent of range (Command 2)",
    )
    read_group.add_argument(
        "--read-all-vars",
        action="store_true",
        help="Read all dynamic variables (Command 3)",
    )
    read_group.add_argument(
        "--read-tag",
        action="store_true",
        help="Read tag, descriptor, and date (Command 13)",
    )
    read_group.add_argument(
        "--read-output",
        action="store_true",
        help="Read output information (Command 15)",
    )
    read_group.add_argument(
        "--read-status",
        action="store_true",
        help="Read additional device status (Command 48)",
    )

    # Scanning Options
    scan_group = hart_parser.add_argument_group("Scanning Options")
    scan_group.add_argument(
        "--scan-addresses",
        type=str,
        metavar="RANGE",
        help="Scan polling address range (e.g., 0-15, 1-10)",
    )
    scan_group.add_argument(
        "--enumerate-commands",
        action="store_true",
        help="Enumerate supported HART commands",
    )
    scan_group.add_argument(
        "--command-range",
        type=str,
        default="0-48",
        metavar="RANGE",
        help="Command range to enumerate (default: 0-48)",
    )
    scan_group.add_argument(
        "--enumerate-device-specific",
        action="store_true",
        help="Enumerate device-specific commands (128-253, honors --command-range)",
    )

    # Security Options
    security_group = hart_parser.add_argument_group("Security Options")
    security_group.add_argument(
        "--security-analysis",
        action="store_true",
        help="Perform security analysis of the device",
    )

    # WirelessHART Options
    wireless_group = hart_parser.add_argument_group("WirelessHART Options")
    wireless_group.add_argument(
        "--detect-wireless",
        action="store_true",
        help="Detect WirelessHART capabilities (probes Commands 20, 85, 768)",
    )
    wireless_group.add_argument(
        "--wireless-info",
        action="store_true",
        help="Show detailed WirelessHART network information",
    )
    wireless_group.add_argument(
        "--list-sub-devices",
        action="store_true",
        help="List sub-devices connected to WirelessHART gateway (Commands 84/85)",
    )

    # Device Lock Options (HART 6+)
    lock_group = hart_parser.add_argument_group("Device Lock Options (HART 6+)")
    lock_group.add_argument(
        "--check-lock",
        action="store_true",
        help="Check device lock state (Command 76)",
    )
    lock_group.add_argument(
        "--bruteforce-lock",
        type=str,
        metavar="FILE",
        help="Bruteforce lock codes from file (one code per line)",
    )
    lock_group.add_argument(
        "--bruteforce-delay",
        type=float,
        default=0.1,
        metavar="SEC",
        help="Delay between bruteforce attempts (default: 0.1s)",
    )
    lock_group.add_argument(
        "--unlock",
        type=str,
        metavar="CODE",
        help="Try to unlock device with specific code (requires --confirm)",
    )
    lock_group.add_argument(
        "--lock",
        type=str,
        metavar="CODE",
        help="Lock device with specific code (requires --confirm)",
    )

    # Write Operations
    write_group = hart_parser.add_argument_group("Write Operations (require --confirm)")
    write_group.add_argument(
        "--write-poll-addr",
        type=int,
        metavar="ADDR",
        help="Write new polling address (0-15)",
    )
    write_group.add_argument(
        "--write-tag",
        type=str,
        metavar="TAG",
        help="Write device tag (max 8 characters)",
    )
    write_group.add_argument(
        "--write-descriptor",
        type=str,
        metavar="DESC",
        help="Write device descriptor (max 16 characters)",
    )
    write_group.add_argument(
        "--write-message",
        type=str,
        metavar="MSG",
        help="Write device message (max 24 characters)",
    )
    write_group.add_argument(
        "--reset-config-flag",
        action="store_true",
        help="Reset configuration changed flag (Command 38)",
    )
    write_group.add_argument(
        "--self-test",
        action="store_true",
        help="Perform device self-test (Command 41)",
    )
    write_group.add_argument(
        "--master-reset",
        action="store_true",
        help="Perform master reset - DANGEROUS (Command 42)",
    )
    write_group.add_argument(
        "--probe-calibration",
        action="store_true",
        help="Probe calibration command accessibility (requires --confirm)",
    )
    write_group.add_argument(
        "--probe-write",
        action="store_true",
        help="Probe write command accessibility (requires --confirm)",
    )

    # Standard dangerous operations (--confirm, --fuzz, --fuzz-iterations)
    add_dangerous_options(hart_parser, include_fuzz=True, fuzz_default_iterations=20)

    # HART-specific fuzz option
    hart_parser.add_argument(
        "--fuzz-commands",
        type=str,
        metavar="LIST",
        help="Comma-separated list of commands to fuzz "
        "(default: 0,1,2,3,6,11,12,13,15,17,18,42,48)",
    )

    # Raw Command
    raw_group = hart_parser.add_argument_group("Raw Command")
    raw_group.add_argument(
        "--raw-command",
        type=int,
        metavar="CMD",
        help="Send raw HART command (0-65535)",
    )
    raw_group.add_argument(
        "--raw-data",
        type=str,
        metavar="HEX",
        help="Hex data payload for raw command (e.g., '0102030405')",
    )

    # Standard discovery options (--quick, --discover, --full, --deep-scan)
    add_discovery_options(hart_parser)

    return hart_parser
