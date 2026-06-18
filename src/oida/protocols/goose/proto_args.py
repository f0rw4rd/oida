"""
Argument parser definition for GOOSE (Generic Object Oriented Substation Event) protocol

This module registers GOOSE-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    add_target_argument,
    create_protocol_parser,
)


def proto_args(parser, parents):
    """Register GOOSE-specific arguments"""
    examples_epilog = """
Examples:
  oida goose eth0                          # Passive GOOSE sniffing on eth0
  oida goose eth0 --timeout 30             # Listen for 30 seconds
  oida goose eth0 --appid 1000            # Filter by AppID
  oida goose --rgoose 192.168.1.0/24       # R-GOOSE UDP listener
  oida goose --mms-enum 192.168.1.100      # Enumerate GoCBs via MMS

Security Testing:
  oida goose eth0 --timeout 60             # Long capture for anomaly detection
  oida goose --mms-enum 192.168.1.100 --mms-port 102  # Custom MMS port
"""

    # Create parser with standard setup
    goose_parser = create_protocol_parser(
        parser,
        name="goose",
        help_text="IEC 61850 GOOSE scanner",
        description="Passive GOOSE sniffer, R-GOOSE listener, and GoCB enumerator",
        parents=parents,
        epilog=examples_epilog,
    )

    # Target argument: interface name for sniffing, or used with --mms-enum/--rgoose
    add_target_argument(
        goose_parser,
        help_text="Network interface for GOOSE sniffing (e.g., eth0), "
        "or target for --rgoose/--mms-enum modes",
    )

    # Capture options
    capture_group = goose_parser.add_argument_group("Capture Options")
    capture_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECS",
        help="Capture/listen timeout in seconds (default: 10)",
    )
    capture_group.add_argument(
        "--appid",
        type=int,
        default=None,
        metavar="ID",
        help="Filter by GOOSE Application ID",
    )

    # R-GOOSE options
    rgoose_group = goose_parser.add_argument_group("R-GOOSE Options")
    rgoose_group.add_argument(
        "--rgoose",
        action="store_true",
        help="Enable R-GOOSE (routable GOOSE over UDP) listener mode",
    )
    rgoose_group.add_argument(
        "--rgoose-port",
        type=int,
        default=None,
        metavar="PORT",
        help="R-GOOSE UDP port (required when --rgoose is used)",
    )
    rgoose_group.add_argument(
        "--rgoose-auth",
        action="store_true",
        help="Enable R-GOOSE authentication per IEC 62351-6",
    )
    rgoose_group.add_argument(
        "--rgoose-key",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to R-GOOSE authentication key file (IEC 62351-6)",
    )

    # MMS GoCB enumeration options
    mms_group = goose_parser.add_argument_group("MMS GoCB Enumeration")
    mms_group.add_argument(
        "--mms-enum",
        type=str,
        default=None,
        metavar="HOST",
        help="Enumerate GoCBs via MMS connection to target IED",
    )
    mms_group.add_argument(
        "--mms-port",
        type=int,
        default=102,
        metavar="PORT",
        help="MMS port for GoCB enumeration (default: 102)",
    )

    return goose_parser
