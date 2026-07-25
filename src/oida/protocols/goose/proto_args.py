"""
Argument parser definition for GOOSE (Generic Object Oriented Substation Event) protocol

This module registers GOOSE-specific command-line arguments.
"""

import argparse

from ...utils.proto_args_factory import (
    create_protocol_parser,
)


def proto_args(parser, parents):
    """Register GOOSE-specific arguments"""
    examples_epilog = """
Examples:
  oida goose eth0                          # Passive GOOSE sniffing on eth0
  oida goose eth0 --timeout 30             # Listen for 30 seconds
  oida goose eth0 --appid 1000            # Filter by AppID (decimal)
  oida goose eth0 --gocb-ref 'LD/LLN0$GO$gcb01'  # Live capture of a known GoCB
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

    # Target argument: interface name for sniffing. Optional because the
    # MMS GoCB-enumeration mode (--mms-enum <ip>) and the R-GOOSE listener
    # mode (--rgoose) carry their own target and do not need a positional;
    # see cli.py which derives the run target from --mms-enum when the
    # positional is absent. add_target_argument() registers a *required*
    # positional, so register it directly here with nargs="?" instead.
    goose_parser.add_argument(
        "target",
        nargs="?",
        default="",
        help="Network interface for GOOSE sniffing (e.g., eth0). "
        "Optional in --mms-enum/--rgoose modes.",
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
        help="Filter by GOOSE Application ID (decimal, e.g. 1000; shown as hex 0x03E8 in capture output)",
    )
    capture_group.add_argument(
        "--gocb-ref",
        type=str,
        default="",
        metavar="REF",
        help="GOOSE Control Block reference for live capture "
        "(e.g. 'LD/LLN0$GO$gcb01'); required for passive GOOSE capture. "
        "Use --mms-enum <ip> to discover GoCB references first.",
    )

    # R-GOOSE options (not yet implemented in the high-level API).
    # --rgoose is kept visible so the mode reports a clear "not yet
    # supported" message rather than silently sniffing; the auth/key
    # sub-flags are entirely non-functional and hidden to avoid
    # advertising capabilities that do not exist.
    rgoose_group = goose_parser.add_argument_group("R-GOOSE Options")
    rgoose_group.add_argument(
        "--rgoose",
        action="store_true",
        help="Enable R-GOOSE (routable GOOSE over UDP) listener mode (UNIMPLEMENTED)",
    )
    rgoose_group.add_argument(
        "--rgoose-port",
        type=int,
        default=None,
        metavar="PORT",
        help=argparse.SUPPRESS,
    )
    rgoose_group.add_argument(
        "--rgoose-auth",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    rgoose_group.add_argument(
        "--rgoose-key",
        type=str,
        default=None,
        metavar="PATH",
        help=argparse.SUPPRESS,
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

    tls_group = goose_parser.add_argument_group("TLS Options (MMS GoCB enumeration)")
    tls_group.add_argument(
        "--tls",
        action="store_true",
        help="Connect the MMS GoCB-enumeration session over TLS (default port "
        "3782). Certificate validation is DISABLED by default; supply --tls-ca "
        "or --tls-pin to enable it.",
    )
    tls_group.add_argument(
        "--tls-port",
        type=int,
        default=3782,
        metavar="PORT",
        help="TLS port used when --tls is set and --mms-port is the default (default: 3782)",
    )
    tls_group.add_argument(
        "--tls-ca",
        metavar="CA_CERT",
        help="CA certificate (PEM) to validate the server chain (enables validation)",
    )
    tls_group.add_argument(
        "--tls-pin",
        metavar="SERVER_CERT",
        help="Pin this exact server certificate (PEM); strict binding without a CA",
    )
    tls_group.add_argument(
        "--tls-client-cert",
        metavar="CERT",
        help="Client certificate (PEM) for mutual TLS",
    )
    tls_group.add_argument(
        "--tls-client-key",
        metavar="KEY",
        help="Client private key (PEM) for mutual TLS",
    )

    return goose_parser
