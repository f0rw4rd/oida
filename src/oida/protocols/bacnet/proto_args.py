"""
BACnet protocol CLI arguments (simplified)

Examples:
    oida bacnet 192.168.1.0/24              # Discover devices
    oida bacnet 192.168.1.100               # Identify device
    oida bacnet 192.168.1.100 -e            # Enumerate objects
    oida bacnet 192.168.1.100 --assess      # Security assessment
    oida bacnet 192.168.1.100 -r AI:1:pv    # Read property
"""

from argparse import SUPPRESS

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
)


def proto_args(parser, parents):
    """Register BACnet-specific arguments"""
    examples = """
Examples:
  oida bacnet 192.168.1.0/24                  # Discover all devices
  oida bacnet 192.168.1.100                   # Identify single device
  oida bacnet 192.168.1.100 -e                # Enumerate all objects
  oida bacnet 192.168.1.100 -e --values       # Enumerate with values
  oida bacnet 192.168.1.100 --assess          # Full security assessment
  oida bacnet 192.168.1.100 --dump -o backup  # Export device state
  oida bacnet 192.168.1.100 -r AI:1:pv        # Read analogInput:1:presentValue
  oida bacnet 192.168.1.100 --monitor         # Live value monitoring
"""

    p = create_protocol_parser(
        parser,
        name="bacnet",
        help_text="BACnet building automation scanner (port 47808)",
        description="Scan BACnet/IP building automation systems",
        parents=parents,
        epilog=examples,
    )

    # Target (positional)
    add_target_argument(p, help_text="Target IP, CIDR, or broadcast")

    # Network Options (--port, --timeout)
    add_network_options(p, default_port=47808)

    # BACnet-specific options
    bacnet_group = p.add_argument_group("BACnet Options")
    bacnet_group.add_argument(
        "--device-id",
        type=int,
        metavar="ID",
        help="Target specific device instance ID",
    )

    # Actions
    actions = p.add_argument_group("Actions")
    actions.add_argument(
        "-e",
        "--enum",
        action="store_true",
        dest="enumerate_objects",
        help="Enumerate all objects on device",
    )
    actions.add_argument(
        "--values",
        action="store_true",
        dest="present_value",
        help="Read present values (use with -e)",
    )
    actions.add_argument(
        "-r",
        "--read",
        type=str,
        metavar="SPEC",
        help="Read property (e.g., 'AI:1:pv' or 'analogInput:1:presentValue')",
    )
    actions.add_argument(
        "-w",
        "--write",
        type=str,
        metavar="SPEC",
        help="Write property (e.g., 'AV:1:pv:72.5') - requires --confirm",
    )
    actions.add_argument(
        "--dump",
        action="store_true",
        help="Export full device state to file",
    )
    actions.add_argument(
        "--diff",
        type=str,
        metavar="FILE",
        help="Compare current state against baseline file",
    )
    actions.add_argument(
        "--monitor",
        action="store_true",
        help="Continuous value monitoring",
    )
    actions.add_argument(
        "--interval",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Monitor interval (default: 1.0s)",
    )

    # Network Discovery
    network = p.add_argument_group("Network Discovery")
    network.add_argument(
        "--networks",
        action="store_true",
        help="Discover remote networks behind routers",
    )
    network.add_argument(
        "--scan-network",
        type=int,
        metavar="N",
        help="Scan specific remote network number for devices",
    )
    network.add_argument(
        "--scan-all-networks",
        action="store_true",
        help="Scan all discovered remote networks for devices",
    )

    # Security
    security = p.add_argument_group("Security")
    security.add_argument(
        "--assess",
        action="store_true",
        help="Full security assessment (access, config, encryption)",
    )
    security.add_argument(
        "--brute-force",
        action="store_true",
        help="Test common passwords for DCC/ReinitializeDevice",
    )
    security.add_argument(
        "--passwords",
        type=str,
        metavar="FILE",
        dest="password_list",
        help="Custom password wordlist",
    )
    security.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (writes, tests)",
    )

    # Hidden/advanced options (still functional but not shown in basic help)
    # These are used internally by shortcuts and for backward compatibility
    p.add_argument("--who-is", action="store_true", help=SUPPRESS)
    p.add_argument("--identify", "-i", action="store_true", help=SUPPRESS)
    p.add_argument("--services", action="store_true", help=SUPPRESS)
    p.add_argument("--files", action="store_true", help=SUPPRESS)
    p.add_argument("--check-anonymous", action="store_true", help=SUPPRESS)
    p.add_argument("--check-schedules", action="store_true", help=SUPPRESS)
    p.add_argument("--check-calendars", action="store_true", help=SUPPRESS)
    p.add_argument("--check-alarms", action="store_true", help=SUPPRESS)
    p.add_argument("--check-trendlogs", action="store_true", help=SUPPRESS)
    p.add_argument("--check-priority", action="store_true", help=SUPPRESS)
    p.add_argument("--check-bacnet-sc", action="store_true", help=SUPPRESS)
    p.add_argument("--enum-life-safety", action="store_true", help=SUPPRESS)
    p.add_argument("--enum-bbmd", action="store_true", help=SUPPRESS)
    p.add_argument("--enum-fdt", action="store_true", help=SUPPRESS)
    p.add_argument("--enum-routers", action="store_true", help=SUPPRESS)
    p.add_argument("--who-has", type=str, help=SUPPRESS)
    p.add_argument("--test-dcc", action="store_true", help=SUPPRESS)
    p.add_argument("--test-reinit-pass", action="store_true", help=SUPPRESS)
    p.add_argument("--password", type=str, help=SUPPRESS)
    p.add_argument("--check-reinit", action="store_true", help=SUPPRESS)
    p.add_argument("--check-oos", action="store_true", help=SUPPRESS)
    p.add_argument("--check-life-safety", action="store_true", help=SUPPRESS)
    p.add_argument("--enumerate-writable", action="store_true", help=SUPPRESS)
    p.add_argument("--enumerate-properties", action="store_true", help=SUPPRESS)
    p.add_argument("--read-file", type=int, help=SUPPRESS)
    p.add_argument("--priority", type=int, help=SUPPRESS)
    p.add_argument("--cov", action="store_true", help=SUPPRESS)
    p.add_argument("--control-points", action="store_true", help=SUPPRESS)
    p.add_argument("--values-only", action="store_true", help=SUPPRESS)
    p.add_argument("--full-properties", action="store_true", help=SUPPRESS)
    # Six dispatcher-read flags were absent from proto_args, so passing
    # them on the CLI raised 'unrecognized arguments' and the only way to
    # exercise the code paths was to monkey-patch args in tests.
    p.add_argument(
        "--file-access-method", choices=["stream", "record"], default="stream", help=SUPPRESS
    )
    p.add_argument("--file-chunk-size", type=int, default=1024, help=SUPPRESS)
    p.add_argument("--cov-lifetime", type=int, default=300, help=SUPPRESS)
    p.add_argument("--cov-duration", type=int, default=30, help=SUPPRESS)
    p.add_argument("--read-range-count", type=int, default=50, help=SUPPRESS)
    # --output / --format are declared on the MAIN parser (cli.py); the
    # state.py mixin reads them via the shared Namespace. We don't
    # re-declare them here — the test_no_duplicate_output_verbose_flags
    # contract enforces single-source-of-truth.
    # --use-bac0: opt-in back-compat for the BAC0 broadcast path. The
    # default is now bacpypes3 for every target (see CODE_REVIEW.md HIGH:
    # The BAC0/bacpypes3 dispatch had a 172.0.0.0/8 routing bug and
    # asymmetric feature coverage). Operators with BAC0-tuned workflows
    # opt back in here; new users get the consistent bacpypes3 path.
    p.add_argument("--use-bac0", action="store_true", help=SUPPRESS)
    p.add_argument("--object-types", type=str, help=SUPPRESS)
    p.add_argument("--object-type", type=str, help=SUPPRESS)
    p.add_argument("--max-objects", type=int, default=1000, help=SUPPRESS)
    p.add_argument("--vendor-info", action="store_true", help=SUPPRESS)
    p.add_argument("--test-write", action="store_true", help=SUPPRESS)
    p.add_argument("--bbmd", type=str, help=SUPPRESS)
    p.add_argument("--interface", type=str, help=SUPPRESS)
    p.add_argument("--device-range", type=str, help=SUPPRESS)
    p.add_argument("--retries", type=int, default=1, help=SUPPRESS)
    p.add_argument("--enum-networks", action="store_true", help=SUPPRESS)
    p.add_argument("--assess-network", action="store_true", help=SUPPRESS)
    p.add_argument("--assess-access", action="store_true", help=SUPPRESS)
    p.add_argument("--assess-config", action="store_true", help=SUPPRESS)
    p.add_argument("--assess-info", action="store_true", help=SUPPRESS)
    p.add_argument("--quick", action="store_true", help=SUPPRESS)
    p.add_argument("--discover", action="store_true", help=SUPPRESS)
    p.add_argument("--full", action="store_true", help=SUPPRESS)
    p.add_argument("--safe", action="store_true", help=SUPPRESS)
    p.add_argument("--rpm", action="store_true", help=SUPPRESS)
    p.add_argument("--deep-enum", action="store_true", help=SUPPRESS)
    p.add_argument("--enum-programs", action="store_true", help=SUPPRESS)
    p.add_argument("--enum-loops", action="store_true", help=SUPPRESS)
    p.add_argument("--vendor-scan", action="store_true", help=SUPPRESS)
    p.add_argument("--discover-mstp", action="store_true", help=SUPPRESS)
    p.add_argument("--read-range", action="store_true", help=SUPPRESS)
    p.add_argument("--test-priority-writes", action="store_true", help=SUPPRESS)
    p.add_argument("--test-time-sync", action="store_true", help=SUPPRESS)
    p.add_argument("--test-oos", action="store_true", help=SUPPRESS)
    p.add_argument("--test-bbmd-injection", action="store_true", help=SUPPRESS)

    return p
