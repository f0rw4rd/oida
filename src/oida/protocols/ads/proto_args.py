"""
Argument parser definition for Beckhoff ADS protocol.

Migrated to proto_args_factory in §3 sync. ADS has 23+ argument groups
beyond network/target so the bulk of the file stays local; the factory
handles only the parser construction + standard target + standard
--port (48898 ADS-default).
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
)


def proto_args(parser, parents):
    """
    Register ADS-specific arguments

    Args:
        parser: argparse subparsers object
        parents: List of parent parsers to inherit from

    Returns:
        argparse.ArgumentParser: ADS protocol subparser
    """
    ads_parser = create_protocol_parser(
        parser,
        name="ads",
        help_text="Beckhoff ADS scanner",
        description="Scan and interact with Beckhoff TwinCAT/ADS devices",
        parents=parents,
    )

    # Target specification (positional)
    add_target_argument(ads_parser)

    # Network options — port 48898 is the ADS TCP listener.
    add_network_options(
        ads_parser, default_port=48898, include_timeout=False,
        port_help="ADS TCP port (default: 48898)",
    )

    # AMS/ADS Configuration
    ads_group = ads_parser.add_argument_group("ADS Options")

    ads_group.add_argument(
        "-n",
        "--netid-ext",
        type=str,
        metavar="EXT",
        help='AMS Net ID extension appended to target IP (e.g., "2.1" -> IP.2.1). Default: 1.1',
    )

    ads_group.add_argument(
        "--ams-netid",
        "--target-ams",
        type=str,
        metavar="NETID",
        help='Full AMS Net ID (e.g., "192.168.1.1.1.1"). Overrides --netid-ext.',
    )

    ads_group.add_argument(
        "-L",
        "--local-netid",
        type=str,
        metavar="NETID",
        help="Local AMS Net ID. Auto-configured if empty.",
    )

    ads_group.add_argument(
        "-T",
        "--port-type",
        choices=[
            "TC3PLC1",
            "TC3PLC2",
            "TC3PLC3",
            "TC3PLC4",  # TwinCAT 3 PLC runtimes
            "SPS1",
            "SPS2",
            "SPS3",
            "SPS4",  # TwinCAT 2 PLC runtimes
            "NC",
            "CNC",
            "NCSAF",  # Motion control
            "CUSTOMER1",
            "CUSTOMER2",  # Custom ports
        ],
        default="TC3PLC1",
        help="ADS runtime port type (default: TC3PLC1)",
    )

    ads_group.add_argument(
        "-P",
        "--ads-port",
        type=int,
        metavar="PORT",
        help="Explicit ADS port number (overrides --port-type). E.g., 851 for TC3PLC1.",
    )

    ads_group.add_argument(
        "--ads-timeout",
        type=int,
        default=500,
        metavar="MS",
        help="ADS operation timeout in milliseconds (default: 500)",
    )

    # Discovery options
    discovery_group = ads_parser.add_argument_group("Discovery Options")

    discovery_group.add_argument(
        "-i",
        "--device-info",
        action="store_true",
        help="Read device information (name, version, state)",
    )

    discovery_group.add_argument(
        "-l",
        "--list-symbols",
        action="store_true",
        help="List all PLC symbols (names and types only)",
    )

    discovery_group.add_argument(
        "-e",
        "--enumerate-symbols",
        action="store_true",
        help="Enumerate symbols with values (respects --max-symbols)",
    )

    discovery_group.add_argument(
        "--max-symbols",
        type=int,
        default=1000,
        metavar="N",
        help="Maximum symbols to enumerate (default: 1000)",
    )

    discovery_group.add_argument(
        "-r",
        "--scan-routes",
        action="store_true",
        help="Scan AMS routing table via SystemService",
    )

    discovery_group.add_argument(
        "-s",
        "--scan-ports",
        action="store_true",
        help="Scan common ADS ports (12 PLC runtime ports)",
    )

    discovery_group.add_argument(
        "-S",
        "--scan-ports-extended",
        action="store_true",
        help="Scan extended ADS ports (50+ ports including system services)",
    )

    discovery_group.add_argument(
        "--target-desc",
        action="store_true",
        help="Get XML device description via SystemService",
    )

    discovery_group.add_argument(
        "--check-secure",
        action="store_true",
        help="Check Secure ADS (TLS on port 8016) and analyze certificate",
    )

    discovery_group.add_argument(
        "--udp-discovery",
        action="store_true",
        help="Perform UDP broadcast discovery (port 48899) to find ADS devices",
    )

    discovery_group.add_argument(
        "--license-info",
        action="store_true",
        help="Query TwinCAT license information (SystemID, PlatformID, licenses)",
    )

    discovery_group.add_argument(
        "--io-devices",
        action="store_true",
        help="Enumerate I/O devices via IO port (EtherCAT masters, terminals)",
    )

    discovery_group.add_argument(
        "--task-info",
        action="store_true",
        help="Read PLC task runtime data (cycle times, priorities) via ig=0xF200",
    )

    discovery_group.add_argument(
        "--list-files",
        type=str,
        nargs="?",
        const="C:\\TwinCAT\\",
        metavar="PATH",
        help="List files via SystemService (default: C:\\TwinCAT\\)",
    )

    discovery_group.add_argument(
        "--read-file",
        type=str,
        metavar="PATH",
        help="Read file content from target (e.g., 'C:\\\\TwinCAT\\\\3.1\\\\Boot\\\\Plc\\\\Port_851.bootdata')",
    )

    discovery_group.add_argument(
        "--read-registry",
        type=str,
        metavar="HIVE:KEY[:VALUE]",
        help="Read registry (e.g., 'HKLM:SOFTWARE\\\\Beckhoff\\\\TwinCAT3')",
    )

    discovery_group.add_argument(
        "--download-program",
        action="store_true",
        help="Download PLC symbol table and datatypes",
    )

    discovery_group.add_argument(
        "--scan-ethercat",
        action="store_true",
        help="Scan EtherCAT master/slave configuration",
    )

    discovery_group.add_argument(
        "--scan-coe",
        action="store_true",
        help="Scan CoE object dictionary on EtherCAT slaves (via ADS bridge)",
    )

    discovery_group.add_argument(
        "--coe-range",
        type=str,
        metavar="RANGES",
        help=(
            "Custom CoE index ranges (overrides defaults). "
            "Comma-separated indices or ranges with 0x prefix. "
            "E.g., '0x2000-0x3000,0xF110,0x7000-0x7FFF'"
        ),
    )

    discovery_group.add_argument(
        "--read-coe",
        type=str,
        metavar="PORT:INDEX:SUB",
        help="Read CoE SDO object (e.g., '1003:0x1008:0' for Device Name on slave port 1003)",
    )

    discovery_group.add_argument(
        "--write-coe",
        type=str,
        metavar="PORT:INDEX:SUB:DATA",
        help="Write CoE SDO object (hex data, e.g., '1003:0xFB00:1:01020304'). Requires --confirm.",
    )

    discovery_group.add_argument(
        "--scan-coe-access",
        action="store_true",
        help="Scan CoE dictionary with access type detection (reads + write-back tests). Requires --confirm.",
    )

    discovery_group.add_argument(
        "--eeprom-dump",
        action="store_true",
        help="Dump raw EEPROM from EtherCAT slaves (via ADS master port)",
    )

    discovery_group.add_argument(
        "--esc-registers",
        action="store_true",
        help="Dump ESC registers from EtherCAT slaves (via ADS bridge)",
    )

    discovery_group.add_argument(
        "--foe-read",
        type=str,
        metavar="PORT:FILENAME",
        help="Read file from EtherCAT slave via FoE (e.g., '1001:firmware.bin')",
    )

    discovery_group.add_argument(
        "--scan-foe",
        action="store_true",
        help="Scan FoE (File over EtherCAT) support on all slaves, probe common filenames",
    )

    discovery_group.add_argument(
        "--foe-list",
        type=str,
        metavar="PORT",
        help="List accessible FoE files on a slave port (e.g., '1001')",
    )

    discovery_group.add_argument(
        "--scan-soe",
        action="store_true",
        help="Scan SoE (Servo-over-EtherCAT) IDNs on all slaves",
    )

    discovery_group.add_argument(
        "--read-soe",
        type=str,
        metavar="PORT:IDN[:DRIVE]",
        help="Read SoE IDN from slave (e.g., '1001:135' or '1001:135:0')",
    )

    discovery_group.add_argument(
        "--scan-fsoe",
        action="store_true",
        help="Scan FSoE (Functional Safety over EtherCAT) objects on all slaves (0xF1xx/0xF9xx)",
    )

    # Route manipulation (dangerous)
    route_group = ads_parser.add_argument_group("Route Manipulation (Dangerous)")

    route_group.add_argument(
        "--add-route",
        type=str,
        metavar="NETID:IP[:NAME]",
        help="Add AMS route (e.g., '192.168.1.50.1.1:192.168.1.50'). Requires --confirm.",
    )

    route_group.add_argument(
        "--foe-write",
        type=str,
        metavar="PORT:LOCAL_FILE:REMOTE_NAME",
        help="Write file to EtherCAT slave via FoE (e.g., '1001:fw.bin:firmware.bin'). Requires --confirm.",
    )

    route_group.add_argument(
        "--foe-delete",
        type=str,
        metavar="PORT:FILENAME",
        help="Delete file on EtherCAT slave via FoE (e.g., '1001:systrace'). Requires --confirm.",
    )

    # Symbol operations
    symbol_group = ads_parser.add_argument_group("Symbol Operations")

    symbol_group.add_argument(
        "--read-symbol",
        type=str,
        metavar="NAME",
        help="Read a specific symbol by name (e.g., 'MAIN.counter')",
    )

    symbol_group.add_argument(
        "--write-symbol",
        type=str,
        metavar="NAME:VALUE",
        help="Write value to symbol (e.g., 'MAIN.counter:42'). Requires --confirm.",
    )

    symbol_group.add_argument(
        "--symbol-filter",
        type=str,
        metavar="PATTERN",
        help="Filter symbols by name pattern (e.g., 'MAIN.*' or '*counter*')",
    )

    # Memory operations
    memory_group = ads_parser.add_argument_group("Memory Operations")

    memory_group.add_argument(
        "-R",
        "--memory-read",
        type=str,
        metavar="GROUP:OFFSET:SIZE",
        help="Read memory (e.g., '0x4020:0:4' for 4 bytes from M area offset 0)",
    )

    memory_group.add_argument(
        "-W",
        "--memory-write",
        type=str,
        metavar="GROUP:OFFSET:DATA",
        help="Write memory (hex data). Requires --confirm.",
    )

    memory_group.add_argument(
        "-m",
        "--test-memory",
        action="store_true",
        help="Test read access to common memory areas",
    )

    # State control
    state_group = ads_parser.add_argument_group("State Control")

    state_group.add_argument(
        "--state",
        action="store_true",
        help="Show current PLC state (Run/Stop/etc.)",
    )

    state_group.add_argument(
        "--set-state",
        choices=["RUN", "STOP", "RESET", "CONFIG", "RECONFIG"],
        metavar="STATE",
        help="Set PLC state (DANGEROUS). Requires --confirm.",
    )

    # Security testing / Fuzzing
    security_group = ads_parser.add_argument_group("Security Testing")

    security_group.add_argument(
        "--fuzz",
        nargs="?",
        const="symbols",
        choices=["symbols", "memory", "all"],
        metavar="MODE",
        help="Fuzz testing mode: symbols=writable symbols, memory=memory areas, all=both",
    )

    security_group.add_argument(
        "--fuzz-coe",
        action="store_true",
        help="Fuzz CoE SDO objects on EtherCAT slaves (via ADS bridge). Requires --confirm.",
    )

    security_group.add_argument(
        "--fuzz-symbol",
        type=str,
        metavar="NAME",
        help="Specific symbol to fuzz (e.g., 'MAIN.counter')",
    )

    security_group.add_argument(
        "--fuzz-iterations",
        type=int,
        default=10,
        metavar="N",
        help="Fuzz iterations per target (default: 10)",
    )

    security_group.add_argument(
        "--test-write",
        action="store_true",
        help="Test write access to symbols (safe: writes same value back)",
    )

    security_group.add_argument(
        "--force-write",
        action="store_true",
        help="Fuzz all readable objects, even if write-back test was rejected",
    )

    security_group.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (write/fuzz/state-change)",
    )

    # Monitoring
    monitor_group = ads_parser.add_argument_group("Monitoring")

    monitor_group.add_argument(
        "--watch",
        type=str,
        metavar="SYMBOL[:INTERVAL_MS]",
        help="Watch PLC symbol for changes (e.g., 'MAIN.counter' or 'MAIN.counter:500'). Ctrl+C to stop.",
    )

    return ads_parser


# Flags whose help text already says "Requires --confirm" or "DANGEROUS".
# validate_args() refuses any of these without --confirm so the safety
# annotation is actually enforced (the audit found these were advisory
# only, mirroring the dnp3 / ethercat bugs).  Map: argparse dest -> CLI form.
_CONFIRM_REQUIRED_FLAGS = {
    # --scan-coe was here previously but it's purely a read of the CoE
    # object dictionary — the help text says "Scan" and the code does
    # SDO uploads only. Gating it as DANGEROUS contradicted that
    # contract and broke the recon workflow.
    "write_coe": "--write-coe",
    "add_route": "--add-route",
    "foe_write": "--foe-write",
    "foe_delete": "--foe-delete",
    "write_symbol": "--write-symbol",
    "memory_write": "--memory-write",
    "set_state": "--set-state",
    "fuzz": "--fuzz",
    "fuzz_coe": "--fuzz-coe",
}


def validate_args(args) -> None:
    """Enforce --confirm on dangerous ADS operations.

    Raises:
        ConfigurationError: if any flag in ``_CONFIRM_REQUIRED_FLAGS`` was
            passed without ``--confirm``.

    Mirrors the dnp3 / ethercat pattern. All listed flags can disrupt a
    live PLC (state change, CoE writes, FoE file transfer, memory writes,
    fuzzing).  The help text on each flag already says "Requires --confirm";
    this turns that promise into a hard gate.
    """
    from ...utils.exceptions import ConfigurationError

    triggered = [cli for dest, cli in _CONFIRM_REQUIRED_FLAGS.items() if getattr(args, dest, None)]
    if triggered and not getattr(args, "confirm", False):
        ops = ", ".join(sorted(triggered))
        raise ConfigurationError(
            f"--confirm is required for dangerous ADS operations ({ops}). "
            "These flags can disrupt a live PLC (state change, CoE/symbol/"
            "memory writes, FoE file transfer, fuzzing). Re-run with --confirm "
            "to acknowledge.",
            protocol="ADS",
        )
