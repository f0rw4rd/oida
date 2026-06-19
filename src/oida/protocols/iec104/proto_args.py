"""
Argument parser definition for IEC 60870-5-104 protocol

This module registers IEC 104-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_dangerous_options,
    add_listen_options,
    add_tls_options,
    add_full_width_and_json_log,
)


def proto_args(parser, parents):
    """Register IEC 104-specific arguments"""
    iec104_parser = create_protocol_parser(
        parser,
        name="iec104",
        help_text="IEC 60870-5-104 scanner",
        description="Scan and interact with IEC 104 devices (also supports IEC 101 serial)",
        parents=parents,
        epilog="""
Examples:
  oida iec104 192.168.1.100                       # Basic discovery (TESTFR only)
  oida iec104 192.168.1.100 --interrogate         # General interrogation
  oida iec104 192.168.1.100 --probe-files         # Detect file-transfer capability
  oida iec104 192.168.1.100 --listen -T 120       # Passive listen for 2 minutes
  oida iec104 192.168.1.100 -S                    # Station scan (common address 1-254)
  oida iec104 192.168.1.100 -S 1-10               # Station scan (range)
  oida iec104 192.168.1.100 -W 100:on --confirm   # Write single command (requires --confirm)
  oida iec104 --iec101 /dev/ttyUSB0:9600:E:1      # IEC 101 serial mode
""",
    )

    # Target (positional)
    add_target_argument(iec104_parser)

    # Network Options (--port, --timeout)
    add_network_options(iec104_parser, default_port=2404)

    # TLS Options (--tls, --tls-cert, --tls-key)
    tls_group = add_tls_options(
        iec104_parser, default_tls_port=19998, include_cert=False, include_insecure=False
    )
    tls_group.add_argument(
        "--tls-cert", type=str, metavar="FILE", help="Client certificate file for mutual TLS"
    )
    tls_group.add_argument(
        "--tls-key", type=str, metavar="FILE", help="Client private key file for mutual TLS"
    )

    # IEC 101 Serial Mode
    serial_group = iec104_parser.add_argument_group("IEC 101 Serial Mode")
    serial_group.add_argument(
        "--iec101",
        type=str,
        metavar="PORT:BAUD:PARITY:STOP",
        help="Enable IEC 101 serial mode. Format: /dev/ttyUSB0:9600:E:1",
    )
    serial_group.add_argument(
        "--list-ports",
        action="store_true",
        help="List available serial ports and exit",
    )
    serial_group.add_argument(
        "--link-address",
        type=int,
        default=1,
        help="IEC 101 link layer address (default: 1)",
    )
    serial_group.add_argument(
        "--balanced",
        action="store_true",
        help="Use balanced transmission mode (default: unbalanced)",
    )

    # Scan Phase Flags
    phase_group = iec104_parser.add_argument_group("Scan Phase Flags")
    phase_group.add_argument(
        "-I",
        "--interrogate",
        action="store_true",
        help="Run general interrogation (GI) to discover data points",
    )
    phase_group.add_argument(
        "-G",
        "--interrogate-groups",
        action="store_true",
        help="Run group interrogation (groups 1-16) to map point-to-group layout",
    )
    phase_group.add_argument(
        "-S",
        "--station-scan",
        type=str,
        nargs="?",
        const="1-254",
        default=None,
        metavar="START-END",
        help="Scan for active Common Addresses. Optional range (default: 1-254)",
    )
    # IEC 104 Options
    iec104_group = iec104_parser.add_argument_group("IEC 104 Options")
    iec104_group.add_argument(
        "-a",
        "--asdu-address",
        type=int,
        default=-1,
        help="ASDU address (default: -1 = auto-discover the Common Address)",
    )
    iec104_group.add_argument("-c", "--common-address", type=int, help="Common address of ASDU")
    iec104_group.add_argument(
        "-w",
        "--wait-time",
        type=int,
        default=3,
        help="Time to wait for interrogation responses in seconds (default: 3)",
    )
    iec104_group.add_argument(
        "-X",
        "--probe-custom-types",
        action="store_true",
        help="Probe for custom/vendor-specific Type IDs (128-255)",
    )
    iec104_group.add_argument(
        "--t1",
        type=int,
        metavar="SECONDS",
        help="APCI message ack timeout in seconds (default: 15)",
    )
    iec104_group.add_argument(
        "--t3",
        type=int,
        metavar="SECONDS",
        help="APCI keepalive/test interval in seconds (default: 20)",
    )
    iec104_group.add_argument(
        "--originator",
        type=int,
        metavar="ADDR",
        help="Originator address (0-255) to identify this client in device logs",
    )
    # File Transfer capability detection (Type IDs 120-127). c104 exposes no
    # high-level file-transfer API, so only capability detection is supported —
    # not the actual F_* ASDU download/upload/delete/log exchange.
    file_group = iec104_parser.add_argument_group("File Transfer")
    file_group.add_argument(
        "--probe-files",
        action="store_true",
        help="Detect file-transfer capability (reports Type IDs 120-127)",
    )

    # Read Operations
    read_group = iec104_parser.add_argument_group("Read Operations")
    read_group.add_argument(
        "-R",
        "--read-ioa",
        type=str,
        metavar="IOA[,IOA,...]",
        help="Read specific IOA(s) via C_RD_NA_1 (Type 102), comma-separated",
    )
    read_group.add_argument(
        "-C",
        "--counter-interrogation",
        action="store_true",
        help="Send counter interrogation (Type 101) to read integrated totals",
    )
    read_group.add_argument(
        "-K",
        "--clock-read",
        action="store_true",
        help="Read device clock via clock sync command (Type 103)",
    )

    # Write Operations
    write_group = iec104_parser.add_argument_group("Write Operations")
    write_group.add_argument(
        "-W",
        "--write-single",
        type=str,
        metavar="IOA[:VALUE]",
        help="Write single command to IOA (Type 45). Values: on/off/1/0",
    )
    write_group.add_argument(
        "--write-double",
        type=str,
        metavar="IOA[:VALUE]",
        help="Write double command to IOA (Type 46). Values: on/off/intermediate",
    )
    write_group.add_argument(
        "--write-float",
        type=str,
        metavar="IOA[:VALUE]",
        help="Write float setpoint to IOA (Type 50). Value: float",
    )
    write_group.add_argument(
        "--write-scaled",
        type=str,
        metavar="IOA[:VALUE]",
        help="Write scaled integer setpoint to IOA (Type 49). Value: int16",
    )
    write_group.add_argument(
        "--write-normalized",
        type=str,
        metavar="IOA[:VALUE]",
        help="Write normalized value to IOA (Type 48). Value: -1.0 to 1.0",
    )
    write_group.add_argument(
        "--write-step",
        type=str,
        metavar="IOA[:VALUE]",
        help="Write step command to IOA (Type 47). Values: up/down",
    )
    write_group.add_argument(
        "-V",
        "--value",
        type=str,
        metavar="VALUE",
        help="Value to write: on/off for single, float for setpoints, up/down for step",
    )
    write_group.add_argument(
        "--select-execute",
        action="store_true",
        help="Use select-before-execute mode instead of direct command",
    )
    write_group.add_argument(
        "--write-type",
        type=int,
        metavar="TYPE_ID",
        help="Write using custom type ID (e.g., 45, 50, or 128-255 for vendor types)",
    )
    write_group.add_argument(
        "--write-ioa",
        type=int,
        metavar="IOA",
        help="Target IOA for --write-type",
    )
    write_group.add_argument(
        "--reset-process",
        action="store_true",
        help="[experimental] Send C_RP_NA_1 (Type 105) reset process command — requires --confirm",
    )
    write_group.add_argument(
        "--param-normalized",
        type=str,
        metavar="IOA[:VALUE]",
        help="[experimental] Write normalized parameter (Type 110, P_ME_NA_1). Value: -1.0 to 1.0",
    )
    write_group.add_argument(
        "--param-scaled",
        type=str,
        metavar="IOA[:VALUE]",
        help="[experimental] Write scaled parameter (Type 111, P_ME_NB_1). Value: int16",
    )
    write_group.add_argument(
        "--param-float",
        type=str,
        metavar="IOA[:VALUE]",
        help="[experimental] Write float parameter (Type 112, P_ME_NC_1). Value: float",
    )
    write_group.add_argument(
        "--param-activate",
        type=str,
        metavar="IOA[:VALUE]",
        help="[experimental] Activate parameter set (Type 113, P_AC_NA_1). Value: 1=act, 2=deact, 3=both",
    )

    # Output Options (--full-width, --json-log only — -o/-f/-v/-d come from main parser)
    # Cannot use add_output_options() because -W is already taken by --write-single,
    # so we use the lower-level helper that skips the -W short alias.
    output_group = iec104_parser.add_argument_group("Output Options")
    add_full_width_and_json_log(output_group, include_short=False)

    # Listen Mode (--listen, --listen-time, --listen-output, --listen-filter)
    listen_group = add_listen_options(iec104_parser)
    listen_group.add_argument(
        "--listen-raw",
        action="store_true",
        help="Include raw hex bytes in output",
    )

    # Fuzzing & dangerous operations (--confirm, --fuzz, --fuzz-iterations)
    fuzz_group = add_dangerous_options(iec104_parser, include_fuzz=True, fuzz_default_iterations=20)
    fuzz_group.add_argument(
        "--test-commands",
        action="store_true",
        help="Test control-command acceptance at --test-command-ioa "
        "(C_SC/C_DC) — requires --confirm",
    )
    fuzz_group.add_argument(
        "--test-command-ioa",
        type=int,
        default=None,
        metavar="IOA",
        help="Target IOA for --test-commands (default: --write-single's IOA)",
    )
    fuzz_group.add_argument(
        "--fuzz-ioa",
        type=int,
        default=1,
        metavar="IOA",
        help="Target IOA for fuzzing (default: 1)",
    )

    return iec104_parser
