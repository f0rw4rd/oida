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
    add_file_transfer_options,
    add_tls_options,
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
  oida iec104 192.168.1.100                  # Basic discovery (TESTFR only)
  oida iec104 192.168.1.100 --interrogate    # General interrogation
  oida iec104 192.168.1.100 --probe-files     # Probe file transfer capability
  oida iec104 192.168.1.100 --listen -T 120  # Listen for 2 minutes
  oida iec104 192.168.1.100 --list-files     # Probe file transfer
  oida iec104 192.168.1.100 -S                    # Station scan (CA 1-254)
  oida iec104 192.168.1.100 -S 1-10               # Station scan (CA 1-10)
  oida iec104 192.168.1.100 -W 100:on --confirm
  oida iec104 --iec101 /dev/ttyUSB0:9600:E:1 # IEC 101 serial mode
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
        "-a", "--asdu-address", type=int, default=1, help="ASDU address (default: 1)"
    )
    iec104_group.add_argument(
        "-r", "--ioa-range", type=str, help='Information Object Address range (e.g., "0-1000")'
    )
    iec104_group.add_argument("-c", "--common-address", type=int, help="Common address of ASDU")
    iec104_group.add_argument(
        "--max-commands",
        type=int,
        default=100,
        help="Maximum number of commands to test (default: 100)",
    )
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
    # File Transfer (--list-files, --read-file, --write-file, --file-output)
    file_group = add_file_transfer_options(iec104_parser, include_write=False)
    file_group.add_argument(
        "--probe-files",
        action="store_true",
        help="Probe for file transfer capability (Type IDs 120-127)",
    )
    file_group.add_argument(
        "-D",
        "--download-file",
        type=int,
        metavar="IOA",
        help="Download file by IOA using c104 (Type 120-125)",
    )
    file_group.add_argument(
        "--delete-file",
        type=int,
        metavar="IOA",
        help="Delete file by IOA (Type 122, SCQ=4) - requires --confirm",
    )
    file_group.add_argument(
        "--upload-file",
        type=str,
        metavar="PATH",
        help="Local file to upload to device - requires --confirm",
    )
    file_group.add_argument(
        "--upload-ioa",
        type=int,
        metavar="IOA",
        help="Target IOA for upload",
    )
    file_group.add_argument(
        "--upload-nof",
        type=int,
        default=1,
        choices=[1, 2],
        help="File type: 1=transparent (default), 2=disturbance recording",
    )
    file_group.add_argument(
        "--query-log",
        type=int,
        metavar="IOA",
        help="Query archive log by IOA (Type 127)",
    )
    file_group.add_argument(
        "--log-start",
        type=str,
        metavar="TIME",
        help="Log query start time (ISO format or 'now-1h')",
    )
    file_group.add_argument(
        "--log-end",
        type=str,
        metavar="TIME",
        help="Log query end time (ISO format or 'now')",
    )
    file_group.add_argument(
        "--log-type",
        type=int,
        default=2,
        choices=[1, 2, 3, 4],
        help="Log type: 1=transparent, 2=disturbance (default), 3=events, 4=analogue",
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
    # so we add only the iec104-specific extras here.
    output_group = iec104_parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--full-width",
        action="store_true",
        default=False,
        help="Show full-width tables without truncating to terminal width",
    )
    output_group.add_argument(
        "--json-log",
        type=str,
        metavar="FILE",
        help="Write structured JSON log events to FILE (NDJSON format)",
    )

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
        help="Test command execution (write operations) — requires --confirm",
    )
    fuzz_group.add_argument(
        "--fuzz-ioa",
        type=int,
        default=1,
        metavar="IOA",
        help="Target IOA for fuzzing (default: 1)",
    )

    return iec104_parser
