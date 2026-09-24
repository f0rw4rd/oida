"""
Protocol Argument Factory

This module provides shared argument group builders to eliminate duplicate
proto_args.py boilerplate across all protocol implementations.

Instead of manually recreating common argument patterns in every protocol's
proto_args.py file, use these factory functions to build consistent, reusable
argument groups.

Example usage:
    from oida.utils.proto_args_factory import (
        add_network_options,
        add_auth_options,
        add_output_options,
        add_dangerous_options,
        add_target_argument,
        create_protocol_parser,
        configure_from_args,
    )

    def proto_args(parser, parents):
        # Create parser with standard setup
        proto_parser = create_protocol_parser(
            parser,
            name="modbus",
            help_text="Modbus TCP/RTU scanner",
            description="Scan and interact with Modbus devices",
            parents=parents,
        )

        # Add target argument
        add_target_argument(proto_parser)

        # Add standard option groups
        network = add_network_options(proto_parser, default_port=502)
        auth = add_auth_options(proto_parser)
        output = add_output_options(proto_parser)
        dangerous = add_dangerous_options(proto_parser)

        # Customize further if needed
        network.add_argument("--tls", action="store_true", help="Use TLS")

        return proto_parser

    # After parsing:
    args = parser.parse_args()
    configure_from_args(args, logger=logger)  # configures exports globally
"""

import argparse
from typing import Optional

# Re-export from export_utils for convenience


def create_protocol_parser(
    subparsers,
    name: str,
    help_text: str,
    description: str,
    parents: Optional[list] = None,
    epilog: Optional[str] = None,
    formatter_class=None,
    aliases: Optional[list] = None,
):
    """
    Create a protocol subparser with standard setup.

    Args:
        subparsers: argparse subparsers object from add_subparsers()
        name: Protocol name (e.g., "modbus", "opcua")
        help_text: Short help text shown in protocol list
        description: Longer description shown in --help
        parents: Optional list of parent parsers to inherit from
        epilog: Optional epilog text with examples
        formatter_class: Optional formatter class (default: RawDescriptionHelpFormatter if epilog provided)

    Returns:
        argparse.ArgumentParser: The created protocol subparser

    Example:
        parser = create_protocol_parser(
            subparsers,
            name="modbus",
            help_text="Modbus TCP/RTU scanner",
            description="Scan and interact with Modbus devices",
            parents=parents,
        )
    """
    if parents is None:
        parents = []

    # Auto-select formatter if epilog is provided
    if formatter_class is None and epilog is not None:
        formatter_class = argparse.RawDescriptionHelpFormatter

    kwargs = {
        "help": help_text,
        "description": description,
        "parents": parents,
    }

    if epilog is not None:
        kwargs["epilog"] = epilog

    if formatter_class is not None:
        kwargs["formatter_class"] = formatter_class

    if aliases:
        kwargs["aliases"] = aliases

    return subparsers.add_parser(name, **kwargs)


def add_target_argument(
    parser,
    help_text: str = (
        "Target IP address, CIDR range, IP range, hostname, or file "
        "(any form may carry a port, e.g. 10.0.0.1:5020)"
    ),
):
    """
    Add standard target positional argument.

    Args:
        parser: argparse parser or subparser
        help_text: Help text for the target argument

    Returns:
        None (modifies parser in place)

    Example:
        add_target_argument(parser)
        add_target_argument(parser, help_text="Target OPC UA endpoint (e.g., opc.tcp://host:4840)")
    """
    parser.add_argument("target", help=help_text)


def add_network_options(
    parser,
    default_port: int = 502,
    include_timeout: bool = True,
    port_help: Optional[str] = None,
    default_timeout: int = 2,
    timeout_help: Optional[str] = None,
):
    """
    Add standard network options group.

    This creates a "Network Options" argument group with common network parameters
    like port and timeout.

    Args:
        parser: argparse parser or subparser
        default_port: Default port number for the protocol
        include_timeout: Whether to include --timeout argument
        port_help: Custom help text for --port (auto-generated if None)
        default_timeout: Default timeout in seconds (default: 2)
        timeout_help: Custom help text for --timeout (auto-generated if None)

    Returns:
        argparse._ArgumentGroup: The network options group for further customization

    Example:
        network = add_network_options(parser, default_port=502)
        network.add_argument("--tls", action="store_true", help="Use TLS encryption")
    """
    network_group = parser.add_argument_group("Network Options")

    if port_help is None:
        port_help = f"Target port (default: {default_port}; a port in the target wins)"

    network_group.add_argument("--port", "-p", type=int, default=default_port, help=port_help)

    if include_timeout:
        if timeout_help is None:
            timeout_help = f"Connection timeout in seconds (default: {default_timeout})"
        network_group.add_argument(
            "--timeout",
            type=int,
            default=default_timeout,
            metavar="SECS",
            help=timeout_help,
        )

    return network_group


def add_auth_options(
    parser,
    include_creds_file: bool = True,
    include_username: bool = True,
    include_password: bool = True,
    username_help: str = "Username for authentication",
    password_help: str = "Password for authentication",
):
    """
    Add authentication options group.

    This creates an "Authentication" or "Authentication Options" argument group
    with common authentication parameters.

    Args:
        parser: argparse parser or subparser
        include_creds_file: Whether to include --credentials file argument
        include_username: Whether to include --username argument
        include_password: Whether to include --password argument
        username_help: Custom help text for --username
        password_help: Custom help text for --password

    Returns:
        argparse._ArgumentGroup: The auth options group for further customization

    Example:
        auth = add_auth_options(parser)
        auth.add_argument("--certificate", help="Client certificate file")
    """
    auth_group = parser.add_argument_group("Authentication Options")

    if include_username:
        auth_group.add_argument("--username", "-u", type=str, help=username_help)

    if include_password:
        auth_group.add_argument("--password", "-P", type=str, help=password_help)

    if include_creds_file:
        auth_group.add_argument(
            "--credentials",
            type=str,
            metavar="FILE",
            help="Credentials file (format: username:password per line)",
        )

    return auth_group


def add_full_width_and_json_log(parser, include_short: bool = True):
    """Add the iec104-shared `--full-width` and `--json-log` flags.

    Extracted so protocols that can't call ``add_output_options()`` (e.g. iec104
    where ``-W`` collides with ``--write-single``) can still get the shared
    declarations.

    Args:
        parser: argparse parser, subparser, or argument group.
        include_short: Whether to register ``-W`` as a short alias for
            ``--full-width``. iec104 sets this False.
    """
    # NOTE: both flags are also declared on the main parser (cli.py), so they
    # may already be set in the namespace from the global (pre-protocol)
    # position. Use argparse.SUPPRESS as the default here so that *not* passing
    # them at the subparser level leaves the global value intact instead of
    # clobbering it back to the subparser default (None / False). Without this,
    # `oida --json-log FILE iec104 ...` silently disabled structured logging.
    fw_args = ["-W", "--full-width"] if include_short else ["--full-width"]
    parser.add_argument(
        *fw_args,
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show full-width tables without truncating to terminal width",
    )
    parser.add_argument(
        "--json-log",
        type=str,
        metavar="FILE",
        default=argparse.SUPPRESS,
        help="Write structured JSON log events to FILE (NDJSON format)",
    )


def add_output_options(
    parser,
    include_format: bool = True,
    include_verbose: bool = True,
    default_format: str = "csv,json",
    formats: Optional[list] = None,
):
    """
    Add output format options group.

    This creates an "Output Options" argument group with standard output
    formatting arguments including export directory, format, verbose, and debug.

    Args:
        parser: argparse parser or subparser
        include_format: Whether to include --format argument
        include_verbose: Whether to include --verbose and --debug arguments
        default_format: Default output format (default: "csv,json")
        formats: List of supported formats (default: None = free-form string)

    Returns:
        argparse._ArgumentGroup: The output options group for further customization

    Example:
        output = add_output_options(parser)
        # After parsing, call configure_from_args(args, logger) to set up exports
    """
    output_group = parser.add_argument_group("Output Options")

    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        help="Output directory for exported files (CSV/JSON)",
    )

    if include_format:
        if formats is None:
            # Free-form format string (csv, json, xml, or comma-separated)
            output_group.add_argument(
                "-f",
                "--format",
                type=str,
                metavar="FMT",
                default=default_format,
                help=f"Export format(s): csv, json, xml, or comma-separated (default: {default_format})",
            )
        else:
            # Restricted choices
            output_group.add_argument(
                "-f",
                "--format",
                choices=formats,
                default=default_format,
                help=f"Output format (default: {default_format})",
            )

    add_full_width_and_json_log(output_group, include_short=True)

    if include_verbose:
        output_group.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Verbose output",
        )
        output_group.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help="Debug output (implies verbose)",
        )

    return output_group


def add_dangerous_options(
    parser,
    include_fuzz: bool = True,
    include_write: bool = False,
    fuzz_default_iterations: int = 10,
    group_name: str | None = None,
    include_max_targets: bool = True,
):
    """
    Add active testing options group (fuzzing, write, control operations).

    Creates a "Fuzzing" or "Active Testing" argument group with options
    that require explicit confirmation via --confirm.

    Args:
        parser: argparse parser or subparser
        include_fuzz: Whether to include fuzzing-related arguments
        include_write: Whether to include write operation arguments
        fuzz_default_iterations: Default number of fuzz iterations
        group_name: Override the argument group name (default: auto-detect)
        include_max_targets: Whether to include --fuzz-max-targets. Protocols
            that fuzz a single fixed target (e.g. IEC 104 fuzzes one --fuzz-ioa)
            never read it, so they pass ``False`` rather than advertise a dead
            flag. Only meaningful when ``include_fuzz`` is True.

    Returns:
        argparse._ArgumentGroup: The options group for further customization

    Example:
        fuzz_group = add_dangerous_options(parser, include_fuzz=True)
        fuzz_group.add_argument("--cpu-stop", action="store_true", help="Stop CPU")
    """
    if group_name is None:
        group_name = "Fuzzing" if include_fuzz else "Active Testing"
    dangerous_group = parser.add_argument_group(group_name)

    dangerous_group.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (write, fuzz, control commands)",
    )

    if include_fuzz:
        dangerous_group.add_argument(
            "--fuzz",
            action="store_true",
            help="Enable fuzzing mode (requires --confirm)",
        )

        dangerous_group.add_argument(
            "--fuzz-iterations",
            type=int,
            default=fuzz_default_iterations,
            metavar="N",
            help=f"Number of fuzz iterations per target (default: {fuzz_default_iterations})",
        )

        if include_max_targets:
            dangerous_group.add_argument(
                "--fuzz-max-targets",
                type=int,
                default=10,
                metavar="N",
                help="Maximum number of targets to fuzz (default: 10)",
            )

    if include_write:
        dangerous_group.add_argument(
            "--write",
            action="store_true",
            help="Enable write operations (requires --confirm)",
        )

        dangerous_group.add_argument(
            "--test-write",
            action="store_true",
            help="Test write access safely (writes same value back)",
        )

    return dangerous_group


def add_scan_options(
    parser,
    include_threads: bool = True,
    include_delay: bool = True,
    include_retries: bool = True,
    default_threads: int = 10,
    default_delay: float = 0.0,
    default_retries: int = 3,
):
    """
    Add scan behavior options group.

    This creates a "Scan Options" or "Scan Behavior" argument group with
    parameters controlling scanning behavior.

    Args:
        parser: argparse parser or subparser
        include_threads: Whether to include --threads argument
        include_delay: Whether to include --delay argument
        include_retries: Whether to include --retries argument
        default_threads: Default number of threads
        default_delay: Default delay between requests
        default_retries: Default number of retries

    Returns:
        argparse._ArgumentGroup: The scan options group for further customization

    Example:
        scan = add_scan_options(parser)
        scan.add_argument("--quick", action="store_true", help="Quick scan mode")
    """
    scan_group = parser.add_argument_group("Scan Options")

    if include_threads:
        scan_group.add_argument(
            "-t",
            "--threads",
            type=int,
            default=default_threads,
            metavar="N",
            help=f"Number of concurrent threads (default: {default_threads})",
        )

    if include_delay:
        scan_group.add_argument(
            "--delay",
            type=float,
            default=default_delay,
            metavar="SECS",
            help=f"Delay between requests in seconds (default: {default_delay})",
        )

    if include_retries:
        scan_group.add_argument(
            "--retries",
            type=int,
            default=default_retries,
            metavar="N",
            help=f"Number of retries on failure (default: {default_retries})",
        )

    return scan_group


def add_discovery_options(
    parser,
    include_quick: bool = True,
    include_deep: bool = True,
    include_quick_mode: bool = True,
    include_deep_scan: bool = True,
):
    """
    Add discovery/enumeration options group.

    This creates a "Discovery Options" argument group with common discovery
    and enumeration parameters.

    A protocol that reads only some of these dests should switch the rest off
    rather than advertise a dead flag. ``include_quick``/``include_deep`` drop a
    whole pair; ``include_quick_mode``/``include_deep_scan`` drop just the
    ``--quick``/``--deep-scan`` half when the protocol still honours
    ``--discover``/``--full``.

    Args:
        parser: argparse parser or subparser
        include_quick: Whether to include the --discover/--quick pair
        include_deep: Whether to include the --full/--deep-scan pair
        include_quick_mode: Whether to include --quick (requires include_quick)
        include_deep_scan: Whether to include --deep-scan (requires include_deep)

    Returns:
        argparse._ArgumentGroup: The discovery options group for further customization

    Example:
        discovery = add_discovery_options(parser)
        discovery.add_argument("--enumerate-all", action="store_true")
    """
    discovery_group = parser.add_argument_group("Discovery Options")

    if include_quick:
        discovery_group.add_argument(
            "--discover",
            action="store_true",
            help="Quick discovery mode (device identification only)",
        )

        if include_quick_mode:
            discovery_group.add_argument(
                "--quick",
                action="store_true",
                help="Quick scan mode (basic enumeration)",
            )

    if include_deep:
        discovery_group.add_argument(
            "--full",
            action="store_true",
            help="Full scan mode (comprehensive enumeration)",
        )

        if include_deep_scan:
            discovery_group.add_argument(
                "--deep-scan",
                action="store_true",
                help="Deep scan mode (exhaustive enumeration, slower)",
            )

    return discovery_group


def add_monitor_options(
    parser,
    include_interval: bool = True,
    include_duration: bool = True,
    default_interval: float = 1.0,
    include_monitor: bool = True,
):
    """
    Add monitoring/continuous scan options group.

    This creates a "Monitoring" or "Monitor Mode" argument group for
    continuous monitoring functionality.

    Args:
        parser: argparse parser or subparser
        include_interval: Whether to include --interval argument
        include_duration: Whether to include --duration argument
        default_interval: Default polling interval in seconds
        include_monitor: Whether to include the --monitor toggle. Protocols whose
            continuous mode is driven by something else (e.g. OPC UA's
            ``--subscribe``) and never read ``--monitor`` should pass ``False``
            rather than advertise a flag that silently does a single read.

    Returns:
        argparse._ArgumentGroup: The monitor options group for further customization

    Example:
        monitor = add_monitor_options(parser)
        monitor.add_argument("--on-change", action="store_true")
    """
    monitor_group = parser.add_argument_group("Monitoring")

    if include_monitor:
        monitor_group.add_argument(
            "--monitor",
            action="store_true",
            help="Continuous monitoring mode (runs indefinitely)",
        )

    if include_interval:
        monitor_group.add_argument(
            "--interval",
            type=float,
            default=default_interval,
            metavar="SECS",
            help=f"Polling interval in seconds (default: {default_interval})",
        )

    if include_duration:
        monitor_group.add_argument(
            "--duration",
            type=int,
            metavar="SECS",
            help="Optional maximum monitoring duration in seconds (0 = infinite)",
        )

    return monitor_group


def add_serial_options(
    parser,
    include_port: bool = True,
    include_baudrate: bool = True,
    include_parity: bool = True,
    default_baudrate: int = 9600,
    default_parity: str = "N",
):
    """
    Add serial/RTU communication options group.

    This creates a "Serial Options" or "Serial/RTU Options" argument group
    for serial communication protocols.

    Args:
        parser: argparse parser or subparser
        include_port: Whether to include --serial-port argument
        include_baudrate: Whether to include --baudrate argument
        include_parity: Whether to include --parity argument
        default_baudrate: Default serial baudrate
        default_parity: Default parity setting (N, E, O)

    Returns:
        argparse._ArgumentGroup: The serial options group for further customization

    Example:
        serial = add_serial_options(parser)
        serial.add_argument("--stopbits", type=int, default=1)
    """
    serial_group = parser.add_argument_group("Serial/RTU Options")

    if include_port:
        serial_group.add_argument(
            "--serial-port",
            "-s",
            type=str,
            metavar="PORT",
            help="Serial port for communication (e.g., /dev/ttyUSB0, COM1)",
        )

    if include_baudrate:
        baudrate_help = (
            f"Serial baudrate (default: {default_baudrate}). "
            "Common: 4800, 9600, 19200, 38400, 57600, 115200"
        )
        serial_group.add_argument(
            "--baudrate",
            "-b",
            type=int,
            default=default_baudrate,
            help=baudrate_help,
        )

    if include_parity:
        serial_group.add_argument(
            "--parity",
            choices=["N", "E", "O"],
            default=default_parity,
            help=f"Serial parity: N=None, E=Even, O=Odd (default: {default_parity})",
        )

    return serial_group


def add_tls_options(
    parser,
    include_cert: bool = True,
    include_insecure: bool = True,
    include_tls_flag: bool = True,
    include_ca: bool = True,
    default_tls_port: Optional[int] = None,
):
    """
    Add TLS/SSL options group.

    Args:
        parser: argparse parser or subparser
        include_cert: Whether to include certificate arguments (--tls-cert, --tls-key)
        include_insecure: Whether to include --tls-insecure argument
        include_tls_flag: Whether to include --tls flag (skip for protocols where
            TLS is inferred from the URL scheme, e.g. wss://)
        include_ca: Whether to include --tls-ca argument
        default_tls_port: Optional port hint for help text

    Returns:
        argparse._ArgumentGroup: The TLS options group for further customization
    """
    tls_group = parser.add_argument_group("TLS/SSL Options")

    if include_tls_flag:
        tls_help = "Enable TLS encryption"
        if default_tls_port:
            tls_help += f" (changes default port to {default_tls_port})"
        tls_group.add_argument("--tls", action="store_true", help=tls_help)

    if include_cert:
        tls_group.add_argument(
            "--tls-cert",
            type=str,
            metavar="FILE",
            help="Client certificate file for mutual TLS",
        )

        tls_group.add_argument(
            "--tls-key",
            type=str,
            metavar="FILE",
            help="Client private key file for mutual TLS",
        )

    if include_ca:
        tls_group.add_argument(
            "--tls-ca",
            type=str,
            metavar="FILE",
            help="CA certificate file for server verification",
        )

    if include_insecure:
        tls_group.add_argument(
            "--tls-insecure",
            action="store_true",
            help="Skip TLS certificate verification",
        )

    return tls_group


def add_file_transfer_options(
    parser,
    include_read: bool = True,
    include_write: bool = True,
    include_list: bool = True,
):
    """
    Add file transfer options group.

    Args:
        parser: argparse parser or subparser
        include_read: Whether to include --read-file argument
        include_write: Whether to include --write-file argument
        include_list: Whether to include --list-files argument

    Returns:
        argparse._ArgumentGroup: The file transfer options group
    """
    file_group = parser.add_argument_group("File Transfer")

    if include_list:
        file_group.add_argument(
            "--list-files",
            type=str,
            nargs="?",
            const=".",
            metavar="PATH",
            help="List files in directory (default: root)",
        )

    if include_read:
        file_group.add_argument(
            "--read-file",
            type=str,
            metavar="PATH",
            help="Read/download file from device",
        )

    if include_write:
        file_group.add_argument(
            "--write-file",
            type=str,
            metavar="PATH",
            help="Write/upload file to device (requires --confirm)",
        )

    file_group.add_argument(
        "--file-output",
        type=str,
        metavar="PATH",
        help="Output path for downloaded file",
    )

    return file_group


def add_listen_options(
    parser,
    include_duration: bool = True,
    include_output: bool = True,
    include_filter: bool = True,
    default_duration: int = 60,
):
    """
    Add passive listen/capture options group.

    Args:
        parser: argparse parser or subparser
        include_duration: Whether to include --listen-time argument
        include_output: Whether to include --listen-output argument
        include_filter: Whether to include --listen-filter argument
        default_duration: Default listen duration in seconds

    Returns:
        argparse._ArgumentGroup: The listen options group
    """
    listen_group = parser.add_argument_group("Listen Mode")

    listen_group.add_argument(
        "--listen",
        "-L",
        action="store_true",
        help="Enable passive listen mode - capture spontaneous messages",
    )

    if include_duration:
        listen_group.add_argument(
            "--listen-time",
            "-T",
            type=int,
            default=default_duration,
            metavar="SECS",
            help=f"Listen duration in seconds (default: {default_duration}, 0=infinite)",
        )

    if include_output:
        listen_group.add_argument(
            "--listen-output",
            "-O",
            type=str,
            metavar="FILE",
            help="Output file for captured messages (JSONL format)",
        )

    if include_filter:
        listen_group.add_argument(
            "--listen-filter",
            "-F",
            type=str,
            metavar="FILTER",
            help="Filter expression for captured messages",
        )

    return listen_group


def add_brute_options(
    parser,
    include_wordlist: bool = True,
    include_rate: bool = True,
    default_rate: float = 1.0,
    include_brute: bool = True,
    include_default_creds: bool = True,
):
    """
    Add credential brute-force options group.

    Args:
        parser: argparse parser or subparser
        include_wordlist: Whether to include --wordlist argument
        include_rate: Whether to include rate limiting argument
        default_rate: Default attempts per second
        include_brute: Whether to include the --brute toggle. Protocols whose
            brute-force is driven by file inputs (e.g. OPC UA's
            ``--username FILE``/``--password FILE``) and never read ``--brute``
            should pass ``False`` so the flag isn't advertised as a dead option.
        include_default_creds: Whether to include --default-creds. Protocols that
            ship no built-in credential list to spray should pass ``False``
            rather than advertise a flag that silently changes nothing.

    Returns:
        argparse._ArgumentGroup: The brute-force options group
    """
    brute_group = parser.add_argument_group("Credential Testing")

    if include_brute:
        brute_group.add_argument(
            "--brute",
            action="store_true",
            help="Enable credential brute-force",
        )

    if include_default_creds:
        brute_group.add_argument(
            "--default-creds",
            action="store_true",
            help="Test built-in default credentials for this protocol",
        )

    if include_wordlist:
        brute_group.add_argument(
            "--wordlist",
            type=str,
            metavar="FILE",
            help="Password wordlist file (one per line)",
        )

    if include_rate:
        brute_group.add_argument(
            "--brute-rate",
            type=float,
            default=default_rate,
            metavar="SECS",
            help=f"Delay between auth attempts (default: {default_rate}s)",
        )

    brute_group.add_argument(
        "--continue-on-success",
        action="store_true",
        default=False,
        help="Keep testing credentials after the first valid hit (default: stop on first success)",
    )

    return brute_group


def add_control_options(parser, confirm_required: bool = True):
    """
    Add control/command options group for ICS protocols.

    Args:
        parser: argparse parser or subparser
        confirm_required: Whether to note that --confirm is required

    Returns:
        argparse._ArgumentGroup: The control options group
    """
    control_group = parser.add_argument_group("Control Operations")

    confirm_note = " (requires --confirm)" if confirm_required else ""

    control_group.add_argument(
        "--cpu-start",
        action="store_true",
        help=f"Start CPU/PLC execution{confirm_note}",
    )

    control_group.add_argument(
        "--cpu-stop",
        action="store_true",
        help=f"Stop CPU/PLC execution{confirm_note}",
    )

    return control_group
