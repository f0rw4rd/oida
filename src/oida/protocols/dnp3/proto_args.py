"""
Argument parser definition for DNP3 protocol

This module registers DNP3-specific command-line arguments
for the yadnp3 (opendnp3) backend.
"""

import re
from datetime import datetime, timezone

from oida.utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_dangerous_options,
)
from oida.utils.exceptions import ConfigurationError


def proto_args(parser, parents):
    """Register DNP3-specific arguments"""
    dnp3_parser = create_protocol_parser(
        parser,
        name="dnp3",
        help_text="DNP3 SCADA protocol scanner",
        description="Scan and interact with DNP3 outstations using yadnp3 (opendnp3)",
        parents=parents,
        epilog="""
Examples:
  oida dnp3 192.168.1.100                              # Basic discovery + integrity poll
  oida dnp3 192.168.1.100 -r 1-100                     # Scan for outstations in range
  oida dnp3 192.168.1.100 -a                           # Dump device attributes (Group 0)
  oida dnp3 192.168.1.100 -e                           # Enumerate all data points
  oida dnp3 192.168.1.100 -o 10 --bo-direct 0 --confirm        # Direct Operate on BO
  oida dnp3 192.168.1.100 -o 10 -l /                   # List directory on outstation 10
  oida dnp3 192.168.1.100 -o 10 -R /config.txt         # Read file from outstation
  oida dnp3 192.168.1.100 -o 10 -D /old.txt --confirm  # Delete file
  oida dnp3 192.168.1.100 -o 10 -F --confirm           # Freeze counters
  oida dnp3 192.168.1.100 -o 10 -C -N --confirm        # Freeze+clear, no ack (stealth)
  oida dnp3 192.168.1.100 -o 10 -K --confirm           # Stop/kill application (DoS)
  oida dnp3 192.168.1.100 -o 10 -S --confirm           # Start application
  oida dnp3 192.168.1.100 -d                           # Measure delay
  oida dnp3 192.168.1.100 --cold-restart -o 10 --confirm
  oida dnp3 192.168.1.100 --record-time -o 10          # Record current time
  oida dnp3 192.168.1.100 --assign-class 1:0-9:1 -o 10 --confirm  # Assign BI 0-9 to Class 1
  oida dnp3 192.168.1.100 --read-octet 110:0-4 -o 10   # Read octet strings
  oida dnp3 192.168.1.100 --transport serial --serial-device /dev/ttyUSB0  # Serial transport
  oida dnp3 192.168.1.100 --sa --sa-user 1 --sa-key 0123...  # Secure Authentication v5
  oida dnp3 192.168.1.100 --security-stats -o 10       # Read security statistics
  oida dnp3 192.168.1.100 --activate-config -o 10 --confirm  # Activate pending config
  oida dnp3 192.168.1.100 --write-file /config.txt --write-data @local.txt -o 10 --confirm
""",
    )

    # Target (positional)
    add_target_argument(dnp3_parser)

    # Network Options (--port, --timeout)
    add_network_options(dnp3_parser, default_port=20000)

    # DNP3 Addressing
    addr_group = dnp3_parser.add_argument_group("DNP3 Addressing")
    addr_group.add_argument(
        "-m",
        "--master-addr",
        type=int,
        default=1,
        help="Master link address (default: 1)",
    )
    addr_group.add_argument(
        "-o",
        "--outstation-addr",
        type=int,
        default=None,
        help="Outstation link address (required for control operations, default: 1024 for discovery)",
    )
    addr_group.add_argument(
        "-r",
        "--scan-range",
        type=str,
        metavar="START-END",
        help="Scan for outstations in address range (e.g., 1-100)",
    )
    addr_group.add_argument(
        "--scan-timeout",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help="Timeout per address during range scan (default: 0.5s)",
    )

    # Transport Options
    transport_group = dnp3_parser.add_argument_group("Transport Options")
    transport_group.add_argument(
        "--transport",
        type=str,
        choices=["tcp", "serial", "udp"],
        default="tcp",
        help="Transport type (default: tcp)",
    )
    transport_group.add_argument(
        "--serial-device",
        type=str,
        metavar="PATH",
        help="Serial device path (e.g., /dev/ttyUSB0). Required when --transport=serial",
    )
    transport_group.add_argument(
        "--baud",
        type=int,
        default=9600,
        help="Serial baud rate (default: 9600)",
    )
    transport_group.add_argument(
        "--data-bits",
        type=int,
        default=8,
        choices=[5, 6, 7, 8],
        help="Serial data bits (default: 8)",
    )
    transport_group.add_argument(
        "--stop-bits",
        type=int,
        default=1,
        choices=[1, 2],
        help="Serial stop bits (default: 1)",
    )
    transport_group.add_argument(
        "--parity",
        type=str,
        default="none",
        choices=["none", "even", "odd"],
        help="Serial parity (default: none)",
    )

    # Secure Authentication v5
    sa_group = dnp3_parser.add_argument_group("Secure Authentication v5")
    sa_group.add_argument(
        "--sa",
        action="store_true",
        help="Enable Secure Authentication v5",
    )
    sa_group.add_argument(
        "--sa-user",
        type=int,
        default=1,
        metavar="USER_ID",
        help="SA v5 user ID (default: 1)",
    )
    sa_group.add_argument(
        "--sa-key",
        type=str,
        metavar="HEX_KEY",
        help="SA v5 update key in hex (e.g., 0123456789abcdef...)",
    )

    # Channel Retry Tuning
    retry_group = dnp3_parser.add_argument_group("Channel Retry Tuning")
    retry_group.add_argument(
        "--retry-min",
        type=float,
        metavar="SECONDS",
        help="Minimum retry delay in seconds (default: library default)",
    )
    retry_group.add_argument(
        "--retry-max",
        type=float,
        metavar="SECONDS",
        help="Maximum retry delay in seconds (default: library default)",
    )
    retry_group.add_argument(
        "--no-reconnect",
        action="store_true",
        help="Disable automatic reconnection on channel failure",
    )

    # Polling Options
    poll_group = dnp3_parser.add_argument_group("Polling Options")
    poll_group.add_argument(
        "-c",
        "--class-poll",
        type=str,
        choices=["0", "1", "2", "3", "all"],
        default="all",
        help="Poll specific event class (default: all = integrity poll)",
    )
    poll_group.add_argument(
        "--skip-device-attrs",
        action="store_true",
        help="Skip querying DNP3 Group 0 device attributes (vendor/model identification)",
    )
    poll_group.add_argument(
        "-a",
        "--dump-attrs",
        action="store_true",
        help="Dump all device attributes (Group 0 variation 255 discovery)",
    )
    poll_group.add_argument(
        "-g",
        "--read-variation",
        type=str,
        metavar="GROUP.VAR",
        help="Read specific group/variation (e.g., 30.0 for Analog Input default)",
    )
    poll_group.add_argument(
        "--enumerate-points",
        "-e",
        action="store_true",
        help="Enumerate all data point ranges from device attributes",
    )
    poll_group.add_argument(
        "--probe-objects",
        action="store_true",
        help="Probe all DNP3 groups 0-122 to discover supported objects (read-only)",
    )
    poll_group.add_argument(
        "--security-stats",
        action="store_true",
        help="Read security statistics (Group 121) from outstation",
    )

    # Binary Output Control Operations
    bo_group = dnp3_parser.add_argument_group("Binary Output Control")
    bo_group.add_argument(
        "-b",
        "--bo-direct",
        type=int,
        metavar="INDEX",
        help="Send DIRECT_OPERATE to binary output index (requires --confirm)",
    )
    bo_group.add_argument(
        "-B",
        "--bo-sbo",
        type=int,
        metavar="INDEX",
        help="Full SELECT-BEFORE-OPERATE cycle (requires --confirm)",
    )
    bo_group.add_argument(
        "--control-code",
        type=int,
        default=3,
        choices=[0, 1, 2, 3, 4, 5, 6],
        help=(
            "CROB control code: 0=NUL, 1=PULSE_ON, 2=PULSE_OFF, "
            "3=LATCH_ON, 4=LATCH_OFF, 5=CLOSE, 6=TRIP (default: 3)"
        ),
    )

    # Analog Output Control Operations (Group 41)
    ao_group = dnp3_parser.add_argument_group("Analog Output Control")
    ao_group.add_argument(
        "--ao-direct",
        type=int,
        metavar="INDEX",
        help="Send DIRECT_OPERATE to analog output index (requires --confirm)",
    )
    ao_group.add_argument(
        "--ao-sbo",
        type=int,
        metavar="INDEX",
        help="Full SELECT-BEFORE-OPERATE on analog output (requires --confirm)",
    )
    ao_group.add_argument(
        "--ao-value",
        type=str,
        metavar="VALUE",
        help="Value to write to analog output (required with --ao-direct/--ao-sbo)",
    )
    ao_group.add_argument(
        "--ao-type",
        type=str,
        choices=["int16", "int32", "float", "double"],
        default="float",
        help="Analog output data type: int16 (G41V2), int32 (G41V1), float (G41V3), double (G41V4) (default: float)",
    )

    # File Transfer Operations (Group 70)
    file_group = dnp3_parser.add_argument_group("File Transfer Operations")
    file_group.add_argument(
        "-l",
        "--list-dir",
        type=str,
        metavar="PATH",
        help="List directory contents on outstation (e.g., / or /config)",
    )
    file_group.add_argument(
        "-R",
        "--read-file",
        type=str,
        metavar="PATH",
        help="Read file from outstation (e.g., /config.txt)",
    )
    file_group.add_argument(
        "-f",
        "--file-info",
        type=str,
        metavar="PATH",
        help="Get file metadata (size, type, permissions)",
    )
    file_group.add_argument(
        "-s",
        "--save-file",
        type=str,
        metavar="LOCAL_PATH",
        help="Save downloaded file to local path (used with --read-file)",
    )
    file_group.add_argument(
        "--write-file",
        type=str,
        metavar="PATH",
        help="Write file to outstation (requires --write-data and --confirm)",
    )
    file_group.add_argument(
        "--write-data",
        type=str,
        metavar="DATA_OR_@FILE",
        help="Data to write: inline text or @local_file_path (used with --write-file)",
    )
    file_group.add_argument(
        "--file-auth",
        type=str,
        metavar="PATH",
        help="Authenticate a file on the outstation (SA v5, requires --confirm)",
    )

    # Unsolicited Response Control
    unsol_group = dnp3_parser.add_argument_group("Unsolicited Response Control")
    unsol_group.add_argument(
        "-U",
        "--enable-unsol",
        action="store_true",
        help="Enable unsolicited responses on outstation (requires --confirm)",
    )
    unsol_group.add_argument(
        "--disable-unsol",
        action="store_true",
        help="Disable unsolicited responses on outstation (requires --confirm)",
    )

    # Dead Band Configuration (Group 34)
    deadband_group = dnp3_parser.add_argument_group("Dead Band Configuration")
    deadband_group.add_argument(
        "-w",
        "--write-deadband",
        type=str,
        metavar="INDEX:VALUE",
        action="append",
        help="Write dead band value (e.g., 0:100 for index 0, value 100). Can be repeated.",
    )
    deadband_group.add_argument(
        "--deadband-type",
        type=str,
        choices=["uint16", "uint32", "float"],
        default="float",
        help=(
            "Dead band value type recorded in results. NOTE: the opendnp3 binding "
            "always transmits Group 34 Variation 3 (float) on the wire; uint16/uint32 "
            "are metadata only."
        ),
    )

    # Freeze Operations (Group 20-23 targets)
    freeze_group = dnp3_parser.add_argument_group("Freeze Operations")
    freeze_group.add_argument(
        "-F",
        "--freeze-immediate",
        action="store_true",
        help="Immediate freeze of counters (requires --confirm)",
    )
    freeze_group.add_argument(
        "-C",
        "--freeze-clear",
        action="store_true",
        help="Freeze and clear counters (requires --confirm)",
    )
    freeze_group.add_argument(
        "-T",
        "--freeze-at-time",
        type=str,
        metavar="TIME",
        help="Freeze at specified time (ISO format or relative like +60s) (requires --confirm)",
    )
    freeze_group.add_argument(
        "-N",
        "--freeze-no-ack",
        action="store_true",
        help="Send freeze without acknowledgment (use with --freeze-immediate or --freeze-clear)",
    )

    # Application Control Operations
    app_group = dnp3_parser.add_argument_group("Application Control")
    app_group.add_argument(
        "-K",
        "--stop-app",
        action="store_true",
        help="Stop/kill outstation application (requires --confirm)",
    )
    app_group.add_argument(
        "-S",
        "--start-app",
        action="store_true",
        help="Start outstation application (requires --confirm)",
    )
    app_group.add_argument(
        "-I",
        "--init-data",
        action="store_true",
        help="Initialize/clear device data (requires --confirm)",
    )
    app_group.add_argument(
        "-A",
        "--init-app",
        action="store_true",
        help="Initialize application (requires --confirm)",
    )

    # Configuration Management
    config_group = dnp3_parser.add_argument_group("Configuration Management")
    config_group.add_argument(
        "--save-config",
        action="store_true",
        help="Save configuration to non-volatile memory (requires --confirm)",
    )
    config_group.add_argument(
        "--activate-config",
        action="store_true",
        help="Activate a pending configuration on the outstation (requires --confirm)",
    )

    # File Delete Operation
    file_group.add_argument(
        "-D",
        "--delete-file",
        type=str,
        metavar="PATH",
        help="Delete file on outstation (requires --confirm)",
    )

    # Diagnostic/Stealth Operations
    diag_group = dnp3_parser.add_argument_group("Diagnostic Operations")
    diag_group.add_argument(
        "-n",
        "--no-ack",
        action="store_true",
        help=(
            "Prefer no-acknowledgment (NR) variants where the opendnp3 stack "
            "supports them (currently freeze operations); implies --freeze-no-ack"
        ),
    )
    diag_group.add_argument(
        "-d",
        "--delay-measure",
        action="store_true",
        help="Measure communication round-trip delay",
    )
    diag_group.add_argument(
        "--record-time",
        action="store_true",
        help="Send RECORD_CURRENT_TIME command (FC 0x18)",
    )

    # Class Assignment Operations
    class_group = dnp3_parser.add_argument_group("Class Assignment")
    class_group.add_argument(
        "--assign-class",
        type=str,
        metavar="GROUP:START-END:CLASS",
        action="append",
        help=(
            "Assign points to event class. Format: GROUP:START-END:CLASS "
            "(e.g., 1:0-9:1 assigns BI 0-9 to Class 1). "
            "Can be repeated. (requires --confirm)"
        ),
    )

    # Octet String Operations
    octet_group = dnp3_parser.add_argument_group("Octet String Operations")
    octet_group.add_argument(
        "-O",
        "--read-octet",
        type=str,
        metavar="GROUP:START-END",
        help="Read octet strings. Format: GROUP:START-END (e.g., 110:0-9). Group 110=static, 111=events",
    )

    # Restart Commands
    restart_group = dnp3_parser.add_argument_group("Restart Commands")
    restart_group.add_argument(
        "--cold-restart",
        action="store_true",
        help="Execute cold restart (requires --confirm)",
    )
    restart_group.add_argument(
        "--warm-restart",
        action="store_true",
        help="Execute warm restart (requires --confirm)",
    )

    # Time Synchronization
    time_group = dnp3_parser.add_argument_group("Time Synchronization")
    time_group.add_argument(
        "--time-sync",
        type=str,
        choices=["lan", "non-lan"],
        metavar="MODE",
        help="Perform time synchronization (lan or non-lan)",
    )

    # TLS Options
    tls_group = dnp3_parser.add_argument_group("TLS Options")
    tls_group.add_argument(
        "--tls",
        action="store_true",
        help="Enable TLS encrypted channel",
    )
    tls_group.add_argument(
        "--tls-cert",
        type=str,
        metavar="PATH",
        help="Path to TLS client certificate (PEM)",
    )
    tls_group.add_argument(
        "--tls-key",
        type=str,
        metavar="PATH",
        help="Path to TLS client private key (PEM)",
    )

    # Active Testing (--confirm)
    add_dangerous_options(dnp3_parser, include_fuzz=False)

    return dnp3_parser


def validate_args(args) -> None:
    """Validate DNP3 argument combinations.

    Raises:
        ConfigurationError: If validation fails.
    """

    # Control operations that require explicit --outstation-addr
    control_ops = []
    if getattr(args, "bo_direct", None) is not None:
        control_ops.append("--bo-direct")
    if getattr(args, "bo_sbo", None) is not None:
        control_ops.append("--bo-sbo")
    if getattr(args, "ao_direct", None) is not None:
        control_ops.append("--ao-direct")
    if getattr(args, "ao_sbo", None) is not None:
        control_ops.append("--ao-sbo")
    if getattr(args, "cold_restart", False):
        control_ops.append("--cold-restart")
    if getattr(args, "warm_restart", False):
        control_ops.append("--warm-restart")
    if getattr(args, "enable_unsol", False):
        control_ops.append("--enable-unsol")
    if getattr(args, "disable_unsol", False):
        control_ops.append("--disable-unsol")
    if getattr(args, "write_deadband", None):
        control_ops.append("--write-deadband")
    if getattr(args, "time_sync", False):
        # Type 50 time-sync writes the outstation clock - same blast
        # radius as the other control ops; was missing from this list.
        control_ops.append("--time-sync")
    # Freeze operations
    if getattr(args, "freeze_immediate", False):
        control_ops.append("--freeze-immediate")
    if getattr(args, "freeze_clear", False):
        control_ops.append("--freeze-clear")
    if getattr(args, "freeze_at_time", None):
        control_ops.append("--freeze-at-time")
    # Application control operations
    if getattr(args, "stop_app", False):
        control_ops.append("--stop-app")
    if getattr(args, "start_app", False):
        control_ops.append("--start-app")
    if getattr(args, "init_data", False):
        control_ops.append("--init-data")
    if getattr(args, "init_app", False):
        control_ops.append("--init-app")
    # Configuration management
    if getattr(args, "save_config", False):
        control_ops.append("--save-config")
    if getattr(args, "activate_config", False):
        control_ops.append("--activate-config")
    # File operations
    if getattr(args, "delete_file", None):
        control_ops.append("--delete-file")
    if getattr(args, "write_file", None):
        control_ops.append("--write-file")
    if getattr(args, "file_auth", None):
        control_ops.append("--file-auth")
    # Class assignment
    if getattr(args, "assign_class", None):
        control_ops.append("--assign-class")
    if control_ops and getattr(args, "outstation_addr", None) is None:
        ops_str = ", ".join(control_ops)
        raise ConfigurationError(
            f"--outstation-addr is required for control operations ({ops_str})",
            protocol="DNP3",
        )

    # All control ops also require --confirm. Help text on every dangerous flag
    # already says "(requires --confirm)" - enforce it here so users can't drive
    # a live outstation by accident.
    if control_ops and not getattr(args, "confirm", False):
        ops_str = ", ".join(control_ops)
        raise ConfigurationError(
            f"--confirm is required for control operations ({ops_str}). "
            "These flags can disrupt physical processes; re-run with --confirm to acknowledge.",
            protocol="DNP3",
        )

    # Validate analog output operations require --ao-value
    ao_direct = getattr(args, "ao_direct", None)
    ao_sbo = getattr(args, "ao_sbo", None)
    ao_value = getattr(args, "ao_value", None)

    if (ao_direct is not None or ao_sbo is not None) and ao_value is None:
        raise ConfigurationError(
            "--ao-value is required when using --ao-direct or --ao-sbo",
            protocol="DNP3",
        )

    # Validate --ao-value is a valid number
    if ao_value is not None:
        try:
            float(ao_value)
        except ValueError:
            raise ConfigurationError(
                f"--ao-value must be a numeric value, got: {ao_value}",
                protocol="DNP3",
            )

    # Validate --write-file requires --write-data
    write_file = getattr(args, "write_file", None)
    write_data = getattr(args, "write_data", None)
    if write_file and not write_data:
        raise ConfigurationError(
            "--write-data is required when using --write-file",
            protocol="DNP3",
        )

    # Validate --write-deadband format (INDEX:VALUE)
    deadband_entries = getattr(args, "write_deadband", None)
    if deadband_entries:
        for entry in deadband_entries:
            try:
                parts = entry.split(":")
                if len(parts) != 2:
                    raise ValueError("must be INDEX:VALUE format")
                idx = int(parts[0])
                float(parts[1])  # Validate value is numeric
                if idx < 0:
                    raise ValueError("index must be non-negative")
            except ValueError as e:
                raise ConfigurationError(
                    f"invalid --write-deadband '{entry}': {e}",
                    protocol="DNP3",
                )

    # Validate scan-range format if provided
    scan_range = getattr(args, "scan_range", None)
    if scan_range:
        try:
            parts = scan_range.split("-")
            if len(parts) != 2:
                raise ValueError("must be START-END format")
            start, end = int(parts[0]), int(parts[1])
            if start < 0 or end < 0:
                raise ValueError("addresses must be non-negative")
            if start > end:
                raise ValueError("START must be <= END")
            if end > 65519:  # DNP3 max link address
                raise ValueError("address must be <= 65519")
        except ValueError as e:
            raise ConfigurationError(
                f"invalid --scan-range: {e}",
                protocol="DNP3",
            )

    # Validate TLS requires both cert and key - refuse to silently fall back to
    # cleartext TCP (the channel builder only uses TLS when both are present).
    if getattr(args, "tls", False):
        if not getattr(args, "tls_cert", None) or not getattr(args, "tls_key", None):
            raise ConfigurationError(
                "--tls requires both --tls-cert and --tls-key; refusing to fall "
                "back to plaintext TCP",
                protocol="DNP3",
            )

    # Validate --freeze-at-time format if provided
    freeze_at_time = getattr(args, "freeze_at_time", None)
    if freeze_at_time:
        try:
            _parse_freeze_time(freeze_at_time)
        except ValueError as e:
            raise ConfigurationError(
                f"invalid --freeze-at-time: {e}",
                protocol="DNP3",
            )

    # Validate --freeze-no-ack requires a freeze operation
    freeze_no_ack = getattr(args, "freeze_no_ack", False)
    if freeze_no_ack:
        has_freeze_op = getattr(args, "freeze_immediate", False) or getattr(
            args, "freeze_clear", False
        )
        if not has_freeze_op:
            raise ConfigurationError(
                "--freeze-no-ack requires --freeze-immediate or --freeze-clear",
                protocol="DNP3",
            )

    # Validate --assign-class format (GROUP:START-END:CLASS)
    assign_class_entries = getattr(args, "assign_class", None)
    if assign_class_entries:
        for entry in assign_class_entries:
            try:
                parts = entry.split(":")
                if len(parts) != 3:
                    raise ValueError("must be GROUP:START-END:CLASS format")
                group = int(parts[0])
                range_parts = parts[1].split("-")
                start_idx = int(range_parts[0])
                end_idx = int(range_parts[1]) if len(range_parts) > 1 else start_idx
                target_class = int(parts[2])
                if group < 0:
                    raise ValueError("group must be non-negative")
                if start_idx < 0 or end_idx < 0:
                    raise ValueError("indices must be non-negative")
                if start_idx > end_idx:
                    raise ValueError("start index must be <= end index")
                if target_class not in [0, 1, 2, 3]:
                    raise ValueError("class must be 0, 1, 2, or 3")
            except ValueError as e:
                raise ConfigurationError(
                    f"invalid --assign-class '{entry}': {e}",
                    protocol="DNP3",
                )

    # Validate --read-octet format (GROUP:START-END)
    read_octet = getattr(args, "read_octet", None)
    if read_octet:
        try:
            parts = read_octet.split(":")
            if len(parts) < 2:
                raise ValueError("must be GROUP:START-END or GROUP:INDEX format")
            group = int(parts[0])
            range_parts = parts[1].split("-")
            start_idx = int(range_parts[0])
            end_idx = int(range_parts[1]) if len(range_parts) > 1 else start_idx
            if group not in [110, 111]:
                raise ValueError("group must be 110 (static) or 111 (events)")
            if start_idx < 0 or end_idx < 0:
                raise ValueError("indices must be non-negative")
            if start_idx > end_idx:
                raise ValueError("start index must be <= end index")
        except ValueError as e:
            raise ConfigurationError(
                f"invalid --read-octet '{read_octet}': {e}",
                protocol="DNP3",
            )

    # Validate --sa-key format (hex string)
    sa_key = getattr(args, "sa_key", None)
    if sa_key:
        try:
            bytes.fromhex(sa_key)
        except ValueError:
            raise ConfigurationError(
                f"--sa-key must be a valid hex string, got: {sa_key}",
                protocol="DNP3",
            )

    # Validate serial transport requires --serial-device
    transport = getattr(args, "transport", "tcp")
    serial_device = getattr(args, "serial_device", None)
    if transport == "serial" and not serial_device:
        raise ConfigurationError(
            "--serial-device is required when --transport=serial",
            protocol="DNP3",
        )


def _parse_freeze_time(time_str: str) -> int:
    """Parse freeze time specification to milliseconds since epoch.

    Accepts:
    - Relative time: +60s, +5m, +1h (seconds, minutes, hours from now)
    - ISO format: 2024-01-15T10:30:00 or 2024-01-15T10:30:00Z

    Returns:
        Milliseconds since Unix epoch

    Raises:
        ValueError: If format is invalid
    """
    # Relative time format: +60s, +5m, +1h
    relative_match = re.match(r"^\+(\d+)([smh])$", time_str)
    if relative_match:
        value = int(relative_match.group(1))
        unit = relative_match.group(2)
        multipliers = {"s": 1, "m": 60, "h": 3600}
        seconds = value * multipliers[unit]
        future_time = datetime.now(timezone.utc).timestamp() + seconds
        return int(future_time * 1000)

    # ISO format
    try:
        # Try with timezone
        if time_str.endswith("Z"):
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        elif "+" in time_str or time_str.count("-") > 2:
            dt = datetime.fromisoformat(time_str)
        else:
            # Assume UTC if no timezone
            dt = datetime.fromisoformat(time_str).replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        raise ValueError(
            f"invalid time format: {time_str}. "
            "Use +60s (relative) or ISO format (2024-01-15T10:30:00)"
        )
