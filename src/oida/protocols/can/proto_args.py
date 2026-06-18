"""
Argument parser definition for CAN protocol.

This module registers CAN-specific command-line arguments following
the NXC pattern.
"""

from typing import Any

from ...utils.proto_args_factory import (
    add_dangerous_options,
    add_monitor_options,
    create_protocol_parser,
)
from .constants import CAN_BAUDRATES, DEFAULT_BAUDRATE


def proto_args(parser: Any, parents: list) -> Any:
    """Register CAN-specific arguments."""

    examples_epilog = """
Examples:
  oida can can0                                 # Sniff traffic on can0 (10s)
  oida can vcan0 --bus-type virtual             # Use virtual CAN interface
  oida can can0 -B 250000                       # Use 250 kbit/s baudrate
  oida can can0 --sniff-time 30                 # Sniff for 30 seconds
  oida can can0 --uds-scan                      # Discover UDS-capable ECUs
  oida can can0 --uds-scan --extended           # Include extended ID range
  oida can can0 --filter-id 0x7E0-0x7EF        # Filter specific ID range
  oida can can0 --send 0x7DF#02013E0000000000   # Send raw CAN frame
  oida can can0 --monitor                       # Continuous monitoring mode
  oida can can0 --obd2                          # Probe OBD-II services
  oida can can0 --id-scan                       # Scan all standard IDs

XCP/CCP:
  oida can can0 --xcp-scan                      # Discover XCP-enabled ECUs
  oida can can0 --xcp-info --xcp-req-id 0x100 --xcp-resp-id 0x101
  oida can can0 --ccp-scan                      # Discover CCP-enabled ECUs

CANopen (CiA 301):
  oida can can0 --canopen-scan                   # Full CANopen node discovery + fingerprinting
  oida can can0 --canopen-info 1                 # Get device info for node 1
  oida can can0 --canopen-sdo-read 1:0x1000:0    # Read OD entry 0x1000 sub 0 from node 1
  oida can can0 --canopen-od-scan 1              # Enumerate Object Dictionary on node 1
  oida can can0 --canopen-monitor                # Monitor EMCY + heartbeat traffic
  oida can can0 --canopen-pdo --canopen-pdo-node 1  # Discover PDO mappings
  oida can can0 --modbus-gateway                 # Detect CANopen-to-Modbus gateways (CiA 309)

Enhanced UDS:
  oida can can0 --uds-sessions --uds-target-id 0x7E0
  oida can can0 --uds-dids 0xF180-0xF19F       # Scan standard F-DIDs
  oida can can0 --uds-seeds --seed-level 0x01 --seed-count 20
  oida can can0 --uds-routines                  # Enumerate available routines
  oida can can0 --uds-reset --confirm           # Reset ECU (requires --confirm)

Replay:
  oida can can0 --replay traffic.log            # Replay a candump log file
"""

    can_parser = create_protocol_parser(
        parser,
        name="can",
        help_text="CAN bus scanner and analyzer",
        description="Scan and interact with Controller Area Network (CAN) bus devices",
        parents=parents,
        epilog=examples_epilog,
    )

    # Positional: target interface
    can_parser.add_argument(
        "target",
        help="CAN interface name (e.g., can0, vcan0, slcan0)",
    )

    # --- CAN Bus Options ---
    bus_group = can_parser.add_argument_group("CAN Bus Options")

    _baudrate_list = ", ".join(
        f"{k}={v}" for k, v in sorted(CAN_BAUDRATES.items(), key=lambda x: x[1])
    )
    bus_group.add_argument(
        "-B",
        "--baudrate",
        type=int,
        default=DEFAULT_BAUDRATE,
        metavar="BPS",
        help=f"CAN bus bitrate in bits/sec (default: {DEFAULT_BAUDRATE}). Common: {_baudrate_list}",
    )

    bus_group.add_argument(
        "--bus-type",
        type=str,
        default="socketcan",
        metavar="TYPE",
        help=(
            "python-can interface type (default: socketcan). "
            "Options: socketcan, virtual, pcan, ixxat, kvaser, vector, slcan, serial, udp_multicast"
        ),
    )

    bus_group.add_argument(
        "--channel",
        type=str,
        metavar="CHAN",
        help="CAN channel (overrides target for some bus types)",
    )

    bus_group.add_argument(
        "--fd",
        action="store_true",
        help="Enable CAN FD (Flexible Data-rate) mode",
    )

    bus_group.add_argument(
        "--extended",
        action="store_true",
        help="Include extended (29-bit) arbitration IDs in scans",
    )

    bus_group.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECS",
        help="Communication timeout in seconds (default: 5.0)",
    )

    # --- Sniff Options ---
    sniff_group = can_parser.add_argument_group("Sniff Options")

    sniff_group.add_argument(
        "--sniff-time",
        type=int,
        default=10,
        metavar="SECS",
        help="Duration to sniff CAN traffic in seconds (default: 10)",
    )

    sniff_group.add_argument(
        "--filter-id",
        type=str,
        metavar="IDS",
        help=(
            "Filter arbitration IDs during sniff. "
            "Formats: 0x7E0 (single), 0x7E0-0x7EF (range), 0x100,0x200,0x300 (list)"
        ),
    )

    sniff_group.add_argument(
        "--no-sniff",
        action="store_true",
        help="Skip passive traffic sniffing phase",
    )

    # --- Active Scanning ---
    scan_group = can_parser.add_argument_group("Active Scanning")

    scan_group.add_argument(
        "--uds-scan",
        action="store_true",
        help="Discover UDS (ISO 14229) capable ECUs and enumerate services",
    )

    scan_group.add_argument(
        "--obd2",
        action="store_true",
        help="Probe OBD-II (ISO 15031) services and read vehicle data",
    )

    scan_group.add_argument(
        "--id-scan",
        action="store_true",
        help="Actively scan all standard (11-bit) arbitration IDs for responses",
    )

    scan_group.add_argument(
        "--id-scan-range",
        type=str,
        default="0x000-0x7FF",
        metavar="RANGE",
        help="Arbitration ID range for active scanning (default: 0x000-0x7FF)",
    )

    scan_group.add_argument(
        "--uds-services",
        type=str,
        metavar="IDS",
        help=(
            "Specific UDS service IDs to probe (comma-separated hex, e.g., 0x10,0x22,0x27). "
            "Default: probe all known services"
        ),
    )

    scan_group.add_argument(
        "--uds-dids",
        type=str,
        metavar="RANGE",
        help="DID range to read via UDS ReadDataByIdentifier (e.g., 0xF180-0xF19F)",
    )

    scan_group.add_argument(
        "--uds-target-id",
        type=str,
        metavar="ID",
        help="Target UDS request arbitration ID for enhanced UDS features (default: 0x7E0)",
    )

    # --- XCP Protocol Discovery ---
    xcp_group = can_parser.add_argument_group("XCP Protocol (Calibration)")

    xcp_group.add_argument(
        "--xcp-scan",
        action="store_true",
        help="Scan for XCP (Universal Calibration Protocol) enabled ECUs",
    )

    xcp_group.add_argument(
        "--xcp-info",
        action="store_true",
        help=(
            "Gather info from an XCP slave (GET_ID, GET_STATUS, GET_COMM_MODE_INFO). "
            "Requires --xcp-req-id and --xcp-resp-id"
        ),
    )

    xcp_group.add_argument(
        "--xcp-memory-read",
        action="store_true",
        help=(
            "Read memory from XCP slave via SHORT_UPLOAD (requires --confirm). "
            "Requires --xcp-req-id, --xcp-resp-id, --xcp-address"
        ),
    )

    xcp_group.add_argument(
        "--xcp-req-id",
        type=str,
        metavar="ID",
        help="XCP slave request (CRO) arbitration ID (hex, e.g., 0x100)",
    )

    xcp_group.add_argument(
        "--xcp-resp-id",
        type=str,
        metavar="ID",
        help="XCP slave response (DTO) arbitration ID (hex, e.g., 0x101)",
    )

    xcp_group.add_argument(
        "--xcp-address",
        type=str,
        metavar="ADDR",
        help="Memory address for XCP read (hex, e.g., 0x00000000)",
    )

    xcp_group.add_argument(
        "--xcp-length",
        type=int,
        default=6,
        metavar="N",
        help="Number of bytes to read via XCP SHORT_UPLOAD (default: 6, max 6 on CAN)",
    )

    # --- CCP Protocol Discovery ---
    ccp_group = can_parser.add_argument_group("CCP Protocol (CAN Calibration)")

    ccp_group.add_argument(
        "--ccp-scan",
        action="store_true",
        help="Scan for CCP (CAN Calibration Protocol) enabled ECUs",
    )

    ccp_group.add_argument(
        "--ccp-cro-id",
        type=str,
        default="0x701",
        metavar="ID",
        help="CCP CRO (master->slave) CAN ID (default: 0x701)",
    )

    ccp_group.add_argument(
        "--ccp-dto-id",
        type=str,
        default="0x702",
        metavar="ID",
        help="CCP DTO (slave->master) CAN ID (default: 0x702)",
    )

    # --- CANopen Protocol (CiA 301) ---
    canopen_group = can_parser.add_argument_group("CANopen Protocol (CiA 301)")

    canopen_group.add_argument(
        "--canopen-scan",
        action="store_true",
        help="Scan for CANopen nodes (1-127) via heartbeat + node guarding and fingerprint each",
    )

    canopen_group.add_argument(
        "--canopen-info",
        type=str,
        metavar="NODE_ID",
        help="Get device info for a specific CANopen node (reads identity objects via SDO)",
    )

    canopen_group.add_argument(
        "--canopen-sdo-read",
        type=str,
        metavar="NODE:INDEX:SUB",
        help=(
            "Read a specific OD entry via SDO upload "
            "(e.g., 1:0x1000:0 = node 1, index 0x1000, sub-index 0)"
        ),
    )

    canopen_group.add_argument(
        "--canopen-od-scan",
        type=str,
        metavar="NODE_ID",
        help="Enumerate Object Dictionary entries on a node (scans 0x1000-0x1029 by default)",
    )

    canopen_group.add_argument(
        "--canopen-od-range",
        type=str,
        metavar="RANGE",
        help="OD index range for --canopen-od-scan (e.g., 0x1000-0x1FFF, default: 0x1000-0x1029)",
    )

    canopen_group.add_argument(
        "--canopen-monitor",
        action="store_true",
        help="Monitor EMCY (emergency) and heartbeat traffic to map network state",
    )

    canopen_group.add_argument(
        "--canopen-pdo",
        action="store_true",
        help="Discover PDO mappings (TPDO/RPDO communication and mapping parameters)",
    )

    canopen_group.add_argument(
        "--canopen-pdo-node",
        type=str,
        metavar="NODE_ID",
        help="Target node for PDO discovery (used with --canopen-pdo)",
    )

    canopen_group.add_argument(
        "--modbus-gateway",
        action="store_true",
        help="Detect CANopen-to-Modbus gateway devices (CiA 309) and enumerate register mappings",
    )

    # --- Enhanced UDS ---
    uds_group = can_parser.add_argument_group("Enhanced UDS")

    uds_group.add_argument(
        "--uds-sessions",
        action="store_true",
        help="Enumerate supported UDS diagnostic sessions (0x10)",
    )

    uds_group.add_argument(
        "--uds-seeds",
        action="store_true",
        help="Collect SecurityAccess (0x27) seeds for randomness analysis",
    )

    uds_group.add_argument(
        "--seed-level",
        type=str,
        default="0x01",
        metavar="LEVEL",
        help="SecurityAccess sub-function level for seed collection (default: 0x01)",
    )

    uds_group.add_argument(
        "--seed-count",
        type=int,
        default=10,
        metavar="N",
        help="Number of seeds to collect (default: 10)",
    )

    uds_group.add_argument(
        "--uds-routines",
        action="store_true",
        help="Enumerate available routines via RoutineControl (0x31)",
    )

    uds_group.add_argument(
        "--uds-reset",
        action="store_true",
        help="Send ECUReset (0x11) command (requires --confirm)",
    )

    uds_group.add_argument(
        "--uds-reset-type",
        type=str,
        default="0x01",
        metavar="TYPE",
        help="ECU reset sub-function: 0x01=hard, 0x02=keyOffOn, 0x03=soft (default: 0x01)",
    )

    # --- Send / Replay ---
    send_group = can_parser.add_argument_group("Send / Replay")

    send_group.add_argument(
        "--send",
        type=str,
        metavar="ID#DATA",
        help=("Send raw CAN frame: ARBID#HEXDATA (e.g., 0x7DF#0201000000000000 or 7E0#023E00)"),
    )

    send_group.add_argument(
        "--send-file",
        type=str,
        metavar="FILE",
        help="Send CAN frames from file (one ID#DATA per line)",
    )

    send_group.add_argument(
        "--replay",
        type=str,
        metavar="FILE",
        help="Replay CAN traffic from candump/log file",
    )

    send_group.add_argument(
        "--replay-speed",
        type=float,
        default=1.0,
        metavar="FACTOR",
        help="Replay speed multiplier (default: 1.0 = real-time, 0 = no delay)",
    )

    # --- Monitoring ---
    monitor_group = add_monitor_options(can_parser, default_interval=0.0)

    monitor_group.add_argument(
        "--on-change",
        action="store_true",
        help="Only display when data payload changes for an arbitration ID",
    )

    monitor_group.add_argument(
        "--log-file",
        type=str,
        metavar="FILE",
        help="Log captured traffic to file (candump format)",
    )

    # --- Security Testing ---
    fuzz_group = add_dangerous_options(can_parser, include_fuzz=True)

    fuzz_group.add_argument(
        "--fuzz-id",
        type=str,
        metavar="ID",
        help="Target arbitration ID for fuzzing (hex, e.g., 0x7E0)",
    )

    fuzz_group.add_argument(
        "--fuzz-mode",
        choices=["random", "sequential", "boundary", "smart"],
        default="random",
        help=(
            "Fuzzing mode: random=random bytes, sequential=walk data values, "
            "boundary=edge cases, smart=protocol-aware (default: random)"
        ),
    )

    return can_parser
