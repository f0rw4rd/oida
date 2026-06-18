"""
Argument parser definition for Siemens S7 protocol (Snap7)

This module registers S7-specific command-line arguments
following the NXC pattern.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_brute_options,
    add_dangerous_options,
    add_monitor_options,
    add_control_options,
    add_output_options,
)


def proto_args(parser, parents):
    """Register S7-specific arguments"""
    s7_parser = create_protocol_parser(
        parser,
        name="s7",
        help_text="Siemens S7 scanner",
        description="Scan and interact with Siemens S7 PLCs",
        parents=parents,
        epilog="""
Examples:
  oida s7 192.168.1.100                      # Basic discovery
  oida s7 192.168.1.100 -i                   # Get PLC info
  oida s7 192.168.1.100 -e                   # List data blocks
  oida s7 192.168.1.100 -r 1:0:100           # Read DB1 bytes 0-100
  oida s7 192.168.1.100 -I 0:10 -Q 0:8      # Read inputs + outputs
  oida s7 192.168.1.100 --monitor I,Q,M      # Monitor I/O
  oida s7 192.168.1.100 -P passwords.txt     # Brute-force from file
  oida s7 192.168.1.100 -L -E                # List and enumerate SZL
  oida s7 192.168.1.100 --audit              # Full security audit
  oida s7 192.168.1.100 --audit-quick        # Quick audit (no password test)
  oida s7 192.168.1.100 --default-creds      # Test default passwords
  oida s7 192.168.1.100 --brute --wordlist pw # Brute-force with wordlist
  oida s7 192.168.1.100 --fuzz --confirm     # Fuzz DBs + memory areas
  oida s7 192.168.1.100 --fuzz db --confirm  # Fuzz data blocks only
""",
    )

    # Target (positional)
    add_target_argument(s7_parser)

    # Network Options (--port, --timeout)
    add_network_options(s7_parser, default_port=102)

    # S7 Connection Parameters
    s7_group = s7_parser.add_argument_group("S7 Connection Parameters")
    s7_group.add_argument(
        "-R",
        "--rack",
        type=int,
        default=0,
        help="PLC rack number (default: 0)",
    )
    s7_group.add_argument(
        "-s",
        "--slot",
        type=int,
        default=None,
        help="PLC slot number (auto-detected if not specified)",
    )
    s7_group.add_argument(
        "-P",
        "--password",
        type=str,
        help="PLC password or wordlist file (if path exists, brute-force with it)",
    )
    s7_group.add_argument(
        "-C",
        "--connection-type",
        type=str,
        choices=["PG", "OP", "S7Basic"],
        default="PG",
        help="Connection type (default: PG for programming device)",
    )
    s7_group.add_argument(
        "-N",
        "--pdu-size",
        type=int,
        choices=[240, 480, 960],
        default=480,
        help="PDU size for communication (default: 480)",
    )

    # Output Options (--output, --format, -v, -d)
    add_output_options(s7_parser)

    # Discovery Options
    discovery_group = s7_parser.add_argument_group("Discovery Options")
    discovery_group.add_argument(
        "-i",
        "--info",
        action="store_true",
        help="Get CPU info, state, order code, and firmware version",
    )
    discovery_group.add_argument(
        "-e",
        "--enumerate-dbs",
        action="store_true",
        help="Enumerate all data blocks (DBs)",
    )
    discovery_group.add_argument(
        "-T",
        "--test-memory-areas",
        action="store_true",
        help="Test access to different memory areas (I, Q, M, DB)",
    )
    discovery_group.add_argument(
        "-F",
        "--full-scan",
        action="store_true",
        help="Scan all rack/slot combinations (finds S7-300/400 modules)",
    )
    discovery_group.add_argument(
        "-S",
        "--scan-programs",
        action="store_true",
        help="Scan for programs and blocks in PLC",
    )

    # System Information
    info_group = s7_parser.add_argument_group("System Information")
    info_group.add_argument(
        "-L",
        "--list-szl",
        action="store_true",
        help="List available SZL (System Status List) IDs",
    )
    info_group.add_argument(
        "-E",
        "--enumerate-szl",
        action="store_true",
        help="Enumerate all valuable SZL data (firmware, protection, diagnostics)",
    )
    info_group.add_argument(
        "--read-szl-id",
        type=str,
        metavar="ID:INDEX",
        help="Read specific SZL by ID and index (e.g., 0x0011:0)",
    )
    info_group.add_argument(
        "-G",
        "--get-datetime",
        action="store_true",
        help="Get PLC date and time",
    )
    info_group.add_argument(
        "--set-datetime",
        type=str,
        metavar="DATETIME",
        help="Set PLC date/time (format: YYYY-MM-DD HH:MM:SS)",
    )
    info_group.add_argument(
        "--sync-datetime",
        action="store_true",
        help="Sync PLC time with host system",
    )

    # Memory Read Operations
    read_group = s7_parser.add_argument_group("Memory Read Operations")
    read_group.add_argument(
        "-I",
        "--read-inputs",
        type=str,
        metavar="START:SIZE",
        help="Read inputs area (e.g., 0:10 reads 10 bytes from offset 0)",
    )
    read_group.add_argument(
        "-Q",
        "--read-outputs",
        type=str,
        metavar="START:SIZE",
        help="Read outputs area (e.g., 0:8)",
    )
    read_group.add_argument(
        "-M",
        "--read-markers",
        type=str,
        metavar="START:SIZE",
        help="Read markers/flags area (e.g., 0:20)",
    )
    read_group.add_argument(
        "--read-timers",
        type=str,
        metavar="START:COUNT",
        help="Read timers (S7-300/400 only)",
    )
    read_group.add_argument(
        "--read-counters",
        type=str,
        metavar="START:COUNT",
        help="Read counters (S7-300/400 only)",
    )
    read_group.add_argument(
        "-r",
        "--read-db",
        type=str,
        metavar="DB:START:SIZE",
        help="Read data block (e.g., 1:0:100 reads DB1 offset 0-100)",
    )
    read_group.add_argument(
        "-D",
        "--dump-db",
        type=int,
        metavar="NUM",
        help="Dump entire data block to hex",
    )

    # Memory Write Operations
    write_group = s7_parser.add_argument_group("Memory Write Operations")
    write_group.add_argument(
        "-w",
        "--write-db",
        type=str,
        metavar="DB:START:HEXDATA",
        help="Write to data block (e.g., 1:0:DEADBEEF)",
    )
    write_group.add_argument(
        "--write-markers",
        type=str,
        metavar="START:HEXDATA",
        help="Write to markers area (e.g., 0:FF00)",
    )
    write_group.add_argument(
        "--write-outputs",
        type=str,
        metavar="START:HEXDATA",
        help="Write to outputs area (e.g., 0:FF)",
    )
    write_group.add_argument(
        "--write-inputs",
        type=str,
        metavar="START:HEXDATA",
        help="Write to inputs area - use with caution",
    )
    write_group.add_argument(
        "--write-timers",
        type=str,
        metavar="START:HEXDATA",
        help="Write to timers (S7-300/400 only)",
    )
    write_group.add_argument(
        "--write-counters",
        type=str,
        metavar="START:HEXDATA",
        help="Write to counters (S7-300/400 only)",
    )
    write_group.add_argument(
        "--db-fill",
        type=str,
        metavar="DB:BYTE",
        help="Fill entire data block with byte (e.g., 1:00)",
    )
    write_group.add_argument(
        "--test-write",
        action="store_true",
        help="Test write access safely (writes same value back)",
    )

    # Block Operations
    block_group = s7_parser.add_argument_group("Block Operations")
    block_group.add_argument(
        "-l",
        "--list-blocks",
        action="store_true",
        help="List all blocks on PLC (OB, FB, FC, DB, etc.)",
    )
    block_group.add_argument(
        "-B",
        "--get-block-info",
        type=str,
        metavar="TYPE:NUM",
        help="Get detailed block info (e.g., DB:1, FB:10)",
    )
    block_group.add_argument(
        "--list-blocks-of-type",
        type=str,
        choices=["OB", "FB", "FC", "DB", "SFB", "SFC", "SDB"],
        help="List all blocks of specific type",
    )
    block_group.add_argument(
        "-U",
        "--upload-db",
        type=int,
        metavar="NUM",
        help="Upload (read) data block from PLC",
    )
    block_group.add_argument(
        "--upload-block",
        type=str,
        metavar="TYPE:NUM",
        help="Upload full block with headers (e.g., FB:1)",
    )
    block_group.add_argument(
        "--download-db",
        type=str,
        metavar="FILE",
        help="Download (write) data block to PLC",
    )
    block_group.add_argument(
        "--delete-block",
        type=str,
        metavar="TYPE:NUM",
        help="Delete block from PLC (e.g., DB:10)",
    )
    block_group.add_argument(
        "--db-target",
        type=int,
        metavar="NUM",
        help="Target DB number for --download-db",
    )
    block_group.add_argument(
        "-O",
        "--output-file",
        type=str,
        metavar="FILE",
        help="Output file for --upload-db or --upload-block",
    )

    # CPU Control (--cpu-start, --cpu-stop, --restart)
    control_group = add_control_options(s7_parser)
    control_group.add_argument(
        "--cpu-hot-start",
        action="store_true",
        help="Start CPU (hot start, preserves state)",
    )
    control_group.add_argument(
        "-K",
        "--copy-ram-to-rom",
        action="store_true",
        help="Copy RAM to ROM (persist changes)",
    )
    control_group.add_argument(
        "--compress",
        action="store_true",
        help="Compress PLC memory",
    )

    # Monitor Mode (--monitor, --interval, --duration)
    monitor_group = add_monitor_options(s7_parser, default_interval=0.5)
    monitor_group.add_argument(
        "--monitor-size",
        type=int,
        default=16,
        metavar="BYTES",
        help="Number of bytes to monitor per area (default: 16)",
    )
    monitor_group.add_argument(
        "--monitor-bits",
        action="store_true",
        help="Show individual bit changes",
    )

    # Credential Testing (--brute, --default-creds, --wordlist, --brute-rate, --stop-on-success)
    brute_group = add_brute_options(s7_parser, default_rate=0.5)
    brute_group.add_argument(
        "-n",
        "--null-password",
        action="store_true",
        help="Test null/empty password access",
    )
    brute_group.add_argument(
        "--logout",
        action="store_true",
        help="Logout from authenticated session",
    )

    # Security Audit
    audit_group = s7_parser.add_argument_group("Security Audit")
    audit_group.add_argument(
        "--audit",
        action="store_true",
        help="Run comprehensive security audit (device ID, memory access, write access, "
        "block enumeration, CPU protection, default passwords, SZL disclosure)",
    )
    audit_group.add_argument(
        "--audit-quick",
        action="store_true",
        help="Quick audit (skips slow password brute-force test)",
    )

    # Fuzzing (--confirm + S7-specific fuzzing)
    fuzz_group = add_dangerous_options(s7_parser, include_fuzz=False, group_name="Fuzzing")
    fuzz_group.add_argument(
        "--fuzz",
        type=str,
        nargs="?",
        const="all",
        choices=["db", "memory", "all"],
        metavar="MODE",
        help="Fuzz PLC data: db=data blocks, memory=markers+outputs, all=both (default: all). "
        "Reads current values, writes mutated payloads, checks for anomalies, restores originals. "
        "Requires --confirm",
    )
    fuzz_group.add_argument(
        "--fuzz-db",
        type=str,
        metavar="DB:START:SIZE",
        help="Target a specific DB range instead of auto-discovering (e.g., '1:0:10')",
    )
    fuzz_group.add_argument(
        "--fuzz-iterations",
        type=int,
        default=10,
        metavar="N",
        help="Number of fuzz iterations per target (default: 10)",
    )
    fuzz_group.add_argument(
        "--fuzz-max-targets",
        type=int,
        default=10,
        metavar="N",
        help="Maximum number of auto-discovered DBs to fuzz (default: 10)",
    )

    return s7_parser
