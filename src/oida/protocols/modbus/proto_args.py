"""
Argument parser definition for Modbus protocol

This module registers Modbus-specific command-line arguments
following the NXC pattern.
"""

from ...utils.cli import bounded_int
from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_network_options,
    add_serial_options,
    add_tls_options,
    add_dangerous_options,
    add_monitor_options,
    add_scan_options,
)


def proto_args(parser, parents):
    """Register Modbus-specific arguments"""
    modbus_parser = create_protocol_parser(
        parser,
        name="modbus",
        help_text="Modbus TCP/RTU/TLS scanner",
        description="Scan and interact with Modbus devices (TCP, TLS, RTU, UDP)",
        parents=parents,
        epilog="""
Examples:
  oida modbus 192.168.1.100                    # Connect and show basic info
  oida modbus 192.168.1.100 -i                 # Confirm device is accessible (same as default)
  oida modbus 192.168.1.100 -r 0-100           # Read holding registers 0-100
  oida modbus 192.168.1.100 -r 0-100 -d f32    # Decode registers as float32
  oida modbus 192.168.1.100 -r 0-50 -R coil    # Read coils 0-50
  oida modbus 192.168.1.100 --test-write       # Find writable registers (safe)
  oida modbus 192.168.1.100 --monitor -r 0-10  # Watch registers in real-time

Type-Aware Write Operations (use -d to specify encoding type):
  oida modbus 192.168.1.100 -w 100=3.14159 -d f32 --confirm   # Write float32
  oida modbus 192.168.1.100 -w 100=-1000000 -d i32 --confirm  # Write int32
  oida modbus 192.168.1.100 -w 100=Hello -d str --confirm     # Write string
  oida modbus 192.168.1.100 -w 100=DEADBEEF -d hex --confirm  # Write hex bytes
  oida modbus 192.168.1.100 -w 100=1234 -d bcd --confirm      # Write BCD value

Type-Aware Fuzzing (use -d for edge-case payloads per type):
  oida modbus 192.168.1.100 --fuzz -r 0-10 --confirm           # Raw byte fuzz
  oida modbus 192.168.1.100 --fuzz -r 0-10 -d f32 --confirm    # Float32 edge cases
  oida modbus 192.168.1.100 --fuzz -r 0-10 -d i32 --confirm    # Int32 boundaries
  oida modbus 192.168.1.100 --fuzz --fuzz-mode function --confirm        # Fuzz FC 65-127
  oida modbus 192.168.1.100 --fuzz --fuzz-mode full -r 0-10 -d f32 --confirm  # Full fuzz

Map-Based Fuzzing (use vendor register map for types and addresses):
  oida modbus 192.168.1.100 --fuzz --register-map schneider-m340 --confirm
  oida modbus 192.168.1.100 --fuzz --register-map siemens-s7-1200 --confirm

SunSpec Discovery (solar inverters, meters, battery controllers):
  oida modbus 192.168.1.100 -S                   # Discover SunSpec models
  oida modbus 192.168.1.100 -S -v                # Verbose (show raw hex, types)
  oida modbus 192.168.1.100 --sunspec-assess     # Discover + security assessment

Custom Function Codes:
  oida modbus 192.168.1.100 --raw-fc 65 --payload "01 02 03"
  oida modbus 192.168.1.100 --raw-fc 65 --payload-hex "0102"
""",
    )

    # Target (positional, optional for --list-maps)
    modbus_parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address, CIDR range, IP range, hostname, or file",
    )

    # Network Options (--port, --timeout)
    network_group = add_network_options(modbus_parser, default_port=502)
    network_group.add_argument(
        "--udp", action="store_true", help="Use UDP transport instead of TCP"
    )
    network_group.add_argument(
        "--rtu-over-tcp",
        action="store_true",
        help="Use RTU framing over TCP (for serial-to-Ethernet gateways)",
    )
    network_group.add_argument(
        "--ascii-over-tcp",
        action="store_true",
        help="Use ASCII framing over TCP (for serial-to-Ethernet gateways)",
    )

    # TLS Options (--tls, --tls-cert, --tls-key, --tls-ca, --tls-insecure)
    add_tls_options(modbus_parser, default_tls_port=802)

    # Serial/RTU Options (--serial-port, --baudrate, --parity)
    serial_group = add_serial_options(modbus_parser)
    serial_group.add_argument(
        "--ascii",
        action="store_true",
        help="Use ASCII framing instead of RTU for serial communication",
    )

    # Read Operations (most common use case - put first)
    read_group = modbus_parser.add_argument_group("Read Operations (FC 1-4)")
    read_group.add_argument(
        "-r",
        "--scan-range",
        type=str,
        metavar="RANGE",
        help='Read registers in range (e.g., "0-100", "1000-1050", "0,10,20")',
    )
    read_group.add_argument(
        "-R",
        "--register-type",
        choices=["holding", "input", "coil", "discrete", "all"],
        default="holding",
        help="Register type: holding (FC 3), input (FC 4), coil (FC 1), discrete (FC 2)",
    )

    # Modbus Core Options
    modbus_group = modbus_parser.add_argument_group("Modbus Options")
    modbus_group.add_argument(
        "--unit-id",
        type=bounded_int(0, 247),
        default=None,
        help="Modbus unit ID / slave ID (0-247, default: 1)",
    )
    modbus_group.add_argument(
        "-U",
        "--discover-units",
        action="store_true",
        help="Discover active Modbus unit IDs",
    )
    modbus_group.add_argument(
        "--unit-range",
        type=str,
        default="1-247",
        metavar="RANGE",
        help="Unit ID range for discovery (default: 1-247)",
    )
    modbus_group.add_argument(
        "--broadcast",
        action="store_true",
        help="Broadcast mode (unit ID 0) - write to all slaves, no response expected (serial RTU only)",
    )

    # SunSpec Discovery
    sunspec_group = modbus_parser.add_argument_group("SunSpec Discovery")
    sunspec_group.add_argument(
        "-S",
        "--sunspec",
        action="store_true",
        help="Discover SunSpec models (probes marker at 40000/0/50000, walks model chain)",
    )
    sunspec_group.add_argument(
        "--sunspec-assess",
        action="store_true",
        help="Run security assessment on discovered SunSpec models (implies -S)",
    )

    # Function Code Scanning
    fc_group = modbus_parser.add_argument_group("Function Code Scanning")
    fc_group.add_argument(
        "--scan-fc",
        action="store_true",
        help="Enumerate supported function codes (shows detailed output)",
    )
    fc_group.add_argument(
        "--fc-all",
        action="store_true",
        help="Scan all function codes (1-127)",
    )
    fc_group.add_argument(
        "--fc-range",
        type=str,
        default="1-8,11,12,15-17,20-23,43",
        metavar="RANGE",
        help="Range of function codes to enumerate (default: common PLC FCs)",
    )

    # Write Operations (FC 5-6, 15-16)
    write_group = modbus_parser.add_argument_group("Write Operations (FC 5-6, 15-16)")
    write_group.add_argument(
        "-w",
        "--write",
        type=str,
        metavar="ADDR=VALUE",
        help=(
            "Write register(s) at ADDR. Use -d TYPE for typed encoding: "
            "-w 100=3.14 -d f32 writes float to regs 100-101. "
            "Without -d, VALUE is raw integer. Requires --confirm"
        ),
    )
    write_group.add_argument(
        "--write-coil",
        type=str,
        metavar="ADDR=0|1",
        help="FC 5: Write single coil (requires --confirm)",
    )
    write_group.add_argument(
        "--write-multiple",
        type=str,
        metavar="ADDR=V1,V2,V3",
        help="FC 16: Write multiple registers (requires --confirm)",
    )
    write_group.add_argument(
        "--write-multiple-coils",
        type=str,
        metavar="ADDR=1,0,1,1",
        help="FC 15: Write multiple coils (requires --confirm)",
    )
    write_group.add_argument(
        "--test-write",
        action="store_true",
        help="Test write access by writing same value back (safest)",
    )
    write_group.add_argument(
        "--test-write-thorough",
        action="store_true",
        help="Test write by temporarily changing then restoring value",
    )
    write_group.add_argument(
        "--restore-on-exit", action="store_true", help="Restore original values after write test"
    )

    # Diagnostics (FC 8)
    diag_group = modbus_parser.add_argument_group("Diagnostics (FC 8)")
    diag_group.add_argument(
        "--diag",
        nargs="?",
        const="all",
        metavar="TESTS",
        help="Run diagnostics: all, echo, counters, clear, restart, register",
    )
    diag_group.add_argument(
        "--diag-data",
        metavar="HEX",
        help="Custom echo data for diagnostic test (e.g. 0x1234)",
    )

    # Device Identification (FC 43/14)
    mei_group = modbus_parser.add_argument_group("Device Identification (FC 43/14)")
    mei_group.add_argument(
        "-i",
        "--identify",
        action="store_true",
        help="Confirm Modbus device is accessible (minimal probe)",
    )
    mei_group.add_argument(
        "--mei-object",
        choices=["basic", "regular", "extended", "specific", "all"],
        default="all",
        help="MEI object category to read (default: all)",
    )
    mei_group.add_argument(
        "--mei-object-id", type=int, metavar="ID", help="Specific MEI object ID (0x00-0xFF)"
    )
    mei_group.add_argument(
        "--server-id",
        action="store_true",
        help="Read Server ID (FC 17) - device ID, run status, vendor info",
    )
    mei_group.add_argument(
        "--exception-status",
        action="store_true",
        help="Read Exception Status (FC 7) - 8 status bits from device",
    )

    # CANopen MEI (FC 43/13) - CiA 309-2
    canopen_group = modbus_parser.add_argument_group("CANopen MEI (FC 43/13 - CiA 309-2)")
    canopen_group.add_argument(
        "--canopen-read",
        type=str,
        metavar="NODE:INDEX:SUBINDEX",
        help="Read CANopen object via MEI 43/13 (e.g., 1:0x1000:0 for device type)",
    )
    canopen_group.add_argument(
        "--canopen-write",
        type=str,
        metavar="NODE:INDEX:SUBINDEX=VALUE",
        help="Write CANopen object via MEI 43/13 (requires --confirm)",
    )
    canopen_group.add_argument(
        "--canopen-info",
        action="store_true",
        help="Read CANopen gateway info via MEI 43/13",
    )

    # Communication Events (FC 11-12)
    events_group = modbus_parser.add_argument_group("Communication Events (FC 11-12)")
    events_group.add_argument(
        "--events", action="store_true", help="Read event counter (FC 11) and log (FC 12)"
    )

    # File Records (FC 20-21)
    file_group = modbus_parser.add_argument_group("File Records (FC 20-21)")
    file_group.add_argument(
        "--file-read",
        type=str,
        metavar="FILE:REC[:LEN]",
        help="FC 20: Read file record (file_number:record_number[:length])",
    )
    file_group.add_argument(
        "--file-write",
        type=str,
        metavar="FILE:REC:DATA",
        help="FC 21: Write file record (requires --confirm)",
    )

    # Atomic Operations (FC 22-23)
    atomic_group = modbus_parser.add_argument_group("Atomic Operations (FC 22-23)")
    atomic_group.add_argument(
        "--mask-write",
        type=str,
        metavar="ADDR:AND:OR",
        help="FC 22: Mask write register (address:and_mask:or_mask)",
    )
    atomic_group.add_argument(
        "--atomic-rw",
        type=str,
        metavar="READ:WRITE",
        help="FC 23: Atomic read-write (read_addr-count:write_addr=val1,val2...)",
    )

    # FIFO Queue (FC 24)
    fifo_group = modbus_parser.add_argument_group("FIFO Queue (FC 24)")
    fifo_group.add_argument(
        "--fifo", type=int, metavar="ADDR", help="Read FIFO queue at pointer address"
    )

    # Data Decoding/Encoding
    decode_group = modbus_parser.add_argument_group("Data Decoding/Encoding")
    decode_group.add_argument(
        "-d",
        "--decode",
        type=str,
        metavar="TYPE",
        help=(
            "Data type for decoding reads AND encoding writes/fuzzes. "
            "Types: f32, f64, i16, i32, i64, u16, u32, u64, str, hex, bits, bcd. "
            "Aliases: float, double, int, uint, string, text"
        ),
    )
    decode_group.add_argument(
        "-e",
        "--endian",
        choices=["big", "little", "big-swap", "little-swap"],
        default="big",
        help="Byte/word order for encoding and decoding (default: big)",
    )
    decode_group.add_argument(
        "--decode-all",
        action="store_true",
        help="Show all possible decodings for each register group",
    )
    decode_group.add_argument(
        "-W",
        "--decode-width",
        type=int,
        metavar="N",
        help="Registers per value (str: chars, custom grouping: N regs)",
    )
    decode_group.add_argument(
        "--filter-zero",
        action="store_true",
        help="Hide registers with zero/null values",
    )
    decode_group.add_argument(
        "--register-map",
        type=str,
        metavar="MAP",
        help=(
            "Use vendor register map for decoding or fuzzing. "
            "With --fuzz, fuzzes writable (rw/w) registers by default. "
            "Add --fuzz-all-access to include read-only registers. "
            "(e.g., schneider-m340, siemens-s7-1200)"
        ),
    )
    decode_group.add_argument(
        "--list-maps",
        action="store_true",
        help="List available register maps and exit",
    )
    decode_group.add_argument(
        "--read-name",
        type=str,
        metavar="NAME",
        help="Read register by friendly name from register map",
    )
    decode_group.add_argument(
        "--write-name",
        type=str,
        metavar="NAME=VALUE",
        help="Write register by friendly name (requires --confirm)",
    )
    decode_group.add_argument(
        "--list-names",
        action="store_true",
        help="List all named registers in the register map",
    )
    decode_group.add_argument(
        "--search-name",
        type=str,
        metavar="QUERY",
        help="Search register names in the register map",
    )

    # Monitor Mode (--monitor, --interval, --duration)
    monitor_group = add_monitor_options(modbus_parser)
    monitor_group.add_argument(
        "--on-change", action="store_true", help="Only output on value changes"
    )
    monitor_group.add_argument(
        "--log-file", type=str, metavar="FILE", help="Log monitored values to file"
    )

    # Scan Options group (used below for --scan-mode etc.); --threads/--delay/
    # --retries are not wired in the modbus scanner, so they stay disabled.
    scan_group = add_scan_options(
        modbus_parser, include_threads=False, include_delay=False, include_retries=False
    )
    scan_group.add_argument(
        "--scan-mode",
        choices=["discovery", "registers", "full", "quick"],
        default="discovery",
        help="Scan mode (default: discovery)",
    )
    scan_group.add_argument(
        "--max-registers",
        type=int,
        default=125,
        metavar="N",
        help="Maximum registers per read request (default: 125)",
    )

    # Custom Function Codes
    raw_fc_group = modbus_parser.add_argument_group("Custom Function Codes")
    raw_fc_group.add_argument(
        "--raw-fc",
        "--custom-fc",
        type=int,
        metavar="FC",
        help="Send raw request to custom function code (1-127)",
    )
    raw_fc_group.add_argument(
        "--payload",
        type=str,
        metavar="DATA",
        help="Payload as hex (e.g., '01 02 0a' or '01020a0b' or @file.bin)",
    )
    raw_fc_group.add_argument(
        "--response-format",
        choices=["hex", "hexdump"],
        default="hex",
        help="Response display format: hex (compact) or hexdump (with offset)",
    )
    raw_fc_group.add_argument(
        "--save-response",
        type=str,
        metavar="FILE",
        help="Save raw response bytes to file",
    )

    # Fuzzing (--confirm, --fuzz, --fuzz-iterations)
    # Modbus fuzzes one unit ID on one connection (--fuzz-mode picks what to mutate),
    # so --fuzz-max-targets (a multi-target cap) is never read — omit it instead of
    # advertising an unused flag.
    fuzz_group = add_dangerous_options(modbus_parser, include_fuzz=True, include_max_targets=False)
    fuzz_group.add_argument(
        "--fuzz-mode",
        choices=["basic", "function", "data", "boundary", "full"],
        default="basic",
        metavar="MODE",
        help=(
            "Fuzz testing mode: "
            "basic/data/boundary=register fuzzing (use -r for range), "
            "function=FC 65-127 only, "
            "full=registers+functions. "
            "Combine with -d TYPE for type-aware payloads (e.g., -d f32 for float edge cases)"
        ),
    )
    fuzz_group.add_argument(
        "--fuzz-all-access",
        action="store_true",
        help="Fuzz all registers from map including read-only (default: only rw/w)",
    )
    fuzz_group.add_argument(
        "--fuzz-max-addresses",
        type=int,
        default=10,
        metavar="N",
        help="Maximum register addresses to fuzz (default: 10)",
    )
    fuzz_group.add_argument(
        "--enumerate-functions", action="store_true", help="Enumerate all supported function codes"
    )

    return modbus_parser
