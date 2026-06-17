"""PROFINET protocol CLI arguments.

Migrated to proto_args_factory in §3 sync. Profinet keeps its local
``--fuzz`` (nargs='?' choices=['basic','full']) and its custom target
help (target = interface OR IP) — neither maps cleanly onto the factory
helpers, so we use the factory only for the parser-construction
boilerplate.
"""

import argparse

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
)


def proto_args(parser, parents):
    """Register PROFINET-specific arguments.

    Args:
        parser: argparse subparsers object
        parents: List of parent parsers to inherit from

    Returns:
        argparse.ArgumentParser: PROFINET protocol subparser
    """
    examples_epilog = """
Examples:
  oida profinet eth0                           # Discover devices + read I&M
  oida profinet eth0 --no-rpc                  # DCP discovery only
  oida profinet eth0 -s                        # Show slot/subslot structure
  oida profinet eth0 -e                        # Enumerate known indices (~50)
  oida profinet eth0 -e --slot 1               # Enumerate slot 1 (all subslots)
  oida profinet eth0 -e --slot 2/1             # Enumerate slot 2, subslot 1
  oida profinet eth0 --enum-smart              # Smart enum with adaptive probing
  oida profinet eth0 --gsdml device.xml -e     # Enumerate using GSDML indices
  oida profinet eth0 --flash -m 00:01:02:03:04:05  # Flash device LED
  oida profinet eth0 --set-name "plc-01" -m 00:01:02:03:04:05
  oida profinet 192.168.10.2 -R -V 0x02B8 -D 0x07A3  # RPC-only mode
  oida profinet eth0 --topology                       # Read port topology + LLDP peers
  oida profinet eth0 --module-diff                    # Check configuration mismatches
  oida profinet eth0 --alarms                         # Read alarm data
  oida profinet eth0 --write-im1 "Motor A" "Hall 3" --confirm  # Write I&M1
  oida profinet eth0 --write-im2 "2025-01-15" --confirm        # Write I&M2
  oida profinet eth0 --write-im3 "Pump Station" --confirm      # Write I&M3

Security Testing:
  oida profinet eth0 -e --test-write --confirm       # Find RW indices
  oida profinet eth0 -e --detect-write-only --confirm  # Detect write-only
  oida profinet eth0 --fuzz --confirm                # Fuzz RW indices (I&M1-3)
  oida profinet eth0 --fuzz full --confirm           # Full fuzzing with overflow
  oida profinet eth0 --fuzz --fuzz-indices 0xAFF1 --confirm  # Fuzz specific
"""

    profinet_parser = create_protocol_parser(
        parser,
        name="profinet",
        help_text="PROFINET DCP/RPC scanner",
        description="Discover and interact with PROFINET IO devices",
        parents=parents,
        epilog=examples_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    add_target_argument(
        profinet_parser,
        help_text="Network interface for DCP discovery, or IP address with --rpc-only",
    )

    # Discovery options
    discovery_group = profinet_parser.add_argument_group("Discovery Options")

    discovery_group.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=3.0,
        help="Discovery timeout in seconds (default: 3.0)",
    )

    discovery_group.add_argument(
        "--no-rpc",
        dest="no_rpc",
        action="store_true",
        help="DCP discovery only, skip RPC operations",
    )

    # RPC operations
    rpc_group = profinet_parser.add_argument_group("RPC Operations")

    rpc_group.add_argument(
        "-R",
        "--rpc-only",
        action="store_true",
        help="Skip DCP discovery, connect directly via RPC (target must be IP)",
    )

    rpc_group.add_argument(
        "-V",
        "--vendor-id",
        type=lambda x: int(x, 0),
        default=0,
        help="Vendor ID for RPC-only (hex: 0x02B8 or decimal)",
    )

    rpc_group.add_argument(
        "-D",
        "--device-id",
        type=lambda x: int(x, 0),
        default=0,
        help="Device ID for RPC-only (hex: 0x07A3 or decimal)",
    )

    rpc_group.add_argument(
        "--no-read-im",
        dest="read_im",
        action="store_false",
        default=True,
        help="Disable I&M data reading",
    )

    rpc_group.add_argument(
        "--read-diagnosis",
        action="store_true",
        help="Read diagnosis data via RPC",
    )

    rpc_group.add_argument(
        "--topology",
        action="store_true",
        help="Read physical topology (PDRealData) - port link states and LLDP peers",
    )

    rpc_group.add_argument(
        "--module-diff",
        action="store_true",
        help="Read ModuleDiffBlock - compare expected vs actual module configuration",
    )

    rpc_group.add_argument(
        "--alarms",
        action="store_true",
        help="Read alarm data from device",
    )

    rpc_group.add_argument(
        "--write-im1",
        nargs=2,
        metavar=("TAG_FUNC", "TAG_LOC"),
        help="Write I&M1 tag function and location (requires --confirm)",
    )

    rpc_group.add_argument(
        "--write-im2",
        metavar="DATE",
        help="Write I&M2 installation date (max 16 chars, requires --confirm)",
    )

    rpc_group.add_argument(
        "--write-im3",
        metavar="DESCRIPTOR",
        help="Write I&M3 descriptor (max 54 chars, requires --confirm)",
    )

    rpc_group.add_argument(
        "-s",
        "--slots",
        action="store_true",
        help="Discover and display slot/subslot structure",
    )

    rpc_group.add_argument(
        "--slot",
        type=str,
        help="Select slot/subslot: '1' (all subslots) or '1/1' (specific)",
    )

    rpc_group.add_argument(
        "-e",
        "--enum",
        action="store_true",
        help="Enumerate all known record indices (~50)",
    )

    rpc_group.add_argument(
        "--enum-all",
        action="store_true",
        help="Enumerate ALL possible indices (0x0000-0xFFFF, ~65k) - SLOW",
    )

    rpc_group.add_argument(
        "--enum-smart",
        action="store_true",
        help="Smart enumeration: scan key ranges + probe user space at 0x100 intervals",
    )

    rpc_group.add_argument(
        "--enum-range",
        help="Enumerate custom index range (e.g., 0x8000-0x80FF or 0xAFF0-0xAFF5)",
    )

    rpc_group.add_argument(
        "--gsdml",
        metavar="FILE",
        help="Load GSDML file (.xml or .zip) to get device-specific indices",
    )

    rpc_group.add_argument(
        "-x",
        "--show-data",
        dest="show_data",
        action="store_true",
        default=False,
        help="Show raw hex data for readable indices",
    )

    rpc_group.add_argument(
        "-r",
        "--read-index",
        help="Read specific index (e.g., 0xAFF0 or 0xF841)",
    )

    rpc_group.add_argument(
        "-w",
        "--write-index",
        help="Write to index: INDEX:HEXDATA (e.g., 0x8029:01020304 or 0xAFF1:48656C6C6F)",
    )

    rpc_group.add_argument(
        "--test-write",
        action="store_true",
        help="Test write access (requires --confirm)",
    )

    # Device targeting and write operations
    target_group = profinet_parser.add_argument_group("Device Targeting")

    target_group.add_argument(
        "-m",
        "--mac",
        dest="mac_address",
        help="Target MAC address for unicast operations",
    )

    target_group.add_argument(
        "--flash",
        action="store_true",
        help="Flash device LED for identification (requires -m)",
    )

    target_group.add_argument(
        "-n",
        "--set-name",
        help="Set station name (requires -m)",
    )

    target_group.add_argument(
        "--set-ip",
        help="Set IP: IP/CIDR/GATEWAY (e.g., 192.168.1.100/24/192.168.1.1)",
    )

    target_group.add_argument(
        "--reset-factory",
        action="store_true",
        help="Reset device to factory defaults (requires -m)",
    )

    # Security Testing
    security_group = profinet_parser.add_argument_group("Security Testing")

    security_group.add_argument(
        "--fuzz",
        nargs="?",
        const="basic",
        choices=["basic", "boundary", "full"],
        metavar="MODE",
        help="Fuzz RW indices: basic=type-aware, boundary=limits, full=all mutations",
    )

    security_group.add_argument(
        "--fuzz-indices",
        type=str,
        metavar="INDICES",
        help="Specific indices to fuzz (e.g., '0xAFF1,0xAFF2' or '0xAFF1-0xAFF3')",
    )

    security_group.add_argument(
        "--fuzz-iterations",
        type=int,
        default=10,
        metavar="N",
        help="Fuzz iterations per index (default: 10)",
    )

    security_group.add_argument(
        "--detect-write-only",
        action="store_true",
        help="Detect write-only indices by probing (requires --confirm)",
    )

    security_group.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (required for --fuzz, --detect-write-only, writes)",
    )

    return profinet_parser
