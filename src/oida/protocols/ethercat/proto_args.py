"""
Argument parser definition for EtherCAT protocol.

Migrated to proto_args_factory in §3 sync — uses create_protocol_parser
+ add_target_argument for the boilerplate. EtherCAT keeps its local
`-F/--fuzz` (nargs='?' with choices), its `-y` short alias for
`--confirm`, and its target=interface help override; the factory's
add_dangerous_options would clobber both, so they stay local.
"""

import argparse

from oida.utils.proto_args_factory import create_protocol_parser, add_target_argument

EXAMPLES = r"""
Examples:
  oida ethercat eth0                               # Discover slaves
  oida ethercat eth0 -i                            # Detailed info (all slaves)
  oida ethercat eth0 -S 2 -i                       # Detailed info (slave 2 only)
  oida ethercat eth0 -C                            # Scan CoE dictionary (all slaves)
  oida ethercat eth0 -S 2 -C                       # Scan CoE on slave 2 only
  oida ethercat eth0 -r '1:0x1008:0'              # Read SDO object
  oida ethercat eth0 -e --eeprom-parse             # Dump & parse EEPROM
  oida ethercat eth0 -S 3 -e                       # Dump EEPROM for slave 3
  oida ethercat eth0 -f '1:firmware.bin'           # Read file via FoE
  oida ethercat eth0 --fsoe                        # Scan FSoE safety objects
  oida ethercat eth0 -S 1 --fsoe                   # FSoE scan on slave 1

Security Testing:
  oida ethercat eth0 -F -y                         # Fuzz SDO (default mode)
  oida ethercat eth0 -S 2 -F pdo -y               # Fuzz PDO on slave 2
  oida ethercat eth0 -F all -y                     # Fuzz SDO + PDO
  oida ethercat eth0 -F --fuzz-iterations 50 -y
"""


def proto_args(parser, parents):
    """Register EtherCAT-specific arguments"""
    ethercat_parser = create_protocol_parser(
        parser,
        name="ethercat",
        help_text="EtherCAT scanner",
        description="Scan and interact with EtherCAT devices",
        parents=parents,
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    add_target_argument(
        ethercat_parser,
        help_text="Network interface for EtherCAT communication",
    )

    ethercat_group = ethercat_parser.add_argument_group("EtherCAT Options")
    ethercat_group.add_argument(
        "--interface", type=str, help="Network interface (overrides target)"
    )

    ethercat_group.add_argument(
        "-s",
        "--scan-range",
        type=str,
        default=None,
        help="Slave station address range (default: all discovered slaves)",
    )

    ethercat_group.add_argument(
        "-S",
        "--slave",
        type=int,
        metavar="N",
        help="Target a single slave for all operations (default: all slaves in scan range)",
    )

    ethercat_group.add_argument(
        "-i",
        "--device-info",
        action="store_true",
        help="Detailed device info (versions, identity, error register)",
    )

    ethercat_group.add_argument(
        "-d", "--dump", type=str, metavar="PATH", help="Directory path to dump EEPROM and SDO data"
    )

    # pysoem 1.1.x features
    advanced_group = ethercat_parser.add_argument_group("Advanced Options")

    advanced_group.add_argument(
        "-f",
        "--foe-read",
        type=str,
        metavar="SLAVE:FILENAME",
        help="Read file from slave via FoE (e.g., '1:firmware.bin')",
    )

    advanced_group.add_argument(
        "--foe-write",
        type=str,
        metavar="SLAVE:LOCALPATH",
        help="Write file to slave via FoE (e.g., '1:/path/to/file.bin')",
    )

    advanced_group.add_argument(
        "--dc-analysis",
        action="store_true",
        help="Analyze Distributed Clock synchronization",
    )

    advanced_group.add_argument(
        "-e",
        "--eeprom-dump",
        action="store_true",
        help="Dump full EEPROM contents (addresses 0x00-0x7F)",
    )

    advanced_group.add_argument(
        "--no-emergency-monitor",
        action="store_true",
        help="Disable emergency message monitoring",
    )

    advanced_group.add_argument(
        "--op-state",
        action="store_true",
        help="Transition slaves to OP state (enables outputs - use with caution!)",
    )

    advanced_group.add_argument(
        "--boot-state",
        action="store_true",
        help="Transition slaves to Bootstrap state (for FoE firmware operations)",
    )

    advanced_group.add_argument(
        "--fsoe",
        "--scan-fsoe",
        action="store_true",
        dest="scan_fsoe",
        help="Scan FSoE (Functional Safety) objects (0xF1xx/0xF9xx CoE range)",
    )

    advanced_group.add_argument(
        "--esc-registers",
        "--esc-debug",
        action="store_true",
        dest="esc_debug",
        help="Dump ESC registers for debugging (AL Status, SM config, FMMU, DC)",
    )

    # CoE interaction
    coe_group = ethercat_parser.add_argument_group("CoE Options")

    coe_group.add_argument(
        "-C",
        "--scan-coe",
        "--sdo-scan",
        action="store_true",
        dest="sdo_scan",
        help="Scan CoE object dictionary",
    )

    coe_group.add_argument(
        "--coe-range",
        type=str,
        metavar="RANGES",
        help=(
            "Custom CoE index ranges for --scan-coe (overrides defaults). "
            "Comma-separated indices or ranges with 0x prefix. "
            "E.g., '0x2000-0x3000,0xF110,0x7000-0x7FFF'"
        ),
    )

    coe_group.add_argument(
        "-r",
        "--read-coe",
        "--sdo-read",
        type=str,
        dest="sdo_read",
        metavar="[SLAVE:]INDEX:SUBINDEX",
        help="Read SDO object (e.g., '0x1008:0' or '1:0x7000:1')",
    )

    coe_group.add_argument(
        "-w",
        "--write-coe",
        "--sdo-write",
        type=str,
        dest="sdo_write",
        metavar="[SLAVE:]INDEX:SUBINDEX:VALUE",
        help="Write SDO object (e.g., '0x7000:1:0xFF' or '1:0x7000:1:0x01')",
    )

    coe_group.add_argument(
        "--eeprom-parse",
        action="store_true",
        help="Parse and display EEPROM/ESI structure (strings, SyncM, PDO)",
    )

    coe_group.add_argument(
        "--eeprom-write",
        type=str,
        metavar="[SLAVE:]OFFSET:VALUE",
        help="Write to EEPROM (e.g., '0x08:0x1234' for station alias, '1:0x10:0x06EC' for vendor ID)",
    )

    coe_group.add_argument(
        "--set-alias",
        type=str,
        metavar="[SLAVE:]ALIAS",
        help="Set station alias (e.g., '100' or '1:100')",
    )

    coe_group.add_argument(
        "--set-coe",
        type=str,
        metavar="[SLAVE:]FLAGS",
        help="Set CoE capabilities (e.g., '0x3F' for all, or 'sdo,sdo_info,complete_access')",
    )

    coe_group.add_argument(
        "--set-mailbox",
        type=str,
        metavar="[SLAVE:]PROTOCOLS",
        help="Set mailbox protocols (e.g., '0x04' for CoE, or 'coe,foe')",
    )

    # Security testing
    security_group = ethercat_parser.add_argument_group("Security Testing")

    security_group.add_argument(
        "-F",
        "--fuzz",
        nargs="?",
        const="sdo",
        choices=["sdo", "pdo", "all"],
        metavar="MODE",
        help="Fuzz testing mode: sdo=SDO objects (default), pdo=process data, all=both",
    )

    security_group.add_argument(
        "--fuzz-iterations",
        type=int,
        default=10,
        metavar="N",
        help="Fuzz iterations per target (default: 10)",
    )

    security_group.add_argument(
        "-y",
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (write/fuzz/state-change)",
    )

    return ethercat_parser
