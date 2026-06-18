"""
Argument parser definition for EtherNet/IP protocol

This module registers EtherNet/IP-specific command-line arguments.
"""


def proto_args(parser, parents):
    """Register EtherNet/IP-specific arguments"""
    enip_parser = parser.add_parser(
        "ethernetip",
        help="EtherNet/IP scanner",
        description="Scan and interact with EtherNet/IP devices",
        parents=parents,
    )

    enip_parser.add_argument(
        "target",
        help="Target IP address, CIDR range, IP range, or file",
    )

    # Network Options
    network_group = enip_parser.add_argument_group("Network Options")
    network_group.add_argument(
        "--port", type=int, default=44818, help="EtherNet/IP port (default: 44818)"
    )
    # EtherNet/IP Discovery Options
    enip_group = enip_parser.add_argument_group("EtherNet/IP Discovery")
    enip_group.add_argument(
        "--enumerate-all",
        "-a",
        action="store_true",
        help="Enable all enumeration (identity, services, interfaces, objects, security)",
    )
    enip_group.add_argument(
        "-i",
        "--list-identity",
        action="store_true",
        help="Send ListIdentity command to get device info",
    )
    enip_group.add_argument(
        "--list-services",
        action="store_true",
        help="Send ListServices command to enumerate CIP services",
    )
    enip_group.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Send ListInterfaces command to enumerate network interfaces",
    )
    enip_group.add_argument(
        "-e",
        "--enumerate-objects",
        action="store_true",
        help="Enumerate CIP objects (classes 0x01-0xFF)",
    )
    enip_group.add_argument(
        "-d",
        "--deep-scan",
        action="store_true",
        help="Deep scan: parse complex CIP objects (Parameter, File, Port, vendor-specific)",
    )
    enip_group.add_argument(
        "--full-scan",
        action="store_true",
        help="Upload tag database and UDTs (Rockwell Logix only, slower)",
    )
    enip_group.add_argument(
        "--show-udts",
        action="store_true",
        help="Display UDT/AOI structure definitions (Rockwell Logix only)",
    )
    enip_group.add_argument(
        "--enumerate-slot-objects",
        action="store_true",
        help="Enumerate CIP objects on each backplane slot (requires --discover-routes)",
    )
    enip_group.add_argument(
        "--read-slot-io",
        action="store_true",
        help="Read I/O data (assemblies) from each backplane slot (requires --discover-routes)",
    )
    enip_group.add_argument(
        "--full-enum",
        action="store_true",
        help="Full class enumeration: probe all classes 0x01-0xFF instead of using Message Router Object List",
    )
    enip_group.add_argument(
        "--dump-tags",
        action="store_true",
        help="Dump all tags with values (Rockwell Logix only, not standard CIP)",
    )
    enip_group.add_argument(
        "--tag-output",
        type=str,
        default="",
        help="Output directory for tag dump files (default: current directory)",
    )

    # CIP Options
    cip_group = enip_parser.add_argument_group("CIP Options")
    cip_group.add_argument(
        "--maxclass",
        type=int,
        default=0,
        help="Highest CIP class to test (0=tag-based discovery, default: 0)",
    )
    cip_group.add_argument(
        "--exploreclass",
        type=str,
        default="",
        help="CIP class IDs to enumerate in detail (e.g., 0x1,2,0x9f)",
    )
    cip_group.add_argument(
        "--maxattributes",
        type=int,
        default=100,
        help="Max attributes to test per class (default: 100)",
    )
    cip_group.add_argument(
        "--route-path",
        type=str,
        default="",
        help="CIP route path for backplane routing (e.g., '1/2,1/0' = bp/slot2->bp/slot0)",
    )
    cip_group.add_argument(
        "--slot",
        type=int,
        default=0,
        help="Target CPU slot number (default: 0)",
    )
    cip_group.add_argument(
        "--discover-routes",
        action="store_true",
        help="Discover chassis topology: ports, slots, and valid routes",
    )

    # Security Options
    security_group = enip_parser.add_argument_group("Security Options")
    security_group.add_argument(
        "--check-security",
        action="store_true",
        default=True,
        help="Check for CIP Security support (default: enabled)",
    )
    security_group.add_argument(
        "--no-check-security",
        dest="check_security",
        action="store_false",
        help="Disable CIP Security check",
    )
    security_group.add_argument(
        "--write",
        action="store_true",
        help="Test write access to attributes (use with caution)",
    )
    security_group.add_argument(
        "--fuzz",
        action="store_true",
        help="Fuzz writable attributes (requires --write, may cause DoS)",
    )
    security_group.add_argument(
        "--dump-security",
        action="store_true",
        default=True,
        help="Dump detailed CIP Security settings (enabled by default)",
    )
    security_group.add_argument(
        "--no-dump-security",
        dest="dump_security",
        action="store_false",
        help="Disable CIP Security settings dump",
    )

    # File Operations
    file_group = enip_parser.add_argument_group("File Operations")
    file_group.add_argument(
        "-D",
        "--download-files",
        action="store_true",
        help="Download files from File Object (0x37) - firmware, configs, logs",
    )
    file_group.add_argument(
        "--file-output",
        type=str,
        default="",
        help="Directory to save downloaded files (default: current directory)",
    )
    file_group.add_argument(
        "--max-file-size",
        type=int,
        default=65536,
        help="Maximum file size to download in bytes (default: 65536)",
    )

    # Attack Options (DANGEROUS - require explicit confirmation)
    attack_group = enip_parser.add_argument_group("Attack Options (DANGEROUS)")
    attack_group.add_argument(
        "--cpu-stop",
        action="store_true",
        help="Send CPU STOP command (WILL HALT PLC - requires --confirm)",
    )
    attack_group.add_argument(
        "--crash-ethernet",
        action="store_true",
        help="Crash Ethernet card (WILL DISCONNECT DEVICE - requires --confirm)",
    )
    attack_group.add_argument(
        "--reset-ethernet",
        action="store_true",
        help="Reset Ethernet interface (may briefly disconnect device)",
    )
    attack_group.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous attack operations (required for --cpu-stop, --crash-ethernet)",
    )

    return enip_parser
