"""
Argument parser definition for unified network discovery protocol
"""


def proto_args(parser, parents):
    """Register discovery-specific arguments"""
    discovery_parser = parser.add_parser(
        "discovery",
        help="Unified network discovery (passive + active)",
        description="Discover devices on a network interface using passive listening and active probing.",
        parents=parents,
    )

    discovery_parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Network interface (e.g., eth0, enp0s3)",
    )

    # Main options
    discovery_parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=3,
        help="Discovery timeout in seconds (default: 3)",
    )
    discovery_parser.add_argument(
        "-a",
        "--active",
        action="store_true",
        default=False,
        help="Enable active probing (ARP, DCP, SSDP, DNS-SD, ICS protocols)",
    )
    discovery_parser.add_argument(
        "-P",
        "--no-passive",
        action="store_true",
        default=False,
        help="Disable passive listening (LLDP, mDNS, CDP, etc.)",
    )
    discovery_parser.add_argument(
        "-A",
        "--arp",
        action="store_true",
        default=False,
        help="ARP scan only (disables all other discovery methods)",
    )
    discovery_parser.add_argument(
        "--no-arp",
        action="store_true",
        default=False,
        help="Disable ARP scanning in active mode",
    )
    discovery_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help="Force large ARP scans without confirmation (>255 hosts)",
    )
    discovery_parser.add_argument(
        "-R",
        "--rate-limit",
        type=float,
        default=0,
        dest="rate_limit",
        metavar="PPS",
        help="Rate limit for active scans in packets/sec (0=unlimited, e.g., 10 for OT-safe scanning)",
    )

    # Useful filters
    discovery_parser.add_argument(
        "--ics-only",
        action="store_true",
        default=False,
        help="Only show industrial/ICS devices",
    )
    discovery_parser.add_argument(
        "-s",
        "--subnet",
        type=str,
        help="Subnet for ARP scan (auto-detected if not specified)",
    )

    # Unreachable IP detection
    scope_group = discovery_parser.add_argument_group("Reachability Detection")
    scope_group.add_argument(
        "--no-reach-warnings",
        action="store_true",
        default=False,
        dest="no_scope_warnings",  # Keep internal name for compatibility
        help="Disable unreachable IP warnings (IPs not in interface subnet)",
    )
    scope_group.add_argument(
        "--expected-network",
        type=str,
        metavar="CIDR",
        help="Expected network CIDR for reachability checking (default: auto-detect)",
    )

    # Continuous mode
    discovery_parser.add_argument(
        "-c",
        "--continuous",
        action="store_true",
        default=False,
        help="Run continuously until Ctrl+C",
    )
    discovery_parser.add_argument(
        "--scan-interval",
        type=int,
        default=300,
        help="Interval between active scans in continuous mode (default: 300s)",
    )

    # Protocol toggles (use --no-X to disable specific protocols)
    proto_group = discovery_parser.add_argument_group("Protocol Toggles")
    for proto, desc in [
        ("lldp", "LLDP"),
        ("dcp", "PROFINET DCP"),
        ("mdns", "mDNS/Bonjour"),
        ("ssdp", "SSDP/UPnP"),
        ("cdp", "Cisco CDP"),
        ("dns-sd", "DNS-SD"),
        ("ws-discovery", "WS-Discovery"),
        ("llmnr", "LLMNR"),
        ("knx", "KNX"),
        ("bacnet", "BACnet"),
        ("ethernetip", "EtherNet/IP"),
        ("codesys", "CODESYS"),
        ("ads", "Beckhoff ADS"),
        ("netbios", "NetBIOS"),
        ("stp", "STP"),
        ("moxa", "Moxa"),
        ("lantronix", "Lantronix"),
        ("ipv6", "IPv6"),
        ("dhcp", "DHCP"),
        ("fins", "FINS/Omron"),
        ("hsrp", "HSRP"),
        ("igmp", "IGMP"),
        ("ospf", "OSPF"),
        ("eigrp", "EIGRP"),
        ("rip", "RIP/RIPv2"),
        ("pim", "PIM"),
        ("hid", "HID Access Control"),
        ("mssql", "MS-SQL Browser"),
        ("bjnp", "Canon BJNP"),
        ("sonicwall", "SonicWall"),
        ("db2", "IBM DB2"),
        ("sybase", "Sybase ASA"),
        ("xdmcp", "XDMCP"),
        ("jenkins", "Jenkins"),
        ("pcanywhere", "PC-Anywhere"),
    ]:
        proto_group.add_argument(
            f"--no-{proto}",
            action="store_true",
            default=False,
            dest=f"no_{proto.replace('-', '_')}",
            help=f"Disable {desc} discovery",
        )

    # Packet capture
    pcap_group = discovery_parser.add_argument_group("Packet Capture")
    pcap_group.add_argument(
        "-w",
        "--pcap",
        action="store_true",
        default=False,
        help="Capture full traffic to pcap file for analysis",
    )
    pcap_group.add_argument(
        "--pcap-max-size",
        type=int,
        default=500,
        help="Max pcap file size in MB (default: 500)",
    )
    pcap_group.add_argument(
        "--pcap-filter",
        type=str,
        default="",
        help="BPF filter for pcap capture (default: capture all)",
    )

    # Enrichment options (post-discovery lookups)
    enrich_group = discovery_parser.add_argument_group("Enrichment Options")
    enrich_group.add_argument(
        "--enrich",
        action="store_true",
        default=False,
        help="Enable enrichment phase (ping, rDNS, NetBIOS, mDNS lookups)",
    )
    enrich_group.add_argument(
        "--no-ping",
        action="store_true",
        default=False,
        help="Skip ping verification in enrichment",
    )
    enrich_group.add_argument(
        "--no-rdns",
        action="store_true",
        default=False,
        help="Skip reverse DNS lookups in enrichment",
    )
    enrich_group.add_argument(
        "--no-netbios-enrich",
        action="store_true",
        default=False,
        help="Skip NetBIOS name resolution in enrichment",
    )
    enrich_group.add_argument(
        "--no-mdns-enrich",
        action="store_true",
        default=False,
        help="Skip mDNS name resolution in enrichment",
    )

    return discovery_parser
