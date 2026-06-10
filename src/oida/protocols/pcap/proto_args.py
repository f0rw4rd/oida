"""
Argument parser definition for PCAP analysis protocol.

Uses the framework factory pattern for consistent CLI flags.
"""

from ...utils.proto_args_factory import (
    add_full_width_and_json_log,
    create_protocol_parser,
)


def proto_args(parser, parents):
    """Register pcap-specific arguments"""
    pcap_parser = create_protocol_parser(
        parser,
        name="pcap",
        help_text="Offline PCAP analysis (credentials, ICS traffic, DNS, files)",
        description=(
            "Analyze pcap/pcapng files offline. Extracts credentials, "
            "ICS protocol traffic, DNS records, TLS certificates, and "
            "carved files via PyShark streaming pipeline."
        ),
        parents=parents,
        epilog="""
Examples:
  oida pcap capture.pcap                          # Full analysis (all listeners)
  oida pcap capture.pcap --quick                  # Quick scan (core protocols only)
  oida pcap capture.pcap -p ics                   # ICS protocols only
  oida pcap capture.pcap -p modbus,dnp3           # Specific protocols
  oida pcap capture.pcap --category credential    # All credential listeners
  oida pcap capture.pcap --exclude routing,fhrp   # Skip routing/FHRP
  oida pcap capture.pcap -e                       # All extractions (file carving)
  oida pcap capture.pcap -E                       # Extract files (HTTP, SMB, etc.)
  oida pcap capture.pcap --list-listeners         # Show available listeners

Listener categories:
  ics         Modbus, IEC104, OPC UA, S7comm, DNP3, BACnet, EtherNet/IP, FINS, MMS
  credential  FTP, Telnet, HTTP, LDAP, Kerberos, NTLM, databases, RADIUS, etc.
  network     TLS, DNS, HTTP, SNMP, SMB, IGMP
  routing     OSPF, EIGRP, RIP, PIM, BGP
  fhrp        HSRP, GLBP, VRRP
""",
    )

    pcap_parser.add_argument(
        "target",
        help="Path to pcap/pcapng file",
    )

    # Listener Filtering
    filter_group = pcap_parser.add_argument_group("Listener Filtering")
    filter_group.add_argument(
        "-p",
        "--protocols",
        type=str,
        default=None,
        metavar="LIST",
        help="Filter listeners by name or tag (e.g. ics, credential, modbus,ftp)",
    )
    filter_group.add_argument(
        "--category",
        type=str,
        default=None,
        metavar="LIST",
        help="Filter by category: ics, credential, network, routing, fhrp",
    )
    filter_group.add_argument(
        "--exclude",
        type=str,
        default=None,
        metavar="LIST",
        help="Exclude listeners by name, tag, or category",
    )
    filter_group.add_argument(
        "--quick",
        action="store_true",
        default=False,
        help="Quick scan preset (DNS, TLS, HTTP, FTP, Telnet, SMB, SNMP, core ICS)",
    )
    filter_group.add_argument(
        "--list-listeners",
        action="store_true",
        default=False,
        help="Show available listeners and exit",
    )
    filter_group.add_argument(
        "-s",
        "-S",
        "--stats",
        action="store_true",
        default=False,
        help="Show traffic statistics (protocol hierarchy, conversations, open ports)",
    )
    filter_group.add_argument(
        "-A",
        "--assets",
        action="store_true",
        default=False,
        help="Show discovered asset inventory table after analysis",
    )

    filter_group.add_argument(
        "-X",
        "--x509",
        action="store_true",
        default=False,
        help="Parse x509 certificates and store security findings",
    )

    # Extract All
    filter_group.add_argument(
        "-e",
        "--extract-all",
        action="store_true",
        default=False,
        help="Enable all extractions (-E file carving)",
    )

    # File Extraction
    extract_group = pcap_parser.add_argument_group("File Extraction")
    extract_group.add_argument(
        "-E",
        "--extract-files",
        action="store_true",
        default=False,
        help="Extract files from PCAP (HTTP, SMB, FTP, TFTP, DICOM)",
    )
    extract_group.add_argument(
        "--extract-dir",
        type=str,
        default=None,
        help="Output directory for extracted files (default: auto)",
    )
    extract_group.add_argument(
        "--extract-protocols",
        type=str,
        default="http,smb,ftp-data,tftp,dicom,imf",
        help="Protocols to extract (comma-separated, default: all)",
    )

    # Hash Export
    hash_group = pcap_parser.add_argument_group("Hash Export")
    hash_group.add_argument(
        "--hashcat",
        action="store_true",
        default=False,
        help="Export crackable hashes in hashcat-compatible format (NTLM, Kerberos, HTTP Digest, SIP, VNC)",
    )

    # Protocol Dissection
    dissect_group = pcap_parser.add_argument_group("Protocol Dissection")
    dissect_group.add_argument(
        "--decode-as",
        type=str,
        default=None,
        metavar="HINTS",
        help=(
            "tshark decode-as hints for non-standard ports, semicolon-separated. "
            "Example: 'tcp.port==13600,mqtt;tcp.port==12001,opcua'"
        ),
    )

    # Output Options (--full-width / -W and --json-log; -o/-f/-v/-d come from
    # the main parser). Without this, -W/--full-width is only accepted *before*
    # the subcommand and the assets table always truncates to terminal width.
    output_group = pcap_parser.add_argument_group("Output Options")
    add_full_width_and_json_log(output_group, include_short=True)

    return pcap_parser
