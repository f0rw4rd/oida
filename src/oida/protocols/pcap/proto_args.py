"""
Argument parser definition for PCAP analysis protocol.

Uses the framework factory pattern for consistent CLI flags.
"""

from ...utils.proto_args_factory import (
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

    # File Extraction
    # -e/--extract-all and -E/--extract-files are aliases for the same action
    # (file carving is currently the only extraction sub-feature). They share a
    # dest so both set extract_files; --extract-all is kept for forward
    # compatibility if more extraction sub-features are added later.
    extract_group = pcap_parser.add_argument_group("File Extraction")
    extract_group.add_argument(
        "-e",
        "-E",
        "--extract-files",
        "--extract-all",
        dest="extract_files",
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
        help=(
            "Export crackable hashes for hashcat/John (writes hashcat.txt with -o, "
            "else prints to console): NTLM 5500/5600, Kerberos, IPMI 7300, iSCSI 4800, "
            "MySQL 11200, PostgreSQL 11100, SIP 11400, CRAM-MD5 10200, TACACS+ 16100, "
            "RADIUS CHAP 4800 / MS-CHAPv2 5500; John-only for VNC, HTTP Digest (hdaa), "
            "OSPF/RIP (net-md5)"
        ),
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

    # Output Options (--full-width, --json-log, -o/-f/-v/-d) come from the shared
    # std_parser parent (cli.py), which injects them into every protocol
    # subparser, so they are accepted both before and after the subcommand.

    return pcap_parser
