"""
Argument parser definition for SNMP protocol.

Registers SNMP-specific command-line arguments for standalone
``oida snmp`` usage.
"""

from oida.utils.proto_args_factory import create_protocol_parser, add_network_options


def proto_args(parser, parents):
    """Register SNMP-specific arguments."""
    snmp_parser = create_protocol_parser(
        parser,
        name="snmp",
        help_text="SNMP device scanner",
        description="Query SNMP agents for system info, vendor details, host enumeration",
        parents=parents,
        epilog="""
Authentication (-C):
  -C is version-aware: plain string = community, colon-separated = SNMPv3.
  Format: -C community | -C user:authpass | -C user:authpass:privpass

  -C public                         # v1/v2c community (default)
  -C private                        # v1/v2c community 'private'
  -C public,private,SCADA           # try multiple communities
  -C admin:admin123:admin123        # v3 authPriv  (SHA + AES128)
  -C operator:oper1                 # v3 authNoPriv (SHA, no encryption)

  Override auth/priv algorithms (default: -a SHA -x AES128):
  -a (auth)  MD5 | SHA | SHA256 | SHA384 | SHA512
  -x (priv)  DES | 3DES | AES128 | AES192 | AES256

  -C admin:pass:priv                      # SHA + AES128
  -C admin:pass:priv -a SHA256 -x AES256  # SHA256 + AES256
  -C admin:pass:priv -a MD5 -x DES        # MD5 + DES (legacy)
  -C admin:pass:priv -a SHA512 -x AES192  # SHA512 + AES192
  -C admin:pass -a MD5                     # authNoPriv, MD5

  Flags match Net-SNMP (snmpget/snmpwalk) convention:
  -u user  -a PROTOCOL  -A PASSPHRASE  -x PROTOCOL  -X PASSPHRASE  -l LEVEL

SNMPv3 Brute-Force (-E, always requires --confirm):
  -E                          discover users -> brute auth -> brute priv
  -E admin                    target single user
  -E admin -A admin123        test known credentials
  -E admin -A passwords.txt   brute with wordlist
  -E users.txt -A pw.txt      both from files
  -u/-A/-X all accept a string or a file path (auto-detected).

Examples:
  oida snmp 192.168.1.1                            # Basic scan (v2c, community=public)
  oida snmp 192.168.1.1 -C admin:pass:priv         # SNMPv3 authPriv (SHA+AES128)
  oida snmp 192.168.1.0/24 -t 20                   # Scan subnet with 20 threads
  oida snmp 192.168.1.1 --default-creds --confirm   # Test ~30 ICS community strings
  oida snmp 192.168.1.1 -C communities.txt --confirm  # Brute from file
  oida snmp 192.168.1.1 -w .1.3.6.1.2.1.2.2       # Walk interface table
  oida snmp 192.168.1.1 -w list:siemens             # Walk Siemens enterprise subtrees
  oida snmp 192.168.1.1 -W                          # Walk all vendor subtrees
  oida snmp 192.168.1.1 -g .1.3.6.1.2.1.1.1.0     # GET sysDescr
  oida snmp 192.168.1.1 -w IF-MIB::ifTable -m /usr/share/snmp/mibs/
  oida snmp 192.168.1.1 -e                          # Enumerate all host tables
  oida snmp 192.168.1.1 --enum-users --confirm        # v3: discover valid usernames only
  oida snmp 192.168.1.1 --enum-users --confirm -u users.txt  # v3: test custom username list
  oida snmp 192.168.1.1 -E --confirm                # v3: discover users + brute creds
  oida snmp 192.168.1.1 -E admin -A admin123        # v3: test known creds (no --confirm)
  oida snmp 192.168.1.1 -E admin -A pw.txt --confirm  # v3: brute with wordlist
""",
    )

    # Target (positional)
    snmp_parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address, CIDR range, IP range, hostname, or file",
    )

    # Network options (--port, --timeout)
    add_network_options(snmp_parser, default_port=161)

    # SNMP options
    snmp_group = snmp_parser.add_argument_group("SNMP Options")
    snmp_group.add_argument(
        "-C",
        "--auth",
        type=str,
        default="public",
        dest="auth",
        help=(
            "SNMP credentials. Plain string = v1/v2c community (default: public). "
            "user:authpass:privpass = SNMPv3 authPriv. user:authpass = SNMPv3 authNoPriv"
        ),
    )
    snmp_group.add_argument(
        "-V",
        "--snmp-version",
        type=str,
        choices=["auto", "1", "2c", "3"],
        default="auto",
        dest="snmp_version",
        help="SNMP version (default: auto - probe v1/v2c/v3)",
    )
    snmp_group.add_argument(
        "--test-write",
        action="store_true",
        default=False,
        dest="test_write",
        help="Test if current credentials have write access (VACM check + idempotent SET probe)",
    )

    # Raw query options
    query_group = snmp_parser.add_argument_group("Raw Queries")
    query_group.add_argument(
        "-w",
        "--walk",
        nargs="?",
        const=".1.3.6.1.2.1",
        default=None,
        metavar="OID",
        help="Walk OID subtree or list:<name> (default: .1.3.6.1.2.1 = MIB-2)",
    )
    query_group.add_argument(
        "-g",
        "--get",
        type=str,
        metavar="OID[,...]",
        dest="get_oids",
        help="GET one or more OIDs (comma-separated)",
    )
    query_group.add_argument(
        "-W",
        "--walk-all",
        action="store_true",
        default=False,
        dest="walk_all",
        help="Walk all known vendor enterprise subtrees",
    )
    query_group.add_argument(
        "--set",
        nargs=3,
        metavar=("OID", "TYPE", "VALUE"),
        default=None,
        dest="set_oid",
        help=(
            "SET a single OID (requires --confirm). "
            "TYPE: i=INTEGER, s=STRING, x=HEX, o=OID, a=IPADDR"
        ),
    )
    query_group.add_argument(
        "--walk-write",
        nargs="?",
        const=".1.3.6.1.2.1",
        default=None,
        metavar="OID",
        dest="walk_write",
        help=(
            "Walk subtree then test idempotent SET on each OID (requires --confirm). "
            "Default subtree: .1.3.6.1.2.1 (MIB-2)"
        ),
    )
    query_group.add_argument(
        "-B",
        "--bulk",
        action="store_true",
        help="Use GETBULK instead of GETNEXT for walks (v2c/v3 only)",
    )

    # MIB loading
    mib_group = snmp_parser.add_argument_group("MIB Loading")
    mib_group.add_argument(
        "-m",
        "--mib-dir",
        type=str,
        action="append",
        metavar="PATH",
        dest="mib_dirs",
        help="Directory containing ASN.1 .mib files (can be repeated)",
    )

    # Community brute-force
    brute_group = snmp_parser.add_argument_group("Community Brute-Force")
    brute_group.add_argument(
        "--default-creds",
        action="store_true",
        default=False,
        dest="default_creds",
        help="Test ~30 built-in ICS community strings (requires --confirm)",
    )
    brute_group.add_argument(
        "--brute-rate",
        type=float,
        default=0.2,
        dest="brute_rate",
        metavar="SECS",
        help="Delay between brute-force attempts in seconds (default: 0.2)",
    )
    # Safety gate - required before any brute-force runs
    snmp_parser.add_argument(
        "--confirm",
        action="store_true",
        default=False,
        dest="confirm_brute",
        help=(
            "Confirm active/write intent (required for --default-creds, -E, "
            "--enum-users, --set, --walk-write)"
        ),
    )

    # SNMPv3 overrides - flag letters match Net-SNMP (snmpget/snmpwalk)
    v3_group = snmp_parser.add_argument_group("SNMPv3 Overrides (snmpget-compatible flags)")
    v3_group.add_argument(
        "-u",
        "--snmp-user",
        type=str,
        default="",
        dest="snmp_user",
        help="SNMPv3 username or wordlist file (overrides -C)",
    )
    v3_group.add_argument(
        "-a",
        "--snmp-auth-protocol",
        type=str,
        choices=["MD5", "SHA", "SHA256", "SHA384", "SHA512"],
        default="SHA",
        dest="snmp_auth_protocol",
        help="SNMPv3 auth protocol (default: SHA)",
    )
    v3_group.add_argument(
        "-A",
        "--snmp-auth-pass",
        type=str,
        default="",
        dest="snmp_auth_pass",
        help="SNMPv3 auth passphrase or wordlist file (overrides -C)",
    )
    v3_group.add_argument(
        "-x",
        "--snmp-priv-protocol",
        type=str,
        choices=["DES", "3DES", "AES128", "AES192", "AES256"],
        default="AES128",
        dest="snmp_priv_protocol",
        help="SNMPv3 privacy protocol (default: AES128)",
    )
    v3_group.add_argument(
        "-X",
        "--snmp-priv-pass",
        type=str,
        default="",
        dest="snmp_priv_pass",
        help="SNMPv3 privacy passphrase or wordlist file (overrides -C)",
    )
    v3_group.add_argument(
        "-l",
        "--snmp-security-level",
        type=str,
        choices=["noAuthNoPriv", "authNoPriv", "authPriv"],
        default="authPriv",
        dest="snmp_security_level",
        help="SNMPv3 security level (default: authPriv)",
    )

    # Host enumeration
    host_enum_group = snmp_parser.add_argument_group("Host Enumeration")
    host_enum_group.add_argument(
        "-e",
        "--enum",
        type=str,
        nargs="?",
        const="all",
        default=None,
        metavar="CATEGORY[,...]",
        help=(
            "Enumerate host tables. Bare --enum = all categories. "
            "Categories: interfaces, tcp, udp, routes, arp, cam, processes, "
            "software, storage, users, shares, traps, creds, system, services, "
            "filesystems, ipv6, extend"
        ),
    )
    host_enum_group.add_argument(
        "--enum-limit",
        type=int,
        default=0,
        metavar="N",
        dest="enum_limit",
        help="Cap entries per enumeration table (0 = built-in default caps: "
        "2000 for large tables, 500 for credential/IPv6; default: 0)",
    )

    # SNMPv3 enumeration & brute-force
    enum_group = snmp_parser.add_argument_group("SNMPv3 Brute-Force")
    enum_group.add_argument(
        "-E",
        "--enum-v3",
        type=str,
        nargs="?",
        const="",
        default=None,
        metavar="USER|FILE",
        dest="enum_v3",
        help=(
            "SNMPv3 brute-force. Bare -E = discover users then brute auth/priv. "
            "-E USER = target single user. -E users.txt = load targets from file. "
            "Combine with -A pass or -A wordlist.txt to supply passwords"
        ),
    )
    enum_group.add_argument(
        "--enum-users",
        action="store_true",
        default=False,
        dest="enum_users",
        help="SNMPv3 user enumeration only (phase 1 of -E). Discovers valid usernames via noAuthNoPriv probes",
    )
    return snmp_parser
