"""
Argument parser definition for OPC UA protocol

This module registers OPC UA-specific command-line arguments
following the NXC pattern.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_auth_options,
    add_dangerous_options,
    add_discovery_options,
    add_brute_options,
    add_file_transfer_options,
    add_monitor_options,
)


def proto_args(parser, parents):
    """Register OPC UA-specific arguments"""
    opcua_parser = create_protocol_parser(
        parser,
        name="opcua",
        help_text="OPC UA scanner",
        description="Scan and interact with OPC UA servers",
        parents=parents,
        epilog="""
Examples:
  oida opcua opc.tcp://192.168.1.100:4840      # Connect and show server info
  oida opcua 192.168.1.100 --get-endpoints     # List endpoints, policies and token types
  oida opcua 192.168.1.100 --find-servers      # Ask the discovery service what it hosts
  oida opcua 192.168.1.100 --dump              # Browse the address space
  oida opcua 192.168.1.100 --dump-values       # Browse and read every value
  oida opcua 192.168.1.100 --dump-methods      # Show callable methods
  oida opcua 192.168.1.100 --dump-write        # Show writable nodes

Authentication (note: -p is --port; the short flag for --password is -P):
  oida opcua 192.168.1.100 --username admin --password s3cret
  oida opcua 192.168.1.100 -u admin -P s3cret
  oida opcua 192.168.1.100 -u users.txt -P passwords.txt   # File-driven credential testing
  oida opcua 192.168.1.100 -u users.txt -P passwords.txt --brute-rate 0.5 --continue-on-success

Encrypted sessions (Sign/SignAndEncrypt need a client keypair):
  oida opcua 192.168.1.100 --mode Sign --policy Basic256Sha256 \\
      --certificate client.der --privatekey client_key.pem --get-endpoints
  oida opcua 192.168.1.100 --mode SignAndEncrypt --policy Basic256Sha256 \\
      --certificate client.der --privatekey client_key.pem -u admin -P s3cret --dump

Browsing the address space (breadth is set by --max-depth/--max-nodes):
  oida opcua 192.168.1.100 --dump --ns 2                   # Only namespace index 2
  oida opcua 192.168.1.100 --dump --start-node "ns=2;i=1"  # Start below a known node
  oida opcua 192.168.1.100 -D --max-depth 5 --max-nodes 200  # Dump everything, bounded
  oida opcua 192.168.1.100 --dump-namespaces               # Namespace table only
  oida opcua 192.168.1.100 --dump-examples                 # Ready-to-run commands for this server

Reading and writing nodes:
  oida opcua 192.168.1.100 --node-id "ns=2;i=10"                    # Read one value
  oida opcua 192.168.1.100 --node-id "ns=2;i=10" --read-attributes  # All attributes
  oida opcua 192.168.1.100 --node-id "ns=2;i=40" --write-value 1500 --confirm
  oida opcua 192.168.1.100 --call-method StartPump --confirm
  oida opcua 192.168.1.100 --call-method SetTemperature --method-args "[21.5]" --confirm

Watching values (use --subscribe; there is no polling mode):
  oida opcua 192.168.1.100 --subscribe --duration 30
  oida opcua 192.168.1.100 --subscribe --start-node "ns=2;i=2" --duration 30
  oida opcua 192.168.1.100 --subscribe --subscription-interval 250 --duration 30
  oida opcua 192.168.1.100 --subscribe-events --duration 60      # Alarms and events

Historical data:
  oida opcua 192.168.1.100 --history-read --node-id "ns=2;i=10" --history-max 100
  oida opcua 192.168.1.100 --history-read --node-id "ns=2;i=10" \\
      --history-start 2024-01-01T00:00:00 --history-end 2024-01-02T00:00:00

File transfer (OPC UA FileType nodes):
  oida opcua 192.168.1.100 --dump-files                            # Find FileType nodes
  oida opcua 192.168.1.100 --read-file "ns=2;i=240" --file-output out.txt
  oida opcua 192.168.1.100 --write-file "ns=2;i=230" --file-data "<recipe/>" --confirm

Security assessment:
  oida opcua 192.168.1.100 --scan-writable           # Which nodes accept writes
  oida opcua 192.168.1.100 --test-cert-trust         # Does it accept untrusted certs
  oida opcua 192.168.1.100 --test-rbac --rbac-detailed   # Per-role permission matrix
  oida opcua 192.168.1.100 --test-subscription-limits --confirm  # Subscription exhaustion

Fuzzing (all require --confirm):
  oida opcua 192.168.1.100 --fuzz --fuzz-mode nodes --fuzz-iterations 50 --confirm
  oida opcua 192.168.1.100 --fuzz --fuzz-mode methods --fuzz-iterations 50 --confirm
  oida opcua 192.168.1.100 --fuzz --fuzz-node "ns=2;i=40" --confirm
  oida opcua 192.168.1.100 --fuzz --fuzz-method StartPump --confirm
""",
    )

    # Target (positional)
    add_target_argument(
        opcua_parser,
        help_text="Target OPC UA endpoint (e.g., opc.tcp://192.168.1.100:4840)",
    )

    # Network Options (--port, --timeout)
    add_network_options(opcua_parser, default_port=4840)

    # Authentication Options (--username, --password).
    # --credentials is omitted: OPC UA loads credential lists by passing a file path to
    # --username/--password (load_credentials auto-detects files), and nothing here ever
    # read args.credentials, so the flag silently left the client on anonymous auth.
    auth_group = add_auth_options(opcua_parser, include_creds_file=False)
    auth_group.add_argument("--certificate", type=str, help="Path to client certificate file")
    auth_group.add_argument("--privatekey", type=str, help="Path to client private key file")

    # Security Options
    security_group = opcua_parser.add_argument_group("Security Options")
    security_group.add_argument(
        "--mode",
        "--security-mode",
        choices=["None", "Sign", "SignAndEncrypt"],
        default="None",
        help="Security mode (default: None)",
    )
    security_group.add_argument(
        "--policy",
        "--security-policy",
        choices=["None", "Basic128Rsa15", "Basic256", "Basic256Sha256"],
        default="None",
        help="Security policy (default: None)",
    )

    # Discovery Options. NOTE: --discover/--quick/--full/--deep-scan are not offered.
    # OPC UA discovery is driven by the explicit services below (--get-endpoints,
    # --find-servers, ...) and by the dump options; the generic scan-mode flags were
    # accepted but never consumed, so a scan with --quick or --deep-scan produced output
    # byte-identical to a plain scan. Dump breadth is controlled by --max-depth/--max-nodes.
    discovery_group = add_discovery_options(opcua_parser, include_quick=False, include_deep=False)
    discovery_group.add_argument(
        "--get-endpoints",
        action="store_true",
        help="Get server endpoints and security info",
    )
    discovery_group.add_argument(
        "--find-servers",
        action="store_true",
        help="Discover servers via FindServers service",
    )
    discovery_group.add_argument(
        "--find-servers-on-network",
        action="store_true",
        help="Discover servers via GDS/LDS discovery service",
    )
    discovery_group.add_argument(
        "--gds-url",
        metavar="URL",
        help="GDS endpoint URL for discovery operations",
    )

    # Address Space Dump Options
    dump_group = opcua_parser.add_argument_group("Address Space Dump")
    dump_group.add_argument(
        "-d",
        "--dump",
        action="store_true",
        help="Fast dump of address space (names/types only)",
    )
    dump_group.add_argument(
        "-D",
        "--dump-all",
        action="store_true",
        help="Full dump with DataType, Access levels (slower)",
    )
    dump_group.add_argument(
        "--dump-methods",
        action="store_true",
        help="Only show method nodes",
    )
    dump_group.add_argument(
        "--dump-write",
        action="store_true",
        help="Only show writable variable nodes",
    )
    dump_group.add_argument(
        "--dump-values",
        action="store_true",
        help="Include current values in dump (use with --dump-all)",
    )
    dump_group.add_argument(
        "--dump-namespaces",
        action="store_true",
        help="Only show namespace table",
    )
    dump_group.add_argument(
        "--dump-examples",
        action="store_true",
        help="Show example CLI usage for methods (use with --dump-methods)",
    )
    dump_group.add_argument(
        "--dump-history",
        action="store_true",
        help="Show nodes with historizing enabled",
    )
    dump_group.add_argument(
        "--dump-files",
        action="store_true",
        help="Show FileType nodes (file transfer endpoints)",
    )
    dump_group.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum dump depth (default: 3)",
    )
    dump_group.add_argument(
        "--max-nodes",
        type=int,
        default=1000,
        help="Maximum nodes to scan (default: 1000)",
    )
    dump_group.add_argument(
        "--ns",
        type=str,
        metavar="NS",
        help="Filter by namespace index (e.g., '2' or '2,3')",
    )
    dump_group.add_argument(
        "--start-node",
        type=str,
        metavar="NODE_ID",
        help="Start browsing from specific node (e.g., 'ns=2;i=5001')",
    )

    # Node Operations
    node_group = opcua_parser.add_argument_group("Node Operations")
    node_group.add_argument(
        "--node-id",
        type=str,
        help="Specific node ID to read (e.g., ns=2;i=2)",
    )
    node_group.add_argument(
        "--write-value",
        type=str,
        metavar="VALUE",
        help="Write value to node (use with --node-id, requires --confirm)",
    )
    node_group.add_argument(
        "--read-attributes",
        action="store_true",
        help="Read all attributes (use with --node-id)",
    )

    # Method Invocation
    method_group = opcua_parser.add_argument_group("Method Options")
    method_group.add_argument(
        "--call-method",
        metavar="NODE_ID",
        help="Call method by NodeId (e.g., 'ns=2;i=1000')",
    )
    method_group.add_argument(
        "--method-args",
        metavar="JSON",
        help="JSON array of method arguments (e.g., '[42.5, \"test\"]')",
    )

    # Subscription/Monitor (--duration, plus the --subscribe* flags below).
    # --monitor and --interval are omitted: OPC UA watches values by subscribing to the
    # server (--subscribe / --subscribe-events, paced by --subscription-interval), and
    # nothing here read args.monitor or args.interval. Passing --monitor performed a
    # single read and returned immediately, ignoring --duration entirely.
    monitor_group = add_monitor_options(opcua_parser, include_monitor=False, include_interval=False)
    monitor_group.add_argument(
        "--subscribe",
        action="store_true",
        help="Subscribe to node value changes",
    )
    monitor_group.add_argument(
        "--subscription-interval",
        type=int,
        default=1000,
        help="Subscription publishing interval in ms (default: 1000)",
    )
    monitor_group.add_argument(
        "--subscribe-events",
        action="store_true",
        help="Subscribe to server events and alarms",
    )

    # Historical Data Access
    history_group = opcua_parser.add_argument_group("Historical Data Access")
    history_group.add_argument(
        "--history-read",
        action="store_true",
        help="Read historical data from node (use with --node-id)",
    )
    history_group.add_argument(
        "--history-start",
        type=str,
        metavar="DATETIME",
        help="Start time for history (ISO format, e.g., '2024-01-01T00:00:00')",
    )
    history_group.add_argument(
        "--history-end",
        type=str,
        metavar="DATETIME",
        help="End time for history (ISO format, default: now)",
    )
    history_group.add_argument(
        "--history-max",
        type=int,
        default=100,
        metavar="N",
        help="Maximum historical values to retrieve (default: 100)",
    )
    history_group.add_argument(
        "--history-raw",
        action="store_true",
        help="Read raw historical data points (the only supported history mode)",
    )

    # File Transfer (--read-file, --write-file, --file-output)
    file_group = add_file_transfer_options(opcua_parser, include_list=False)
    file_group.add_argument(
        "--file-data",
        type=str,
        metavar="PATH_OR_DATA",
        help="File path or data to upload (use with --write-file)",
    )

    # Credential Testing (--brute-rate, --continue-on-success).
    # OPC UA brute-force is driven by file inputs (--username FILE / --password
    # FILE), not a --brute toggle, and it has no password --wordlist path, so
    # both are omitted rather than advertised as dead flags. --default-creds is
    # omitted for the same reason: there is no built-in OPC UA credential list to
    # spray, so the flag left the client on anonymous auth and changed nothing.
    add_brute_options(
        opcua_parser,
        default_rate=0.5,
        include_wordlist=False,
        include_brute=False,
        include_default_creds=False,
    )

    # Security Analysis
    sec_analysis_group = opcua_parser.add_argument_group("Security Analysis")
    sec_analysis_group.add_argument(
        "--test-cert-trust",
        action="store_true",
        help="Test if server accepts untrusted self-signed client certificates "
        "(both application/secure-channel and X509 user-identity tokens)",
    )
    sec_analysis_group.add_argument(
        "--test-subscription-limits",
        action="store_true",
        help="Test for subscription-based DoS vulnerabilities",
    )
    sec_analysis_group.add_argument(
        "--scan-writable",
        action="store_true",
        help="Scan for writable nodes via AccessLevel + AccessRestrictions (read-only check)",
    )
    sec_analysis_group.add_argument(
        "--test-rbac",
        action="store_true",
        help="Test RBAC by comparing access across auth methods",
    )
    sec_analysis_group.add_argument(
        "--rbac-detailed",
        action="store_true",
        help="Include per-node permission matrix in RBAC test",
    )

    # Fuzzing (--confirm, --fuzz, --fuzz-iterations)
    fuzz_group = add_dangerous_options(opcua_parser, include_fuzz=True)
    fuzz_group.add_argument(
        "--fuzz-mode",
        choices=["nodes", "methods", "all"],
        default="nodes",
        help="What to fuzz: writable nodes, callable methods, or both (default: nodes)",
    )
    fuzz_group.add_argument(
        "--fuzz-node",
        type=str,
        metavar="NODE_ID",
        help="Specific node ID to fuzz (e.g., 'ns=2;i=1001')",
    )
    fuzz_group.add_argument(
        "--fuzz-method",
        type=str,
        metavar="NODE_ID",
        help="Specific method NodeId to fuzz (e.g., 'ns=2;i=1000')",
    )

    return opcua_parser
