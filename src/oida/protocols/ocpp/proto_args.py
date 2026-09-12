"""
Argument parser definition for OCPP protocol

This module registers OCPP-specific command-line arguments
following the NXC pattern.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_network_options,
    add_auth_options,
    add_tls_options,
    add_dangerous_options,
    add_brute_options,
)


def proto_args(parser, parents):
    """Register OCPP-specific arguments"""
    ocpp_parser = create_protocol_parser(
        parser,
        name="ocpp",
        help_text="OCPP (Open Charge Point Protocol) scanner for EV charging infrastructure",
        description="Scan OCPP WebSocket endpoints for EV charging stations (CSMS/CPO)",
        parents=parents,
        epilog="""
Examples:
  oida ocpp ws://192.168.1.100:9000/CP_001           # Connect and detect version
  oida ocpp 192.168.1.100                             # Auto-construct ws:// URL
  oida ocpp ws://charger.local:9000/CP_001 -e         # Enumerate supported actions
  oida ocpp wss://csms.example.com/CP_001              # TLS via wss:// scheme
  oida ocpp ws://192.168.1.100:9000/CP_001 -u admin -P pass  # Basic Auth

Version Detection:
  oida ocpp ws://host:9000/CP_001 -V 1.6             # Force OCPP 1.6
  oida ocpp ws://host:9000/CP_001 -V 2.0.1           # Force OCPP 2.0.1
  oida ocpp ws://host:9000/CP_001 -E                  # Probe all OCPP versions

Discovery:
  oida ocpp ws://host:9000/CP_001 -e                  # Enumerate safe actions
  oida ocpp ws://host:9000/CP_001 -e --confirm         # Enumerate all (incl. dangerous)
  oida ocpp ws://host:9000/CP_001 -c                  # Get configuration keys
  oida ocpp ws://host:9000/CP_001 -D                  # DataTransfer vendor probe
  oida ocpp ws://host:9000/CP_001 -m                  # Probe MeterValues data
  oida ocpp ws://host:9000/CP_001 -n                  # Enumerate connectors
  oida ocpp ws://host:9000/CP_001 -L                  # Local auth list version
  oida ocpp ws://host:9000/CP_001 --composite-schedule  # Read charging schedule
  oida ocpp ws://host:9000/CP_001 --installed-certs   # PKI cert inventory (2.0.1)
  oida ocpp ws://host:9000/CP_001 -e -c -D -m         # All discovery at once

Security Checks (passive, no --confirm needed):
  oida ocpp ws://host:9000/CP_001 --check-auth        # Check anonymous access
  oida ocpp ws://host:9000/CP_001 --check-boot        # Check boot acceptance

Security Probes (active, requires --confirm):
  oida ocpp ws://host:9000/CP_001 -s --confirm         # Run ALL security tests
  oida ocpp ws://host:9000/CP_001 --test-reset --confirm
  oida ocpp ws://host:9000/CP_001 --test-unlock --confirm
  oida ocpp ws://host:9000/CP_001 --test-firmware --confirm

Connector / Trigger / Status:
  oida ocpp ws://host:9000/CP_001 -C 1 -S             # Status of connector 1
  oida ocpp ws://host:9000/CP_001 -T StatusNotification
  oida ocpp ws://host:9000/CP_001 -a RFID0001         # Test auth token

Charging Flow Tests (requires --confirm):
  oida ocpp ws://host:9000/CP_001 --charging --confirm     # All charging tests
  oida ocpp ws://host:9000/CP_001 --test-charging --confirm

Raw Messages:
  oida ocpp ws://host:9000/CP_001 -r '[2,"id","Heartbeat",{}]'

Credential Testing:
  oida ocpp ws://host:9000/CP_001 -u CP001 -P wordlist.txt  # HTTP Basic Auth brute force
  oida ocpp ws://host:9000/CP_001 --brute --default-creds    # Test default credentials
  oida ocpp ws://host:9000/CP_001 --brute --wordlist tags.txt # IdTag brute force

Listen Mode (passive monitoring):
  oida ocpp ws://host:9000/CP_001 -l                   # Listen indefinitely (Ctrl+C)
  oida ocpp ws://host:9000/CP_001 -l --listen-timeout 60  # Listen for 60s then exit
  oida ocpp ws://host:9000/CP_001 -l -e                # Enumerate, then listen

WebSocket Path Discovery:
  oida ocpp 192.168.1.100 --ws-brute                  # Brute-force paths (built-in list)
  oida ocpp 192.168.1.100 --ws-brute paths.txt        # Custom wordlist
  oida ocpp 192.168.1.100:8180 --ws-brute              # Specific port
""",
    )

    # Target (positional)
    ocpp_parser.add_argument(
        "target",
        help=(
            "Target OCPP endpoint: WebSocket URL (ws://host:port/cpId) "
            "or IP address (auto-constructs ws:// URL)"
        ),
    )

    # === Network Options ===
    network_group = add_network_options(
        ocpp_parser,
        default_port=9000,
        include_timeout=True,
        port_help="WebSocket port (default: 9000 for ws://, 443 for wss://)",
    )

    network_group.add_argument(
        "--ws-path",
        type=str,
        metavar="PATH",
        help="Override WebSocket URL path component (e.g., /ocpp/CP_001)",
    )

    network_group.add_argument(
        "--ws-brute",
        nargs="?",
        const=True,
        default=None,
        metavar="FILE",
        help="Brute-force WebSocket paths (optional: custom wordlist file, default: built-in list)",
    )

    # === OCPP Options ===
    ocpp_group = ocpp_parser.add_argument_group("OCPP Options")

    ocpp_group.add_argument(
        "-V",
        "--version",
        type=str,
        choices=["1.6", "2.0.1", "2.1", "auto"],
        default="auto",
        help="OCPP version to use for scanning (default: auto-detect)",
    )

    ocpp_group.add_argument(
        "--charge-point-id",
        "--cp-id",
        type=str,
        default="CP_SCANNER_001",
        metavar="ID",
        help="Charge Point ID for WebSocket path (default: CP_SCANNER_001)",
    )

    ocpp_group.add_argument(
        "--vendor",
        type=str,
        default="SecurityAudit",
        metavar="NAME",
        help="Vendor name for BootNotification (default: SecurityAudit)",
    )

    ocpp_group.add_argument(
        "--model",
        type=str,
        default="OIDA-Scanner",
        metavar="NAME",
        help="Model name for BootNotification (default: OIDA-Scanner)",
    )

    ocpp_group.add_argument(
        "-C",
        "--connector-id",
        type=int,
        default=0,
        metavar="ID",
        help="Target connector ID for connector-specific operations (default: 0 = charge point itself)",
    )

    # === Authentication Options ===
    auth_group = add_auth_options(
        ocpp_parser,
        include_creds_file=False,
        username_help="HTTP Basic Auth username (typically the Charge Point ID)",
        password_help="HTTP Basic Auth password (authorization key)",
    )

    auth_group.add_argument(
        "-a",
        "--auth-id",
        type=str,
        metavar="TOKEN",
        help="Authorization ID token (RFID/badge) to test Authorize action",
    )

    # === TLS Options (wss:// auto-enables TLS, no --tls flag needed) ===
    add_tls_options(
        ocpp_parser,
        include_tls_flag=False,
        include_cert=True,
        include_ca=True,
        include_insecure=True,
    )

    # === Discovery Options ===
    discovery_group = ocpp_parser.add_argument_group("Discovery Options")

    discovery_group.add_argument(
        "-e",
        "--enumerate",
        action="store_true",
        help="Enumerate supported OCPP actions",
    )

    discovery_group.add_argument(
        "-E",
        "--enum-versions",
        action="store_true",
        help="Probe supported OCPP versions (1.6, 2.0.1, 2.1)",
    )

    discovery_group.add_argument(
        "-c",
        "--get-config",
        action="store_true",
        help="Attempt to retrieve configuration keys (OCPP 1.6)",
    )

    discovery_group.add_argument(
        "-D",
        "--data-transfer",
        action="store_true",
        help="Send DataTransfer probe for vendor extensions",
    )

    discovery_group.add_argument(
        "--firmware-info",
        action="store_true",
        help="Gather firmware details via BootNotification and configuration keys",
    )

    discovery_group.add_argument(
        "-S",
        "--status",
        action="store_true",
        help="Send StatusNotification probe to check connector status handling",
    )

    discovery_group.add_argument(
        "-T",
        "--trigger",
        type=str,
        metavar="MESSAGE",
        help="Send TriggerMessage to request a specific message from the Charge Point",
    )

    discovery_group.add_argument(
        "-m",
        "--meter-values",
        action="store_true",
        help="Probe MeterValues (energy, power, current, voltage) via TriggerMessage",
    )

    discovery_group.add_argument(
        "-n",
        "--enum-connectors",
        action="store_true",
        help="Enumerate connectors and their status (IDs 0-10)",
    )

    discovery_group.add_argument(
        "--max-connector-id",
        type=int,
        default=10,
        metavar="N",
        help="Maximum connector ID to probe during enumeration (default: 10)",
    )

    discovery_group.add_argument(
        "-L",
        "--local-list-version",
        action="store_true",
        help="Query local authorization list version (GetLocalListVersion)",
    )

    discovery_group.add_argument(
        "--composite-schedule",
        action="store_true",
        help="Read composite charging schedule for a connector (GetCompositeSchedule)",
    )

    discovery_group.add_argument(
        "--installed-certs",
        action="store_true",
        help="List installed certificates on charge point (OCPP 2.0.1 GetInstalledCertificateIds)",
    )

    # === Security Options ===
    security_group = ocpp_parser.add_argument_group("Security Assessment")

    # Passive checks (analysis only, no side-effects)
    security_group.add_argument(
        "--check-auth",
        action="store_true",
        help="Check if anonymous connections are accepted (no HTTP Basic Auth)",
    )

    security_group.add_argument(
        "--check-boot",
        action="store_true",
        help="Check if BootNotification from unknown CP is accepted",
    )

    security_group.add_argument(
        "--check-config-keys",
        action="store_true",
        help="Check for exposed security config keys (AuthorizationKey, SecurityProfile)",
    )

    # Active probes (send commands to test authorization enforcement, requires --confirm)
    security_group.add_argument(
        "--test-config-write",
        action="store_true",
        help="Test config write access (requires --confirm)",
    )

    security_group.add_argument(
        "--test-charging-profile",
        action="store_true",
        help="Test charging profile writes (requires --confirm)",
    )

    security_group.add_argument(
        "--test-remote-start",
        action="store_true",
        help="Test unauthorized RemoteStartTransaction (requires --confirm)",
    )

    security_group.add_argument(
        "--test-reset",
        action="store_true",
        help="Test unauthorized Soft Reset (requires --confirm)",
    )

    security_group.add_argument(
        "--test-unlock",
        action="store_true",
        help="Test unauthorized UnlockConnector (requires --confirm)",
    )

    security_group.add_argument(
        "--test-firmware",
        action="store_true",
        help="Test unauthorized UpdateFirmware (requires --confirm)",
    )

    security_group.add_argument(
        "--test-availability",
        action="store_true",
        help="Test unauthorized ChangeAvailability (requires --confirm)",
    )

    security_group.add_argument(
        "--test-clear-cache",
        action="store_true",
        help="Test unauthorized ClearCache (requires --confirm)",
    )

    security_group.add_argument(
        "--test-diagnostics",
        action="store_true",
        help="Test GetDiagnostics/GetLog SSRF (requires --confirm)",
    )

    security_group.add_argument(
        "--test-remote-stop",
        action="store_true",
        help="Test unauthorized RemoteStopTransaction (requires --confirm)",
    )

    security_group.add_argument(
        "--test-reserve",
        action="store_true",
        help="Test unauthorized ReserveNow (requires --confirm)",
    )

    security_group.add_argument(
        "--test-local-list",
        action="store_true",
        help="Test SendLocalList access (requires --confirm)",
    )

    security_group.add_argument(
        "--test-network-profile",
        action="store_true",
        help="Test SetNetworkProfile redirect (OCPP 2.0.1, requires --confirm)",
    )

    security_group.add_argument(
        "--test-install-cert",
        action="store_true",
        help="Test InstallCertificate acceptance (OCPP 2.0.1, requires --confirm)",
    )

    security_group.add_argument(
        "--test-display-msg",
        action="store_true",
        help="Test SetDisplayMessage (OCPP 2.0.1, requires --confirm)",
    )

    security_group.add_argument(
        "--test-customer-info",
        action="store_true",
        help="Test CustomerInformation PII access (OCPP 2.0.1, requires --confirm)",
    )

    security_group.add_argument(
        "--test-ssrf-extended",
        action="store_true",
        help="Test extended SSRF payloads via UpdateFirmware/GetDiagnostics (requires --confirm)",
    )

    security_group.add_argument(
        "--test-ws-hijack",
        action="store_true",
        help="Test WebSocket connection hijacking / SaiFlow (requires --confirm)",
    )

    security_group.add_argument(
        "-s",
        "--security",
        action="store_true",
        help="Run ALL security tests (passive checks + active probes, probes require --confirm)",
    )

    # === Charging Flow Tests ===
    charging_group = ocpp_parser.add_argument_group("Charging Flow Tests")

    charging_group.add_argument(
        "--test-authorize",
        action="store_true",
        help="Test authorization bypass (requires --confirm)",
    )

    charging_group.add_argument(
        "--test-charging",
        action="store_true",
        help="Test full charging session flow (requires --confirm)",
    )

    charging_group.add_argument(
        "--test-meter-inject",
        action="store_true",
        help="Test meter value injection (requires --confirm)",
    )

    charging_group.add_argument(
        "--charging",
        action="store_true",
        help="Run ALL charging flow tests (requires --confirm)",
    )

    # === Raw Message ===
    raw_group = ocpp_parser.add_argument_group("Raw OCPP-J Messages")

    raw_group.add_argument(
        "-r",
        "--raw-message",
        type=str,
        metavar="JSON",
        help=('Send arbitrary OCPP-J message (JSON array). Example: \'[2,"id","Heartbeat",{}]\''),
    )

    # === Listen Mode ===
    listen_group = ocpp_parser.add_argument_group("Listen Mode")

    listen_group.add_argument(
        "-l",
        "--listen",
        action="store_true",
        help="Listen mode: connect, authenticate, then keep WebSocket open and "
        "log all server-initiated commands (Ctrl+C to stop)",
    )

    listen_group.add_argument(
        "--listen-timeout",
        type=int,
        default=None,
        metavar="SECS",
        help="Exit listen mode after N seconds (default: run until Ctrl+C)",
    )

    # === Active Testing ===
    add_dangerous_options(ocpp_parser, include_fuzz=False)

    # === Credential Testing ===
    add_brute_options(ocpp_parser, default_rate=0.5)

    return ocpp_parser
