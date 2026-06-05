"""
Argument parser definition for KNX/EIB protocol.

Migrated to proto_args_factory in §3 sync. KNX keeps a custom `target`
(nargs='?' with the KNX multicast address as default) so we set up
that argument by hand after `create_protocol_parser`. The
`add_network_options` helper would add --port + --timeout but KNX wants
a custom default port (3671) and timeout type (float), so we keep the
network group local.
"""

from ...utils.proto_args_factory import create_protocol_parser


def proto_args(parser, parents):
    """Register KNX-specific arguments"""
    knx_parser = create_protocol_parser(
        parser,
        name="knx",
        help_text="KNX/EIB building automation scanner",
        description="Scan and interact with KNX building automation systems",
        parents=parents,
    )

    knx_parser.add_argument(
        "target",
        nargs="?",
        default="224.0.23.12",
        help="Target IP (multicast 224.0.23.12 or unicast)",
    )

    network_group = knx_parser.add_argument_group("Network Options")
    network_group.add_argument("--port", type=int, default=3671, help="KNX port (default: 3671)")
    network_group.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0)",
    )
    network_group.add_argument(
        "--nat",
        action="store_true",
        default=True,
        help="Use NAT mode for unicast (default: enabled)",
    )
    network_group.add_argument(
        "--no-nat", action="store_true", help="Disable NAT mode (use explicit local IP in requests)"
    )

    knx_group = knx_parser.add_argument_group("KNX Options")
    knx_group.add_argument("--interface", type=str, help="Network interface for multicast")

    knx_group.add_argument(
        "--tcp", action="store_true", help="Use TCP tunneling instead of UDP (for KNX IP routers)"
    )

    knx_group.add_argument(
        "-i", "--individual-address", type=str, help='KNX individual address (e.g., "1.1.1")'
    )

    knx_group.add_argument("-g", "--group-address", type=str, help="KNX group address to read")

    # Device information and memory operations
    device_group = knx_parser.add_argument_group("Device Operations")

    device_group.add_argument(
        "--device-info",
        action="store_true",
        help="Read comprehensive device information (descriptor, serial, manufacturer)",
    )

    device_group.add_argument(
        "--enumerate-objects", action="store_true", help="Enumerate all interface objects on device"
    )

    device_group.add_argument(
        "--prog-mode", action="store_true", help="Check if device is in programming mode"
    )

    device_group.add_argument(
        "--firmware-info", action="store_true", help="Read firmware and BCU information"
    )

    device_group.add_argument(
        "--vendor-objects",
        action="store_true",
        help="Discover vendor-specific interface objects (200-255)",
    )

    device_group.add_argument(
        "--prop-dump", action="store_true", help="Dump all properties of all interface objects"
    )

    device_group.add_argument(
        "--memory-dump",
        type=str,
        metavar="START:LENGTH",
        help="Dump memory range (e.g., '0x0100:256' or '256:128')",
    )

    device_group.add_argument(
        "--memory-ext",
        type=str,
        metavar="START:LENGTH",
        help="Extended memory dump (24-bit addresses, e.g., '0x010000:256')",
    )

    device_group.add_argument(
        "--memory-user",
        type=str,
        metavar="START:LENGTH",
        help="User memory dump (e.g., '0x0100:128')",
    )

    device_group.add_argument(
        "--memory-write",
        type=str,
        metavar="ADDR:DATA",
        help="Write to memory address (e.g., '0x0116:00')",
    )

    device_group.add_argument(
        "--property-read",
        type=str,
        metavar="OBJ:PROP",
        help="Read interface object property (e.g., '0:78' for serial number)",
    )

    device_group.add_argument(
        "--property-write",
        type=str,
        metavar="OBJ:PROP:DATA",
        help="Write hex data to property (e.g., '0:78:00FA12') - requires --confirm",
    )

    device_group.add_argument(
        "--fuzz-property",
        type=str,
        metavar="OBJ:PROP",
        help="Fuzz a writable property (e.g., '0:19') - requires --confirm",
    )

    device_group.add_argument(
        "--fuzz-iterations",
        type=int,
        default=10,
        metavar="N",
        help="Number of fuzz iterations (default: 10)",
    )

    device_group.add_argument(
        "--adc-read", type=int, metavar="CHANNEL", help="Read ADC channel value (0-63)"
    )

    device_group.add_argument(
        "--group-write",
        type=str,
        metavar="ADDR:VALUE",
        help="Write value to group address (e.g., '1/0/1:01')",
    )

    device_group.add_argument(
        "--restart", action="store_true", help="Restart/reboot the target device (requires -i)"
    )

    device_group.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (memory/property write, fuzzing, key write)",
    )

    device_group.add_argument(
        "--prop-desc",
        type=str,
        metavar="OBJ:PROP",
        help="Read property description/metadata (e.g., '0:78' for access rights, max count)",
    )

    # Scanning and discovery
    recon_group = knx_parser.add_argument_group("Reconnaissance")

    recon_group.add_argument(
        "--gateway-scan", action="store_true", help="Discover KNX/IP gateways via multicast"
    )

    recon_group.add_argument(
        "--bus-scan", action="store_true", help="Scan bus for devices and listen for traffic"
    )

    recon_group.add_argument(
        "--listen",
        action="store_true",
        help="Passive listen mode - monitor bus traffic without sending probes",
    )

    recon_group.add_argument(
        "-L",
        "--listen-time",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Listen duration in seconds (default: 30). Implies --listen if set.",
    )

    recon_group.add_argument(
        "--slow-scan",
        action="store_true",
        help="Use slow scan method (nm_individual_address_check) with --bus-scan",
    )

    recon_group.add_argument(
        "--serial-scan",
        type=str,
        metavar="SERIAL",
        help="Find device by serial number (6 bytes hex, e.g., '00FA12345678')",
    )

    recon_group.add_argument(
        "-r",
        "--scan-range",
        type=str,
        metavar="RANGE",
        help="Custom scan range: '1.1.1-1.1.255' or '1.1.1-1.1.5,2.2.1-2.2.10' or '-' for all",
    )

    # BCU Authentication
    auth_group = knx_parser.add_argument_group("Authentication")

    auth_group.add_argument(
        "--auth-test",
        type=str,
        nargs="?",
        const="FFFFFFFF",
        metavar="KEY",
        help="Test BCU key (hex, default: FFFFFFFF factory key)",
    )

    auth_group.add_argument(
        "--key-file",
        type=str,
        metavar="FILE",
        help="File with BCU keys to test (one 8-char hex key per line)",
    )

    auth_group.add_argument(
        "--key-range",
        type=str,
        metavar="START-END",
        help="Hex key range to test (e.g., '00000000-000000FF')",
    )

    auth_group.add_argument(
        "--brute-delay",
        type=int,
        default=100,
        metavar="MS",
        help="Delay between key attempts in milliseconds (default: 100)",
    )

    auth_group.add_argument(
        "--continue-on-success",
        action="store_true",
        default=False,
        help="Keep testing keys after the first valid hit (default: stop on first success)",
    )

    auth_group.add_argument(
        "--key-write",
        type=str,
        metavar="KEY:LEVEL",
        help="Write BCU key (DANGEROUS, e.g., 'FFFFFFFF:0') - requires --confirm",
    )

    # ETS Project Operations
    ets_group = knx_parser.add_argument_group("ETS Project Operations")

    ets_group.add_argument(
        "--knxproj",
        type=str,
        metavar="FILE",
        help="Parse .knxproj file (ETS5/ETS6 project)",
    )

    ets_group.add_argument(
        "--knxproj-password",
        type=str,
        metavar="PASS",
        help="Password for encrypted project file",
    )

    ets_group.add_argument(
        "--knxproj-wordlist",
        type=str,
        metavar="FILE",
        help="Wordlist for password cracking",
    )

    ets_group.add_argument(
        "--knxproj-threads",
        type=int,
        default=16,
        metavar="N",
        help="Threads for password cracking (default: 16)",
    )

    ets_group.add_argument(
        "--knxproj-info",
        action="store_true",
        help="Show project info only (no full parse)",
    )

    ets_group.add_argument(
        "--knxproj-hash",
        action="store_true",
        help="Extract hash in hashcat/john format (no cracking)",
    )

    ets_group.add_argument(
        "--knxproj-fast",
        action="store_true",
        help="Fast mode: test ZIP decryption only (skip XML parsing)",
    )

    return knx_parser
