"""
Argument parser definition for CoAP protocol

This module registers CoAP-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_dangerous_options,
)


def proto_args(parser, parents):
    """Register CoAP-specific arguments"""
    coap_parser = create_protocol_parser(
        parser,
        name="coap",
        help_text="CoAP IoT/ICS device scanner with LwM2M fingerprinting",
        description="Scan and interact with CoAP (RFC 7252) devices",
        parents=parents,
        epilog="""
Examples:
  oida coap 192.168.1.100                          # Discover resources via .well-known/core
  oida coap 192.168.1.100 -L                       # Fingerprint LwM2M device (/3/0)
  oida coap 192.168.1.100 -F                       # Enumerate all LwM2M objects
  oida coap 192.168.1.100 -R                       # Probe common IoT paths
  oida coap 192.168.1.100 -M --confirm             # Test all CoAP methods on resources
  oida coap 192.168.1.100 -O -N 10                 # Subscribe to observable resources
  oida coap 192.168.1.100 --put /actuator/led 1 --confirm  # Write value to resource
  oida coap 192.168.1.100 -D -P secret -u client    # Connect via DTLS-PSK
  oida coap 192.168.1.100 --dtls-cert c.pem --dtls-key k.pem  # DTLS certificate auth
  oida coap 192.168.1.100 --fetch /sensor/data     # FETCH resource (RFC 8132)
  oida coap 192.168.1.100 --patch /config '{}' --confirm    # PATCH resource
  oida coap 192.168.1.100 --block-size 256         # Use 256-byte block transfers
""",
    )

    add_target_argument(coap_parser, help_text="Target IP or hostname")

    # Network options (--port, --timeout)
    add_network_options(coap_parser, default_port=5683)

    # Discovery options
    discovery_group = coap_parser.add_argument_group("Discovery")
    discovery_group.add_argument(
        "-r",
        "--resources",
        action="store_true",
        default=True,
        help="Enumerate resources via /.well-known/core (default: enabled)",
    )
    discovery_group.add_argument(
        "-R",
        "--probe-paths",
        nargs="?",
        const=True,
        default=False,
        metavar="WORDLIST",
        help="Probe common IoT resource paths (optionally load paths from a wordlist file)",
    )

    # LwM2M options
    lwm2m_group = coap_parser.add_argument_group("LwM2M")
    lwm2m_group.add_argument(
        "-L",
        "--lwm2m",
        action="store_true",
        help="Probe LwM2M Device Object /3/0 for device info",
    )
    lwm2m_group.add_argument(
        "-F",
        "--lwm2m-full",
        action="store_true",
        help="Full LwM2M object enumeration (all standard objects)",
    )

    # Method testing
    method_group = coap_parser.add_argument_group("Method Testing")
    method_group.add_argument(
        "-M",
        "--methods",
        action="store_true",
        help="Test GET/PUT/POST/DELETE/FETCH/PATCH/iPATCH on all discovered resources",
    )

    # Observe
    observe_group = coap_parser.add_argument_group("Observe")
    observe_group.add_argument(
        "-O",
        "--observe",
        action="store_true",
        help="Subscribe to observable resources and collect notifications",
    )
    observe_group.add_argument(
        "-N",
        "--observe-count",
        type=int,
        default=5,
        metavar="N",
        help="Max notifications to collect per resource (default: 5)",
    )

    # DTLS / Security
    security_group = coap_parser.add_argument_group("DTLS / Security")
    security_group.add_argument(
        "-D",
        "--dtls",
        action="store_true",
        help="Use DTLS (CoAPs, port 5684) instead of plain CoAP",
    )
    security_group.add_argument(
        "-P",
        "--psk",
        type=str,
        metavar="KEY",
        help="Pre-shared key for DTLS-PSK (hex string, or path to wordlist file for bruteforce)",
    )
    security_group.add_argument(
        "-u",
        "--psk-identity",
        type=str,
        metavar="ID",
        help="PSK identity for DTLS-PSK (string, or path to wordlist file for bruteforce)",
    )
    security_group.add_argument(
        "--dtls-cert",
        type=str,
        metavar="PATH",
        help="Client certificate file for DTLS certificate auth (PEM format)",
    )
    security_group.add_argument(
        "--dtls-key",
        type=str,
        metavar="PATH",
        help="Client private key file for DTLS certificate auth (PEM format)",
    )
    security_group.add_argument(
        "--dtls-ca",
        type=str,
        metavar="PATH",
        help="CA certificate file for DTLS server verification (PEM format)",
    )
    security_group.add_argument(
        "--dtls-rpk",
        type=str,
        metavar="PATH",
        help="Raw Public Key file for DTLS RPK auth (DER or PEM format)",
    )

    # Write operations + confirm via factory
    write_group = coap_parser.add_argument_group("Write Operations (require --confirm)")
    write_group.add_argument(
        "--put",
        nargs=2,
        metavar=("PATH", "VALUE"),
        help="PUT a value to a resource path (e.g., --put /actuator/led 1)",
    )
    write_group.add_argument(
        "--post",
        nargs=2,
        metavar=("PATH", "VALUE"),
        help="POST a value to a resource path",
    )
    write_group.add_argument(
        "--delete",
        type=str,
        metavar="PATH",
        help="DELETE a resource (e.g., --delete /config/temp)",
    )
    write_group.add_argument(
        "--fetch",
        nargs="+",
        metavar="ARG",
        help="FETCH a resource (RFC 8132). Usage: --fetch PATH [PAYLOAD]",
    )
    write_group.add_argument(
        "--patch",
        nargs=2,
        metavar=("PATH", "VALUE"),
        help="PATCH a resource value (RFC 8132, require --confirm)",
    )
    write_group.add_argument(
        "--ipatch",
        nargs=2,
        metavar=("PATH", "VALUE"),
        help="iPATCH (idempotent PATCH) a resource value (RFC 8132, require --confirm)",
    )

    write_group.add_argument(
        "--content-format",
        type=str,
        metavar="FMT",
        help="Content-Format for write payloads. "
        "Name (text, json, cbor, xml, octet, senml, lwm2m-tlv, lwm2m-json) "
        "or numeric ID (e.g. 50 for application/json)",
    )

    # Block-wise transfer (RFC 7959)
    transfer_group = coap_parser.add_argument_group("Block-wise Transfer (RFC 7959)")
    transfer_group.add_argument(
        "--block-size",
        type=int,
        default=512,
        choices=[16, 32, 64, 128, 256, 512, 1024],
        metavar="SIZE",
        help="Block size for block-wise transfers (default: 512, options: 16/32/64/128/256/512/1024)",
    )

    # Dangerous options (--confirm)
    add_dangerous_options(coap_parser, include_fuzz=False)

    return coap_parser
