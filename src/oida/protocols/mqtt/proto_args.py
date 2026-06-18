#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MQTT Protocol CLI Arguments

Defines command-line arguments for the MQTT scanner.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_auth_options,
    add_tls_options,
    add_brute_options,
    add_listen_options,
    add_dangerous_options,
)


def proto_args(parser, parents):
    """
    Register MQTT-specific CLI arguments

    Args:
        parser: argparse subparsers object
        parents: List of parent parsers to inherit from
    """
    mqtt_parser = create_protocol_parser(
        parser,
        name="mqtt",
        help_text="MQTT broker scanner with Sparkplug B support",
        description="""
MQTT Protocol Scanner

Scans MQTT brokers for:
- Anonymous authentication vulnerabilities
- Default/weak credentials
- Topic enumeration and discovery
- $SYS broker information disclosure
- Sparkplug B ICS/SCADA infrastructure
- TLS configuration issues

Examples:
  oida mqtt 192.168.1.100
  oida mqtt 192.168.1.100 --enumerate --timeout 30
  oida mqtt 192.168.1.100 --default-creds
  oida mqtt broker.example.com --tls
  oida mqtt 192.168.1.100 --listen --listen-output capture.jsonl
        """,
        parents=parents,
        formatter_class=lambda prog: __import__("argparse").RawDescriptionHelpFormatter(
            prog, max_help_position=40
        ),
    )

    # Target (positional, required)
    add_target_argument(mqtt_parser, help_text="MQTT broker address (IP or hostname)")

    # === Network Options ===
    add_network_options(
        mqtt_parser,
        default_port=1883,
        include_timeout=True,
        port_help="MQTT port (default: 1883, or 8883 with --tls)",
    )

    # === Authentication Options ===
    auth_group = add_auth_options(
        mqtt_parser,
        include_creds_file=False,
        username_help="MQTT username",
        password_help="MQTT password",
    )

    auth_group.add_argument(
        "-i",
        "--client-id",
        type=str,
        default="",
        help="MQTT client ID (default: auto-generated)",
    )

    auth_group.add_argument(
        "-V",
        "--protocol-version",
        type=int,
        choices=[3, 4, 5],
        default=4,
        help="MQTT protocol version: 3=3.1, 4=3.1.1, 5=5.0 (default: 4)",
    )

    # === TLS Options (central) ===
    add_tls_options(
        mqtt_parser,
        include_cert=True,
        include_insecure=True,
        include_tls_flag=True,
        include_ca=True,
        default_tls_port=8883,
    )

    # === Credential Testing (central) ===
    add_brute_options(
        mqtt_parser,
        include_wordlist=True,
        include_rate=True,
        default_rate=0.0,
    )

    # === Topic Enumeration Options ===
    topic_group = mqtt_parser.add_argument_group("Topic Enumeration")

    topic_group.add_argument(
        "--enumerate",
        "-e",
        action="store_true",
        help="Enable topic enumeration ($SYS/#, #, spBv1.0/#)",
    )

    topic_group.add_argument(
        "--topics",
        type=str,
        default="#",
        help="Topic pattern or file path with topics (one per line)",
    )

    topic_group.add_argument(
        "-E",
        "--enumerate-common",
        action="store_true",
        default=False,
        help="Bruteforce common ICS/IoT topics (useful when # is blocked)",
    )

    topic_group.add_argument(
        "--topic-list",
        type=str,
        default="",
        metavar="FILE",
        help="Custom topic list file (one topic per line, # for comments)",
    )

    # === Listen Mode (central) ===
    listen_group = add_listen_options(
        mqtt_parser,
        include_duration=True,
        include_output=True,
        include_filter=True,
        default_duration=60,
    )

    # MQTT-specific listen addition
    listen_group.add_argument(
        "-U",
        "--unique",
        action="store_true",
        help="Only show unique topics (filter duplicate messages)",
    )

    # === Publish Options (mosquitto_pub compatible) ===
    pub_group = mqtt_parser.add_argument_group("Publish")

    pub_group.add_argument(
        "-m",
        "--message",
        type=str,
        help="Message payload to publish (requires --topics and --confirm)",
    )

    pub_group.add_argument(
        "--payload-file",
        type=str,
        metavar="FILE",
        help="Read payload from file (requires --topics and --confirm)",
    )

    pub_group.add_argument(
        "-n",
        "--null",
        action="store_true",
        help="Publish null (empty) message",
    )

    pub_group.add_argument(
        "-q",
        "--qos",
        type=int,
        choices=[0, 1, 2],
        default=0,
        help="QoS level (default: 0)",
    )

    pub_group.add_argument(
        "-r",
        "--retain",
        action="store_true",
        help="Set retain flag",
    )

    pub_group.add_argument(
        "--hex",
        action="store_true",
        help="Parse -m as hex bytes (e.g., '01:02:FF' or '0102FF')",
    )

    # === Fuzzing ===
    fuzz_group = add_dangerous_options(
        mqtt_parser,
        include_fuzz=True,
        fuzz_default_iterations=20,
    )

    # Add MQTT-specific fuzz option
    fuzz_group.add_argument(
        "-z",
        "--fuzz-topics",
        type=str,
        default="",
        metavar="TOPICS",
        help="Comma-separated topics to fuzz (default: use discovered topics)",
    )

    # === Protocol Enumeration ===
    proto_enum_group = mqtt_parser.add_argument_group("Protocol Enumeration")

    proto_enum_group.add_argument(
        "-B",
        "--enum-versions",
        action="store_true",
        help="Enumerate supported MQTT protocol versions (3.1, 3.1.1, 5.0) and capabilities (pre-auth)",
    )

    # === MQTT 5.0 Properties ===
    v5_group = mqtt_parser.add_argument_group("MQTT 5.0 Properties")

    v5_group.add_argument(
        "-R",
        "--response-topic",
        type=str,
        metavar="TOPIC",
        help="Response topic for request/response pattern",
    )

    v5_group.add_argument(
        "-J",
        "--correlation-id",
        type=str,
        metavar="ID",
        help="Correlation data to match response with request",
    )

    v5_group.add_argument(
        "-Y",
        "--content-type",
        type=str,
        metavar="MIME",
        help="Content type (e.g., 'application/json')",
    )

    v5_group.add_argument(
        "-X",
        "--message-expiry",
        type=int,
        metavar="SECS",
        help="Message expiry interval in seconds",
    )

    v5_group.add_argument(
        "-W",
        "--user-prop",
        action="append",
        metavar="K=V",
        help="User property (repeatable)",
    )

    return mqtt_parser
