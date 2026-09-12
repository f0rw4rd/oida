#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TASE.2/ICCP Protocol CLI Arguments

Defines command-line arguments for the TASE.2 protocol scanner.
"""

import argparse

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
)


def proto_args(parser: argparse._SubParsersAction, parents: list) -> None:
    """
    Register TASE.2 protocol arguments.

    Args:
        parser: argparse subparsers object
        parents: List of parent parsers to inherit from
    """
    tase2_parser = create_protocol_parser(
        parser,
        name="tase2",
        help_text="TASE.2/ICCP protocol scanner",
        description="""
TASE.2/ICCP Protocol Scanner

Scan TASE.2/ICCP servers used for inter-control center communications
in the electric utility industry. Supports discovery of domains (VCC/ICC),
data points, transfer sets, and control operations.

Requires: pyiec61850-ng (pip install oida[tase2])
        """,
        parents=parents,
    )

    # Target argument
    add_target_argument(tase2_parser)

    # Network options with TASE.2-specific additions
    network_group = add_network_options(
        tase2_parser, default_port=102, include_timeout=True, default_timeout=5
    )
    network_group.add_argument(
        "--local-ap-title",
        type=str,
        default="",
        help="Local AP title (e.g., 1.1.1.999)",
    )
    network_group.add_argument(
        "--remote-ap-title",
        type=str,
        default="",
        help="Remote AP title",
    )

    # Discovery options (enabled by default; pass --no-* to disable)
    discovery_group = tase2_parser.add_argument_group("Discovery Options")
    discovery_group.add_argument(
        "--no-discover-vcc",
        dest="discover_vcc",
        action="store_false",
        default=True,
        help="Skip Virtual Control Center discovery (default: enabled)",
    )
    discovery_group.add_argument(
        "--no-discover-icc",
        dest="discover_icc",
        action="store_false",
        default=True,
        help="Skip Indication Control Center discovery (default: enabled)",
    )
    discovery_group.add_argument(
        "--no-analyze-blt",
        dest="analyze_blt",
        action="store_false",
        default=True,
        help="Skip bilateral table analysis (default: enabled)",
    )
    discovery_group.add_argument(
        "--no-enumerate-points",
        dest="enumerate_points",
        action="store_false",
        default=True,
        help="Skip data point enumeration (default: enabled)",
    )
    discovery_group.add_argument(
        "--max-points",
        type=int,
        default=100,
        help="Maximum points to enumerate per domain (default: 100)",
    )

    # Testing options
    test_group = tase2_parser.add_argument_group("Testing Options")
    test_group.add_argument(
        "--test-rbe",
        action="store_true",
        default=False,
        help="Test Report-by-Exception capability (Block 2)",
    )
    test_group.add_argument(
        "--test-control",
        action="store_true",
        default=False,
        help="Test device control operations (Block 5)",
    )
    test_group.add_argument(
        "--test-write",
        action="store_true",
        default=False,
        help="Test write access to data points",
    )

    # Action commands
    action_group = tase2_parser.add_argument_group("Action Commands")
    action_group.add_argument(
        "--list-domains",
        action="store_true",
        help="List all domains (VCC/ICC)",
    )
    action_group.add_argument(
        "--list-variables",
        type=str,
        metavar="DOMAIN",
        help="List variables in a domain",
    )
    action_group.add_argument(
        "--list-data-sets",
        nargs="?",
        const=True,
        metavar="DOMAIN",
        help="List data sets (optionally for a domain)",
    )
    action_group.add_argument(
        "--list-transfer-sets",
        type=str,
        metavar="DOMAIN",
        help="List DS transfer sets in a domain",
    )

    # Data access commands
    data_group = tase2_parser.add_argument_group("Data Access Commands")
    data_group.add_argument(
        "--read-point",
        type=str,
        metavar="DOMAIN/NAME",
        help="Read a data point value",
    )
    data_group.add_argument(
        "--write-point",
        type=str,
        metavar="DOMAIN/NAME:VALUE",
        help="Write a value to a data point",
    )

    # Control commands (Block 5)
    control_group = tase2_parser.add_argument_group("Control Commands (Block 5)")
    control_group.add_argument(
        "--send-command",
        type=str,
        metavar="DOMAIN/DEVICE:CMD",
        help="Send a command to a device",
    )
    control_group.add_argument(
        "--select-device",
        type=str,
        metavar="DOMAIN/DEVICE",
        help="Select a device (SBO)",
    )
    control_group.add_argument(
        "--operate-device",
        type=str,
        metavar="DOMAIN/DEVICE:VALUE",
        help="Operate a device after select",
    )

    # Transfer set commands (Block 2)
    rbe_group = tase2_parser.add_argument_group("Transfer Set Commands (Block 2)")
    rbe_group.add_argument(
        "--enable-rbe",
        type=str,
        metavar="DOMAIN/TSET",
        help="Enable a DS transfer set",
    )
    rbe_group.add_argument(
        "--disable-rbe",
        type=str,
        metavar="DOMAIN/TSET",
        help="Disable a DS transfer set",
    )

    # Info commands
    info_group = tase2_parser.add_argument_group("Information Commands")
    info_group.add_argument(
        "--get-blt",
        action="store_true",
        help="Get bilateral table information",
    )
    info_group.add_argument(
        "--get-server-info",
        action="store_true",
        help="Get server information",
    )
    info_group.add_argument(
        "--get-features",
        action="store_true",
        help="Get supported conformance blocks (Supported_Features)",
    )
    info_group.add_argument(
        "--get-version",
        action="store_true",
        help="Get TASE.2 protocol version",
    )

    # Data type and bulk operations (Block 1)
    data_type_group = tase2_parser.add_argument_group("Data Type Operations (Block 1)")
    data_type_group.add_argument(
        "--get-data-type",
        type=str,
        metavar="DOMAIN/NAME",
        help="Get type information for a data value",
    )
    data_type_group.add_argument(
        "--read-points",
        type=str,
        metavar="DOMAIN/NAME1,NAME2,...",
        help="Read multiple data points in bulk",
    )

    # Data set operations (Block 1)
    ds_group = tase2_parser.add_argument_group("Data Set Operations (Block 1)")
    ds_group.add_argument(
        "--get-ds-members",
        type=str,
        metavar="DOMAIN/DATASET",
        help="Get list of variables in a data set",
    )
    ds_group.add_argument(
        "--read-data-set",
        type=str,
        metavar="DOMAIN/DATASET",
        help="Read all values in a data set",
    )
    ds_group.add_argument(
        "--create-data-set",
        type=str,
        metavar="DOMAIN/NAME:VAR1,VAR2,...",
        help="Create a new data set with specified members",
    )
    ds_group.add_argument(
        "--delete-data-set",
        type=str,
        metavar="DOMAIN/DATASET",
        help="Delete a data set",
    )

    # Device tag operations (Block 5)
    tag_group = tase2_parser.add_argument_group("Device Tag Operations (Block 5)")
    tag_group.add_argument(
        "--get-tag",
        type=str,
        metavar="DOMAIN/DEVICE",
        help="Get tag value for a device",
    )
    tag_group.add_argument(
        "--set-tag",
        type=str,
        metavar="DOMAIN/DEVICE:TAG[:REASON]",
        help="Set tag for a device (NO_TAG, OPEN_AND_CLOSE_INHIBIT, CLOSE_ONLY)",
    )

    # Information Messages operations (Block 4)
    im_group = tase2_parser.add_argument_group("Information Messages (Block 4)")
    im_group.add_argument(
        "--list-im-stores",
        nargs="?",
        const=True,
        metavar="DOMAIN",
        help="List Information Message stores (optionally for a domain)",
    )
    im_group.add_argument(
        "--list-messages",
        type=str,
        metavar="DOMAIN/STORE",
        help="List messages in an IM store",
    )
    im_group.add_argument(
        "--read-message",
        type=str,
        metavar="DOMAIN/STORE/MSGID",
        help="Read message content",
    )
    im_group.add_argument(
        "--write-message",
        type=str,
        metavar="DOMAIN/STORE:CONTENT",
        help="Write message to store",
    )
    im_group.add_argument(
        "--delete-message",
        type=str,
        metavar="DOMAIN/STORE/MSGID",
        help="Delete message from store",
    )
    im_group.add_argument(
        "--test-im",
        action="store_true",
        default=False,
        help="Test Information Message access (Block 4)",
    )

    # Safety confirmation
    safety_group = tase2_parser.add_argument_group("Safety")
    safety_group.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dangerous operations (required for write, control, delete, and tag operations)",
    )

    # Epilog with examples
    tase2_parser.epilog = """
Examples:
  # Basic scan
  oida tase2 192.168.1.100

  # Scan with custom port and AP titles
  oida tase2 192.168.1.100 --port 102 --local-ap-title 1.1.1.999

  # Full enumeration with RBE and control testing
  oida tase2 192.168.1.100 --test-rbe --test-control

  # Get server capabilities and version
  oida tase2 192.168.1.100 --get-features --get-version

  # List domains and variables
  oida tase2 192.168.1.100 --list-domains
  oida tase2 192.168.1.100 --list-variables ICC1

  # Get data point type information
  oida tase2 192.168.1.100 --get-data-type ICC1/Voltage

  # Read multiple points
  oida tase2 192.168.1.100 --read-points ICC1/Voltage,Current,Power

  # Data set operations
  oida tase2 192.168.1.100 --get-ds-members ICC1/DataSet1
  oida tase2 192.168.1.100 --read-data-set ICC1/DataSet1
  oida tase2 192.168.1.100 --create-data-set VCC/MySet:Voltage,Current

  # Read a data point
  oida tase2 192.168.1.100 --read-point ICC1/Voltage

  # Write a setpoint (requires write access)
  oida tase2 192.168.1.100 --write-point ICC1/Setpoint:230.0

  # Device tag operations
  oida tase2 192.168.1.100 --get-tag ICC1/Breaker1
  oida tase2 192.168.1.100 --set-tag ICC1/Breaker1:CLOSE_ONLY:Maintenance

  # Control command with SBO
  oida tase2 192.168.1.100 --select-device ICC1/Breaker1
  oida tase2 192.168.1.100 --operate-device ICC1/Breaker1:1

  # Scan multiple targets
  oida tase2 192.168.1.0/24 -t 20 --enumerate-points

  # Information Message operations (Block 4)
  oida tase2 192.168.1.100 --list-im-stores
  oida tase2 192.168.1.100 --list-im-stores ICC1
  oida tase2 192.168.1.100 --list-messages ICC1/OperatorMessages
  oida tase2 192.168.1.100 --read-message ICC1/OperatorMessages/MSG001
  oida tase2 192.168.1.100 --test-im

Note: Requires pyiec61850-ng. Install with: pip install oida[tase2]
"""
