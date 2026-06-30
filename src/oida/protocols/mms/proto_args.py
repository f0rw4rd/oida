"""
Argument parser definition for MMS (Manufacturing Message Specification) protocol

This module registers MMS-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_dangerous_options,
)


def proto_args(parser, parents):
    """Register MMS-specific arguments"""
    # Create parser with standard setup
    mms_parser = create_protocol_parser(
        parser,
        name="mms",
        help_text="MMS/IEC 61850 scanner",
        description="Scan and interact with MMS/IEC 61850 devices",
        parents=parents,
        epilog="""
Examples:
  oida mms 192.168.1.100                       # Connect + map the data model (tree)
  oida mms 192.168.1.100 -i                    # Query server identity (vendor/model/revision)
  oida mms 192.168.1.100 -l                    # Enumerate logical-device / node names only
  oida mms 192.168.1.100 --read-values         # Read every discovered data object value
  oida mms 192.168.1.100 --max-objects 200     # Cap discovery at 200 objects

Reading specific objects (-r takes a reference substring, as printed in the tree):
  oida mms 192.168.1.100 -r GGIO1.Mod          # Read one object by qualified LN.DO name
  oida mms 192.168.1.100 -r LLN0               # Read everything under a logical node

Write / fuzz testing (DANGEROUS - require --confirm):
  oida mms 192.168.1.100 --test-write --confirm                  # Probe writable objects
  oida mms 192.168.1.100 --fuzz --confirm                        # Fuzz writable objects
  oida mms 192.168.1.100 --fuzz-reference GGIO1.SPCSO1 --confirm  # Fuzz one reference
""",
    )

    # Add target argument
    add_target_argument(mms_parser)

    # Add network options (port, timeout)
    add_network_options(mms_parser, default_port=102, port_help="MMS port (default: 102)")

    # MMS-specific options (match scanner protocol_options)
    mms_group = mms_parser.add_argument_group("MMS Options")
    mms_group.add_argument(
        "-i",
        "--identify",
        action="store_true",
        help="Query the MMS server identity (vendor/model/revision)",
    )
    mms_group.add_argument(
        "-l",
        "--get-name-list",
        action="store_true",
        help="Enumerate the logical-device/node name list",
    )
    mms_group.add_argument(
        "-r",
        "--variable",
        type=str,
        metavar="REF",
        help="Read a single variable/data object by reference (substring match)",
    )
    mms_group.add_argument(
        "--read-values",
        action="store_true",
        help="Read values from discovered data objects",
    )
    mms_group.add_argument(
        "--test-write",
        action="store_true",
        help="Test write access to data objects",
    )
    mms_group.add_argument(
        "--max-objects",
        type=int,
        default=1000,
        metavar="N",
        help="Maximum number of data objects to discover (default: 1000)",
    )

    # Add dangerous options (fuzzing with --confirm)
    dangerous = add_dangerous_options(mms_parser, include_fuzz=True, include_write=False)

    # Customize fuzzing options for MMS
    dangerous.add_argument(
        "--fuzz-reference",
        type=str,
        metavar="REF",
        help="Specific data object reference to fuzz",
    )

    return mms_parser
