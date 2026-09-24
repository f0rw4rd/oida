"""
Argument parser definition for ASTM/LIS protocol

This module registers ASTM E1381/E1394 (CLSI LIS01/LIS02) specific
command-line arguments for the laboratory information system protocol.
"""

from oida.utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_tls_options,
    add_dangerous_options,
)


def proto_args(parser, parents):
    """Register ASTM/LIS-specific arguments"""
    astm_parser = create_protocol_parser(
        parser,
        name="astm",
        help_text="ASTM/LIS laboratory protocol scanner",
        description="Scan and interact with ASTM E1381/E1394 laboratory endpoints",
        parents=parents,
        epilog="""
Examples:
  oida astm 192.168.1.100                     # Basic discovery
  oida astm 192.168.1.100 --probe-ops         # Probe supported record types
  oida astm 192.168.1.100 --enum-tests        # Enumerate available tests
  oida astm 192.168.1.100 --enum-instruments  # Enumerate connected analyzers
  oida astm 192.168.1.100 --send-query        # Send query record
  oida astm 192.168.1.100 --tls               # Use TLS encryption
""",
    )

    # Target (positional)
    add_target_argument(astm_parser)

    # Network Options (--port, --timeout)
    add_network_options(astm_parser, default_port=12000)

    # TLS Options (--tls, --tls-cert, --tls-key, --tls-ca, --tls-insecure)
    # No default_tls_port: create_conn_obj() always uses --port (default 12000)
    # and does not switch ports for --tls, so the help must not claim it does.
    add_tls_options(astm_parser)

    # NOTE: --discover/--quick/--full/--deep-scan were removed. They were
    # accepted by argparse but never consumed by this protocol's cli_runner
    # (nothing under src/oida/protocols/astm/ or central CLI code read their
    # dests), and --quick was falsely advertised above as a real scan mode.
    # Rather than silently keep advertising modes with no effect, the flags
    # are gone; a default scan is the only mode.

    # NOTE: Output options (--output, --format, --verbose, --debug) are
    # provided by the main parser and must NOT be re-added here.

    # ASTM-Specific Options
    astm_group = astm_parser.add_argument_group("ASTM Options")

    astm_group.add_argument(
        "--sender-name",
        type=str,
        default="OIDA",
        metavar="NAME",
        help="Sender name for header record (default: OIDA)",
    )

    astm_group.add_argument(
        "--sender-id",
        type=str,
        default="",
        metavar="ID",
        help="Sender ID for header record",
    )

    astm_group.add_argument(
        "--receiver-name",
        type=str,
        default="",
        metavar="NAME",
        help="Receiver name for header record (auto-detected if empty)",
    )

    astm_group.add_argument(
        "--receiver-id",
        type=str,
        default="",
        metavar="ID",
        help="Receiver ID for header record",
    )

    astm_group.add_argument(
        "--astm-version",
        type=str,
        default="E1394",
        choices=["E1381", "E1394", "LIS01", "LIS02"],
        help="ASTM version (default: E1394)",
    )

    # Record Operations
    record_group = astm_parser.add_argument_group("Record Operations")

    record_group.add_argument(
        "--probe-ops",
        action="store_true",
        help="Probe supported record types (H, P, O, R, Q)",
    )

    record_group.add_argument(
        "--send-query",
        action="store_true",
        help="Send Q (Query) record for patient/order information",
    )

    record_group.add_argument(
        "--send-order",
        action="store_true",
        help="Send O (Order) record (requires --confirm)",
    )

    record_group.add_argument(
        "--send-result",
        action="store_true",
        help="Send R (Result) record (requires --confirm)",
    )

    record_group.add_argument(
        "--send-patient",
        action="store_true",
        help="Send P (Patient) record (requires --confirm)",
    )

    # Patient/Order Data
    data_group = astm_parser.add_argument_group("Patient/Order Data")

    data_group.add_argument(
        "--patient-id",
        type=str,
        metavar="ID",
        help="Patient ID for queries/records",
    )

    data_group.add_argument(
        "--patient-name",
        type=str,
        metavar="NAME",
        help="Patient name (format: LAST^FIRST^MIDDLE)",
    )

    data_group.add_argument(
        "--sample-id",
        type=str,
        metavar="ID",
        help="Sample/specimen ID for orders",
    )

    data_group.add_argument(
        "--order-id",
        type=str,
        metavar="ID",
        help="Order ID for queries",
    )

    data_group.add_argument(
        "--test-id",
        type=str,
        metavar="ID",
        help="Test ID (e.g., GLU, CBC, BMP)",
    )

    data_group.add_argument(
        "--result-value",
        type=str,
        metavar="VALUE",
        help="Result value for R record",
    )

    data_group.add_argument(
        "--result-units",
        type=str,
        metavar="UNITS",
        help="Result units (e.g., mg/dL, g/L)",
    )

    data_group.add_argument(
        "--reference-range",
        type=str,
        metavar="RANGE",
        help="Reference range (e.g., 70-100)",
    )

    data_group.add_argument(
        "--abnormal-flag",
        type=str,
        choices=["L", "H", "LL", "HH", "N", "<", ">", "A"],
        metavar="FLAG",
        help="Abnormal flag: L(ow), H(igh), LL/HH(critical), N(ormal), A(bnormal)",
    )

    # Data Modification Options
    modify_group = astm_parser.add_argument_group("Data Modification (requires --confirm)")

    modify_group.add_argument(
        "--action-code",
        type=str,
        choices=["N", "A", "C", "P", "R", "X"],
        default="N",
        metavar="CODE",
        help="Order action code: N(ew), A(dd), C(ancel), P(ending), R(equest), X(delete)",
    )

    modify_group.add_argument(
        "--result-status",
        type=str,
        choices=["P", "F", "C", "X", "I", "S", "M", "R", "N", "W"],
        default="F",
        metavar="STATUS",
        help="Result status: P(relim), F(inal), C(orrected), X(canceled), I(ncomplete)",
    )

    modify_group.add_argument(
        "--priority",
        type=str,
        choices=["S", "A", "R", "P", "T"],
        default="R",
        metavar="PRI",
        help="Order priority: S(tat), A(SAP), R(outine), P(reop), T(iming critical)",
    )

    modify_group.add_argument(
        "--cancel-order",
        action="store_true",
        help="Cancel an existing order (sets action-code=C)",
    )

    modify_group.add_argument(
        "--correct-result",
        action="store_true",
        help="Send corrected result (sets result-status=C)",
    )

    modify_group.add_argument(
        "--delete-result",
        action="store_true",
        help="Delete/cancel a result (sets result-status=X)",
    )

    # Enumeration Options
    enum_group = astm_parser.add_argument_group("Enumeration")

    enum_group.add_argument(
        "--enum-tests",
        action="store_true",
        help="Enumerate available lab tests",
    )

    enum_group.add_argument(
        "--enum-instruments",
        action="store_true",
        help="Enumerate connected analyzers/instruments",
    )

    enum_group.add_argument(
        "--enum-patients",
        action="store_true",
        help="Enumerate patient records (requires --confirm)",
    )

    # Fuzzing (--confirm, --fuzz, --fuzz-iterations)
    fuzz_group = add_dangerous_options(astm_parser, include_fuzz=True, fuzz_default_iterations=10)

    fuzz_group.add_argument(
        "--fuzz-record",
        type=str,
        choices=["H", "P", "O", "R", "Q", "C", "L"],
        metavar="TYPE",
        help="Specific record type to fuzz",
    )

    fuzz_group.add_argument(
        "--fuzz-frame",
        action="store_true",
        help="Fuzz ASTM framing (STX/ETX/checksums)",
    )

    return astm_parser
