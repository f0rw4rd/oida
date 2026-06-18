"""
Argument parser definition for DICOM protocol

This module registers DICOM-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_tls_options,
    add_dangerous_options,
    add_discovery_options,
)


def proto_args(parser, parents):
    """Register DICOM-specific arguments"""
    dicom_parser = create_protocol_parser(
        parser,
        name="dicom",
        help_text="DICOM medical imaging protocol scanner",
        description="Scan and interact with DICOM PACS servers",
        parents=parents,
        epilog="""
Examples:
  oida dicom 192.168.1.100                          # Basic C-ECHO discovery
  oida dicom 192.168.1.100 --find                   # C-FIND patient query
  oida dicom 192.168.1.100 --find --patient-name "*"  # Wildcard search
  oida dicom 192.168.1.100 --find --query-level STUDY # Study-level query
  oida dicom 192.168.1.100 --get --study-uid 1.2.3  # Retrieve images
  oida dicom 192.168.1.100 --store --store-file x.dcm # Upload image
  oida dicom 192.168.1.100 --move --dest-aet OTHER --study-uid 1.2.3  # Transfer
  oida dicom 192.168.1.100 --aet-brute              # Brute force AE Titles
  oida dicom 192.168.1.100 --dump-all               # Full bulk export
  oida dicom 192.168.1.100 --probe-ops              # Probe SOP classes
  oida dicom 192.168.1.100 --tls                    # Use TLS encryption
""",
    )

    # Target (positional)
    add_target_argument(dicom_parser)

    # Network Options (--port, --timeout)
    add_network_options(dicom_parser, default_port=104)

    # TLS Options (--tls, --tls-cert, --tls-key, --tls-ca, --tls-insecure)
    add_tls_options(dicom_parser, default_tls_port=2762)

    # Discovery Options (--discover, --quick, --full, --deep-scan)
    add_discovery_options(dicom_parser)

    # DICOM Association Options
    assoc_group = dicom_parser.add_argument_group("DICOM Association")

    assoc_group.add_argument(
        "--aet",
        type=str,
        default="OIDA",
        metavar="TITLE",
        help="Calling AE Title (default: OIDA)",
    )

    assoc_group.add_argument(
        "--called-aet",
        type=str,
        default="ANY-SCP",
        metavar="TITLE",
        help="Called AE Title (default: ANY-SCP)",
    )

    assoc_group.add_argument(
        "--max-pdu",
        type=int,
        default=16384,
        metavar="SIZE",
        help="Maximum PDU size (default: 16384)",
    )

    # Service Class Operations
    svc_group = dicom_parser.add_argument_group("Service Operations")

    svc_group.add_argument(
        "--find",
        action="store_true",
        help="Perform C-FIND query (patient/study/series/image)",
    )

    svc_group.add_argument(
        "--get",
        action="store_true",
        help="Retrieve images via C-GET (requires --study-uid or --series-uid)",
    )

    svc_group.add_argument(
        "--store",
        action="store_true",
        help="Upload DICOM files via C-STORE (requires --store-file or --store-dir)",
    )

    svc_group.add_argument(
        "--move",
        action="store_true",
        help="Transfer images via C-MOVE (requires --dest-aet and --study-uid)",
    )

    svc_group.add_argument(
        "--probe-ops",
        action="store_true",
        help="Probe supported SOP classes and transfer syntaxes",
    )

    svc_group.add_argument(
        "--dump-all",
        action="store_true",
        help="Recursive bulk export: enumerate all patients/studies/series and retrieve images",
    )

    # Query/Retrieve Options
    query_group = dicom_parser.add_argument_group("Query/Retrieve (C-FIND)")

    query_group.add_argument(
        "--patient-id",
        type=str,
        metavar="ID",
        help="Patient ID for C-FIND query",
    )

    query_group.add_argument(
        "--patient-name",
        type=str,
        metavar="NAME",
        help="Patient name for query (wildcards: * ?)",
    )

    query_group.add_argument(
        "--study-date",
        type=str,
        metavar="DATE",
        help="Study date range (YYYYMMDD or YYYYMMDD-YYYYMMDD)",
    )

    query_group.add_argument(
        "--modality",
        type=str,
        metavar="MOD",
        help="Modality filter (CT, MR, US, XA, etc.)",
    )

    query_group.add_argument(
        "--accession-number",
        type=str,
        metavar="NUM",
        help="Accession number for query",
    )

    query_group.add_argument(
        "--study-uid",
        type=str,
        metavar="UID",
        help="Study Instance UID for query/retrieve",
    )

    query_group.add_argument(
        "--series-uid",
        type=str,
        metavar="UID",
        help="Series Instance UID for query/retrieve",
    )

    query_group.add_argument(
        "--query-level",
        type=str,
        choices=["PATIENT", "STUDY", "SERIES", "IMAGE"],
        default="PATIENT",
        help="Query retrieve level (default: PATIENT)",
    )

    query_group.add_argument(
        "--max-results",
        type=int,
        default=100,
        metavar="N",
        help="Maximum query results (default: 100)",
    )

    # Tag Extraction Options
    tag_group = dicom_parser.add_argument_group("Tag Extraction")

    tag_group.add_argument(
        "--dump-tags",
        action="store_true",
        help="Extract all DICOM tags from C-FIND results",
    )

    tag_group.add_argument(
        "--phi-only",
        action="store_true",
        help="Only extract PHI-containing tags (with --dump-tags)",
    )

    tag_group.add_argument(
        "--metadata",
        action="store_true",
        help="Extract additional metadata fields from query results",
    )

    tag_group.add_argument(
        "--extract-fields",
        type=str,
        metavar="TAGS",
        help="Extract specific DICOM tags (comma-separated, e.g., 'PatientName,StudyDate')",
    )

    # Enumeration Options
    enum_group = dicom_parser.add_argument_group("Enumeration")

    enum_group.add_argument(
        "--enum-operators",
        action="store_true",
        help="Enumerate operators, physicians, and personnel from study metadata",
    )

    enum_group.add_argument(
        "--enum-devices",
        action="store_true",
        help="Enumerate modalities, station names, and manufacturers",
    )

    enum_group.add_argument(
        "--time-analysis",
        action="store_true",
        help="Analyze study dates for retention policy and access patterns",
    )

    # Worklist Options
    wl_group = dicom_parser.add_argument_group("Modality Worklist")

    wl_group.add_argument(
        "--worklist",
        action="store_true",
        help="Query Modality Worklist for scheduled procedures",
    )

    wl_group.add_argument(
        "--worklist-modality",
        type=str,
        metavar="MOD",
        help="Filter worklist by modality (CT, MR, etc.)",
    )

    wl_group.add_argument(
        "--worklist-date",
        type=str,
        metavar="DATE",
        help="Filter worklist by scheduled date (YYYYMMDD)",
    )

    wl_group.add_argument(
        "--worklist-station",
        type=str,
        metavar="AET",
        help="Filter worklist by station AE Title",
    )

    # Retrieve/Transfer Options
    xfer_group = dicom_parser.add_argument_group("Retrieve/Transfer Options")

    xfer_group.add_argument(
        "--output-dir",
        type=str,
        default="./dicom_output",
        metavar="DIR",
        help="Directory for retrieved images (default: ./dicom_output)",
    )

    xfer_group.add_argument(
        "--dest-aet",
        type=str,
        metavar="AE",
        help="Destination AE Title for C-MOVE transfer",
    )

    xfer_group.add_argument(
        "--store-file",
        type=str,
        metavar="FILE",
        help="DICOM file to upload via C-STORE",
    )

    xfer_group.add_argument(
        "--store-dir",
        type=str,
        metavar="DIR",
        help="Directory of .dcm files to upload via C-STORE",
    )

    # Bulk Export Limits
    bulk_group = dicom_parser.add_argument_group("Bulk Export Limits (--dump-all)")

    bulk_group.add_argument(
        "--max-patients",
        type=int,
        default=10,
        metavar="N",
        help="Maximum patients to enumerate in bulk export (default: 10)",
    )

    bulk_group.add_argument(
        "--max-studies",
        type=int,
        default=50,
        metavar="N",
        help="Maximum studies per patient in bulk export (default: 50)",
    )

    # AE Title Enumeration
    ae_group = dicom_parser.add_argument_group("AE Title Enumeration")

    # nargs="?" + const=True + default=None so the scanner can distinguish:
    #   not specified  -> None  (scanner skips brute force)
    #   --aet-brute    -> True  (use default wordlist)
    #   --aet-brute F  -> "F"   (use custom wordlist file)
    ae_group.add_argument(
        "--aet-brute",
        nargs="?",
        const=True,
        default=None,
        metavar="FILE",
        help="Brute-force AE Titles (optionally specify wordlist file)",
    )

    ae_group.add_argument(
        "--ae-wordlist",
        type=str,
        metavar="FILE",
        help="AE Title wordlist file (alternative to --aet-brute FILE)",
    )

    ae_group.add_argument(
        "--common-ae",
        action="store_true",
        help="Test common vendor default AE Titles",
    )

    # Fuzzing (--confirm, --fuzz, --fuzz-iterations)
    add_dangerous_options(dicom_parser, include_fuzz=True, fuzz_default_iterations=10)

    return dicom_parser
