"""
Argument parser definition for FHIR R4 protocol

This module registers FHIR-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_tls_options,
    add_dangerous_options,
    add_auth_options,
    add_brute_options,
)


def proto_args(parser, parents):
    """Register FHIR-specific arguments"""
    fhir_parser = create_protocol_parser(
        parser,
        name="fhir",
        help_text="FHIR R4 healthcare protocol scanner",
        description="Scan and interact with FHIR R4 REST API servers",
        parents=parents,
        epilog="""
Examples:
  # Discovery and Reconnaissance (read-only)
  oida fhir https://fhir.example.com/r4                    # Basic discovery
  oida fhir https://fhir.example.com/r4 -C                 # Get CapabilityStatement
  oida fhir https://fhir.example.com/r4 -E                 # Enumerate all resources

  # Patient Search
  oida fhir https://fhir.example.com/r4 -p                 # List patients
  oida fhir https://fhir.example.com/r4 -p -N "Doe"        # Filter by name
  oida fhir https://fhir.example.com/r4 -p -W -n 50        # Wildcard, max 50

  # Clinical Data Search
  oida fhir https://fhir.example.com/r4 -O -I PT001        # Observations for patient
  oida fhir https://fhir.example.com/r4 -m -I PT001        # Medications for patient
  oida fhir https://fhir.example.com/r4 -c -I PT001        # Conditions for patient

  # Read Specific Resource
  oida fhir https://fhir.example.com/r4 --read-patient PT001
  oida fhir https://fhir.example.com/r4 --read-observation OBS123

  # Authentication Testing
  oida fhir https://fhir.example.com/r4 -A                 # Test auth mechanisms
  oida fhir https://fhir.example.com/r4 -x -I PT001        # Test cross-patient access

  # Authenticated Access
  oida fhir https://fhir.example.com/r4 -T "Bearer xxx" -p
  oida fhir https://fhir.example.com/r4 -u admin -P pass -p

  # Credential Testing (Brute Force)
  oida fhir https://fhir.example.com/r4 --brute --default-creds
  oida fhir https://fhir.example.com/r4 --brute -u admin --wordlist passwords.txt

  # Export Results
  oida fhir https://fhir.example.com/r4 -p -o ./results -f json

  # Public Test Servers
  oida fhir https://hapi.fhir.org/baseR4 -C
  oida fhir https://hapi.fhir.org/baseR4 -p -n 10
""",
    )

    # Target (positional) - FHIR base URL
    add_target_argument(
        fhir_parser,
        help_text="FHIR server base URL (e.g., https://fhir.example.com/r4)",
    )

    # Network Options (port comes from URL, just add timeout)
    network_group = fhir_parser.add_argument_group("Network Options")
    network_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECS",
        help="Connection timeout in seconds (default: 30)",
    )

    # TLS Options (--tls, --tls-cert, --tls-key, --tls-ca, --tls-insecure)
    add_tls_options(fhir_parser, include_cert=True, include_insecure=True)

    # ============================================================================
    # Discovery Options
    # ============================================================================
    discovery_group = fhir_parser.add_argument_group("Discovery Options")

    discovery_group.add_argument(
        "-C",
        "--caps",
        "--capability-statement",
        action="store_true",
        dest="caps",
        help="Display full CapabilityStatement (server metadata)",
    )

    discovery_group.add_argument(
        "-E",
        "--enum-all",
        action="store_true",
        help="Enable all enumeration options (patients, observations, medications, conditions)",
    )

    discovery_group.add_argument(
        "--fhir-version",
        type=str,
        default="R4",
        choices=["DSTU2", "STU3", "R4", "R4B", "R5"],
        help="FHIR version to use (default: R4)",
    )

    # ============================================================================
    # Authentication Options (Basic Auth + OAuth2)
    # ============================================================================
    # Add standard auth options: --username/-u, --password/-P, --credentials
    auth_group = add_auth_options(
        fhir_parser,
        username_help="Username for HTTP Basic authentication",
        password_help="Password for HTTP Basic authentication",
    )

    # OAuth2 / Bearer Token options
    auth_group.add_argument(
        "-T",
        "--token",
        type=str,
        metavar="TOKEN",
        help="Bearer token for authentication (with or without 'Bearer ' prefix)",
    )

    auth_group.add_argument(
        "--client-id",
        type=str,
        metavar="ID",
        help="OAuth2 client ID (for SMART on FHIR)",
    )

    auth_group.add_argument(
        "--client-secret",
        type=str,
        metavar="SECRET",
        help="OAuth2 client secret",
    )

    auth_group.add_argument(
        "--scope",
        type=str,
        metavar="SCOPES",
        help="OAuth2 scopes (space-separated, e.g., 'patient/*.read user/*.read')",
    )

    auth_group.add_argument(
        "--auth-url",
        type=str,
        metavar="URL",
        help="OAuth2 authorization URL (auto-detected from metadata if not provided)",
    )

    auth_group.add_argument(
        "--token-url",
        type=str,
        metavar="URL",
        help="OAuth2 token URL (auto-detected from metadata if not provided)",
    )

    # ============================================================================
    # Credential Testing (Brute Force)
    # ============================================================================
    # Add standard brute options: --brute, --default-creds, --wordlist, --brute-rate
    brute_group = add_brute_options(fhir_parser, default_rate=0.5)

    brute_group.add_argument(
        "--user-file",
        type=str,
        metavar="FILE",
        help="Username wordlist file (one per line)",
    )

    brute_group.add_argument(
        "--pass-file",
        type=str,
        metavar="FILE",
        help="Password wordlist file (one per line)",
    )

    brute_group.add_argument(
        "--brute-method",
        type=str,
        choices=["basic", "oauth2", "both"],
        default="basic",
        help="Authentication method to brute force (default: basic)",
    )

    # ============================================================================
    # Resource Search Options
    # ============================================================================
    search_group = fhir_parser.add_argument_group("Resource Search")

    search_group.add_argument(
        "--search-patients",
        action="store_true",
        help="Search for Patient resources",
    )

    search_group.add_argument(
        "-O",
        "--search-observations",
        action="store_true",
        help="Search for Observation resources (lab results, vitals)",
    )

    search_group.add_argument(
        "-m",
        "--search-medications",
        action="store_true",
        help="Search for MedicationRequest resources",
    )

    search_group.add_argument(
        "-c",
        "--search-conditions",
        action="store_true",
        help="Search for Condition resources (diagnoses)",
    )

    search_group.add_argument(
        "-e",
        "--search-encounters",
        action="store_true",
        help="Search for Encounter resources (visits)",
    )

    search_group.add_argument(
        "-r",
        "--search-procedures",
        action="store_true",
        help="Search for Procedure resources",
    )

    search_group.add_argument(
        "-a",
        "--search-allergies",
        action="store_true",
        help="Search for AllergyIntolerance resources",
    )

    search_group.add_argument(
        "-i",
        "--search-immunizations",
        action="store_true",
        help="Search for Immunization resources",
    )

    search_group.add_argument(
        "-R",
        "--search-diagnostics",
        action="store_true",
        help="Search for DiagnosticReport resources",
    )

    search_group.add_argument(
        "-D",
        "--search-documents",
        action="store_true",
        help="Search for DocumentReference resources",
    )

    search_group.add_argument(
        "-B",
        "--search-practitioners",
        action="store_true",
        help="Search for Practitioner resources (healthcare providers)",
    )

    search_group.add_argument(
        "-G",
        "--search-organizations",
        action="store_true",
        help="Search for Organization resources (hospitals, clinics)",
    )

    search_group.add_argument(
        "-L",
        "--search-locations",
        action="store_true",
        help="Search for Location resources (rooms, buildings)",
    )

    search_group.add_argument(
        "-V",
        "--search-devices",
        action="store_true",
        help="Search for Device resources (medical deVices)",
    )

    search_group.add_argument(
        "-J",
        "--search-orders",
        action="store_true",
        help="Search for ServiceRequest resources (orders/Jobs)",
    )

    # ============================================================================
    # Search Filters
    # ============================================================================
    filter_group = fhir_parser.add_argument_group("Search Filters")

    filter_group.add_argument(
        "-I",
        "--patient-id",
        type=str,
        metavar="ID",
        help="Filter by patient ID",
    )

    filter_group.add_argument(
        "-N",
        "--patient-name",
        type=str,
        metavar="NAME",
        help="Filter by patient name (supports partial match)",
    )

    filter_group.add_argument(
        "--patient-dob",
        type=str,
        metavar="DATE",
        help="Filter by patient date of birth (YYYY-MM-DD)",
    )

    filter_group.add_argument(
        "--patient-gender",
        type=str,
        choices=["male", "female", "other", "unknown"],
        metavar="GENDER",
        help="Filter by patient gender",
    )

    filter_group.add_argument(
        "-n",
        "--max-results",
        type=int,
        default=100,
        metavar="N",
        help="Maximum number of results to return (default: 100)",
    )

    filter_group.add_argument(
        "-W",
        "--wildcard",
        action="store_true",
        help="Use wildcard search to enumerate all resources",
    )

    filter_group.add_argument(
        "--date-from",
        type=str,
        metavar="DATE",
        help="Filter by date range start (YYYY-MM-DD)",
    )

    filter_group.add_argument(
        "--date-to",
        type=str,
        metavar="DATE",
        help="Filter by date range end (YYYY-MM-DD)",
    )

    filter_group.add_argument(
        "--code",
        type=str,
        metavar="CODE",
        help="Filter by code (LOINC, SNOMED, ICD-10, etc.)",
    )

    filter_group.add_argument(
        "--category",
        type=str,
        metavar="CAT",
        help="Filter by category (e.g., vital-signs, laboratory)",
    )

    # ============================================================================
    # Read by ID
    # ============================================================================
    read_group = fhir_parser.add_argument_group("Read Resource by ID")

    read_group.add_argument(
        "--read-patient",
        type=str,
        metavar="ID",
        help="Read specific Patient by ID",
    )

    read_group.add_argument(
        "--read-observation",
        type=str,
        metavar="ID",
        help="Read specific Observation by ID",
    )

    read_group.add_argument(
        "--read-medication",
        type=str,
        metavar="ID",
        help="Read specific MedicationRequest by ID",
    )

    read_group.add_argument(
        "--read-condition",
        type=str,
        metavar="ID",
        help="Read specific Condition by ID",
    )

    read_group.add_argument(
        "--read-encounter",
        type=str,
        metavar="ID",
        help="Read specific Encounter by ID",
    )

    # ============================================================================
    # Security Testing
    # ============================================================================
    security_group = fhir_parser.add_argument_group("Security Testing")

    security_group.add_argument(
        "-A",
        "--test-auth",
        action="store_true",
        help="Test authentication mechanisms (anonymous access, invalid tokens)",
    )

    security_group.add_argument(
        "-x",
        "--test-cross-patient",
        action="store_true",
        help="Advisory cross-patient access check (prints guidance; requires --patient-id "
        "and manual verification of the result)",
    )

    security_group.add_argument(
        "-S",
        "--test-scope",
        action="store_true",
        help="Advisory OAuth2 scope-enforcement check (detects SMART/OAuth; full "
        "scope-bypass requires manual verification)",
    )

    security_group.add_argument(
        "--test-404-vs-403",
        action="store_true",
        help="Test information leakage via 404 vs 403 responses",
    )

    # ============================================================================
    # Active Testing
    # ============================================================================
    add_dangerous_options(fhir_parser, include_fuzz=False)

    # NOTE: --bulk-export / --bulk-export-type removed for 1.0 — the handler
    # was a placeholder that printed "not implemented" and exited. Use the
    # FHIR $export operation directly via your HTTP client until a real
    # bulk-export implementation lands.

    # ============================================================================
    # Write Operations (require --confirm)
    # ============================================================================
    write_group = fhir_parser.add_argument_group("Write Operations (require --confirm)")

    write_group.add_argument(
        "--create-patient",
        action="store_true",
        help="Create a test Patient resource (requires --confirm)",
    )

    write_group.add_argument(
        "--update-patient",
        type=str,
        metavar="ID",
        help="Update a Patient resource by ID (requires --confirm)",
    )

    write_group.add_argument(
        "--delete-patient",
        type=str,
        metavar="ID",
        help="Delete a Patient resource by ID (requires --confirm)",
    )

    write_group.add_argument(
        "--create-observation",
        action="store_true",
        help="Create a test Observation resource (requires --confirm)",
    )

    write_group.add_argument(
        "--patient-data",
        type=str,
        metavar="JSON",
        help="JSON data for patient create/update (or use --patient-* options)",
    )

    write_group.add_argument(
        "--patient-given-name",
        type=str,
        metavar="NAME",
        help="Given name for patient create/update",
    )

    write_group.add_argument(
        "--patient-family-name",
        type=str,
        metavar="NAME",
        help="Family name for patient create/update",
    )

    write_group.add_argument(
        "--observation-data",
        type=str,
        metavar="JSON",
        help="JSON data for observation create",
    )

    write_group.add_argument(
        "--observation-code",
        type=str,
        metavar="CODE",
        help="LOINC code for observation create (e.g., 8867-4 for heart rate)",
    )

    write_group.add_argument(
        "--observation-value",
        type=str,
        metavar="VALUE",
        help="Value for observation create",
    )

    write_group.add_argument(
        "--observation-unit",
        type=str,
        metavar="UNIT",
        help="Unit for observation create (e.g., /min, kg, mg/dL)",
    )

    # ============================================================================
    # Response Handling
    # ============================================================================
    response_group = fhir_parser.add_argument_group("Response Options")

    response_group.add_argument(
        "-X",
        "--extract-response",
        action="store_true",
        help="Extract and display detailed response data",
    )

    response_group.add_argument(
        "--include",
        type=str,
        metavar="RESOURCES",
        help="Include related resources (comma-separated, e.g., 'Observation,Condition')",
    )

    response_group.add_argument(
        "--revinclude",
        type=str,
        metavar="RESOURCES",
        help="Reverse include resources that reference results",
    )

    response_group.add_argument(
        "--elements",
        type=str,
        metavar="FIELDS",
        help="Return only specified elements (comma-separated)",
    )

    response_group.add_argument(
        "--summary",
        type=str,
        choices=["true", "text", "data", "count", "false"],
        help="Return summary view of resources",
    )

    response_group.add_argument(
        "--save-response",
        type=str,
        metavar="FILE",
        help="Save raw FHIR response to file",
    )

    return fhir_parser
