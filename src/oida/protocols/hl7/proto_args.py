"""
Argument parser definition for HL7 protocol

This module registers HL7-specific command-line arguments.
"""

from ...utils.proto_args_factory import (
    create_protocol_parser,
    add_target_argument,
    add_network_options,
    add_tls_options,
    add_dangerous_options,
    add_auth_options,
)


def proto_args(parser, parents):
    """Register HL7-specific arguments"""
    hl7_parser = create_protocol_parser(
        parser,
        name="hl7",
        help_text="HL7 healthcare protocol scanner",
        description="Scan and interact with HL7 v2.x MLLP servers",
        parents=parents,
        epilog="""
Examples:
  # Discovery and Reconnaissance (read-only)
  oida hl7 192.168.1.100                                  # Basic connection test
  oida hl7 192.168.1.100 --probe-ops                      # Probe all supported message types
  oida hl7 192.168.1.100 -E                               # Full enumeration: patients, providers, locations, observations
  oida hl7 192.168.1.100 -Q -I PT001                      # Query specific patient

  # Patient Query and Enumeration
  oida hl7 192.168.1.100 -Q --enum-patients               # Wildcard query to list all patients
  oida hl7 192.168.1.100 -Q -I "DOE*" -o ./results        # Query with filter, export results

  # Write Operations (all require --confirm)
  oida hl7 192.168.1.100 --send-adt -I PT001 --confirm              # ADT^A01 (Admit)
  oida hl7 192.168.1.100 --send-adt -T A08 -I PT001 --confirm       # ADT^A08 (Update)
  oida hl7 192.168.1.100 --send-orm -I PT001 --order-code CBC --confirm
  oida hl7 192.168.1.100 --send-oru -I PT001 --obx-value 95 --confirm
  oida hl7 192.168.1.100 --send-rx -I PT001 --rx-drug Amoxicillin --confirm

  # Export Results
  oida hl7 192.168.1.100 -Q -I PT001 -o ./results -f json
  oida hl7 192.168.1.100 --send-adt -I PT001 -X --confirm

  # TLS/Security
  oida hl7 192.168.1.100 --tls                            # MLLP over TLS
  oida hl7 192.168.1.100 --tls --tls-cert client.pem --tls-key client.key

  # IHE PCD (Patient Care Device) Operations
  oida hl7 127.0.0.1 --pcd-01 --device-type lvp --flow-rate 125 --vtbi 500 --confirm
  oida hl7 127.0.0.1 --pcd-03 --drug-name Morphine --flow-rate 10 --confirm
  oida hl7 127.0.0.1 --pcd-alarm --alarm-type occlusion --confirm
  oida hl7 127.0.0.1 --pcd-01 --device-type ventilator --confirm
""",
    )

    # Target (positional)
    add_target_argument(hl7_parser)

    # Network Options (--port, --timeout)
    add_network_options(hl7_parser, default_port=2575)

    # TLS Options (--tls, --tls-cert, --tls-key, --tls-ca, --tls-insecure)
    add_tls_options(hl7_parser, default_tls_port=2576, include_cert=True, include_insecure=True)

    # Authentication Options (--username, --password, --credentials)
    add_auth_options(hl7_parser)

    # HL7-Specific Options
    hl7_group = hl7_parser.add_argument_group("HL7 Options")

    hl7_group.add_argument(
        "-V",
        "--hl7-version",
        type=str,
        default=None,
        choices=["2.1", "2.2", "2.3", "2.3.1", "2.4", "2.5", "2.5.1", "2.6", "2.7"],
        help="HL7 version to use (default: auto-detect from server, else 2.5)",
    )

    hl7_group.add_argument(
        "-S",
        "--sending-app",
        type=str,
        default="OIDA",
        metavar="NAME",
        help="Sending application name (default: OIDA)",
    )

    hl7_group.add_argument(
        "-F",
        "--sending-facility",
        type=str,
        default="SECURITY",
        metavar="NAME",
        help="Sending facility name (default: SECURITY)",
    )

    hl7_group.add_argument(
        "-R",
        "--receiving-app",
        type=str,
        default="",
        metavar="NAME",
        help="Receiving application name (auto-detected if empty)",
    )

    hl7_group.add_argument(
        "--receiving-facility",
        type=str,
        default="",
        metavar="NAME",
        help="Receiving facility name (auto-detected if empty)",
    )

    # Message Type Operations
    msg_group = hl7_parser.add_argument_group("Message Operations")

    msg_group.add_argument(
        "--probe-ops",
        action="store_true",
        help="Probe supported message types and trigger events",
    )

    msg_group.add_argument(
        "--send-adt",
        action="store_true",
        help="Send ADT (Admit/Discharge/Transfer) message",
    )

    msg_group.add_argument(
        "-T",
        "--adt-trigger",
        type=str,
        default="A01",
        choices=[
            "A01",
            "A02",
            "A03",
            "A04",
            "A05",
            "A08",
            "A11",
            "A12",
            "A13",
            "A28",
            "A31",
            "A40",
        ],
        metavar="EVENT",
        help="ADT trigger event (default: A01). A01=Admit, A02=Transfer, A03=Discharge, "
        "A04=Register, A05=Pre-Admit, A08=Update, A12=Cancel Transfer, A28=Add Person, A40=Merge",
    )

    msg_group.add_argument(
        "--send-orm",
        action="store_true",
        help="Send ORM (Order) message",
    )

    msg_group.add_argument(
        "--send-oru",
        action="store_true",
        help="Send ORU (Observation Result) message",
    )

    msg_group.add_argument(
        "-Q",
        "--send-qry",
        action="store_true",
        help="Send QRY^Q01 (Patient Query) message",
    )

    msg_group.add_argument(
        "-QO",
        "--query-obs",
        action="store_true",
        help="Send QRY^R02 (Observation Results Query) - get lab results, vitals",
    )

    msg_group.add_argument(
        "-QR",
        "--query-rx",
        action="store_true",
        help="Send QBP^Q31 (Pharmacy Dispense History Query) - get medication history",
    )

    msg_group.add_argument(
        "-QS",
        "--query-orders",
        action="store_true",
        help="Send OSQ^Q06 (Order Status Query) - check order status",
    )

    msg_group.add_argument(
        "--send-siu",
        action="store_true",
        help="Send SIU (Scheduling) message",
    )

    msg_group.add_argument(
        "--send-mdm",
        action="store_true",
        help="Send MDM (Document Notification) message",
    )

    msg_group.add_argument(
        "--send-rx",
        action="store_true",
        help="Send RDE (Pharmacy/Prescription Order) message (requires --confirm)",
    )

    msg_group.add_argument(
        "--send-ras",
        action="store_true",
        help="Send RAS^O17 (Pharmacy Administration) message (requires --confirm)",
    )

    msg_group.add_argument(
        "--send-rgv",
        action="store_true",
        help="Send RGV^O15 (Pharmacy Give) message (requires --confirm)",
    )

    msg_group.add_argument(
        "--send-rds",
        action="store_true",
        help="Send RDS^O13 (Pharmacy Dispense) message (requires --confirm)",
    )

    msg_group.add_argument(
        "-M",
        "--message-type",
        type=str,
        metavar="TYPE",
        help="Send custom message type (e.g., 'RDE^O11', 'BAR^P01')",
    )

    # MFN (Master File Notification) Operations
    mfn_group = hl7_parser.add_argument_group("Master File Operations (MFN)")

    mfn_group.add_argument(
        "--send-mfn",
        action="store_true",
        help="Send MFN (Master File Notification) message (requires --confirm)",
    )

    mfn_group.add_argument(
        "--mfn-type",
        type=str,
        default="M01",
        choices=["M01", "M02", "M04"],
        metavar="EVENT",
        help="MFN event type: M01=General, M02=Staff/Practitioner, M04=Charges (default: M01)",
    )

    mfn_group.add_argument(
        "--query-mfn",
        action="store_true",
        help="Query master file data (MFQ^M01)",
    )

    mfn_group.add_argument(
        "--staff-id",
        type=str,
        metavar="ID",
        help="Staff ID for MFN^M02 messages",
    )

    mfn_group.add_argument(
        "--staff-name",
        type=str,
        metavar="NAME",
        help="Staff name (LAST^FIRST) for MFN^M02",
    )

    mfn_group.add_argument(
        "--staff-type",
        type=str,
        metavar="TYPE",
        help="Staff type (e.g., MD, RN, NP) for MFN^M02",
    )

    mfn_group.add_argument(
        "--charge-code",
        type=str,
        metavar="CODE",
        help="Charge code for MFN^M04 messages",
    )

    mfn_group.add_argument(
        "--charge-price",
        type=str,
        metavar="PRICE",
        help="Charge price for MFN^M04 messages",
    )

    # QBP Special Query Operations
    qbp_group = hl7_parser.add_argument_group("Special Query Operations (QBP)")

    qbp_group.add_argument(
        "--query-whoami",
        action="store_true",
        help="Send QBP^Q40 (WhoAmI) query to identify server capabilities",
    )

    qbp_group.add_argument(
        "--query-tabular",
        action="store_true",
        help="Send QBP^Q13 tabular query (returns RTB response)",
    )

    qbp_group.add_argument(
        "--query-imm",
        action="store_true",
        help="Send QBP^Z34 immunization history query",
    )

    qbp_group.add_argument(
        "--query-imm-forecast",
        action="store_true",
        help="Send QBP^Z44 immunization history + forecast query",
    )

    # BAR/DFT Financial Operations
    fin_group = hl7_parser.add_argument_group("Financial Operations (BAR/DFT)")

    fin_group.add_argument(
        "--send-bar",
        action="store_true",
        help="Send BAR^P01 (Add Billing Account) message (requires --confirm)",
    )

    fin_group.add_argument(
        "--send-dft",
        action="store_true",
        help="Send DFT^P03 (Post Financial Transaction) message (requires --confirm)",
    )

    fin_group.add_argument(
        "--account-number",
        type=str,
        metavar="NUM",
        help="Account number for billing messages",
    )

    fin_group.add_argument(
        "--guarantor-name",
        type=str,
        metavar="NAME",
        help="Guarantor name (LAST^FIRST) for billing",
    )

    fin_group.add_argument(
        "--guarantor-phone",
        type=str,
        metavar="PHONE",
        help="Guarantor phone number",
    )

    fin_group.add_argument(
        "--insurance-company",
        type=str,
        metavar="NAME",
        help="Insurance company name",
    )

    fin_group.add_argument(
        "--insurance-group",
        type=str,
        metavar="NUM",
        help="Insurance group number",
    )

    fin_group.add_argument(
        "--policy-number",
        type=str,
        metavar="NUM",
        help="Insurance policy number",
    )

    fin_group.add_argument(
        "--transaction-amount",
        type=str,
        metavar="AMT",
        help="Financial transaction amount (e.g., '150.00')",
    )

    fin_group.add_argument(
        "--transaction-code",
        type=str,
        metavar="CODE",
        help="Financial transaction code",
    )

    fin_group.add_argument(
        "--transaction-description",
        type=str,
        metavar="DESC",
        help="Financial transaction description (default: 'Office Visit')",
    )

    fin_group.add_argument(
        "--transaction-type",
        type=str,
        default="CG",
        choices=["CG", "CD", "PY"],
        metavar="TYPE",
        help="Transaction type: CG=Charge, CD=Credit, PY=Payment (default: CG)",
    )

    # IHE PCD (Patient Care Device) Operations
    pcd_group = hl7_parser.add_argument_group("IHE PCD Device Integration")

    pcd_group.add_argument(
        "--pcd-01",
        action="store_true",
        help="Send PCD-01 Device Observation (ORU^R01 with MDC codes)",
    )

    pcd_group.add_argument(
        "--pcd-03",
        action="store_true",
        help="Send PCD-03 Infusion Order (RGV^O15 to pump)",
    )

    pcd_group.add_argument(
        "--pcd-alarm",
        action="store_true",
        help="Send PCD-04/10 Device Alarm (ORU^R40/R42)",
    )

    pcd_group.add_argument(
        "--device-type",
        type=str,
        choices=["lvp", "syringe", "pca", "monitor", "ventilator", "pulseox"],
        default="lvp",
        help="Device type for PCD messages (default: lvp)",
    )

    pcd_group.add_argument(
        "--flow-rate",
        type=float,
        metavar="ML_HR",
        help="Infusion flow rate in mL/hr",
    )

    pcd_group.add_argument(
        "--vtbi",
        type=float,
        metavar="ML",
        help="Volume To Be Infused in mL",
    )

    pcd_group.add_argument(
        "--volume-delivered",
        type=float,
        metavar="ML",
        help="Volume already delivered in mL",
    )

    pcd_group.add_argument(
        "--drug-name",
        type=str,
        metavar="NAME",
        help="Drug name for infusion order",
    )

    pcd_group.add_argument(
        "--drug-concentration",
        type=float,
        metavar="MG_ML",
        help="Drug concentration in mg/mL",
    )

    pcd_group.add_argument(
        "--dose-rate",
        type=float,
        metavar="UG_KG_MIN",
        help="Dose rate in mcg/kg/min",
    )

    pcd_group.add_argument(
        "--alarm-type",
        type=str,
        choices=["occlusion", "air", "empty", "battery", "generic"],
        help="Alarm type for PCD-04/10 messages",
    )

    pcd_group.add_argument(
        "--device-id",
        type=str,
        metavar="ID",
        help="Device identifier for PCD messages",
    )

    # Patient Data Options
    patient_group = hl7_parser.add_argument_group("Patient Data (PID segment)")

    patient_group.add_argument(
        "-I",
        "--patient-id",
        type=str,
        metavar="ID",
        help="Patient ID / MRN",
    )

    patient_group.add_argument(
        "-N",
        "--patient-name",
        type=str,
        metavar="NAME",
        help="Patient name (format: Last^First^Middle)",
    )

    patient_group.add_argument(
        "-B",
        "--patient-dob",
        type=str,
        metavar="DATE",
        help="Patient date of birth (YYYYMMDD)",
    )

    patient_group.add_argument(
        "--patient-sex",
        type=str,
        choices=["M", "F", "O", "U"],
        metavar="SEX",
        help="Patient sex (M/F/O/U)",
    )

    patient_group.add_argument(
        "--patient-address",
        type=str,
        metavar="ADDR",
        help="Patient address (format: Street^Unit^City^State^Zip)",
    )

    patient_group.add_argument(
        "--patient-phone",
        type=str,
        metavar="PHONE",
        help="Patient phone number",
    )

    patient_group.add_argument(
        "--mrn",
        type=str,
        metavar="NUMBER",
        help="Medical Record Number (alias for --patient-id)",
    )

    patient_group.add_argument(
        "--ssn",
        type=str,
        metavar="NUMBER",
        help="Social Security Number (use with caution)",
    )

    # Visit Data Options (PV1 segment)
    visit_group = hl7_parser.add_argument_group("Visit Data (PV1 segment)")

    visit_group.add_argument(
        "-C",
        "--patient-class",
        type=str,
        choices=["I", "O", "E", "P", "R"],
        metavar="CLASS",
        help="Patient class: I=Inpatient, O=Outpatient, E=Emergency, P=Preadmit, R=Recurring",
    )

    visit_group.add_argument(
        "--visit-number",
        type=str,
        metavar="NUM",
        help="Visit/Encounter number",
    )

    visit_group.add_argument(
        "-L",
        "--location",
        type=str,
        metavar="LOC",
        help="Patient location (format: Unit^Room^Bed)",
    )

    visit_group.add_argument(
        "--admit-date",
        type=str,
        metavar="DATE",
        help="Admit date/time (YYYYMMDDHHMMSS)",
    )

    # Order Data Options (ORC/OBR segments)
    order_group = hl7_parser.add_argument_group("Order Data (ORC/OBR segments)")

    order_group.add_argument(
        "--order-id",
        type=str,
        metavar="ID",
        help="Order/Placer order number",
    )

    order_group.add_argument(
        "--order-code",
        type=str,
        metavar="CODE",
        help="Order/Service code (e.g., 'CBC^Complete Blood Count')",
    )

    order_group.add_argument(
        "--order-priority",
        type=str,
        default="R",
        choices=["S", "A", "R", "P", "T"],
        metavar="PRI",
        help="Order priority: S=Stat, A=ASAP, R=Routine, P=Preop, T=Timing critical",
    )

    # Observation Data Options (OBX segment)
    obs_group = hl7_parser.add_argument_group("Observation Data (OBX segment)")

    obs_group.add_argument(
        "--obx-type",
        type=str,
        default="NM",
        choices=["NM", "ST", "TX", "CE", "DT", "TM"],
        metavar="TYPE",
        help="Observation value type: NM=Numeric, ST=String, TX=Text, CE=Coded, DT=Date, TM=Time",
    )

    obs_group.add_argument(
        "--obx-id",
        type=str,
        metavar="ID",
        help="Observation identifier (e.g., 'GLU^Glucose')",
    )

    obs_group.add_argument(
        "--obx-value",
        type=str,
        metavar="VALUE",
        help="Observation value",
    )

    obs_group.add_argument(
        "--obx-units",
        type=str,
        metavar="UNITS",
        help="Observation units (e.g., 'mg/dL')",
    )

    # Diagnosis Data Options (DG1 segment)
    dx_group = hl7_parser.add_argument_group("Diagnosis Data (DG1 segment)")

    dx_group.add_argument(
        "--dx-code",
        type=str,
        metavar="CODE",
        help="Diagnosis code (ICD-10, e.g., 'J06.9')",
    )

    dx_group.add_argument(
        "--dx-description",
        type=str,
        metavar="DESC",
        help="Diagnosis description",
    )

    dx_group.add_argument(
        "--dx-type",
        type=str,
        default="A",
        choices=["A", "W", "F"],
        metavar="TYPE",
        help="Diagnosis type: A=Admitting, W=Working, F=Final",
    )

    dx_group.add_argument(
        "--dx-priority",
        type=str,
        metavar="PRI",
        help="Diagnosis priority (1=Primary, 2+=Secondary)",
    )

    dx_group.add_argument(
        "--dx-clinician",
        type=str,
        metavar="NAME",
        help="Diagnosing clinician (format: Last^First^Title)",
    )

    # Procedure Data Options (PR1 segment)
    pr_group = hl7_parser.add_argument_group("Procedure Data (PR1 segment)")

    pr_group.add_argument(
        "--pr-code",
        type=str,
        metavar="CODE",
        help="Procedure code (CPT/HCPCS)",
    )

    pr_group.add_argument(
        "--pr-description",
        type=str,
        metavar="DESC",
        help="Procedure description",
    )

    pr_group.add_argument(
        "--pr-type",
        type=str,
        metavar="TYPE",
        help="Procedure functional type",
    )

    pr_group.add_argument(
        "--pr-practitioner",
        type=str,
        metavar="NAME",
        help="Procedure practitioner (format: Last^First^Title)",
    )

    # Pharmacy/Prescription Data Options (RXO segment)
    rx_group = hl7_parser.add_argument_group("Pharmacy Data (RXO segment)")

    rx_group.add_argument(
        "--rx-code",
        type=str,
        metavar="CODE",
        help="Drug code (NDC)",
    )

    rx_group.add_argument(
        "--rx-drug",
        type=str,
        metavar="NAME",
        help="Drug name",
    )

    rx_group.add_argument(
        "--rx-dose",
        type=str,
        metavar="DOSE",
        help="Requested dose amount",
    )

    rx_group.add_argument(
        "--rx-units",
        type=str,
        metavar="UNITS",
        help="Dose units (e.g., 'mg', 'mL')",
    )

    rx_group.add_argument(
        "--rx-route",
        type=str,
        metavar="ROUTE",
        help="Route of administration (e.g., 'PO', 'IV', 'IM')",
    )

    rx_group.add_argument(
        "--rx-instructions",
        type=str,
        metavar="TEXT",
        help="Administration instructions",
    )

    rx_group.add_argument(
        "--rx-quantity",
        type=str,
        metavar="QTY",
        help="Dispense quantity",
    )

    rx_group.add_argument(
        "--rx-refills",
        type=str,
        metavar="NUM",
        help="Number of refills",
    )

    rx_group.add_argument(
        "--rx-provider",
        type=str,
        metavar="DEA",
        help="Ordering provider DEA number",
    )

    # Pharmacy Administration Options (RXA/RXG/RXD segments for RAS/RGV/RDS)
    pharm_admin_group = hl7_parser.add_argument_group("Pharmacy Administration (RAS/RGV/RDS)")

    pharm_admin_group.add_argument(
        "--admin-code",
        type=str,
        metavar="CODE",
        help="Administered drug code (code^name^NDC format)",
    )

    pharm_admin_group.add_argument(
        "--admin-amount",
        type=str,
        metavar="AMT",
        help="Administered/given amount",
    )

    pharm_admin_group.add_argument(
        "--admin-units",
        type=str,
        metavar="UNITS",
        help="Administered/given units (e.g., 'mg', 'mL')",
    )

    pharm_admin_group.add_argument(
        "--dispense-amount",
        type=str,
        metavar="AMT",
        help="Dispensed amount",
    )

    pharm_admin_group.add_argument(
        "--dispense-units",
        type=str,
        metavar="UNITS",
        help="Dispensed units",
    )

    pharm_admin_group.add_argument(
        "--completion-status",
        type=str,
        default="CP",
        choices=["CP", "RE", "NA", "PA"],
        metavar="STATUS",
        help="Administration completion status: CP=Complete, RE=Refused, NA=Not Admin, PA=Partial",
    )

    # Merge Data Options (MRG segment for ADT^A40)
    merge_group = hl7_parser.add_argument_group("Merge Data (MRG segment for ADT^A40)")

    merge_group.add_argument(
        "--merge-patient-id",
        type=str,
        metavar="ID",
        help="Prior patient ID to merge FROM",
    )

    merge_group.add_argument(
        "--merge-patient-name",
        type=str,
        metavar="NAME",
        help="Prior patient name",
    )

    merge_group.add_argument(
        "--merge-visit",
        type=str,
        metavar="NUM",
        help="Prior visit number",
    )

    # Enumeration Options
    enum_group = hl7_parser.add_argument_group("Enumeration Options")

    enum_group.add_argument(
        "-E",
        "--enum-all",
        action="store_true",
        help="Enable all enumeration: patients, providers, apps, locations, observations, medications, orders",
    )

    enum_group.add_argument(
        "--enum-providers",
        action="store_true",
        help="Enumerate healthcare providers from responses",
    )

    enum_group.add_argument(
        "--enum-apps",
        action="store_true",
        help="Enumerate sending applications and facilities",
    )

    enum_group.add_argument(
        "--enum-locations",
        action="store_true",
        help="Enumerate patient locations (units, rooms, beds)",
    )

    enum_group.add_argument(
        "--enum-patients",
        action="store_true",
        help="Use wildcard query to enumerate all patients (requires --send-qry)",
    )

    # Response Handling
    response_group = hl7_parser.add_argument_group("Response Options")

    response_group.add_argument(
        "-X",
        "--extract-response",
        action="store_true",
        help="Extract and display detailed response data",
    )

    response_group.add_argument(
        "--extract-fields",
        type=str,
        metavar="FIELDS",
        help="Extract specific fields from response (e.g., 'PID-3,PID-5,OBX-5')",
    )

    response_group.add_argument(
        "--save-response",
        type=str,
        metavar="FILE",
        help="Save raw response to file",
    )

    response_group.add_argument(
        "--parse-segments",
        action="store_true",
        help="Parse and display all segments in response",
    )

    # Fuzzing (--confirm, --fuzz, --fuzz-iterations)
    fuzz_group = add_dangerous_options(hl7_parser, include_fuzz=True, fuzz_default_iterations=10)

    fuzz_group.add_argument(
        "--fuzz-segment",
        type=str,
        metavar="SEGMENT",
        help="Specific segment to fuzz (e.g., 'PID', 'OBX')",
    )

    return hl7_parser
