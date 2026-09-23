"""HL7 Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (5 Phases):
    Phase 1 (0-30s): Quick_Coverage - One request per message type (ACK, ADT, ORU, ORM, QRY, MDM)
    Phase 2 (30s-2m): High-crash tests - Oversized fields, buffer overflow, MLLP corruption
    Phase 3 (2m-5m): CVE-targeted - Delimiter injection, encoding manipulation
    Phase 4 (5m-10m): Boundary attacks - Segment fuzzing, field limits
    Phase 5 (10m+): Deep fuzzing - Full message type mutations, edge cases

CVE Coverage (real HL7-over-MLLP wire parser vulnerabilities):
- CVE-2025-53948: Sante PACS Server - crafted HL7 message crashes the main
  thread (double-free, CWE-415) -> DoS. Exercised by oversized-field /
  segment / MLLP-corruption requests.
- CVE-2020-27260: Innokas VC150 - HL7 v2.x delimiter/segment injection
  (CWE-74). Exercised by the delimiter/encoding injection requests.
(Earlier revisions of this file cited CVE-2023-45232 / CVE-2022-38756 /
CVE-2021-43267 / CVE-2020-35497 / CVE-2019-18935; those IDs are EDK2 / Micro
Focus / Linux-TIPC / ovirt / Telerik bugs, NOT HL7, and have been removed.)

Healthcare Protocol Security Notes:
- HL7 parsers are often legacy code with minimal input validation
- MLLP framing errors can cause connection state corruption
- Oversized fields commonly trigger heap/stack overflows
- Delimiter injection can bypass sanitization and reach backend systems
"""

from datetime import datetime
from typing import Any, Dict, List

from boofuzz import Block, Bytes, Group, Request, Static

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.connections import TCPSocketConnection
from oida.fuzz.primitives.dynamic import SmartString
from oida.fuzz.primitives.smart_string import StringContext
from oida.protocols.hl7 import MLLP_START, MLLP_END
from oida.protocols.hl7.segments import HL7SegmentBuilder
from oida.protocols.hl7.utils import probe_server_capabilities


class HL7Fuzzer(BaseFuzzer):
    """HL7 v2.x Protocol Fuzzer for healthcare system security testing

    Targets HL7 vulnerabilities including MLLP framing attacks, delimiter injection,
    oversized field buffer overflows, and encoding character manipulation.

    HL7 v2.x uses TCP port 2575 (MLLP) by default.

    Test Ordering (Optimized for Early Coverage):
    - Phase 1: Quick_Coverage touches all 6 message types in ~30 seconds
    - Phase 2: Oversized fields and MLLP corruption (high crash likelihood)
    - Phase 3: CVE-targeted delimiter and encoding injection
    - Phase 4: Segment fuzzing and boundary attacks
    - Phase 5: Deep mutation of individual message types
    """

    # Protocol-specific monitor: HL7 ACK check every 20 tests
    DEFAULT_MONITORS = "hl7:20"

    PROTOCOL_OPTIONS = {
        "use_capability_detection": {
            "type": bool,
            "default": True,
            "description": "Probe server to detect supported message types before fuzzing",
        },
        "message_types": {
            "type": str,
            "default": None,
            "description": "Comma-separated list of message types to fuzz (overrides detection)",
            "example": "ADT,ORU,ORM",
        },
        "hl7_version": {
            "type": str,
            "default": "2.5",
            "description": "HL7 version (2.3, 2.4, 2.5, 2.5.1)",
            "example": "2.5.1",
        },
        "sending_app": {
            "type": str,
            "default": "FUZZ_APP",
            "description": "Sending application name (MSH-3)",
            "example": "LAB_SYSTEM",
        },
        "sending_facility": {
            "type": str,
            "default": "FUZZ_FAC",
            "description": "Sending facility name (MSH-4)",
            "example": "HOSPITAL_A",
        },
        "receiving_app": {
            "type": str,
            "default": "RECV_APP",
            "description": "Receiving application name (MSH-5)",
            "example": "HIS_SYSTEM",
        },
        "receiving_facility": {
            "type": str,
            "default": "RECV_FAC",
            "description": "Receiving facility name (MSH-6)",
            "example": "HOSPITAL_B",
        },
        "processing_id": {
            "type": str,
            "default": "P",
            "description": "Processing ID: P=Production, D=Debugging, T=Training",
            "example": "T",
        },
    }

    def __init__(self, config, connection_factory=None):
        # Capability detection flag
        self.use_capability_detection = config.get_option("use_capability_detection", True)

        # User-specified message types override
        self.user_message_types = config.get_option("message_types", None)

        # Load configuration options
        self.hl7_version = config.get_option("hl7_version", "2.5")
        self.sending_app = config.get_option("sending_app", "FUZZ_APP")
        self.sending_facility = config.get_option("sending_facility", "FUZZ_FAC")
        self.receiving_app = config.get_option("receiving_app", "RECV_APP")
        self.receiving_facility = config.get_option("receiving_facility", "RECV_FAC")
        self.processing_id = config.get_option("processing_id", "P")

        # Segment builder from protocol module
        self.segment_builder = HL7SegmentBuilder(version=self.hl7_version)

        super().__init__(config, connection_factory)

    def _enumerate_capabilities(self) -> Dict[str, Any]:
        """Enumerate server capabilities by probing for supported message types.

        Overrides BaseFuzzer._enumerate_capabilities (the hook actually invoked
        when config.enumerate=True). The old name `enumerate_protocol` matched
        nothing in the base class, so capability detection never ran.

        Returns:
            Dictionary with detected capabilities (message_types, version, server_app)
        """
        if not self.use_capability_detection:
            return {}

        return self._probe_server_capabilities(self.config)

    def _probe_server_capabilities(self, config) -> Dict[str, Any]:
        """Probe HL7 server to detect supported message types and features.

        Uses shared probe utilities from protocols.hl7.utils.

        Args:
            config: Fuzzer configuration with target info

        Returns:
            Dictionary with detected capabilities
        """
        from oida.utils.ics_logger import get_logger

        port = config.target_port or 2575
        get_logger("HL7", config.target_ip, port)
        self.log.display(f"Probing HL7 capabilities on {config.target_ip}:{port}...")

        # Use shared probe function from protocol module
        capabilities = probe_server_capabilities(
            host=config.target_ip,
            port=port,
            version=self.hl7_version,
            sending_app=self.sending_app,
            sending_facility=self.sending_facility,
            receiving_app=self.receiving_app,
            receiving_facility=self.receiving_facility,
            processing_id=self.processing_id,
            segment_builder=self.segment_builder,
        )

        return capabilities

    def _log_capabilities(self) -> None:
        """Log probed server capabilities.

        Overrides BaseFuzzer._log_capabilities() to display HL7-specific info.
        Called automatically by BaseFuzzer.__init__ after capability enumeration.
        """
        if not self.capabilities:
            return

        fuzz_log = self._get_fuzz_logger()
        capabilities = self.capabilities

        fuzz_log.display("=" * 50)
        fuzz_log.display("HL7 Server Capabilities")
        fuzz_log.display("=" * 50)

        if capabilities.get("server_app"):
            fuzz_log.display(f"Server Application: {capabilities['server_app']}")
        if capabilities.get("server_facility"):
            fuzz_log.display(f"Server Facility: {capabilities['server_facility']}")
        if capabilities.get("detected_version"):
            fuzz_log.display(f"HL7 Version: {capabilities['detected_version']}")

        if capabilities.get("mllp_supported"):
            fuzz_log.display("MLLP: Supported")
        else:
            fuzz_log.display("MLLP: Not detected")

        supported = capabilities.get("message_types", set())
        rejected = capabilities.get("rejected_types", set())

        if supported:
            fuzz_log.display(f"Supported Message Types: {', '.join(sorted(supported))}")
        if rejected:
            fuzz_log.display(f"Rejected Message Types: {', '.join(sorted(rejected))}")

        fuzz_log.display("=" * 50)

    def is_message_type_supported(self, msg_type: str) -> bool:
        """Check if a message type is supported by the server.

        Args:
            msg_type: Message type (e.g., 'ADT', 'ORU')

        Returns:
            True if supported or capability detection is disabled/failed
        """
        # If user specified message types, use those
        if self.user_message_types:
            user_types = {t.strip().upper() for t in self.user_message_types.split(",")}
            return msg_type.upper() in user_types

        # If capability detection disabled, assume all supported
        if not self.use_capability_detection or not self.config.enumerate:
            return True

        # If no message types detected, assume all supported
        if not self.capabilities.get("message_types"):
            return True

        return msg_type.upper() in self.capabilities.get("message_types", set())

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Optimized order for early coverage and crash detection:
        1. Quick_Coverage - all message types once (~30 sec)
        2. High-crash tests - oversized fields, MLLP corruption (buffer overflow)
        3. CVE-targeted - delimiter injection, encoding manipulation
        4. Boundary attacks - segment fuzzing, field limits
        5. Deep fuzzing - individual message type mutations
        """
        return [
            # Phase 1: Quick Coverage (~30 seconds)
            RequestInfo(
                "HL7_Quick_Coverage",
                "Quick sweep of all 6 message types (ACK, ADT, ORU, ORM, QRY, MDM)",
                "baseline",
            ),
            # Phase 2: High-crash tests (30s-2m) - Most likely to find crashes
            RequestInfo(
                "HL7_Oversized_Fields",
                "Oversized field buffer overflow / crafted-message DoS (CVE-2025-53948)",
                "overflow",
            ),
            RequestInfo(
                "HL7_MLLP_Corruption",
                "MLLP frame corruption / crafted-message crash (CVE-2025-53948)",
                "overflow",
            ),
            # Phase 3: CVE-targeted operations (2m-5m)
            RequestInfo(
                "HL7_Delimiter_Injection",
                "HL7 v2.x delimiter/segment injection (CVE-2020-27260)",
                "injection",
            ),
            RequestInfo(
                "HL7_Encoding_Chars",
                "Encoding character manipulation / injection (CVE-2020-27260)",
                "injection",
            ),
            # Phase 4: Boundary attacks (5m-10m)
            RequestInfo("HL7_Segment_Fuzzing", "Unknown/malformed segment types", "boundary"),
            RequestInfo(
                "HL7_Version_Sweep",
                "MSH-12 HL7 v2.x version sweep (2.3/2.4/2.5/2.6/2.7/2.8)",
                "boundary",
            ),
            RequestInfo(
                "HL7_Z_Segment_Injection",
                "Vendor-specific Z-segment injection mid-message",
                "injection",
            ),
            RequestInfo("HL7_Baseline", "Simple ACK message for connectivity test", "baseline"),
            # Phase 5: Deep fuzzing (10m+) - Full message type mutations
            RequestInfo("HL7_ADT_Messages", "ADT messages (admit, discharge, transfer)", "adt"),
            RequestInfo("HL7_ORU_Messages", "ORU observation result messages", "results"),
            RequestInfo("HL7_ORM_Messages", "ORM order messages", "orders"),
            RequestInfo("HL7_Query", "QRY query messages", "query"),
        ]

    def _create_socket(self):
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port or 2575,
            **self._timeout_overrides(),
        )

    def setup_custom_monitors(self) -> list:
        """Setup HL7-specific monitoring"""
        from oida.fuzz.monitors import HL7Monitor

        hl7_monitor = HL7Monitor(
            host=self.config.target_ip,
            port=self.config.target_port or 2575,
            timeout=5,
            check_interval=3,
        )
        return [hl7_monitor]

    def _get_timestamp(self) -> str:
        """Generate HL7 timestamp format: YYYYMMDDHHMMSS"""
        return datetime.now().strftime("%Y%m%d%H%M%S")

    def _get_message_control_id(self) -> str:
        """Generate unique message control ID"""
        return f"MSG{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}"

    def _define_protocol(self) -> None:
        """Define HL7 protocol structure for fuzzing"""

        timestamp = self._get_timestamp()
        msg_ctrl_id = self._get_message_control_id()

        # =====================================================================
        # BASELINE: Simple ACK message for connectivity
        # =====================================================================
        baseline_ack = Request(
            "HL7_Baseline",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # MSH - Message Header
                        Static(
                            "MSH",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ACK|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        # MSA - Message Acknowledgement
                        Static("MSA", f"MSA|AA|{msg_ctrl_id}|\r"),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Touch all 6 message types in a single request to maximize early coverage
        # Message types: ACK, ADT (7 subtypes), ORU, ORM, QRY, MDM (2 subtypes)
        # This catches shallow parsing bugs across all handlers before deep fuzzing
        # =====================================================================
        quick_coverage = Request(
            "HL7_Quick_Coverage",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # MSH - Message Header (not fuzzed for quick sweep)
                        Static(
                            "MSH_Start",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||",
                        ),
                        # Cycle through ALL message types to touch every handler
                        Group(
                            "Quick_Message_Types",
                            values=[
                                # ACK messages
                                b"ACK",
                                # ADT messages - Admit/Discharge/Transfer (all 7 trigger events)
                                b"ADT^A01",  # Admit
                                b"ADT^A02",  # Transfer
                                b"ADT^A03",  # Discharge
                                b"ADT^A04",  # Register
                                b"ADT^A08",  # Update
                                b"ADT^A11",  # Cancel Admit
                                b"ADT^A13",  # Cancel Discharge
                                # ORU messages - Observation Results
                                b"ORU^R01",  # Unsolicited Result
                                # ORM messages - Orders
                                b"ORM^O01",  # Order Message
                                # QRY messages - Queries
                                b"QRY^A19",  # Patient Query
                                # MDM messages - Medical Documents
                                b"MDM^T01",  # Document Notification
                                b"MDM^T02",  # Document with Content
                            ],
                        ),
                        Static(
                            "MSH_Rest", f"|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r"
                        ),
                        # Minimal segments for validity (not fuzzed)
                        Static("EVN", f"EVN|A01|{timestamp}\r"),
                        Static("PID", "PID|1||12345^^^MRN||DOE^JOHN||19800101|M\r"),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ADT MESSAGES: Admit/Discharge/Transfer (Phase 5 - Deep Fuzzing)
        # =====================================================================
        adt_messages = Request(
            "HL7_ADT_Messages",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # MSH - Message Header with fuzzable fields
                        Block(
                            "MSH_Segment",
                            children=(
                                Static("MSH_ID", "MSH"),
                                Static("Field_Sep", "|"),
                                SmartString("Encoding_Chars", "^~\\&", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Sending_App",
                                    self.sending_app,
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep2", "|"),
                                SmartString(
                                    "Sending_Facility",
                                    self.sending_facility,
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep3", "|"),
                                SmartString(
                                    "Receiving_App",
                                    self.receiving_app,
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep4", "|"),
                                SmartString(
                                    "Receiving_Facility",
                                    self.receiving_facility,
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep5", "|"),
                                SmartString("Timestamp", timestamp, max_len=26, fuzzable=True),
                                Static("Sep6", "|"),
                                Static("Security", "|"),
                                Group(
                                    "Message_Type",
                                    values=[
                                        b"ADT^A01",
                                        b"ADT^A02",
                                        b"ADT^A03",
                                        b"ADT^A04",
                                        b"ADT^A08",
                                        b"ADT^A11",
                                        b"ADT^A13",
                                    ],
                                ),
                                Static("Sep7", "|"),
                                SmartString(
                                    "Message_Control_ID",
                                    msg_ctrl_id,
                                    max_len=50,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep8", "|"),
                                SmartString(
                                    "Processing_ID", self.processing_id, max_len=3, fuzzable=True
                                ),
                                Static("Sep9", "|"),
                                SmartString("Version", self.hl7_version, max_len=10, fuzzable=True),
                                Static("Segment_Term", "\r"),
                            ),
                        ),
                        # EVN - Event Type
                        Block(
                            "EVN_Segment",
                            children=(
                                Static("EVN_ID", "EVN|"),
                                SmartString("Event_Type", "A01", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Event_Timestamp", timestamp, max_len=26, fuzzable=True
                                ),
                                Static("Sep2", "|||"),
                                Static("Segment_Term", "\r"),
                            ),
                        ),
                        # PID - Patient Identification
                        Block(
                            "PID_Segment",
                            children=(
                                Static("PID_ID", "PID|1||"),
                                SmartString(
                                    "Patient_ID",
                                    "12345678^^^MRN",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "||"),
                                SmartString(
                                    "Patient_Name",
                                    "DOE^JOHN^A",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep2", "||"),
                                SmartString("DOB", "19800101", max_len=26, fuzzable=True),
                                Static("Sep3", "|"),
                                SmartString("Gender", "M", max_len=10, fuzzable=True),
                                Static("Sep4", "||"),
                                SmartString("Race", "W", max_len=50, fuzzable=True),
                                Static("Sep5", "|"),
                                SmartString(
                                    "Address",
                                    "123 MAIN ST^APT 4^BOSTON^MA^02101^USA",
                                    max_len=500,
                                    fuzzable=True,
                                ),
                                Static("Sep6", "|||"),
                                SmartString("Phone", "555-1234", max_len=50, fuzzable=True),
                                Static("Segment_Term", "\r"),
                            ),
                        ),
                        # PV1 - Patient Visit
                        Block(
                            "PV1_Segment",
                            children=(
                                Static("PV1_ID", "PV1|1|"),
                                SmartString("Patient_Class", "I", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Location", "WEST^101^A^1^^^S", max_len=200, fuzzable=True
                                ),
                                Static("Sep2", "|"),
                                SmartString("Admission_Type", "E", max_len=10, fuzzable=True),
                                Static("Rest", "||||||||||||||||||||||||||||||||||"),
                                Static("Segment_Term", "\r"),
                            ),
                        ),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ORU MESSAGES: Observation Results (Lab Results)
        # =====================================================================
        oru_messages = Request(
            "HL7_ORU_Messages",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # MSH
                        Static(
                            "MSH",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ORU^R01|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        # PID
                        Block(
                            "PID_Segment",
                            children=(
                                Static("PID_ID", "PID|1||"),
                                SmartString(
                                    "Patient_ID",
                                    "12345678^^^MRN",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "||"),
                                SmartString(
                                    "Patient_Name",
                                    "DOE^JOHN^A",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Rest", "||19800101|M\r"),
                            ),
                        ),
                        # ORC - Common Order
                        Block(
                            "ORC_Segment",
                            children=(
                                Static("ORC_ID", "ORC|"),
                                SmartString("Order_Control", "RE", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Placer_Order",
                                    "ORD001^LAB",
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep2", "|"),
                                SmartString(
                                    "Filler_Order",
                                    "FIL001^LAB",
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Rest", "||||||||||||||||\r"),
                            ),
                        ),
                        # OBR - Observation Request
                        Block(
                            "OBR_Segment",
                            children=(
                                Static("OBR_ID", "OBR|1|"),
                                SmartString(
                                    "Placer_Order",
                                    "ORD001^LAB",
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Filler_Order",
                                    "FIL001^LAB",
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep2", "|"),
                                SmartString(
                                    "Universal_Service_ID",
                                    "85025^CBC^L",
                                    max_len=200,
                                    fuzzable=True,
                                ),
                                Static("Rest", f"||{timestamp}||||||{timestamp}||||||||\r"),
                            ),
                        ),
                        # OBX - Observation Result (multiple)
                        Block(
                            "OBX_Segment_1",
                            children=(
                                Static("OBX_ID", "OBX|1|"),
                                SmartString("Value_Type", "NM", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Observation_ID", "1234-5^WBC^LN", max_len=200, fuzzable=True
                                ),
                                Static("Sep2", "||"),
                                SmartString("Value", "7.5", max_len=100, fuzzable=True),
                                Static("Sep3", "|"),
                                SmartString("Units", "K/uL", max_len=50, fuzzable=True),
                                Static("Sep4", "|"),
                                SmartString(
                                    "Reference_Range", "4.5-11.0", max_len=100, fuzzable=True
                                ),
                                Static("Sep5", "|"),
                                SmartString("Abnormal_Flag", "N", max_len=10, fuzzable=True),
                                Static("Rest", "|||F\r"),
                            ),
                        ),
                        Block(
                            "OBX_Segment_2",
                            children=(
                                Static("OBX_ID", "OBX|2|"),
                                SmartString("Value_Type", "NM", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Observation_ID", "1234-6^RBC^LN", max_len=200, fuzzable=True
                                ),
                                Static("Sep2", "||"),
                                SmartString("Value", "4.8", max_len=100, fuzzable=True),
                                Static("Sep3", "|"),
                                SmartString("Units", "M/uL", max_len=50, fuzzable=True),
                                Static("Sep4", "|"),
                                SmartString(
                                    "Reference_Range", "4.5-5.9", max_len=100, fuzzable=True
                                ),
                                Static("Sep5", "|"),
                                SmartString("Abnormal_Flag", "N", max_len=10, fuzzable=True),
                                Static("Rest", "|||F\r"),
                            ),
                        ),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ORM MESSAGES: Order Messages
        # =====================================================================
        orm_messages = Request(
            "HL7_ORM_Messages",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # MSH
                        Static(
                            "MSH",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ORM^O01|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        # PID
                        Block(
                            "PID_Segment",
                            children=(
                                Static("PID_ID", "PID|1||"),
                                SmartString(
                                    "Patient_ID",
                                    "12345678^^^MRN",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "||"),
                                SmartString(
                                    "Patient_Name",
                                    "DOE^JOHN^A",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Rest", "||19800101|M\r"),
                            ),
                        ),
                        # ORC - Common Order
                        Block(
                            "ORC_Segment",
                            children=(
                                Static("ORC_ID", "ORC|"),
                                SmartString("Order_Control", "NW", max_len=10, fuzzable=True),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Placer_Order",
                                    "ORD001^CPOE",
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep2", "||"),
                                SmartString("Order_Status", "IP", max_len=10, fuzzable=True),
                                Static("Rest", "|||||||||||||||\r"),
                            ),
                        ),
                        # OBR - Observation Request
                        Block(
                            "OBR_Segment",
                            children=(
                                Static("OBR_ID", "OBR|1|"),
                                SmartString(
                                    "Placer_Order",
                                    "ORD001^CPOE",
                                    max_len=100,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "||"),
                                SmartString(
                                    "Universal_Service_ID",
                                    "85025^CBC^L",
                                    max_len=200,
                                    fuzzable=True,
                                ),
                                Static("Sep2", "|"),
                                Group("Priority", values=[b"STAT", b"ASAP", b"ROUTINE", b"TIMED"]),
                                Static("Rest", f"|{timestamp}||||||||\r"),
                            ),
                        ),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # QUERY MESSAGES: Patient Query
        # =====================================================================
        query_messages = Request(
            "HL7_Query",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # MSH
                        Static(
                            "MSH",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"QRY^A19|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        # QRD - Query Definition
                        Block(
                            "QRD_Segment",
                            children=(
                                Static("QRD_ID", "QRD|"),
                                SmartString(
                                    "Query_Timestamp", timestamp, max_len=26, fuzzable=True
                                ),
                                Static("Sep1", "|"),
                                SmartString("Query_Format", "R", max_len=10, fuzzable=True),
                                Static("Sep2", "|"),
                                SmartString("Query_Priority", "I", max_len=10, fuzzable=True),
                                Static("Sep3", "|"),
                                SmartString(
                                    "Query_ID",
                                    "QRY001",
                                    max_len=50,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep4", "||"),
                                SmartString("Quantity_Limited", "RD", max_len=10, fuzzable=True),
                                Static("Sep5", "|"),
                                SmartString(
                                    "Who_Subject",
                                    "12345678^^^MRN",
                                    max_len=200,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep6", "|"),
                                SmartString("What_Subject", "DEM", max_len=100, fuzzable=True),
                                Static("Rest", "||||\r"),
                            ),
                        ),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ATTACK: Delimiter Injection
        # =====================================================================
        delimiter_injection = Request(
            "HL7_Delimiter_Injection",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        Static("MSH_Start", "MSH|^~\\&|"),
                        # Inject delimiters in field values
                        Group(
                            "Injected_Sending_App",
                            values=[
                                # Pipe injection
                                b"APP|INJECTED",
                                b"APP||DOUBLE",
                                # Caret injection
                                b"APP^COMPONENT",
                                b"APP^^DOUBLE",
                                # Tilde injection
                                b"APP~REPEAT~AGAIN",
                                # Ampersand injection
                                b"APP&SUB&COMPONENT",
                                # Backslash injection (escape char)
                                b"APP\\ESCAPE\\CHAR",
                                b"APP\\F\\FIELD",
                                b"APP\\S\\COMPONENT",
                                b"APP\\T\\SUBCOMP",
                                b"APP\\R\\REPEAT",
                                b"APP\\E\\ESCAPE",
                                # Combined
                                b"APP|^~\\&|ALL",
                                # Null injection
                                b'APP""NULL',
                                # Segment terminator in value
                                b"APP\rEVN|A01",
                            ],
                        ),
                        Static(
                            "Rest",
                            f"|{self.sending_facility}|{self.receiving_app}|"
                            f"{self.receiving_facility}|{timestamp}||ADT^A01|"
                            f"{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        Static("EVN", f"EVN|A01|{timestamp}\r"),
                        # Inject in patient name
                        Static("PID_Start", "PID|1||12345^^^MRN||"),
                        Group(
                            "Injected_Patient_Name",
                            values=[
                                b"DOE|JOHN",  # Field separator
                                b"DOE^JOHN^MIDDLE^SUFFIX^PREFIX",  # Max components
                                b"DOE~ALT~NAME",  # Repetition
                                b"DOE&SUB&PARTS",  # Subcomponent
                                b"O'BRIEN^JOHN",  # Apostrophe
                                b'DOE"JOHN',  # Quote
                                b"DOE<SCRIPT>JOHN",  # XSS attempt
                                b"DOE;DROP TABLE;JOHN",  # SQL injection
                            ],
                        ),
                        Static("PID_Rest", "||19800101|M\r"),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ATTACK: Segment Fuzzing (Unknown/Malformed Segments)
        # =====================================================================
        segment_fuzzing = Request(
            "HL7_Segment_Fuzzing",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        Static(
                            "MSH",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ADT^A01|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        # Fuzz with unknown segment types
                        Group(
                            "Unknown_Segment",
                            values=[
                                # Valid but rarely used segments
                                b"ZZZ|Custom|Segment|Data\r",
                                b"ZPD|Patient|Custom|Data\r",
                                # Invalid segment IDs
                                b"XXX|Invalid|Segment\r",
                                b"123|Numeric|ID\r",
                                b"|Empty|Segment|ID\r",
                                b"TOOLONG|Segment|ID|Four|Chars\r",
                                b"AB|Two|Char|Segment\r",
                                # Malformed segments
                                b"MSH\r",  # No fields
                                b"PID\r",  # No data
                                b"|\r",  # Just delimiter
                                b"\r",  # Empty segment
                                # Segment with excessive fields
                                b"OBX|" + b"|".join([b"FIELD"] * 100) + b"\r",
                                # Binary data in segment
                                b"BIN|\x00\x01\x02\x03\r",
                                # Unicode in segment
                                b"UNI|Test\x00Null|Test\xffHigh\r",
                            ],
                        ),
                        Static("PID", "PID|1||12345^^^MRN||DOE^JOHN||19800101|M\r"),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ATTACK: HL7 v2.x Version Sweep (MSH-12)
        # Different HL7 v2.x parsers (2.3 through 2.8) take different code
        # paths based on the declared version in MSH-12. Sweeping the version
        # field exercises per-version parsing logic in a single request.
        # See ref/hl7/fuzzer.md recommendation 1.
        # =====================================================================
        version_sweep = Request(
            "HL7_Version_Sweep",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        Static(
                            "MSH_Start",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ADT^A01|{msg_ctrl_id}|{self.processing_id}|",
                        ),
                        # Sweep MSH-12 version across all v2.x revisions
                        Group(
                            "HL7_Version",
                            values=[
                                b"2.3",
                                b"2.3.1",
                                b"2.4",
                                b"2.5",
                                b"2.5.1",
                                b"2.6",
                                b"2.7",
                                b"2.7.1",
                                b"2.8",
                                b"2.8.1",
                                b"2.8.2",
                            ],
                        ),
                        Static("Segment_Term", "\r"),
                        Static("EVN", f"EVN|A01|{timestamp}\r"),
                        Static("PID", "PID|1||12345^^^MRN||DOE^JOHN||19800101|M\r"),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ATTACK: Z-Segment Injection (Vendor-Specific Segments)
        # Z-segments (segment IDs starting with 'Z') are vendor-specific and
        # most parsers must skip them gracefully. Injecting a malformed
        # Z-segment mid-message catches parsers that don't handle unknown
        # vendor segments cleanly. See ref/hl7/fuzzer.md recommendation 3.
        # =====================================================================
        z_segment_injection = Request(
            "HL7_Z_Segment_Injection",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        # Valid MSH header
                        Static(
                            "MSH",
                            f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ADT^A01|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                        ),
                        Static("EVN", f"EVN|A01|{timestamp}\r"),
                        Static("PID", "PID|1||12345^^^MRN||DOE^JOHN||19800101|M\r"),
                        # Inject a malformed Z-segment between PID and PV1
                        Group(
                            "Z_Segment",
                            values=[
                                # Well-formed Z-segments (parsers should skip)
                                b"ZPI|1|VENDOR|DATA\r",
                                b"ZPD|Patient|Custom|Data\r",
                                b"ZVN|VendorName|1.0\r",
                                # Malformed Z-segments (parser stress)
                                b"Z\r",  # Single char ID
                                b"ZZ\r",  # Two char ID
                                b"ZZZZ|TooLong|ID\r",  # 4-char ID
                                b"Z01|Numeric|Suffix\r",  # Numeric suffix
                                b"ZPI\r",  # No fields
                                b"ZPI|\r",  # Trailing separator only
                                b"ZPI|" + b"A" * 5000 + b"\r",  # Oversized Z-segment
                                b"ZPI|" + b"|".join([b"FIELD"] * 50) + b"\r",  # Many fields
                                b"ZPI|\x00\x01\x02|BINARY\r",  # Binary data
                                b"ZPI|MSH|^~\\&|NESTED\r",  # Nested MSH-like content
                                b"ZPI|VENDOR\rPID|FAKE\r",  # Embedded segment terminator
                                b"ZPI|VAL\r\r",  # Double terminator
                            ],
                        ),
                        Static("PV1", "PV1|1|I|WEST^101^A^1^^^S|E\r"),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ATTACK: MLLP Frame Corruption
        # =====================================================================
        mllp_corruption = Request(
            "HL7_MLLP_Corruption",
            children=(
                # Fuzz the MLLP framing
                Group(
                    "MLLP_Start_Corrupt",
                    values=[
                        b"\x0b",  # Valid start
                        b"",  # Missing start
                        b"\x0b\x0b",  # Double start
                        b"\x00",  # Null byte
                        b"\x1c",  # Wrong byte (end marker as start)
                        b"\x0d",  # CR as start
                        b"\x0a",  # LF as start
                        b"\xff",  # High byte
                        b"\x0b\x00",  # Start + null
                    ],
                ),
                Static(
                    "HL7_Message",
                    f"MSH|^~\\&|{self.sending_app}|{self.sending_facility}|"
                    f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                    f"ACK|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r"
                    f"MSA|AA|{msg_ctrl_id}|\r",
                ),
                Group(
                    "MLLP_End_Corrupt",
                    values=[
                        b"\x1c\x0d",  # Valid end
                        b"",  # Missing end
                        b"\x1c",  # Missing CR
                        b"\x0d",  # Missing FS
                        b"\x1c\x1c\x0d",  # Double FS
                        b"\x1c\x0d\x0d",  # Double CR
                        b"\x0d\x1c",  # Reversed order
                        b"\x1c\x0a",  # LF instead of CR
                        b"\x00\x00",  # Null bytes
                    ],
                ),
            ),
        )

        # =====================================================================
        # ATTACK: Oversized Fields
        # =====================================================================
        oversized_fields = Request(
            "HL7_Oversized_Fields",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        Block(
                            "MSH_Segment",
                            children=(
                                Static("MSH_ID", "MSH|^~\\&|"),
                                # Oversized sending application
                                SmartString(
                                    "Sending_App",
                                    "A" * 1000,
                                    max_len=10000,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "|"),
                                SmartString(
                                    "Sending_Facility",
                                    "B" * 1000,
                                    max_len=10000,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep2", "|"),
                                Static("Receiving_App", self.receiving_app),
                                Static("Sep3", "|"),
                                Static("Receiving_Facility", self.receiving_facility),
                                Static(
                                    "Rest",
                                    f"|{timestamp}||ADT^A01|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r",
                                ),
                            ),
                        ),
                        Static("EVN", f"EVN|A01|{timestamp}\r"),
                        Block(
                            "PID_Oversized",
                            children=(
                                Static("PID_ID", "PID|1||"),
                                # Oversized patient ID
                                SmartString(
                                    "Patient_ID",
                                    "X" * 5000,
                                    max_len=50000,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Sep1", "||"),
                                # Oversized patient name
                                SmartString(
                                    "Patient_Name",
                                    "Y" * 5000,
                                    max_len=50000,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("Rest", "||19800101|M\r"),
                            ),
                        ),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # ATTACK: Encoding Character Manipulation
        # =====================================================================
        encoding_chars = Request(
            "HL7_Encoding_Chars",
            children=(
                Bytes("MLLP_Start", MLLP_START, fuzzable=False),
                Block(
                    "HL7_Message",
                    children=(
                        Static("MSH_ID", "MSH|"),
                        # Fuzz the encoding characters (MSH-2)
                        Group(
                            "Encoding_Chars",
                            values=[
                                b"^~\\&",  # Standard
                                b"^~\\",  # Missing subcomponent separator
                                b"^~",  # Missing escape and subcomponent
                                b"^",  # Only component separator
                                b"",  # Empty
                                b"^^^^",  # All same char
                                b"~~~~",  # All tildes
                                b"\\\\\\\\",  # All escapes
                                b"&&&&",  # All ampersands
                                b"^~\\&|",  # Extra delimiter
                                b"^~\\&^~\\&",  # Doubled
                                b"\x00\x00\x00\x00",  # Null bytes
                                b"\xff\xff\xff\xff",  # High bytes
                                b"^~|&",  # Pipe in encoding chars
                                b"A~B&C",  # Letters as separators
                            ],
                        ),
                        Static(
                            "Rest",
                            f"|{self.sending_app}|{self.sending_facility}|"
                            f"{self.receiving_app}|{self.receiving_facility}|{timestamp}||"
                            f"ADT^A01|{msg_ctrl_id}|{self.processing_id}|{self.hl7_version}\r"
                            f"EVN|A01|{timestamp}\r"
                            f"PID|1||12345^^^MRN||DOE^JOHN||19800101|M\r",
                        ),
                    ),
                ),
                Bytes("MLLP_End", MLLP_END, fuzzable=False),
            ),
        )

        # =====================================================================
        # Connect requests to session (OPTIMIZED ORDER)
        # =====================================================================
        # Ordering optimized for maximum early coverage and crash detection:
        #
        # Phase 1 (0-30s): Quick Coverage - all message types once
        # Phase 2 (30s-2m): High-crash tests - overflow, memory corruption
        # Phase 3 (2m-5m): CVE-targeted - injection attacks
        # Phase 4 (5m-10m): Boundary attacks - segment/field fuzzing
        # Phase 5 (10m+): Deep fuzzing - full message mutations

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Touch all 6 message types (13 total variations) for maximum breadth
        if self.is_request_enabled("HL7_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # ==================== PHASE 2: HIGH-CRASH TESTS (30s-2m) ====================
        # Most likely to cause crashes - run early for quick vulnerability discovery
        # CVE-2025-53948: crafted HL7 message crashes server (oversized fields)
        if self.is_request_enabled("HL7_Oversized_Fields"):
            self.session.connect(oversized_fields)

        # CVE-2025-53948: crafted HL7 over MLLP -> main-thread crash (DoS)
        if self.is_request_enabled("HL7_MLLP_Corruption"):
            self.session.connect(mllp_corruption)

        # ==================== PHASE 3: CVE-TARGETED ATTACKS (2m-5m) ====================
        # Known vulnerability patterns in HL7 parsers
        # CVE-2020-27260: HL7 v2.x delimiter/segment injection
        if self.is_request_enabled("HL7_Delimiter_Injection"):
            self.session.connect(delimiter_injection)

        # CVE-2020-27260: encoding-character manipulation / injection
        if self.is_request_enabled("HL7_Encoding_Chars"):
            self.session.connect(encoding_chars)

        # Z-segment injection: vendor-specific segment handling stress test
        if self.is_request_enabled("HL7_Z_Segment_Injection"):
            self.session.connect(z_segment_injection)

        # ==================== PHASE 4: BOUNDARY ATTACKS (5m-10m) ====================
        # Malformed segments and field boundary testing
        if self.is_request_enabled("HL7_Segment_Fuzzing"):
            self.session.connect(segment_fuzzing)

        # HL7 v2.x version sweep: exercises per-version parser code paths
        if self.is_request_enabled("HL7_Version_Sweep"):
            self.session.connect(version_sweep)

        # Baseline connectivity test (useful for validating target is still alive)
        if self.is_request_enabled("HL7_Baseline"):
            self.session.connect(baseline_ack)

        # ==================== PHASE 5: DEEP FUZZING (10m+) ====================
        # Full message type mutations with extensive field fuzzing
        # Only fuzz message types that are supported by the server (if detection enabled)
        if self.is_request_enabled("HL7_ADT_Messages") and self.is_message_type_supported("ADT"):
            self.session.connect(adt_messages)
        elif self.is_request_enabled("HL7_ADT_Messages"):
            self.log.display("Skipping HL7_ADT_Messages (ADT not supported by server)")

        if self.is_request_enabled("HL7_ORU_Messages") and self.is_message_type_supported("ORU"):
            self.session.connect(oru_messages)
        elif self.is_request_enabled("HL7_ORU_Messages"):
            self.log.display("Skipping HL7_ORU_Messages (ORU not supported by server)")

        if self.is_request_enabled("HL7_ORM_Messages") and self.is_message_type_supported("ORM"):
            self.session.connect(orm_messages)
        elif self.is_request_enabled("HL7_ORM_Messages"):
            self.log.display("Skipping HL7_ORM_Messages (ORM not supported by server)")

        if self.is_request_enabled("HL7_Query") and self.is_message_type_supported("QRY"):
            self.session.connect(query_messages)
        elif self.is_request_enabled("HL7_Query"):
            self.log.display("Skipping HL7_Query (QRY not supported by server)")
