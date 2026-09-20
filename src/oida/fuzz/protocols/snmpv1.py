"""SNMP v1 Protocol Fuzzer"""

from boofuzz import Block, Byte, DWord, Group, Request, Size, Static

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import SNMPHealthMonitor
from ..primitives.asn1_blocks import BERSize
from ..primitives.dynamic import SmartBytes, SmartString
from ..primitives.smart_string import StringContext
from .snmp_common import (
    ber_length_group_values,
    encode_oid,
    ip_to_bytes,
    oid_content,
    structured_ber_varbind_values,
)


class SNMPv1Fuzzer(BaseFuzzer):
    """SNMP v1 (Simple Network Management Protocol) Fuzzer

    Supports fuzzing SNMPv1 protocol messages including:
    - GetRequest
    - GetNextRequest
    - SetRequest
    - GetResponse
    - Trap
    """

    PROTOCOL_OPTIONS = {
        "community": {
            "type": str,
            "default": "public",
            "description": "SNMP community string",
        },
        "request_id": {
            "type": int,
            "default": 1,
            "description": "Request ID for PDUs",
        },
        "enterprise_oid": {
            "type": str,
            "default": "1.3.6.1.4.1.12345",
            "description": "Enterprise OID for traps",
        },
        "agent_addr": {
            "type": str,
            "default": None,
            "description": "Agent address for traps (default: target IP)",
        },
        "trap_type": {
            "type": int,
            "default": 6,
            "description": "Generic trap type (0-6)",
            "choices": [0, 1, 2, 3, 4, 5, 6],
        },
        "specific_trap": {
            "type": int,
            "default": 1,
            "description": "Specific trap code",
        },
        "enable_set": {
            "type": bool,
            "default": False,
            "description": "Enable SET requests",
        },
        "oid_prefix": {
            "type": str,
            "default": "1.3.6.1.2.1",
            "description": "OID prefix for requests",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Standard PDUs
            RequestInfo("SNMP_GetRequest", "GET request", "standard"),
            RequestInfo("SNMP_GetNextRequest", "GET-NEXT request", "standard"),
            RequestInfo("SNMP_SetRequest", "SET request (requires enable_set)", "write"),
            # Responses
            RequestInfo("SNMP_GetResponse_NoError", "Response - no error", "response"),
            RequestInfo("SNMP_GetResponse_TooBig", "Response - tooBig", "response"),
            RequestInfo("SNMP_GetResponse_NoSuchName", "Response - noSuchName", "response"),
            RequestInfo("SNMP_GetResponse_BadValue", "Response - badValue", "response"),
            RequestInfo("SNMP_GetResponse_ReadOnly", "Response - readOnly", "response"),
            RequestInfo("SNMP_GetResponse_GenErr", "Response - genErr", "response"),
            # Traps
            RequestInfo("SNMP_Trap", "v1 Trap PDU", "trap"),
            # Attack patterns
            RequestInfo("SNMP_Community_256Bytes", "Long community string", "high_crash"),
            RequestInfo("SNMP_Community_FormatString", "Format string in community", "high_crash"),
            RequestInfo(
                "SNMP_Boundary_Values", "Integer boundary values (0, max, negative)", "boundary"
            ),
            # BER length-of-length mutation (community / OID / varbind-value TLVs)
            RequestInfo(
                "SNMP_BER_LengthOfLength",
                "Long-form / indefinite BER length octets on inner TLVs "
                "(CVE-2019-9162 / CVE-2020-14934 class)",
                "high_crash",
            ),
            RequestInfo(
                "SNMP_BER_Truncated_Length",
                "Inner BER lengths declared shorter than actual content (community / OID / value)",
                "boundary",
            ),
            # Structured BER codec attacks on a varbind (tag confusion /
            # over-declared length / overflow / deep nesting)
            RequestInfo(
                "SNMP_BER_Structured",
                "Structured BER codec attacks on a varbind: tag confusion, "
                "over-declared length, oversized content and deep SEQUENCE nesting "
                "(CVE-2019-9162 class parser attacks)",
                "high_crash",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    # Reply-expectation policy (same pattern as MQTT/CoAP): every SNMPv1 PDU
    # a manager sends gets a GetResponse -- except a v1 Trap PDU (0xA4), which
    # is agent-to-manager and unsolicited: no reply is ever coming, so waiting
    # the full recv timeout per trap case is pure dead time. The PDU tag sits
    # at a fixed offset only in unmutated messages, so classify by scanning
    # for the first context tag (0xA0-0xA5); non-SNMP-looking bytes (empty,
    # short, no PDU tag found) conservatively wait.
    @staticmethod
    def _reply_expected_for_payload(data: bytes) -> bool:
        if not data:
            return True
        for b in data[:64]:
            if 0xA0 <= b <= 0xA5:
                return b != 0xA4  # Trap: fire-and-forget
            if b in (0x30, 0x02, 0x04):  # SEQUENCE / INTEGER / OCTET STRING
                continue
        return True  # No PDU tag found: assume it might get an answer

    reply_policy = _reply_expected_for_payload

    # Cap on the reply-expected wait: real GetResponses arrive in
    # single-digit ms; silence past ~0.15s means the mock dropped the
    # malformed request. Without the cap each dropped request burns the full
    # recv timeout (~2s default, ~0.5s calibrated), capping throughput at a
    # few cases/second (measured 2/s against the docker mock).
    reply_wait_cap = 0.15

    def setup_custom_monitors(self):
        """Setup SNMP-specific monitors"""
        # SNMP runs over UDP; a TCP-connect monitor (SocketHealthMonitor)
        # always fails against it. snmpv2c/v3 already use SNMPHealthMonitor;
        # v1 was left behind doing TCP connects to a UDP port.
        return [
            SNMPHealthMonitor(
                self.config.target_ip, self.config.target_port or 161, retry_count=3, timeout=2
            )
        ]

    def _encode_oid(self, oid_string):
        """Encode OID string to BER format"""
        return encode_oid(oid_string)

    def _ip_to_bytes(self, ip_string):
        """Convert IP address string to bytes"""
        return ip_to_bytes(ip_string)

    def _define_protocol(self):
        """Define SNMP v1 protocol structure"""
        # Get protocol options
        community = self.config.get_option("community", "public")
        request_id = self.config.get_option("request_id", 1)
        enterprise_oid = self.config.get_option("enterprise_oid", "1.3.6.1.4.1.12345")
        agent_addr = self.config.get_option("agent_addr", self.config.target_ip)
        trap_type = self.config.get_option("trap_type", 6)
        specific_trap = self.config.get_option("specific_trap", 1)
        enable_set = self.config.get_option("enable_set", False)
        oid_prefix = self.config.get_option("oid_prefix", "1.3.6.1.2.1")

        # SNMP GetRequest
        get_request = Request(
            "SNMP_GetRequest",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        # SEQUENCE tag
                        Static("Sequence_Tag", b"\x30"),
                        # Length (will be calculated)
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                # Version (INTEGER 0 for v1)
                                Static("Version_Tag", b"\x02\x01\x00"),
                                # Community String (OCTET STRING)
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                # PDU (GetRequest = 0xA0)
                                Static("PDU_Tag", b"\xa0"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        # Request ID (INTEGER)
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord("RequestID", request_id, endian=">", fuzzable=True),
                                        # Error Status (INTEGER 0)
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        # Error Index (INTEGER 0)
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        # Variable Bindings (SEQUENCE)
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                # Variable Binding 1
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        # OID
                                                        Static("OID1_Tag", b"\x06"),
                                                        Size(
                                                            "OID1_Length",
                                                            "OID1_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        # Value (NULL for GetRequest)
                                                        Static("Value1", b"\x05\x00"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # SNMP GetNextRequest
        get_next_request = Request(
            "SNMP_GetNextRequest",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                # PDU (GetNextRequest = 0xA1)
                                Static("PDU_Tag", b"\xa1"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 1, endian=">", fuzzable=True
                                        ),
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        Static("OID1_Tag", b"\x06"),
                                                        Size(
                                                            "OID1_Length",
                                                            "OID1_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value1", b"\x05\x00"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # SNMP SetRequest (if enabled)
        if enable_set:
            set_request = Request(
                "SNMP_SetRequest",
                children=(
                    Block(
                        "SNMP_Message",
                        children=(
                            Static("Sequence_Tag", b"\x30"),
                            BERSize(
                                "Message_Length",
                                "SNMP_Content",
                                fuzzable=False,
                            ),
                            Block(
                                "SNMP_Content",
                                children=(
                                    Static("Version_Tag", b"\x02\x01\x00"),
                                    Static("Community_Tag", b"\x04"),
                                    Size(
                                        "Community_Length",
                                        "Community_String",
                                        endian=">",
                                        output_format="binary",
                                        length=1,
                                        fuzzable=False,
                                    ),
                                    SmartString(
                                        "Community_String",
                                        community,
                                        fuzzable=True,
                                        context=StringContext.CREDENTIAL,
                                    ),
                                    # PDU (SetRequest = 0xA3)
                                    Static("PDU_Tag", b"\xa3"),
                                    Size(
                                        "PDU_Length",
                                        "PDU_Content",
                                        endian=">",
                                        output_format="binary",
                                        length=1,
                                        fuzzable=False,
                                    ),
                                    Block(
                                        "PDU_Content",
                                        children=(
                                            Static("RequestID_Tag", b"\x02"),
                                            Byte("RequestID_Length", 0x04, fuzzable=False),
                                            DWord(
                                                "RequestID",
                                                request_id + 2,
                                                endian=">",
                                                fuzzable=True,
                                            ),
                                            Static("ErrorStatus", b"\x02\x01\x00"),
                                            Static("ErrorIndex", b"\x02\x01\x00"),
                                            Static("VarBindings_Tag", b"\x30"),
                                            Size(
                                                "VarBindings_Length",
                                                "VarBindings_Content",
                                                endian=">",
                                                output_format="binary",
                                                length=1,
                                                fuzzable=False,
                                            ),
                                            Block(
                                                "VarBindings_Content",
                                                children=(
                                                    Static("VarBind1_Tag", b"\x30"),
                                                    Size(
                                                        "VarBind1_Length",
                                                        "VarBind1_Content",
                                                        endian=">",
                                                        output_format="binary",
                                                        length=1,
                                                        fuzzable=False,
                                                    ),
                                                    Block(
                                                        "VarBind1_Content",
                                                        children=(
                                                            Static("OID1_Tag", b"\x06"),
                                                            Size(
                                                                "OID1_Length",
                                                                "OID1_Value",
                                                                endian=">",
                                                                output_format="binary",
                                                                length=1,
                                                                fuzzable=False,
                                                            ),
                                                            SmartBytes(
                                                                "OID1_Value",
                                                                self._encode_oid(
                                                                    f"{oid_prefix}.1.3.0"
                                                                ),
                                                                fuzzable=True,
                                                            ),
                                                            # Value (OCTET STRING)
                                                            Static("Value_Tag", b"\x04"),
                                                            Size(
                                                                "Value_Length",
                                                                "Value_String",
                                                                endian=">",
                                                                output_format="binary",
                                                                length=1,
                                                                fuzzable=False,
                                                            ),
                                                            SmartString(
                                                                "Value_String",
                                                                "TestValue",
                                                                fuzzable=True,
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )

        # GetResponse with noError (0)
        get_response_noerror = Request(
            "SNMP_GetResponse_NoError",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                # PDU (GetResponse = 0xA2)
                                Static("PDU_Tag", b"\xa2"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 10, endian=">", fuzzable=True
                                        ),
                                        # Error Status = 0 (noError)
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        Static("OID1_Tag", b"\x06"),
                                                        Size(
                                                            "OID1_Length",
                                                            "OID1_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        # Value (OCTET STRING with response data)
                                                        Static("Value_Tag", b"\x04"),
                                                        Size(
                                                            "Value_Length",
                                                            "Value_String",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartString(
                                                            "Value_String",
                                                            "ResponseData",
                                                            fuzzable=True,
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # GetResponse with tooBig error (1)
        get_response_toobig = Request(
            "SNMP_GetResponse_TooBig",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("PDU_Tag", b"\xa2"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02\x04"),
                                        DWord(
                                            "RequestID", request_id + 11, endian=">", fuzzable=True
                                        ),
                                        # Error Status = 1 (tooBig)
                                        Static("ErrorStatus", b"\x02\x01\x01"),
                                        Static("ErrorIndex", b"\x02\x01\x01"),
                                        Static(
                                            "VarBindings_Tag", b"\x30\x00"
                                        ),  # Empty var bindings
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # GetResponse with noSuchName error (2)
        get_response_nosuchname = Request(
            "SNMP_GetResponse_NoSuchName",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("PDU_Tag", b"\xa2"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02\x04"),
                                        DWord(
                                            "RequestID", request_id + 12, endian=">", fuzzable=True
                                        ),
                                        # Error Status = 2 (noSuchName)
                                        Static("ErrorStatus", b"\x02\x01\x02"),
                                        Static("ErrorIndex", b"\x02\x01\x01"),
                                        Static("VarBindings_Tag", b"\x30\x00"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # GetResponse with badValue error (3)
        get_response_badvalue = Request(
            "SNMP_GetResponse_BadValue",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("PDU_Tag", b"\xa2"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02\x04"),
                                        DWord(
                                            "RequestID", request_id + 13, endian=">", fuzzable=True
                                        ),
                                        # Error Status = 3 (badValue)
                                        Static("ErrorStatus", b"\x02\x01\x03"),
                                        Static("ErrorIndex", b"\x02\x01\x01"),
                                        Static("VarBindings_Tag", b"\x30\x00"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # GetResponse with readOnly error (4)
        get_response_readonly = Request(
            "SNMP_GetResponse_ReadOnly",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("PDU_Tag", b"\xa2"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02\x04"),
                                        DWord(
                                            "RequestID", request_id + 14, endian=">", fuzzable=True
                                        ),
                                        # Error Status = 4 (readOnly)
                                        Static("ErrorStatus", b"\x02\x01\x04"),
                                        Static("ErrorIndex", b"\x02\x01\x01"),
                                        Static("VarBindings_Tag", b"\x30\x00"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # GetResponse with genErr error (5)
        get_response_generr = Request(
            "SNMP_GetResponse_GenErr",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("PDU_Tag", b"\xa2"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02\x04"),
                                        DWord(
                                            "RequestID", request_id + 15, endian=">", fuzzable=True
                                        ),
                                        # Error Status = 5 (genErr)
                                        Static("ErrorStatus", b"\x02\x01\x05"),
                                        Static("ErrorIndex", b"\x02\x01\x01"),
                                        Static("VarBindings_Tag", b"\x30\x00"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # SNMP Trap
        trap_request = Request(
            "SNMP_Trap",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                # PDU (Trap = 0xA4)
                                Static("PDU_Tag", b"\xa4"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        # Enterprise OID
                                        Static("Enterprise_Tag", b"\x06"),
                                        Size(
                                            "Enterprise_Length",
                                            "Enterprise_OID",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "Enterprise_OID",
                                            self._encode_oid(enterprise_oid),
                                            fuzzable=True,
                                        ),
                                        # Agent Address (IP Address)
                                        Static("AgentAddr_Tag", b"\x40\x04"),
                                        SmartBytes(
                                            "AgentAddr",
                                            self._ip_to_bytes(agent_addr),
                                            size=4,
                                            fuzzable=True,
                                        ),
                                        # Generic Trap (INTEGER)
                                        Static("GenericTrap_Tag", b"\x02\x01"),
                                        Byte("GenericTrap", trap_type, fuzzable=True),
                                        # Specific Trap (INTEGER)
                                        Static("SpecificTrap_Tag", b"\x02\x01"),
                                        Byte("SpecificTrap", specific_trap, fuzzable=True),
                                        # Timestamp (TimeTicks)
                                        Static("Timestamp_Tag", b"\x43\x04"),
                                        DWord("Timestamp", 0, endian=">", fuzzable=True),
                                        # Variable Bindings
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        Static("OID1_Tag", b"\x06"),
                                                        Size(
                                                            "OID1_Length",
                                                            "OID1_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.5.0"),
                                                            fuzzable=True,
                                                        ),
                                                        # Value (OCTET STRING)
                                                        Static("Value_Tag", b"\x04"),
                                                        Size(
                                                            "Value_Length",
                                                            "Value_String",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartString(
                                                            "Value_String",
                                                            "TrapData",
                                                            fuzzable=True,
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Community string 256-byte boundary test
        community_256 = Request(
            "SNMP_Community_256Bytes",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Byte("Community_Length", 256, fuzzable=False),
                                Static("Community_256", b"A" * 256),
                                Static("PDU_Tag", b"\xa0"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 100, endian=">", fuzzable=True
                                        ),
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        Static("OID1_Tag", b"\x06"),
                                                        Size(
                                                            "OID1_Length",
                                                            "OID1_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value1", b"\x05\x00"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Community string with format string patterns
        community_format = Request(
            "SNMP_Community_FormatString",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_FormatStr",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString(
                                    "Community_FormatStr", "%s%s%n%x%p" * 10, fuzzable=True
                                ),
                                Static("PDU_Tag", b"\xa0"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 101, endian=">", fuzzable=True
                                        ),
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        Static("OID1_Tag", b"\x06"),
                                                        Size(
                                                            "OID1_Length",
                                                            "OID1_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value1", b"\x05\x00"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # BOUNDARY: Integer boundary value testing (request-id, error-status, error-index)
        boundary_values = Request(
            "SNMP_Boundary_Values",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize(
                            "Message_Length",
                            "SNMP_Content",
                            fuzzable=False,
                        ),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_Boundary",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_Boundary", community, fuzzable=False),
                                Static("PDU_Tag", b"\xa0"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        # Fuzz request-id with boundary values
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord("RequestID", 0xFFFFFFFF, endian=">", fuzzable=True),
                                        # Fuzz error-status with boundary values
                                        Static("ErrorStatus_Tag", b"\x02\x01"),
                                        Byte("ErrorStatus", 0xFF, fuzzable=True),
                                        # Fuzz error-index with boundary values
                                        Static("ErrorIndex_Tag", b"\x02\x01"),
                                        Byte("ErrorIndex", 0xFF, fuzzable=True),
                                        Static("VarBindings", b"\x30\x00"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # BER length-of-length mutation: emit malformed long-form / indefinite
        # length octets at the inner community, OID and varbind-value TLVs. The
        # definite-form Size fields used elsewhere auto-compute these octets, so
        # the length-of-length machinery is otherwise never fuzzed -- exactly the
        # parse path behind CVE-2019-9162 (net-snmp), CVE-2020-14934 (Contiki-NG),
        # CVE-2015-5621 (net-snmp) and CVE-2022-24805 (kernel BER decoder). The
        # outer SEQUENCE / PDU / varbindings lengths stay valid (auto-computed),
        # so the agent parses a well-formed frame before choking on the inner length.
        ber_length_of_length = Request(
            "SNMP_BER_LengthOfLength",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize("Message_Length", "SNMP_Content", fuzzable=False),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                # Community OCTET STRING with malformed length-of-length
                                Static("Community_Tag", b"\x04"),
                                Group(
                                    "Community_LoL",
                                    values=ber_length_group_values(len(community)),
                                ),
                                SmartString(
                                    "Community_String",
                                    community,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("PDU_Tag", b"\xa0"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 200, endian=">", fuzzable=True
                                        ),
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        # OID with malformed length-of-length
                                                        Static("OID1_Tag", b"\x06"),
                                                        Group(
                                                            "OID1_LoL",
                                                            values=ber_length_group_values(
                                                                len(
                                                                    oid_content(
                                                                        f"{oid_prefix}.1.1.0"
                                                                    )
                                                                )
                                                            ),
                                                        ),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            oid_content(f"{oid_prefix}.1.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        # Varbind value OCTET STRING with
                                                        # malformed length-of-length
                                                        Static("Value_Tag", b"\x04"),
                                                        Group(
                                                            "Value_LoL",
                                                            values=ber_length_group_values(
                                                                len(b"oida-ber")
                                                            ),
                                                        ),
                                                        SmartBytes(
                                                            "Value_String",
                                                            b"oida-ber",
                                                            fuzzable=True,
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # BER truncated length: inner definite-form lengths declared shorter than
        # the content that actually follows (declared < actual) at the community,
        # OID and varbind-value TLVs. Parsers that trust the declared length under-
        # read the field and then desynchronise on the trailing bytes.
        ber_truncated_length = Request(
            "SNMP_BER_Truncated_Length",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize("Message_Length", "SNMP_Content", fuzzable=False),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                # Community declares 2 bytes but carries more
                                Static("Community_Tag", b"\x04"),
                                Static("Community_TruncLen", b"\x02"),
                                SmartBytes("Community_String", b"public-overflow", fuzzable=True),
                                Static("PDU_Tag", b"\xa0"),
                                Size(
                                    "PDU_Length",
                                    "PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 201, endian=">", fuzzable=True
                                        ),
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        Size(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Static("VarBind1_Tag", b"\x30"),
                                                Size(
                                                    "VarBind1_Length",
                                                    "VarBind1_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind1_Content",
                                                    children=(
                                                        # OID declares 2 bytes but carries full body
                                                        Static("OID1_Tag", b"\x06"),
                                                        Static("OID1_TruncLen", b"\x02"),
                                                        SmartBytes(
                                                            "OID1_Value",
                                                            oid_content(f"{oid_prefix}.1.1.0"),
                                                            fuzzable=True,
                                                        ),
                                                        # Value declares 1 byte but carries more
                                                        Static("Value_Tag", b"\x04"),
                                                        Static("Value_TruncLen", b"\x01"),
                                                        SmartBytes(
                                                            "Value_String",
                                                            b"oida-truncated",
                                                            fuzzable=True,
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Structured BER codec attacks on a single varbind. The previously
        # dead ASN1Builder mutators (tag confusion / over-declared length /
        # overflow / deep nesting) are spliced in as a Group where the varbind
        # TLV goes; every enclosing length (message / PDU / varbindings) is an
        # auto-computed BERSize so the outer framing stays valid and the agent
        # reaches varbind BER decoding before choking on the malformed TLV.
        ber_structured = Request(
            "SNMP_BER_Structured",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize("Message_Length", "SNMP_Content", fuzzable=False),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x00"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=False),
                                Static("PDU_Tag", b"\xa0"),
                                BERSize("PDU_Length", "PDU_Content", fuzzable=False),
                                Block(
                                    "PDU_Content",
                                    children=(
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID",
                                            request_id + 300,
                                            endian=">",
                                            fuzzable=False,
                                        ),
                                        Static("ErrorStatus", b"\x02\x01\x00"),
                                        Static("ErrorIndex", b"\x02\x01\x00"),
                                        Static("VarBindings_Tag", b"\x30"),
                                        BERSize(
                                            "VarBindings_Length",
                                            "VarBindings_Content",
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "VarBindings_Content",
                                            children=(
                                                Group(
                                                    "Structured_VarBind",
                                                    values=structured_ber_varbind_values(
                                                        f"{oid_prefix}.1.1.0"
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Connect requests to session
        self.session.connect(get_request)
        self.session.connect(get_next_request)
        if enable_set:
            self.session.connect(set_request)

        # GetResponse PDU and error codes
        self.session.connect(get_response_noerror)
        self.session.connect(get_response_toobig)
        self.session.connect(get_response_nosuchname)
        self.session.connect(get_response_badvalue)
        self.session.connect(get_response_readonly)
        self.session.connect(get_response_generr)

        # Phase 1 SNMP Improvements
        self.session.connect(community_256)
        self.session.connect(community_format)

        # Boundary value testing
        self.session.connect(boundary_values)

        # BER length-of-length mutation
        self.session.connect(ber_length_of_length)
        self.session.connect(ber_truncated_length)

        # Structured BER codec attacks (tag / length-lie / overflow / nesting)
        self.session.connect(ber_structured)

        self.session.connect(trap_request)


__all__ = ["SNMPv1Fuzzer"]
