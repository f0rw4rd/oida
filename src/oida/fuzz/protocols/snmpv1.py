"""SNMP v1 Protocol Fuzzer"""

from boofuzz import Block, Byte, DWord, Request, Size, Static

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import SNMPHealthMonitor
from ..primitives.asn1_blocks import BERSize
from ..primitives.dynamic import SmartBytes, SmartString
from ..primitives.smart_string import StringContext
from .snmp_common import (
    build_ber_length_of_length,
    build_ber_structured,
    build_ber_truncated_length,
    build_boundary_values,
    build_get_next_request,
    build_get_request,
    build_set_request,
    encode_oid,
    ip_to_bytes,
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
    # the full recv timeout per trap case is pure dead time. Classify by
    # WALKING the BER structure (SEQUENCE -> version INTEGER -> community
    # OCTET STRING -> PDU tag), never by scanning for tag bytes: the community
    # string is fuzzed, and any 0xA0-0xA5 byte inside it would otherwise
    # misclassify a GetRequest as a Trap (skipping its reply wait) or mask a
    # real Trap (burning the full timeout per case). Anything unparseable
    # (empty, truncated, over-long lengths) conservatively waits.
    @staticmethod
    def _reply_expected_for_payload(data: bytes) -> bool:
        if not data:
            return True

        def _read_tlv(buf, pos):
            """(tag, value_start, value_end, next_pos) or None if malformed."""
            if pos + 2 > len(buf):
                return None
            tag = buf[pos]
            length = buf[pos + 1]
            if length & 0x80:  # long-form length
                n = length & 0x7F
                if n == 0 or pos + 2 + n > len(buf):
                    return None
                length = int.from_bytes(buf[pos + 2 : pos + 2 + n], "big")
                value_start = pos + 2 + n
            else:
                value_start = pos + 2
            if length > len(buf) - value_start:  # over-declared
                return None
            return tag, value_start, value_start + length, value_start + length

        # SEQUENCE { version INTEGER, community OCTET STRING, PDU }
        outer = _read_tlv(data, 0)
        if outer is None or outer[0] != 0x30:
            return True
        version = _read_tlv(data, outer[1])
        if version is None or version[0] != 0x02:
            return True
        community = _read_tlv(data, version[3])
        if community is None or community[0] != 0x04:
            return True
        pdu = _read_tlv(data, community[3])
        if pdu is None:
            return True
        return pdu[0] != 0xA4  # Trap: fire-and-forget

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
        get_request = build_get_request(
            "SNMP_GetRequest", b"\x02\x01\x00", request_id, community, oid_prefix
        )

        # SNMP GetNextRequest
        get_next_request = build_get_next_request(
            "SNMP_GetNextRequest", b"\x02\x01\x00", request_id + 1, community, oid_prefix
        )

        # SNMP SetRequest (if enabled)
        if enable_set:
            set_request = build_set_request(
                "SNMP_SetRequest", b"\x02\x01\x00", request_id + 2, community, oid_prefix
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
        boundary_values = build_boundary_values("SNMP_Boundary_Values", b"\x02\x01\x00", community)

        # BER length-of-length mutation: emit malformed long-form / indefinite
        # length octets at the inner community, OID and varbind-value TLVs. The
        # definite-form Size fields used elsewhere auto-compute these octets, so
        # the length-of-length machinery is otherwise never fuzzed -- exactly the
        # parse path behind CVE-2019-9162 (net-snmp), CVE-2020-14934 (Contiki-NG),
        # CVE-2015-5621 (net-snmp) and CVE-2022-24805 (kernel BER decoder). The
        # outer SEQUENCE / PDU / varbindings lengths stay valid (auto-computed),
        # so the agent parses a well-formed frame before choking on the inner length.
        ber_length_of_length = build_ber_length_of_length(
            "SNMP_BER_LengthOfLength", b"\x02\x01\x00", request_id + 200, community, oid_prefix
        )

        # BER truncated length: inner definite-form lengths declared shorter than
        # the content that actually follows (declared < actual) at the community,
        # OID and varbind-value TLVs. Parsers that trust the declared length under-
        # read the field and then desynchronise on the trailing bytes.
        ber_truncated_length = build_ber_truncated_length(
            "SNMP_BER_Truncated_Length", b"\x02\x01\x00", request_id + 201, oid_prefix
        )

        # Structured BER codec attacks on a single varbind. The previously
        # dead ASN1Builder mutators (tag confusion / over-declared length /
        # overflow / deep nesting) are spliced in as a Group where the varbind
        # TLV goes; every enclosing length (message / PDU / varbindings) is an
        # auto-computed BERSize so the outer framing stays valid and the agent
        # reaches varbind BER decoding before choking on the malformed TLV.
        ber_structured = build_ber_structured(
            "SNMP_BER_Structured", b"\x02\x01\x00", request_id + 300, community, oid_prefix
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
