"""SNMPv3 Protocol Fuzzer with security features.

Optimized for breadth-first coverage and early crash detection.
Test ordering follows the phased optimization strategy:
- Phase 1: Baseline discovery and standard operations
- Phase 2: Standard authenticated operations (GetNext, SetRequest)
- Phase 3: Attack surface (malformed packets, report PDU fuzzing)
- Phase 4: USM timing/replay protection attacks
- Phase 5: Boundary value testing

CVE Coverage:
- CVE-2012-6151: Net-SNMP engineID DoS via long engineID in AgentX
- CVE-2018-18065: Net-SNMP NULL pointer dereference via malformed SET
- CVE-2019-20892: Net-SNMP double-free via crafted PDU
- CVE-2022-44792: Net-SNMP NULL dereference in SET to nonexistent OID
"""

from boofuzz import Block, Byte, DWord, Group, QWord, Request, Size, Static, Word

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
    hex_to_bytes,
    oid_content,
    structured_ber_varbind_values,
)


class SNMPv3Fuzzer(BaseFuzzer):
    """SNMPv3 Protocol Fuzzer with security features

    Targets SNMPv3 vulnerabilities including USM authentication bypass,
    engine discovery manipulation, timing/replay attacks, and malformed
    security parameter handling.

    Test Ordering (Optimized for Early Coverage):
    - Phase 1: Baseline discovery (engine discovery, authenticated GetBulk)
    - Phase 2: Standard operations (GetNext, Set with auth)
    - Phase 3: Attacks (malformed packets, Report PDU injection)
    - Phase 4: USM timing/replay attacks (engine boots/time manipulation)
    - Phase 5: Boundary value testing (message ID, max-size, flags, model)
    """

    PROTOCOL_OPTIONS = {
        "security_model": {
            "type": int,
            "default": 3,
            "description": "Security model (3 = USM)",
            "example": "3",
        },
        "security_level": {
            "type": int,
            "default": 1,
            "description": "Security level (1=noAuthNoPriv, 2=authNoPriv, 3=authPriv)",
            "choices": [1, 2, 3],
            "example": "2",
        },
        "username": {
            "type": str,
            "default": "testuser",
            "description": "SNMPv3 username",
            "example": "admin",
        },
        "context_name": {
            "type": str,
            "default": "",
            "description": "SNMP context name",
            "example": "bridge1",
        },
        "engine_id": {
            "type": str,
            "default": "8000000001020304",
            "description": "Engine ID (hex string)",
            "example": "8000000001020304",
        },
        "enable_set": {
            "type": bool,
            "default": False,
            "description": "Enable SET requests (may modify target configuration)",
            "example": "true",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Baseline
            RequestInfo("SNMPv3_Discovery", "Engine discovery request", "baseline"),
            RequestInfo("SNMPv3_Authenticated", "Authenticated GetBulk request", "baseline"),
            # Phase 2: Standard operations
            RequestInfo("SNMPv3_GetNextRequest", "GetNext PDU with v3 auth", "standard"),
            RequestInfo(
                "SNMPv3_SetRequest",
                "Set PDU with v3 auth (requires enable_set)",
                "write",
            ),
            # Phase 3: Attacks
            RequestInfo("SNMPv3_Malformed", "Malformed v3 packets", "high_crash"),
            RequestInfo("SNMPv3_Report", "Report PDU injection for engine confusion", "high_crash"),
            # Phase 4: USM timing/replay
            RequestInfo(
                "SNMPv3_TimingAttack",
                "USM timing/replay attack (engine boots/time manipulation)",
                "cve",
            ),
            # Phase 5: Boundary
            RequestInfo(
                "SNMPv3_Boundary",
                "Boundary values for message ID, max-size, flags, security model",
                "boundary",
            ),
            # USM AuthenticationParameters / PrivacyParameters Group-fuzzing
            # CVE-2018-18066 class: HMAC truncation crashes
            RequestInfo(
                "SNMPv3_USMAuthFuzz",
                "USM AuthenticationParameters / PrivacyParameters explicit mutation",
                "cve",
            ),
            # Missing PDU types (audit S8: SetRequest covered conditionally above)
            RequestInfo(
                "SNMPv3_GetBulkRequest",
                "GetBulkRequest PDU (0xA5) with v3 USM framing",
                "standard",
            ),
            RequestInfo(
                "SNMPv3_InformRequest",
                "InformRequest PDU (0xA6) with v3 USM framing",
                "standard",
            ),
            RequestInfo(
                "SNMPv3_Trap",
                "SNMPv2-Trap PDU (0xA7) wrapped in v3 USM framing",
                "trap",
            ),
            # BER length-of-length mutation on inner scoped-PDU TLVs
            RequestInfo(
                "SNMPv3_BER_LengthOfLength",
                "Long-form / indefinite BER length octets on inner scoped-PDU TLVs "
                "(context-name / OID / value; CVE-2019-9162 class)",
                "high_crash",
            ),
            RequestInfo(
                "SNMPv3_BER_Truncated_Length",
                "Inner BER lengths declared shorter than actual content "
                "(context-name / OID / value)",
                "boundary",
            ),
            RequestInfo(
                "SNMPv3_BER_Structured",
                "Structured BER codec attacks on a scoped-PDU varbind: tag confusion, "
                "over-declared length, oversized content and deep SEQUENCE nesting "
                "(CVE-2019-9162 class parser attacks)",
                "high_crash",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    def setup_custom_monitors(self):
        """Setup SNMPv3-specific monitors.

        SNMP is UDP/161; a TCP connect probe always fails against a real agent.
        Use the UDP SNMP liveness monitor. The probe itself is a lightweight
        v2c GET(sysDescr.0) used only to confirm the agent process is alive —
        a v3 agent still services UDP/161 and its ICMP behaviour is the same.
        """
        return [
            SNMPHealthMonitor(
                self.config.target_ip,
                self.config.target_port or 161,
                retry_count=3,
                timeout=2,
            )
        ]

    def _encode_oid(self, oid_string):
        """Encode OID string to BER format"""
        return encode_oid(oid_string)

    def _hex_to_bytes(self, hex_string):
        """Convert hex string to bytes"""
        return hex_to_bytes(hex_string)

    def _define_protocol(self):
        """Define SNMPv3 protocol structure"""
        security_model = self.config.get_option("security_model", 3)
        security_level = self.config.get_option("security_level", 1)
        username = self.config.get_option("username", "testuser")
        context_name = self.config.get_option("context_name", "")
        engine_id = self.config.get_option("engine_id", "8000000001020304")
        enable_set = self.config.get_option("enable_set", False)

        # SNMPv3 Discovery Request
        discovery_request = Request(
            "SNMPv3_Discovery",
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
                                # Version (INTEGER 3 for v3)
                                Static("Version_Tag", b"\x02\x01\x03"),
                                # Global Data
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        # Message ID
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x12345678, endian=">", fuzzable=True),
                                        # Max Size
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        # Message Flags
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x04, fuzzable=True),  # Reportable
                                        # Security Model
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                # Security Parameters (USM)
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                # Authoritative Engine ID (empty for discovery)
                                                Static("EngineID_Tag", b"\x04\x00"),
                                                # Authoritative Engine Boots
                                                Static("EngineBoots_Tag", b"\x02\x01\x00"),
                                                # Authoritative Engine Time
                                                Static("EngineTime_Tag", b"\x02\x01\x00"),
                                                # User Name (empty for discovery)
                                                Static("UserName_Tag", b"\x04\x00"),
                                                # Authentication Parameters
                                                Static("AuthParams_Tag", b"\x04\x00"),
                                                # Privacy Parameters
                                                Static("PrivParams_Tag", b"\x04\x00"),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU Data (encrypted in real implementation)
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        # Context Engine ID
                                        Static("ContextEngineID_Tag", b"\x04\x00"),
                                        # Context Name
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # GetRequest PDU
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
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord("RequestID", 1, endian=">", fuzzable=True),
                                                Static("ErrorStatus", b"\x02\x01\x00"),
                                                Static("ErrorIndex", b"\x02\x01\x00"),
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
                                                                # _encode_oid emits the full
                                                                # OBJECT IDENTIFIER TLV
                                                                # (06 <len> <body>), so no outer
                                                                # tag/length wrapper here.
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1.1.0"
                                                                    ),
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
                ),
            ),
        )

        # SNMPv3 Authenticated Request
        auth_request = Request(
            "SNMPv3_Authenticated",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                # Global Data with authentication
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x87654321, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        # Message Flags with auth
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte(
                                            "MsgFlags",
                                            0x05 if security_level >= 2 else 0x04,
                                            fuzzable=True,
                                        ),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                # USM Security Parameters with credentials
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                # Authoritative Engine ID
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                # Engine Boots
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=True),
                                                # Engine Time
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=True
                                                ),
                                                # User Name
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value",
                                                    username,
                                                    fuzzable=True,
                                                    context=StringContext.CREDENTIAL,
                                                ),
                                                # Authentication Parameters (HMAC-SHA1/MD5)
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "AuthParams_Value",
                                                    b"\x00" * 12,
                                                    max_len=20,
                                                    fuzzable=True,
                                                ),
                                                # Privacy Parameters (DES/AES)
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "PrivParams_Value",
                                                    b"\x00" * 8,
                                                    max_len=16,
                                                    fuzzable=True,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU (would be encrypted with authPriv)
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # GetBulkRequest for SNMPv3
                                        Static("PDU_Tag", b"\xa5"),
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
                                                DWord("RequestID", 100, endian=">", fuzzable=True),
                                                Static("NonRepeaters_Tag", b"\x02\x01"),
                                                Byte("NonRepeaters", 0, fuzzable=True),
                                                Static("MaxRepetitions_Tag", b"\x02\x01"),
                                                Byte("MaxRepetitions", 20, fuzzable=True),
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
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1"
                                                                    ),
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
                ),
            ),
        )

        # SNMPv3 GetNextRequest - walks MIB tree with v3 auth
        get_next_request = Request(
            "SNMPv3_GetNextRequest",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                # Global Data
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x11111111, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte(
                                            "MsgFlags",
                                            0x05 if security_level >= 2 else 0x04,
                                            fuzzable=True,
                                        ),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                # USM Security Parameters
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=True),
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=True
                                                ),
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value",
                                                    username,
                                                    fuzzable=True,
                                                    context=StringContext.CREDENTIAL,
                                                ),
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "AuthParams_Value",
                                                    b"\x00" * 12,
                                                    max_len=20,
                                                    fuzzable=True,
                                                ),
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "PrivParams_Value",
                                                    b"\x00" * 8,
                                                    max_len=16,
                                                    fuzzable=True,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU with GetNextRequest
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # GetNextRequest PDU (0xA1)
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
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord("RequestID", 200, endian=">", fuzzable=True),
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
                                                                # Walk from sysDescr
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1.1.0"
                                                                    ),
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
                ),
            ),
        )

        # SNMPv3 SetRequest - writes values with v3 auth (gated by enable_set)
        if enable_set:
            set_request = Request(
                "SNMPv3_SetRequest",
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
                                    Static("Version_Tag", b"\x02\x01\x03"),
                                    Static("GlobalData_Tag", b"\x30"),
                                    Size(
                                        "GlobalData_Length",
                                        "GlobalData_Content",
                                        endian=">",
                                        output_format="binary",
                                        length=1,
                                        fuzzable=False,
                                    ),
                                    Block(
                                        "GlobalData_Content",
                                        children=(
                                            Static("MessageID_Tag", b"\x02\x04"),
                                            DWord(
                                                "MessageID",
                                                0x22222222,
                                                endian=">",
                                                fuzzable=True,
                                            ),
                                            Static("MaxSize_Tag", b"\x02\x03"),
                                            Byte("MaxSize_Prefix", 0x00),
                                            Word("MaxSize", 65535, endian=">", fuzzable=True),
                                            Static("MsgFlags_Tag", b"\x04\x01"),
                                            # Set requests need auth+reportable (0x05)
                                            Byte(
                                                "MsgFlags",
                                                0x05 if security_level >= 2 else 0x04,
                                                fuzzable=True,
                                            ),
                                            Static("SecurityModel_Tag", b"\x02\x01"),
                                            Byte("SecurityModel", security_model, fuzzable=True),
                                        ),
                                    ),
                                    # USM Security Parameters
                                    Static("SecurityParams_Tag", b"\x04"),
                                    Size(
                                        "SecurityParams_Length",
                                        "SecurityParams_Content",
                                        endian=">",
                                        output_format="binary",
                                        length=1,
                                        fuzzable=False,
                                    ),
                                    Block(
                                        "SecurityParams_Content",
                                        children=(
                                            Static("USM_Sequence_Tag", b"\x30"),
                                            Size(
                                                "USM_Length",
                                                "USM_Content",
                                                endian=">",
                                                output_format="binary",
                                                length=1,
                                                fuzzable=False,
                                            ),
                                            Block(
                                                "USM_Content",
                                                children=(
                                                    Static("EngineID_Tag", b"\x04"),
                                                    Size(
                                                        "EngineID_Length",
                                                        "EngineID_Value",
                                                        endian=">",
                                                        output_format="binary",
                                                        length=1,
                                                        fuzzable=False,
                                                    ),
                                                    SmartBytes(
                                                        "EngineID_Value",
                                                        self._hex_to_bytes(engine_id),
                                                        fuzzable=True,
                                                    ),
                                                    Static("EngineBoots_Tag", b"\x02\x04"),
                                                    DWord(
                                                        "EngineBoots",
                                                        1,
                                                        endian=">",
                                                        fuzzable=True,
                                                    ),
                                                    Static("EngineTime_Tag", b"\x02\x04"),
                                                    DWord(
                                                        "EngineTime",
                                                        12345,
                                                        endian=">",
                                                        fuzzable=True,
                                                    ),
                                                    Static("UserName_Tag", b"\x04"),
                                                    Size(
                                                        "UserName_Length",
                                                        "UserName_Value",
                                                        endian=">",
                                                        output_format="binary",
                                                        length=1,
                                                        fuzzable=False,
                                                    ),
                                                    SmartString(
                                                        "UserName_Value",
                                                        username,
                                                        fuzzable=True,
                                                        context=StringContext.CREDENTIAL,
                                                    ),
                                                    Static("AuthParams_Tag", b"\x04"),
                                                    Size(
                                                        "AuthParams_Length",
                                                        "AuthParams_Value",
                                                        endian=">",
                                                        output_format="binary",
                                                        length=1,
                                                        fuzzable=False,
                                                    ),
                                                    SmartBytes(
                                                        "AuthParams_Value",
                                                        b"\x00" * 12,
                                                        max_len=20,
                                                        fuzzable=True,
                                                    ),
                                                    Static("PrivParams_Tag", b"\x04"),
                                                    Size(
                                                        "PrivParams_Length",
                                                        "PrivParams_Value",
                                                        endian=">",
                                                        output_format="binary",
                                                        length=1,
                                                        fuzzable=False,
                                                    ),
                                                    SmartBytes(
                                                        "PrivParams_Value",
                                                        b"\x00" * 8,
                                                        max_len=16,
                                                        fuzzable=True,
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                    # Scoped PDU with SetRequest
                                    Static("ScopedPDU_Tag", b"\x30"),
                                    Size(
                                        "ScopedPDU_Length",
                                        "ScopedPDU_Content",
                                        endian=">",
                                        output_format="binary",
                                        length=1,
                                        fuzzable=False,
                                    ),
                                    Block(
                                        "ScopedPDU_Content",
                                        children=(
                                            Static("ContextEngineID_Tag", b"\x04"),
                                            Size(
                                                "ContextEngineID_Length",
                                                "ContextEngineID_Value",
                                                endian=">",
                                                output_format="binary",
                                                length=1,
                                                fuzzable=False,
                                            ),
                                            SmartBytes(
                                                "ContextEngineID_Value",
                                                self._hex_to_bytes(engine_id),
                                                fuzzable=True,
                                            ),
                                            Static("ContextName_Tag", b"\x04"),
                                            Size(
                                                "ContextName_Length",
                                                "ContextName_Value",
                                                endian=">",
                                                output_format="binary",
                                                length=1,
                                                fuzzable=False,
                                            ),
                                            SmartString(
                                                "ContextName_Value",
                                                context_name,
                                                fuzzable=True,
                                            ),
                                            # SetRequest PDU (0xA3) - CVE-2018-18065, CVE-2022-44792
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
                                                    Static("RequestID_Tag", b"\x02\x04"),
                                                    DWord(
                                                        "RequestID",
                                                        300,
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
                                                                    # sysContact.0 - commonly writable
                                                                    SmartBytes(
                                                                        "OID1_Value",
                                                                        self._encode_oid(
                                                                            "1.3.6.1.2.1.1.4.0"
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
                                                                        "TestContact",
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
                    ),
                ),
            )

        # SNMPv3 Malformed Security Parameters
        malformed_snmpv3 = Request(
            "SNMPv3_Malformed",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                # Malformed Global Data
                                Static("GlobalData_Tag", b"\x30"),
                                Word(
                                    "Invalid_GlobalData_Length", 0xFFFF, endian=">", fuzzable=True
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        # Invalid Message ID
                                        Static("MessageID_Tag", b"\x02\x08"),
                                        QWord(
                                            "Invalid_MessageID",
                                            0xFFFFFFFFFFFFFFFF,
                                            endian=">",
                                            fuzzable=True,
                                        ),
                                        # Invalid Max Size
                                        Static("MaxSize_Tag", b"\x02\x05"),
                                        Byte("MaxSize_Prefix", 0xFF),
                                        DWord(
                                            "Invalid_MaxSize", 0xFFFFFFFF, endian=">", fuzzable=True
                                        ),
                                        # Invalid Message Flags
                                        Static("MsgFlags_Tag", b"\x04\x04"),
                                        DWord(
                                            "Invalid_MsgFlags",
                                            0xFFFFFFFF,
                                            endian=">",
                                            fuzzable=True,
                                        ),
                                        # Invalid Security Model
                                        Static("SecurityModel_Tag", b"\x02\x02"),
                                        Word(
                                            "Invalid_SecurityModel",
                                            0xFFFF,
                                            endian=">",
                                            fuzzable=True,
                                        ),
                                    ),
                                ),
                                # Malformed Security Parameters
                                Static("SecurityParams_Tag", b"\x04"),
                                Word(
                                    "Invalid_SecurityParams_Length",
                                    20000,
                                    endian=">",
                                    fuzzable=True,
                                ),
                                SmartString(
                                    "Invalid_SecurityParams",
                                    "security-params",
                                    max_len=25000,
                                    fuzzable=True,
                                ),
                                # Invalid Scoped PDU
                                Static("ScopedPDU_Tag", b"\x04"),  # Wrong tag
                                Word("Invalid_ScopedPDU_Length", 30000, endian=">", fuzzable=True),
                                SmartString(
                                    "Invalid_ScopedPDU", "scoped-pdu", max_len=35000, fuzzable=True
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # SNMPv3 Report PDU - tests engine's report handling
        # Report PDUs (0xA8) are normally sent by engines to report errors.
        # Sending crafted reports can confuse state machines or cause DoS.
        report_request = Request(
            "SNMPv3_Report",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x33333333, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        # Reportable flag set
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x04, fuzzable=True),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                # USM with spoofed engine ID
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=True),
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=True
                                                ),
                                                # Empty username (reports don't need auth)
                                                Static("UserName_Tag", b"\x04\x00"),
                                                Static("AuthParams_Tag", b"\x04\x00"),
                                                Static("PrivParams_Tag", b"\x04\x00"),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU with Report PDU
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # Report PDU (0xA8)
                                        Static("PDU_Tag", b"\xa8"),
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
                                                DWord("RequestID", 400, endian=">", fuzzable=True),
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
                                                                # usmStatsUnknownEngineIDs
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.6.3.15.1.1.4.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                # Counter32 value
                                                                Static("Value1_Tag", b"\x41\x04"),
                                                                DWord(
                                                                    "Value1_Counter",
                                                                    1,
                                                                    endian=">",
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
                ),
            ),
        )

        # SNMPv3 Timing Attack - manipulates engine boots/time for replay attacks
        # RFC 3414 defines a 150-second time window for message acceptance.
        # Fuzzing these values tests replay protection robustness.
        timing_attack = Request(
            "SNMPv3_TimingAttack",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x44444444, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        # Auth + Reportable flags
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x05, fuzzable=True),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                # USM with manipulated timing values
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                # Engine Boots - fuzz with boundary values
                                                # RFC 3414: 0 to 2147483647, wraps at max
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineBoots",
                                                    0x7FFFFFFF,
                                                    endian=">",
                                                    fuzzable=True,
                                                ),
                                                # Engine Time - fuzz with extreme values
                                                # RFC 3414: 0 to 2147483647, 150-sec window
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime",
                                                    0x7FFFFFFF,
                                                    endian=">",
                                                    fuzzable=True,
                                                ),
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value",
                                                    username,
                                                    fuzzable=True,
                                                    context=StringContext.CREDENTIAL,
                                                ),
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "AuthParams_Value",
                                                    b"\x00" * 12,
                                                    max_len=20,
                                                    fuzzable=True,
                                                ),
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "PrivParams_Value",
                                                    b"\x00" * 8,
                                                    max_len=16,
                                                    fuzzable=True,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU with GetRequest
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # GetRequest PDU
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
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord("RequestID", 500, endian=">", fuzzable=True),
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
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1.1.0"
                                                                    ),
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
                ),
            ),
        )

        # SNMPv3 Boundary Value Testing - message ID, max-size, flags, security model
        # Tests integer edge cases that may trigger signed/unsigned confusion or overflow
        boundary_request = Request(
            "SNMPv3_Boundary",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        # Message ID at max 32-bit boundary
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord(
                                            "MessageID",
                                            0xFFFFFFFF,
                                            endian=">",
                                            fuzzable=True,
                                        ),
                                        # Max Size at zero (minimum boundary)
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 0, endian=">", fuzzable=True),
                                        # All message flags set (0xFF)
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0xFF, fuzzable=True),
                                        # Security Model at max byte boundary
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", 0xFF, fuzzable=True),
                                    ),
                                ),
                                # USM with boundary engine boots/time
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                # Engine Boots at max 32-bit
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineBoots",
                                                    0xFFFFFFFF,
                                                    endian=">",
                                                    fuzzable=True,
                                                ),
                                                # Engine Time at max 32-bit
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime",
                                                    0xFFFFFFFF,
                                                    endian=">",
                                                    fuzzable=True,
                                                ),
                                                # Empty username
                                                Static("UserName_Tag", b"\x04\x00"),
                                                Static("AuthParams_Tag", b"\x04\x00"),
                                                Static("PrivParams_Tag", b"\x04\x00"),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU with GetRequest
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04\x00"),
                                        Static("ContextName_Tag", b"\x04\x00"),
                                        # GetRequest PDU
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
                                                # Request ID at max boundary
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord(
                                                    "RequestID",
                                                    0xFFFFFFFF,
                                                    endian=">",
                                                    fuzzable=True,
                                                ),
                                                # Error status at max byte
                                                Static("ErrorStatus_Tag", b"\x02\x01"),
                                                Byte("ErrorStatus", 0xFF, fuzzable=True),
                                                # Error index at max byte
                                                Static("ErrorIndex_Tag", b"\x02\x01"),
                                                Byte("ErrorIndex", 0xFF, fuzzable=True),
                                                # Empty var bindings
                                                Static("VarBindings", b"\x30\x00"),
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

        # SNMPv3 USM Authentication/Privacy Parameter Fuzzing
        # ref/snmp/cve_patterns.json#snmpv3-usm-auth-params (CVE-2018-18066 class).
        # The 12-byte AuthenticationParameters and 8-byte PrivacyParameters
        # fields are normally derived from the user password (treated as static
        # post key-derivation in the other v3 requests above). This request
        # mutates them independently as Group() values to exercise HMAC-length
        # validation paths that crash on wrong-size auth digests.
        usm_auth_fuzz = Request(
            "SNMPv3_USMAuthFuzz",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x55555555, endian=">", fuzzable=False),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=False),
                                        # authPriv flags (0x07 = auth+priv+reportable)
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x07, fuzzable=False),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", 3, fuzzable=False),
                                    ),
                                ),
                                # USM Security Parameters - AuthParams/PrivParams
                                # mutated as Group() values
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=False,
                                                ),
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=False),
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=False
                                                ),
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value", username, fuzzable=False
                                                ),
                                                # AuthenticationParameters - 12-byte HMAC
                                                # truncation set per CVE-2018-18066 pattern
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Group(
                                                    "AuthParams_Value",
                                                    values=[
                                                        # Empty (no auth)
                                                        b"",
                                                        # Single byte (truncated)
                                                        b"\x00",
                                                        # Canonical 12-byte HMAC (zeros)
                                                        b"\x00" * 12,
                                                        # 14-byte overlong (per cve_patterns.json)
                                                        b"\xff" * 14,
                                                        # 20-byte full HMAC-SHA1 (RFC 3414 limit)
                                                        b"\xaa" * 20,
                                                        # Oversized to test bounds
                                                        b"A" * 64,
                                                    ],
                                                ),
                                                # PrivacyParameters - 8-byte DES/AES IV salt
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Group(
                                                    "PrivParams_Value",
                                                    values=[
                                                        # Empty
                                                        b"",
                                                        # Single byte
                                                        b"\x00",
                                                        # Canonical 8-byte (zeros)
                                                        b"\x00" * 8,
                                                        # 8-byte all-FF
                                                        b"\xff" * 8,
                                                        # 16-byte (AES-128 IV)
                                                        b"\xaa" * 16,
                                                        # Oversized
                                                        b"B" * 64,
                                                    ],
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                # Minimal Scoped PDU (encrypted in real authPriv,
                                # but kept plaintext here so the agent reaches USM
                                # validation before complaining about decryption)
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=False,
                                        ),
                                        Static("ContextName_Tag", b"\x04\x00"),
                                        # GetRequest PDU
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
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord("RequestID", 600, endian=">", fuzzable=False),
                                                Static("ErrorStatus", b"\x02\x01\x00"),
                                                Static("ErrorIndex", b"\x02\x01\x00"),
                                                Static("VarBindings", b"\x30\x00"),
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

        # SNMPv3 GetBulkRequest - dedicated 0xA5 PDU instance (distinct from
        # auth_request which embeds GetBulk in the baseline-auth path).
        # Audit S8: missing PDU type enumeration.
        get_bulk_request = Request(
            "SNMPv3_GetBulkRequest",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x66666666, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte(
                                            "MsgFlags",
                                            0x05 if security_level >= 2 else 0x04,
                                            fuzzable=True,
                                        ),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=True),
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=True
                                                ),
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value",
                                                    username,
                                                    fuzzable=True,
                                                    context=StringContext.CREDENTIAL,
                                                ),
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "AuthParams_Value",
                                                    b"\x00" * 12,
                                                    max_len=20,
                                                    fuzzable=True,
                                                ),
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "PrivParams_Value",
                                                    b"\x00" * 8,
                                                    max_len=16,
                                                    fuzzable=True,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                # Scoped PDU with GetBulkRequest
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # GetBulkRequest PDU (0xA5)
                                        Static("PDU_Tag", b"\xa5"),
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
                                                DWord("RequestID", 700, endian=">", fuzzable=True),
                                                # non-repeaters
                                                Static("NonRepeaters_Tag", b"\x02\x01"),
                                                Byte("NonRepeaters", 0, fuzzable=True),
                                                # max-repetitions
                                                Static("MaxRepetitions_Tag", b"\x02\x01"),
                                                Byte("MaxRepetitions", 20, fuzzable=True),
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
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1"
                                                                    ),
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
                ),
            ),
        )

        # SNMPv3 InformRequest - acknowledged trap variant (PDU tag 0xA6).
        # Audit S8: missing PDU type enumeration.
        inform_request = Request(
            "SNMPv3_InformRequest",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x77777777, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte(
                                            "MsgFlags",
                                            0x05 if security_level >= 2 else 0x04,
                                            fuzzable=True,
                                        ),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=True),
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=True
                                                ),
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value",
                                                    username,
                                                    fuzzable=True,
                                                    context=StringContext.CREDENTIAL,
                                                ),
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "AuthParams_Value",
                                                    b"\x00" * 12,
                                                    max_len=20,
                                                    fuzzable=True,
                                                ),
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "PrivParams_Value",
                                                    b"\x00" * 8,
                                                    max_len=16,
                                                    fuzzable=True,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # InformRequest PDU (0xA6)
                                        Static("PDU_Tag", b"\xa6"),
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
                                                DWord("RequestID", 800, endian=">", fuzzable=True),
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
                                                        # sysUpTime.0 (TimeTicks)
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
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1.3.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                Static("Value1_Tag", b"\x43\x04"),
                                                                DWord(
                                                                    "Value1_Data",
                                                                    12345,
                                                                    endian=">",
                                                                    fuzzable=True,
                                                                ),
                                                            ),
                                                        ),
                                                        # snmpTrapOID.0
                                                        Static("VarBind2_Tag", b"\x30"),
                                                        Size(
                                                            "VarBind2_Length",
                                                            "VarBind2_Content",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        Block(
                                                            "VarBind2_Content",
                                                            children=(
                                                                SmartBytes(
                                                                    "OID2_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.6.3.1.1.4.1.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                SmartBytes(
                                                                    "Value2_Data",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.4.1.0.1"
                                                                    ),
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
                ),
            ),
        )

        # SNMPv3 Trap - SNMPv2-Trap PDU (0xA7) wrapped in v3 USM framing.
        # Audit S8: missing PDU type enumeration. Traps are unsolicited and
        # commonly exercise different parser paths than request PDUs.
        trap_v3 = Request(
            "SNMPv3_Trap",
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
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x88888888, endian=">", fuzzable=True),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=True),
                                        # Traps are not reportable
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte(
                                            "MsgFlags",
                                            0x01 if security_level >= 2 else 0x00,
                                            fuzzable=True,
                                        ),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=True),
                                    ),
                                ),
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04"),
                                                Size(
                                                    "EngineID_Length",
                                                    "EngineID_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "EngineID_Value",
                                                    self._hex_to_bytes(engine_id),
                                                    fuzzable=True,
                                                ),
                                                Static("EngineBoots_Tag", b"\x02\x04"),
                                                DWord("EngineBoots", 1, endian=">", fuzzable=True),
                                                Static("EngineTime_Tag", b"\x02\x04"),
                                                DWord(
                                                    "EngineTime", 12345, endian=">", fuzzable=True
                                                ),
                                                Static("UserName_Tag", b"\x04"),
                                                Size(
                                                    "UserName_Length",
                                                    "UserName_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartString(
                                                    "UserName_Value",
                                                    username,
                                                    fuzzable=True,
                                                    context=StringContext.CREDENTIAL,
                                                ),
                                                Static("AuthParams_Tag", b"\x04"),
                                                Size(
                                                    "AuthParams_Length",
                                                    "AuthParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "AuthParams_Value",
                                                    b"\x00" * 12,
                                                    max_len=20,
                                                    fuzzable=True,
                                                ),
                                                Static("PrivParams_Tag", b"\x04"),
                                                Size(
                                                    "PrivParams_Length",
                                                    "PrivParams_Value",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                SmartBytes(
                                                    "PrivParams_Value",
                                                    b"\x00" * 8,
                                                    max_len=16,
                                                    fuzzable=True,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04"),
                                        Size(
                                            "ContextEngineID_Length",
                                            "ContextEngineID_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartBytes(
                                            "ContextEngineID_Value",
                                            self._hex_to_bytes(engine_id),
                                            fuzzable=True,
                                        ),
                                        Static("ContextName_Tag", b"\x04"),
                                        Size(
                                            "ContextName_Length",
                                            "ContextName_Value",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        SmartString(
                                            "ContextName_Value", context_name, fuzzable=True
                                        ),
                                        # SNMPv2-Trap PDU (0xA7)
                                        Static("PDU_Tag", b"\xa7"),
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
                                                DWord("RequestID", 900, endian=">", fuzzable=True),
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
                                                        # sysUpTime.0 (TimeTicks)
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
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.2.1.1.3.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                Static("Value1_Tag", b"\x43\x04"),
                                                                DWord(
                                                                    "Value1_Data",
                                                                    54321,
                                                                    endian=">",
                                                                    fuzzable=True,
                                                                ),
                                                            ),
                                                        ),
                                                        # snmpTrapOID.0
                                                        Static("VarBind2_Tag", b"\x30"),
                                                        Size(
                                                            "VarBind2_Length",
                                                            "VarBind2_Content",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        Block(
                                                            "VarBind2_Content",
                                                            children=(
                                                                SmartBytes(
                                                                    "OID2_Value",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.6.3.1.1.4.1.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                SmartBytes(
                                                                    "Value2_Data",
                                                                    self._encode_oid(
                                                                        "1.3.6.1.4.1.0.2"
                                                                    ),
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
                ),
            ),
        )

        # BER length-of-length mutation: malformed long-form / indefinite length
        # octets on the inner scoped-PDU TLVs (context name OCTET STRING, varbind
        # OID, varbind value). Wrapped in noAuthNoPriv discovery framing so the
        # engine reaches scoped-PDU BER parsing without an auth gate. The definite-
        # form Size fields auto-compute these octets everywhere else, so the length-
        # of-length machinery is otherwise never fuzzed -- the parse path behind
        # CVE-2019-9162 (net-snmp), CVE-2020-14934 (Contiki-NG), CVE-2015-5621
        # (net-snmp) and CVE-2022-24805 (kernel BER decoder).
        ber_length_of_length = Request(
            "SNMPv3_BER_LengthOfLength",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize("Message_Length", "SNMP_Content", fuzzable=False),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0x99999999, endian=">", fuzzable=False),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=False),
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x04, fuzzable=False),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=False),
                                    ),
                                ),
                                # Empty USM (discovery / noAuthNoPriv)
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04\x00"),
                                                Static("EngineBoots_Tag", b"\x02\x01\x00"),
                                                Static("EngineTime_Tag", b"\x02\x01\x00"),
                                                Static("UserName_Tag", b"\x04\x00"),
                                                Static("AuthParams_Tag", b"\x04\x00"),
                                                Static("PrivParams_Tag", b"\x04\x00"),
                                            ),
                                        ),
                                    ),
                                ),
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04\x00"),
                                        # Context name OCTET STRING with malformed
                                        # length-of-length
                                        Static("ContextName_Tag", b"\x04"),
                                        Group(
                                            "ContextName_LoL",
                                            values=ber_length_group_values(len(context_name)),
                                        ),
                                        SmartBytes(
                                            "ContextName_Value",
                                            context_name.encode("latin-1"),
                                            fuzzable=True,
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
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord("RequestID", 1000, endian=">", fuzzable=True),
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
                                                                # OID with malformed
                                                                # length-of-length
                                                                Static("OID1_Tag", b"\x06"),
                                                                Group(
                                                                    "OID1_LoL",
                                                                    values=ber_length_group_values(
                                                                        len(
                                                                            oid_content(
                                                                                "1.3.6.1.2.1.1.1.0"
                                                                            )
                                                                        )
                                                                    ),
                                                                ),
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    oid_content(
                                                                        "1.3.6.1.2.1.1.1.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                # Value OCTET STRING with
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
                ),
            ),
        )

        # BER truncated length: inner scoped-PDU definite-form lengths declared
        # shorter than the content that actually follows (declared < actual).
        ber_truncated_length = Request(
            "SNMPv3_BER_Truncated_Length",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize("Message_Length", "SNMP_Content", fuzzable=False),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0xAAAAAAAA, endian=">", fuzzable=False),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00),
                                        Word("MaxSize", 65535, endian=">", fuzzable=False),
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x04, fuzzable=False),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=False),
                                    ),
                                ),
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04\x00"),
                                                Static("EngineBoots_Tag", b"\x02\x01\x00"),
                                                Static("EngineTime_Tag", b"\x02\x01\x00"),
                                                Static("UserName_Tag", b"\x04\x00"),
                                                Static("AuthParams_Tag", b"\x04\x00"),
                                                Static("PrivParams_Tag", b"\x04\x00"),
                                            ),
                                        ),
                                    ),
                                ),
                                Static("ScopedPDU_Tag", b"\x30"),
                                Size(
                                    "ScopedPDU_Length",
                                    "ScopedPDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04\x00"),
                                        # Context name declares 2 bytes but carries more
                                        Static("ContextName_Tag", b"\x04"),
                                        Static("ContextName_TruncLen", b"\x02"),
                                        SmartBytes(
                                            "ContextName_Value", b"ctx-overflow", fuzzable=True
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
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord("RequestID", 1001, endian=">", fuzzable=True),
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
                                                                # OID declares 2 bytes but
                                                                # carries full body
                                                                Static("OID1_Tag", b"\x06"),
                                                                Static("OID1_TruncLen", b"\x02"),
                                                                SmartBytes(
                                                                    "OID1_Value",
                                                                    oid_content(
                                                                        "1.3.6.1.2.1.1.1.0"
                                                                    ),
                                                                    fuzzable=True,
                                                                ),
                                                                # Value declares 1 byte but
                                                                # carries more
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
                ),
            ),
        )

        # Structured BER codec attacks on a scoped-PDU varbind. Wrapped in
        # noAuthNoPriv discovery framing (empty USM) so the engine reaches
        # scoped-PDU BER parsing without an auth gate. The previously dead
        # ASN1Builder mutators (tag confusion / over-declared length / overflow /
        # deep nesting) are spliced in as a Group where the varbind TLV goes;
        # the scoped-PDU / PDU / varbindings lengths are auto-computed BERSize
        # so the outer framing stays valid up to the malformed varbind.
        ber_structured = Request(
            "SNMPv3_BER_Structured",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        BERSize("Message_Length", "SNMP_Content", fuzzable=False),
                        Block(
                            "SNMP_Content",
                            children=(
                                Static("Version_Tag", b"\x02\x01\x03"),
                                Static("GlobalData_Tag", b"\x30"),
                                Size(
                                    "GlobalData_Length",
                                    "GlobalData_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "GlobalData_Content",
                                    children=(
                                        Static("MessageID_Tag", b"\x02\x04"),
                                        DWord("MessageID", 0xBBBBBBBB, endian=">", fuzzable=False),
                                        Static("MaxSize_Tag", b"\x02\x03"),
                                        Byte("MaxSize_Prefix", 0x00, fuzzable=False),
                                        Word("MaxSize", 65535, endian=">", fuzzable=False),
                                        Static("MsgFlags_Tag", b"\x04\x01"),
                                        Byte("MsgFlags", 0x04, fuzzable=False),
                                        Static("SecurityModel_Tag", b"\x02\x01"),
                                        Byte("SecurityModel", security_model, fuzzable=False),
                                    ),
                                ),
                                # Empty USM (discovery / noAuthNoPriv)
                                Static("SecurityParams_Tag", b"\x04"),
                                Size(
                                    "SecurityParams_Length",
                                    "SecurityParams_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "SecurityParams_Content",
                                    children=(
                                        Static("USM_Sequence_Tag", b"\x30"),
                                        Size(
                                            "USM_Length",
                                            "USM_Content",
                                            endian=">",
                                            output_format="binary",
                                            length=1,
                                            fuzzable=False,
                                        ),
                                        Block(
                                            "USM_Content",
                                            children=(
                                                Static("EngineID_Tag", b"\x04\x00"),
                                                Static("EngineBoots_Tag", b"\x02\x01\x00"),
                                                Static("EngineTime_Tag", b"\x02\x01\x00"),
                                                Static("UserName_Tag", b"\x04\x00"),
                                                Static("AuthParams_Tag", b"\x04\x00"),
                                                Static("PrivParams_Tag", b"\x04\x00"),
                                            ),
                                        ),
                                    ),
                                ),
                                Static("ScopedPDU_Tag", b"\x30"),
                                BERSize("ScopedPDU_Length", "ScopedPDU_Content", fuzzable=False),
                                Block(
                                    "ScopedPDU_Content",
                                    children=(
                                        Static("ContextEngineID_Tag", b"\x04\x00"),
                                        Static("ContextName_Tag", b"\x04\x00"),
                                        Static("PDU_Tag", b"\xa0"),
                                        BERSize("PDU_Length", "PDU_Content", fuzzable=False),
                                        Block(
                                            "PDU_Content",
                                            children=(
                                                Static("RequestID_Tag", b"\x02\x04"),
                                                DWord(
                                                    "RequestID", 1002, endian=">", fuzzable=False
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
                                                                "1.3.6.1.2.1.1.1.0"
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
            ),
        )

        # ==================== PHASE 1: BASELINE ====================
        # Engine discovery and authenticated operations for baseline coverage
        if self.is_request_enabled("SNMPv3_Discovery"):
            self.session.connect(discovery_request)
        if self.is_request_enabled("SNMPv3_Authenticated"):
            self.session.connect(auth_request)

        # ==================== PHASE 2: STANDARD OPERATIONS ====================
        # Additional PDU types (GetNext, GetBulk, Inform, Set)
        if self.is_request_enabled("SNMPv3_GetNextRequest"):
            self.session.connect(get_next_request)
        if self.is_request_enabled("SNMPv3_GetBulkRequest"):
            self.session.connect(get_bulk_request)
        if self.is_request_enabled("SNMPv3_InformRequest"):
            self.session.connect(inform_request)
        if enable_set and self.is_request_enabled("SNMPv3_SetRequest"):
            self.session.connect(set_request)

        # ==================== PHASE 3: ATTACKS ====================
        # Malformed packets and report PDU injection (high crash likelihood)
        if self.is_request_enabled("SNMPv3_Malformed"):
            self.session.connect(malformed_snmpv3)
        if self.is_request_enabled("SNMPv3_Report"):
            self.session.connect(report_request)

        # ==================== PHASE 4: USM TIMING/REPLAY ====================
        # Engine boots/time manipulation to test replay protection;
        # explicit USM AuthParams/PrivParams Group mutation (CVE-2018-18066).
        if self.is_request_enabled("SNMPv3_TimingAttack"):
            self.session.connect(timing_attack)
        if self.is_request_enabled("SNMPv3_USMAuthFuzz"):
            self.session.connect(usm_auth_fuzz)

        # ==================== PHASE 5: BOUNDARY ====================
        # Boundary value testing for all header fields
        if self.is_request_enabled("SNMPv3_Boundary"):
            self.session.connect(boundary_request)

        # ==================== PHASE 5: TRAP ====================
        # SNMPv2-Trap PDU wrapped in v3 USM framing
        if self.is_request_enabled("SNMPv3_Trap"):
            self.session.connect(trap_v3)

        # ==================== BER LENGTH-OF-LENGTH MUTATION ====================
        # Malformed long-form / indefinite / truncated inner-TLV length octets
        if self.is_request_enabled("SNMPv3_BER_LengthOfLength"):
            self.session.connect(ber_length_of_length)
        if self.is_request_enabled("SNMPv3_BER_Truncated_Length"):
            self.session.connect(ber_truncated_length)
        if self.is_request_enabled("SNMPv3_BER_Structured"):
            self.session.connect(ber_structured)


__all__ = ["SNMPv3Fuzzer"]
