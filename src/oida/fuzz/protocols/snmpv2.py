"""SNMPv2c Protocol Fuzzer with bulk operations support.

Fuzzer Optimization Strategy (Breadth-First):
==============================================
Phase 1 (Baseline): GetBulkRequest - primary v2c operation
Phase 2 (Standard): GetRequest, GetNextRequest, SetRequest, InformRequest
Phase 3 (Boundary): MaxRepExtreme, ZeroVarBinds, integer/community boundary tests
Phase 4 (Overflow): Malformed BER encoding, invalid tags
Phase 5 (Trap): v2c Trap PDU

Walk recursion cap
==================
GetNext-driven walks must be bounded. WALK_MAX_DEPTH (100) caps both:
  - any future runtime GetNext loop (avoids unbounded recursion when an
    agent returns a varbind cycle - see ref/snmp/cve_patterns.json
    pattern id "snmpv2c-walk-recursion"), and
  - the boofuzz Request.walk() tree traversal used by the benchmark
    suite. Empty Block(children=()) nodes were the structural cause of
    the original WALK_XFAIL recursion; the ZeroVarBinds request below
    now encodes the empty VarBindings SEQUENCE as a single Static
    (0x30 0x00) rather than a Block with no children.
"""

# Maximum walk depth (GetNext chain length and Request.walk() tree depth).
# Bounds GetNext-driven recursion per ref/snmp/cve_patterns.json
# pattern "snmpv2c-walk-recursion".
WALK_MAX_DEPTH = 100

from boofuzz import Block, Byte, DWord, Request, Size, Static, Word

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import SocketHealthMonitor
from ..primitives.asn1_blocks import BERSize
from ..primitives.dynamic import SmartBytes, SmartString
from .snmp_common import encode_oid


class SNMPv2cFuzzer(BaseFuzzer):
    """SNMPv2c Protocol Fuzzer with bulk operations support"""

    PROTOCOL_OPTIONS = {
        "community": {
            "type": str,
            "default": "public",
            "description": "SNMP community string",
            "example": "private",
        },
        "request_id": {
            "type": int,
            "default": 1,
            "description": "Request ID for PDUs",
            "example": "12345",
        },
        "enable_set": {
            "type": bool,
            "default": False,
            "description": "Enable SET requests",
            "example": "true",
        },
        "oid_prefix": {
            "type": str,
            "default": "1.3.6.1.2.1",
            "description": "OID prefix for requests",
            "example": "1.3.6.1.4.1",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Baseline
            RequestInfo("SNMPv2c_GetBulkRequest", "GET-BULK request (primary v2c op)", "baseline"),
            # Phase 2: Standard operations
            RequestInfo("SNMPv2c_GetRequest", "GET request (PDU tag 0xA0)", "standard"),
            RequestInfo("SNMPv2c_GetNextRequest", "GET-NEXT request (PDU tag 0xA1)", "standard"),
            RequestInfo(
                "SNMPv2c_SetRequest",
                "SET request (PDU tag 0xA3, requires enable_set)",
                "write",
            ),
            RequestInfo("SNMPv2c_InformRequest", "INFORM request (PDU tag 0xA6)", "standard"),
            # Phase 3: Boundary
            RequestInfo(
                "SNMPv2c_GetBulk_MaxRepExtreme",
                "GetBulk with extreme max-repetitions (0xFFFFFFFF)",
                "boundary",
            ),
            RequestInfo(
                "SNMPv2c_GetBulk_ZeroVarBinds",
                "GetBulk with zero VarBinds edge case",
                "boundary",
            ),
            RequestInfo(
                "SNMPv2c_BoundaryValues",
                "Boundary values for request-id, error-status, error-index",
                "boundary",
            ),
            RequestInfo("SNMPv2c_BoundaryZeroReqID", "Zero request-id edge case", "boundary"),
            RequestInfo(
                "SNMPv2c_BoundaryEmptyCommunity", "Empty community string (0 bytes)", "boundary"
            ),
            # Phase 4: Overflow
            RequestInfo(
                "SNMPv2c_Malformed", "Malformed BER encoding and invalid tags", "high_crash"
            ),
            # Phase 5: Trap
            RequestInfo("SNMPv2c_Trap", "v2c Trap PDU", "trap"),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    def setup_custom_monitors(self):
        """Setup SNMPv2c-specific monitors"""
        return [
            SocketHealthMonitor(
                self.config.target_ip, self.config.target_port or 161, retry_count=3, timeout=2
            )
        ]

    def _encode_oid(self, oid_string):
        """Encode OID string to BER format"""
        return encode_oid(oid_string)

    def _define_protocol(self):
        """Define SNMPv2c protocol structure"""
        community = self.config.get_option("community", "public")
        request_id = self.config.get_option("request_id", 1)
        enable_set = self.config.get_option("enable_set", False)
        oid_prefix = self.config.get_option("oid_prefix", "1.3.6.1.2.1")

        # SNMPv2c GetBulkRequest
        get_bulk_request = Request(
            "SNMPv2c_GetBulkRequest",
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
                                # Version (INTEGER 1 for v2c)
                                Static("Version_Tag", b"\x02\x01\x01"),
                                # Community String
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
                                # PDU (GetBulkRequest = 0xA5)
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
                                        # Request ID
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord("RequestID", request_id, endian=">", fuzzable=True),
                                        # Non-repeaters (INTEGER)
                                        Static("NonRepeaters_Tag", b"\x02\x01"),
                                        Byte("NonRepeaters", 0, fuzzable=True),
                                        # Max-repetitions (INTEGER)
                                        Static("MaxRepetitions_Tag", b"\x02\x01"),
                                        Byte("MaxRepetitions", 10, fuzzable=True),
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
                                                # Multiple Variable Bindings for bulk operation
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
                                                            self._encode_oid(f"{oid_prefix}.1"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value1", b"\x05\x00"),
                                                    ),
                                                ),
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
                                                        Static("OID2_Tag", b"\x06"),
                                                        Size(
                                                            "OID2_Length",
                                                            "OID2_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID2_Value",
                                                            self._encode_oid(f"{oid_prefix}.2"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value2", b"\x05\x00"),
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

        # SNMPv2c GetRequest (PDU tag 0xA0, version=1 for v2c)
        get_request = Request(
            "SNMPv2c_GetRequest",
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
                                # Version (INTEGER 1 for v2c)
                                Static("Version_Tag", b"\x02\x01\x01"),
                                # Community String
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
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
                                        DWord(
                                            "RequestID", request_id + 3, endian=">", fuzzable=True
                                        ),
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

        # SNMPv2c GetNextRequest (PDU tag 0xA1)
        get_next_request = Request(
            "SNMPv2c_GetNextRequest",
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
                                Static("Version_Tag", b"\x02\x01\x01"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
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
                                            "RequestID", request_id + 4, endian=">", fuzzable=True
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

        # SNMPv2c SetRequest (PDU tag 0xA3), gated by enable_set option
        if enable_set:
            set_request = Request(
                "SNMPv2c_SetRequest",
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
                                    Static("Version_Tag", b"\x02\x01\x01"),
                                    Static("Community_Tag", b"\x04"),
                                    Size(
                                        "Community_Length",
                                        "Community_String",
                                        endian=">",
                                        output_format="binary",
                                        length=1,
                                        fuzzable=False,
                                    ),
                                    SmartString("Community_String", community, fuzzable=True),
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
                                                request_id + 5,
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

        # GetBulk extreme max-repetitions (0xFFFFFFFF) - Test integer overflow handling
        get_bulk_maxrep_extreme = Request(
            "SNMPv2c_GetBulk_MaxRepExtreme",
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
                                Static("Version_Tag", b"\x02\x01\x01"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
                                Static("PDU_Tag", b"\xa5"),  # GetBulkRequest
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
                                        Static("NonRepeaters_Tag", b"\x02\x01"),
                                        Byte("NonRepeaters", 0, fuzzable=True),
                                        # Max-repetitions with extreme value (0xFFFFFFFF)
                                        Static("MaxRepetitions_Tag", b"\x02\x04"),
                                        DWord(
                                            "MaxRepetitions", 0xFFFFFFFF, endian=">", fuzzable=True
                                        ),
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
                                                            self._encode_oid(f"{oid_prefix}.1"),
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

        # GetBulk with 0 VarBinds - Edge case testing
        get_bulk_zero_varbinds = Request(
            "SNMPv2c_GetBulk_ZeroVarBinds",
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
                                Static("Version_Tag", b"\x02\x01\x01"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
                                Static("PDU_Tag", b"\xa5"),  # GetBulkRequest
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
                                            "RequestID", request_id + 2, endian=">", fuzzable=True
                                        ),
                                        Static("NonRepeaters_Tag", b"\x02\x01"),
                                        Byte("NonRepeaters", 0, fuzzable=True),
                                        Static("MaxRepetitions_Tag", b"\x02\x01"),
                                        Byte("MaxRepetitions", 10, fuzzable=True),
                                        # Empty VarBindings SEQUENCE (tag 0x30, length 0).
                                        # Encoded as a single Static rather than
                                        # Block(children=()) — the latter triggers
                                        # Request.walk() recursion (WALK_MAX_DEPTH guard).
                                        Static("VarBindings", b"\x30\x00"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # SNMPv2c Boundary value tests for request-id, error-status, error-index, community
        boundary_values = Request(
            "SNMPv2c_BoundaryValues",
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
                                Static("Version_Tag", b"\x02\x01\x01"),
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_Boundary",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                # Community string fuzzable to test 0, 255, 256 byte lengths
                                SmartString(
                                    "Community_Boundary", "A" * 255, max_len=300, fuzzable=True
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
                                        # Fuzz request-id with boundary values (0, 0xFFFFFFFF)
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

        # SNMPv2c Boundary - zero request-id edge case
        boundary_zero_reqid = Request(
            "SNMPv2c_BoundaryZeroReqID",
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
                                Static("Version_Tag", b"\x02\x01\x01"),
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
                                        # Request ID = 0 (boundary)
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord("RequestID", 0, endian=">", fuzzable=True),
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

        # Boundary - empty community string (0 bytes)
        boundary_empty_community = Request(
            "SNMPv2c_BoundaryEmptyCommunity",
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
                                Static("Version_Tag", b"\x02\x01\x01"),
                                # Empty community string (length = 0)
                                Static("Community_Tag", b"\x04"),
                                Static("Community_Length", b"\x00"),
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
                                            "RequestID",
                                            request_id + 50,
                                            endian=">",
                                            fuzzable=True,
                                        ),
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
        )

        # SNMPv2c InformRequest
        inform_request = Request(
            "SNMPv2c_InformRequest",
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
                                Static("Version_Tag", b"\x02\x01\x01"),  # SNMPv2c
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
                                # PDU (InformRequest = 0xA6)
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
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 10, endian=">", fuzzable=True
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
                                                # sysUpTime.0
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
                                                            self._encode_oid("1.3.6.1.2.1.1.3.0"),
                                                            fuzzable=True,
                                                        ),
                                                        # TimeTicks
                                                        Static("Value1_Tag", b"\x43"),
                                                        Size(
                                                            "Value1_Length",
                                                            "Value1_Data",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
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
                                                        Static("OID2_Tag", b"\x06"),
                                                        Size(
                                                            "OID2_Length",
                                                            "OID2_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID2_Value",
                                                            self._encode_oid(
                                                                "1.3.6.1.6.3.1.1.4.1.0"
                                                            ),
                                                            fuzzable=True,
                                                        ),
                                                        # OID value
                                                        Static("Value2_Tag", b"\x06"),
                                                        Size(
                                                            "Value2_Length",
                                                            "Value2_Data",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "Value2_Data",
                                                            self._encode_oid(f"{oid_prefix}.0.1"),
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

        # SNMPv2c Trap (different from v1)
        trap_v2c = Request(
            "SNMPv2c_Trap",
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
                                Static("Version_Tag", b"\x02\x01\x01"),  # SNMPv2c
                                Static("Community_Tag", b"\x04"),
                                Size(
                                    "Community_Length",
                                    "Community_String",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                SmartString("Community_String", community, fuzzable=True),
                                # PDU (SNMPv2-Trap = 0xA7)
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
                                        Static("RequestID_Tag", b"\x02"),
                                        Byte("RequestID_Length", 0x04, fuzzable=False),
                                        DWord(
                                            "RequestID", request_id + 20, endian=">", fuzzable=True
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
                                                # sysUpTime.0
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
                                                            self._encode_oid("1.3.6.1.2.1.1.3.0"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value1_Tag", b"\x43"),
                                                        Size(
                                                            "Value1_Length",
                                                            "Value1_Data",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
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
                                                        Static("OID2_Tag", b"\x06"),
                                                        Size(
                                                            "OID2_Length",
                                                            "OID2_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID2_Value",
                                                            self._encode_oid(
                                                                "1.3.6.1.6.3.1.1.4.1.0"
                                                            ),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value2_Tag", b"\x06"),
                                                        Size(
                                                            "Value2_Length",
                                                            "Value2_Data",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "Value2_Data",
                                                            self._encode_oid(f"{oid_prefix}.0.2"),
                                                            fuzzable=True,
                                                        ),
                                                    ),
                                                ),
                                                # Custom trap data
                                                Static("VarBind3_Tag", b"\x30"),
                                                Size(
                                                    "VarBind3_Length",
                                                    "VarBind3_Content",
                                                    endian=">",
                                                    output_format="binary",
                                                    length=1,
                                                    fuzzable=False,
                                                ),
                                                Block(
                                                    "VarBind3_Content",
                                                    children=(
                                                        Static("OID3_Tag", b"\x06"),
                                                        Size(
                                                            "OID3_Length",
                                                            "OID3_Value",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartBytes(
                                                            "OID3_Value",
                                                            self._encode_oid(f"{oid_prefix}.1.5.0"),
                                                            fuzzable=True,
                                                        ),
                                                        Static("Value3_Tag", b"\x04"),
                                                        Size(
                                                            "Value3_Length",
                                                            "Value3_Data",
                                                            endian=">",
                                                            output_format="binary",
                                                            length=1,
                                                            fuzzable=False,
                                                        ),
                                                        SmartString(
                                                            "Value3_Data",
                                                            "SNMPv2c Trap Data",
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

        # Malformed SNMPv2c with invalid BER encoding
        malformed_snmpv2c = Request(
            "SNMPv2c_Malformed",
            children=(
                Block(
                    "SNMP_Message",
                    children=(
                        Static("Sequence_Tag", b"\x30"),
                        # Invalid length (too large)
                        Word("Invalid_Length", 0xFFFF, endian=">", fuzzable=True),
                        Block(
                            "SNMP_Content",
                            children=(
                                # Invalid version
                                Static("Version_Tag", b"\x02\x01"),
                                Byte("Invalid_Version", 255, fuzzable=True),
                                # Oversized community string
                                Static("Community_Tag", b"\x04"),
                                Word("Oversized_Length", 10000, endian=">", fuzzable=True),
                                SmartString(
                                    "Oversized_Community", "public", max_len=15000, fuzzable=True
                                ),
                                # Invalid PDU tag
                                Byte("Invalid_PDU_Tag", 0xFF, fuzzable=True),
                                Size(
                                    "PDU_Length",
                                    "Invalid_PDU_Content",
                                    endian=">",
                                    output_format="binary",
                                    length=1,
                                    fuzzable=False,
                                ),
                                Block(
                                    "Invalid_PDU_Content",
                                    children=(
                                        SmartString(
                                            "Random_Data",
                                            "snmp-random-data",
                                            max_len=5000,
                                            fuzzable=True,
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
        if self.is_request_enabled("SNMPv2c_Baseline"):
            self.session.connect(get_bulk_request)

        # ==================== PHASE 2: STANDARD OPERATIONS ====================
        if self.is_request_enabled("SNMPv2c_Standard"):
            self.session.connect(get_request)
            self.session.connect(get_next_request)
            if enable_set:
                self.session.connect(set_request)
            self.session.connect(inform_request)

        # ==================== PHASE 3: BOUNDARY TESTS ====================
        if self.is_request_enabled("SNMPv2c_Boundary"):
            self.session.connect(get_bulk_maxrep_extreme)
            self.session.connect(get_bulk_zero_varbinds)
            self.session.connect(boundary_values)
            self.session.connect(boundary_zero_reqid)
            self.session.connect(boundary_empty_community)

        # ==================== PHASE 4: OVERFLOW / MALFORMED ====================
        if self.is_request_enabled("SNMPv2c_Overflow"):
            self.session.connect(malformed_snmpv2c)

        # ==================== PHASE 5: TRAP ====================
        if self.is_request_enabled("SNMPv2c_Trap"):
            self.session.connect(trap_v2c)


__all__ = ["SNMPv2cFuzzer"]
