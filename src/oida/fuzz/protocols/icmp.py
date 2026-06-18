"""ICMP Protocol Fuzzer

Optimized for breadth-first coverage with progressive depth testing.
High-crash tests (overflow, checksum corruption) run early for fast vulnerability detection.

Optimization Phases:
- Phase 1: Quick type sweep (~30 sec) - all 19 ICMP types once
- Phase 2: High-crash tests (~2 min) - oversized payload, checksum attacks
- Phase 3: CVE-targeted operations (~3 min) - redirect spoofing, extension overflows
- Phase 4: Boundary attacks (~3 min) - type/code boundaries, timestamp attacks
- Phase 5: Comprehensive coverage - all code variations, RFC extensions
"""

from typing import List

from boofuzz import Block, Byte, Bytes, Checksum, DWord, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..primitives.dynamic import SmartBytes, SmartString


class ICMPFuzzer(BaseFuzzer):
    """ICMP Protocol Fuzzer for network layer security testing

    Optimized test ordering for maximum early coverage and crash detection:
    1. Quick_ICMP_Type_Coverage - all types in ~30 seconds
    2. High-crash tests (oversized, checksum corruption)
    3. CVE-targeted tests (redirect spoofing, extension overflows)
    4. Boundary attacks
    5. Comprehensive code variations
    """

    PROTOCOL_OPTIONS = {
        "icmp_type": {
            "type": int,
            "default": 8,
            "description": "ICMP type (8=Echo Request, 0=Echo Reply, 3=Dest Unreachable, 42/43=Extended Echo)",
            "choices": [0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 42, 43, 253, 254],
            "example": "3",
        },
        "icmp_code": {
            "type": int,
            "default": 0,
            "description": "ICMP code (varies by type)",
            "example": "1",
        },
        "include_data": {
            "type": bool,
            "default": True,
            "description": "Include data payload",
            "example": "false",
        },
        "data_size": {
            "type": int,
            "default": 56,
            "description": "Size of data payload in bytes",
            "example": "1024",
        },
        "identifier": {
            "type": int,
            "default": 1,
            "description": "ICMP identifier (for Echo)",
            "example": "12345",
        },
        "sequence": {
            "type": int,
            "default": 1,
            "description": "Starting sequence number",
            "example": "100",
        },
    }

    # Use ping monitor for ICMP - TCP socket monitor doesn't make sense for layer 3 protocols
    DEFAULT_MONITORS = "ping"

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "ICMP_Quick_Coverage", "Quick type sweep (19 types) + baseline", "baseline"
            ),
            # Phase 2: High-Crash Tests
            RequestInfo(
                "ICMP_Overflow_Tests", "Oversized payloads (Ping of Death variants)", "high_crash"
            ),
            RequestInfo("ICMP_Checksum_Tests", "Checksum corruption patterns", "high_crash"),
            # Phase 3: CVE-Targeted
            RequestInfo(
                "ICMP_Redirect_Attacks", "Redirect spoofing (Type 5, CVE-2021-28372)", "cve_target"
            ),
            RequestInfo(
                "ICMP_Extension_Attacks",
                "RFC 4884 extension overflow (CVE-2022-23093)",
                "cve_target",
            ),
            # Phase 4: Boundary Tests
            RequestInfo("ICMP_Type_Code_Boundary", "Type/code field boundary attacks", "boundary"),
            RequestInfo("ICMP_Timestamp_Tests", "Timestamp manipulation attacks", "boundary"),
            # Phase 5: Comprehensive
            RequestInfo(
                "ICMP_Dest_Unreachable", "All Type 3 code variations (16 codes)", "comprehensive"
            ),
            RequestInfo("ICMP_Time_Exceeded", "All Type 11 code variations", "comprehensive"),
            RequestInfo("ICMP_Parameter_Problem", "All Type 12 code variations", "comprehensive"),
            RequestInfo(
                "ICMP_Router_Discovery", "Router Advertisement/Solicitation", "comprehensive"
            ),
            RequestInfo(
                "ICMP_Address_Mask", "Address Mask Request/Reply (RFC 950)", "comprehensive"
            ),
            RequestInfo(
                "ICMP_Extended_Echo", "Extended Echo Request/Reply (RFC 8335)", "comprehensive"
            ),
            RequestInfo("ICMP_Experimental", "Experimental types (253, 254)", "comprehensive"),
            RequestInfo("ICMP_Obsolete", "Obsolete types (Info, Source Quench)", "comprehensive"),
        ]

    """
    ICMP (Internet Control Message Protocol) Fuzzer

    Comprehensive ICMPv4 fuzzer with RFC 792, RFC 950, RFC 4884, and RFC 8335 support.

    Supported message types:
    - Type 0/8: Echo Reply/Request (ping)
    - Type 3: Destination Unreachable (all 16 codes: 0-15)
    - Type 4: Source Quench (deprecated)
    - Type 5: Redirect (all 4 codes: 0-3)
    - Type 9/10: Router Advertisement/Solicitation
    - Type 11: Time Exceeded (both codes: 0-1)
    - Type 12: Parameter Problem (all 3 codes: 0-2)
    - Type 13/14: Timestamp Request/Reply
    - Type 15/16: Information Request/Reply (obsolete)
    - Type 17/18: Address Mask Request/Reply (RFC 950)
    - Type 42/43: Extended Echo Request/Reply (RFC 8335)
    - Type 253/254: Experimental types

    Advanced features:
    - RFC 4884 multi-part ICMP extensions for Types 3, 11, 12
    - MPLS Label Stack extension objects
    - Oversized payload fuzzing (up to 65KB)
    - Checksum corruption patterns
    - Path MTU Discovery (Type 3 Code 4)

    Note: Requires root/admin privileges for raw socket access
    """

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # ICMP uses IPPROTO_ICMP socket - kernel handles IP header and checksum
        # This allows us to send just ICMP packets without constructing IP headers
        config.protocol_type = ProtocolType.ICMP
        super().__init__(config, connection_factory)

    def _define_protocol(self):
        """Define ICMP protocol structure with optimized test ordering

        Test execution order is optimized for:
        1. Maximum early coverage - all ICMP types tested in first 30 seconds
        2. High-crash tests early - overflow/checksum attacks in first 2 minutes
        3. CVE-targeted operations - redirect spoofing, extension attacks
        4. Boundary attacks - type/code/timestamp manipulation
        5. Comprehensive coverage - all code variations and RFC extensions
        """
        # Get protocol options
        icmp_type = self.config.get_option("icmp_type", 8)  # Echo Request
        self.config.get_option("icmp_code", 0)
        include_data = self.config.get_option("include_data", True)
        data_size = self.config.get_option("data_size", 56)
        identifier = self.config.get_option("identifier", 1)
        sequence = self.config.get_option("sequence", 1)

        # ================================================================
        # PHASE 1: QUICK TYPE COVERAGE (~30 seconds)
        # Touch all 19 ICMP types once with minimal parameters
        # Goal: Maximum breadth coverage in minimum time
        # ================================================================

        # Quick Type Sweep - all ICMP types in one request
        quick_type_coverage = Request(
            "Quick_ICMP_Type_Coverage",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Group(
                            "Type_Sweep",
                            values=[
                                b"\x00",  # Echo Reply (Type 0)
                                b"\x03",  # Destination Unreachable (Type 3)
                                b"\x04",  # Source Quench (Type 4) - deprecated
                                b"\x05",  # Redirect (Type 5)
                                b"\x08",  # Echo Request (Type 8)
                                b"\x09",  # Router Advertisement (Type 9)
                                b"\x0a",  # Router Solicitation (Type 10)
                                b"\x0b",  # Time Exceeded (Type 11)
                                b"\x0c",  # Parameter Problem (Type 12)
                                b"\x0d",  # Timestamp Request (Type 13)
                                b"\x0e",  # Timestamp Reply (Type 14)
                                b"\x0f",  # Information Request (Type 15) - obsolete
                                b"\x10",  # Information Reply (Type 16) - obsolete
                                b"\x11",  # Address Mask Request (Type 17)
                                b"\x12",  # Address Mask Reply (Type 18)
                                b"\x2a",  # Extended Echo Request (Type 42)
                                b"\x2b",  # Extended Echo Reply (Type 43)
                                b"\xfd",  # Experimental (Type 253)
                                b"\xfe",  # Experimental (Type 254)
                            ],
                        ),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        # Generic 4-byte header field (covers ID/Seq, Unused, Gateway, etc.)
                        Bytes("Header_Rest", b"\x00\x01\x00\x01", size=4, fuzzable=False),
                        Bytes("Payload", b"quick-type-sweep-payload", fuzzable=False),
                    ),
                ),
            ),
        )

        # Baseline Echo Request (simple connectivity test)
        baseline_echo = Request(
            "ICMP_Baseline_Echo",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte(
                            "Type", 8, fuzzable=True
                        ),  # Echo Request - fuzzable to ensure packet sent
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=False),
                        Word("Sequence", sequence, endian=">", fuzzable=False),
                        Bytes("Payload", b"BASELINE", fuzzable=False),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (~2 minutes)
        # Oversized payloads, checksum corruption - CVE triggers
        # ================================================================

        # Oversized payload fuzzing for buffer overflow testing (Ping of Death variants)
        # CVE-related: ping of death, CVE-2020-16898 (Windows ICMP)
        echo_oversized = Request(
            "ICMP_Echo_Oversized_Payload",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 8, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Data",
                    children=(
                        # Max IP packet size is 65535, minus 20 byte IP header, minus 8 byte ICMP header = 65507
                        SmartString("Payload", "icmp-payload", max_len=65507, fuzzable=True),
                    ),
                ),
            ),
        )

        # Oversized payloads with specific size boundaries
        echo_size_boundaries = Request(
            "ICMP_Echo_Size_Boundaries",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 8, fuzzable=False),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=False),
                        Word("Sequence", sequence, endian=">", fuzzable=False),
                        Group(
                            "Size_Boundary_Payloads",
                            values=[
                                b"A" * 56,  # Standard ping size
                                b"A" * 64,  # Common buffer boundary
                                b"A" * 128,  # Power of 2 boundary
                                b"A" * 256,  # Power of 2 boundary
                                b"A" * 512,  # Power of 2 boundary
                                b"A" * 1024,  # 1KB boundary
                                b"A"
                                * 1472,  # MTU - IP header - ICMP header (common fragmentation point)
                                b"A" * 1500,  # Ethernet MTU
                                b"A" * 4096,  # Page size boundary
                                b"A" * 8192,  # Common buffer size
                                b"A" * 16384,  # Large buffer
                                b"A" * 32768,  # 32KB boundary
                                b"A" * 65507,  # Maximum ICMP payload
                            ],
                        ),
                    ),
                ),
            ),
        )

        # Checksum corruption patterns (CVE-2020-25705 rate limiting bypass)
        echo_bad_checksum = Request(
            "ICMP_Echo_Corrupted_Checksum",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 8, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        # Deliberately wrong checksum values
                        Group(
                            "Checksum_Bad",
                            values=[
                                b"\x00\x00",  # Zero
                                b"\xff\xff",  # Max
                                b"\x12\x34",  # Random
                                b"\xde\xad",  # Distinctive pattern
                                b"\xbe\xef",  # Distinctive pattern
                                b"\x80\x00",  # Sign bit
                                b"\x7f\xff",  # Max positive
                                b"\xca\xfe",  # Distinctive pattern
                            ],
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Data",
                    children=(
                        SmartString("Payload", "checksum-test-data", max_len=1024, fuzzable=True),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (~3 minutes)
        # Redirect spoofing, extension header overflows
        # ================================================================

        # Redirect attacks - CVE-2021-28372 pattern (routing table manipulation)
        redirect_spoofing = Request(
            "ICMP_Redirect_Spoofing",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 5, fuzzable=True),
                        Group(
                            "Redirect_Code",
                            values=[
                                b"\x00",  # Redirect for Network
                                b"\x01",  # Redirect for Host
                                b"\x02",  # Redirect for TOS and Network
                                b"\x03",  # Redirect for TOS and Host
                            ],
                        ),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        # Gateway IP address - attacker-controlled
                        Group(
                            "Gateway_IP_Attack",
                            values=[
                                b"\xc0\xa8\x01\x01",  # 192.168.1.1 (common gateway)
                                b"\x0a\x00\x00\x01",  # 10.0.0.1 (private)
                                b"\x7f\x00\x00\x01",  # 127.0.0.1 (loopback - attack vector)
                                b"\x00\x00\x00\x00",  # 0.0.0.0 (null)
                                b"\xff\xff\xff\xff",  # 255.255.255.255 (broadcast)
                                b"\xc0\xa8\xff\xff",  # 192.168.255.255 (broadcast)
                                b"\x08\x08\x08\x08",  # 8.8.8.8 (external - redirect attack)
                            ],
                        ),
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x01\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02",
                            size=20,
                            fuzzable=True,
                        ),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # RFC 4884 Extension overflow - CVE-2022-23093 (FreeBSD ICMP stack overflow)
        dest_unreach_rfc4884 = Request(
            "ICMP_Dest_Unreach_RFC4884_Extensions",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 4, fuzzable=False),  # Fragmentation needed
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        # Length field in 32-bit words, indicating start of extensions
                        Byte("Length", 5, fuzzable=True),  # 5 words = 20 bytes (IP header)
                        SmartBytes("Unused", b"\x00\x00", size=2, fuzzable=False),
                        Word("Next_Hop_MTU", 1500, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
                Block(
                    "RFC4884_Extension_Header",
                    children=(
                        Byte("Version_Reserved", 0x20, fuzzable=True),  # Version 2, reserved bits
                        Byte("Reserved", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Extension_Objects",
                    children=(
                        # MPLS Label Stack Class (Class 1)
                        Word("Length", 8, endian=">", fuzzable=True),
                        Byte("Class_Num", 1, fuzzable=True),
                        Byte("C_Type", 1, fuzzable=True),
                        # MPLS label, exp, S, TTL
                        SmartBytes("MPLS_Stack", b"\x00\x00\x00\x00", size=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # RFC 4884 Extension Header overflow with large extension objects
        rfc4884_extension_overflow = Request(
            "ICMP_RFC4884_Extension_Overflow",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=False),
                        Byte("Code", 4, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Group(
                            "Length_Attack",
                            values=[
                                b"\x00",  # Zero length (underflow)
                                b"\x01",  # Minimum
                                b"\x05",  # Normal (20 bytes)
                                b"\x20",  # 128 bytes
                                b"\x7f",  # 508 bytes (near max)
                                b"\xff",  # Maximum (1020 bytes)
                            ],
                        ),
                        SmartBytes("Unused", b"\x00\x00", size=2, fuzzable=False),
                        Word("Next_Hop_MTU", 1500, endian=">", fuzzable=False),
                        SmartBytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x01\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02",
                            size=20,
                            fuzzable=False,
                        ),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=False),
                        # RFC 4884 Extension Header
                        Byte("Version_Reserved", 0x20, fuzzable=False),
                        Byte("Reserved", 0, fuzzable=False),
                        Word("Ext_Checksum", 0, endian=">", fuzzable=False),
                        # Oversized extension object
                        Group(
                            "Large_Extension",
                            values=[
                                b"\x00\x08\x01\x01" + b"A" * 4,  # Normal 8-byte object
                                b"\x00\x40\x01\x01" + b"A" * 60,  # 64-byte object
                                b"\x01\x00\x01\x01" + b"A" * 252,  # 256-byte object
                                b"\x04\x00\x01\x01" + b"A" * 1020,  # 1024-byte object (overflow)
                            ],
                        ),
                    ),
                ),
            ),
        )

        # Time Exceeded with RFC 4884 extensions
        time_exceeded_rfc4884 = Request(
            "ICMP_Time_Exceeded_RFC4884_Extensions",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 11, fuzzable=True),
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Byte("Length", 5, fuzzable=True),
                        SmartBytes("Unused", b"\x00\x00\x00", size=3, fuzzable=False),
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
                Block(
                    "RFC4884_Extension_Header",
                    children=(
                        Byte("Version_Reserved", 0x20, fuzzable=True),
                        Byte("Reserved", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Extension_Objects",
                    children=(
                        Word("Length", 8, endian=">", fuzzable=True),
                        Byte("Class_Num", 1, fuzzable=True),
                        Byte("C_Type", 1, fuzzable=True),
                        SmartBytes("Extension_Data", b"\x00\x00\x00\x00", size=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # Parameter Problem with RFC 4884 extensions
        param_problem_rfc4884 = Request(
            "ICMP_Parameter_Problem_RFC4884_Extensions",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 12, fuzzable=True),
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Byte("Pointer", 0, fuzzable=True),
                        Byte("Length", 5, fuzzable=True),
                        SmartBytes("Unused", b"\x00\x00", size=2, fuzzable=False),
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
                Block(
                    "RFC4884_Extension_Header",
                    children=(
                        Byte("Version_Reserved", 0x20, fuzzable=True),
                        Byte("Reserved", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Extension_Objects",
                    children=(
                        Word("Length", 8, endian=">", fuzzable=True),
                        Byte("Class_Num", 1, fuzzable=True),
                        Byte("C_Type", 1, fuzzable=True),
                        SmartBytes("Extension_Data", b"\x00\x00\x00\x00", size=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 4: BOUNDARY ATTACKS (~3 minutes)
        # Type/code boundaries, timestamp manipulation
        # ================================================================

        # Type field boundary testing
        type_boundary_test = Request(
            "ICMP_Type_Boundary",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Group(
                            "Type_Boundary",
                            values=[
                                b"\x00",  # Minimum valid (Echo Reply)
                                b"\x01",  # Unassigned
                                b"\x02",  # Unassigned
                                b"\x06",  # Alternate Host Address (deprecated)
                                b"\x07",  # Unassigned
                                b"\x13",  # Reserved (19)
                                b"\x28",  # Photuris (40)
                                b"\x29",  # ICMP for IPv6 Mobility (41)
                                b"\x2c",  # Type 44 (unassigned)
                                b"\x7f",  # 127 (unassigned)
                                b"\x80",  # 128 (unassigned - sign bit)
                                b"\xfc",  # 252 (unassigned)
                                b"\xff",  # 255 (Reserved)
                            ],
                        ),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Rest", 0, endian=">", fuzzable=False),
                    ),
                ),
            ),
        )

        # Code field boundary testing for Dest Unreachable (Type 3)
        code_boundary_type3 = Request(
            "ICMP_Code_Boundary_Type3",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=False),
                        Group(
                            "Code_Boundary",
                            values=[
                                b"\x00",  # Net Unreachable
                                b"\x0f",  # 15 - Precedence Cutoff (max valid)
                                b"\x10",  # 16 - Invalid
                                b"\x7f",  # 127 - Invalid (mid)
                                b"\x80",  # 128 - Invalid (sign bit)
                                b"\xff",  # 255 - Invalid (max)
                            ],
                        ),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=False),
                        Bytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x01\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02",
                            fuzzable=False,
                        ),
                        Bytes("Original_Data", b"\x00" * 8, fuzzable=False),
                    ),
                ),
            ),
        )

        # Timestamp manipulation attacks
        timestamp_attacks = Request(
            "ICMP_Timestamp_Attacks",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 13, fuzzable=True),  # Timestamp Request
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                        # Timestamp fields - 32-bit milliseconds since midnight UTC
                        Group(
                            "Originate_Timestamp_Attack",
                            values=[
                                b"\x00\x00\x00\x00",  # Zero
                                b"\x00\x00\x00\x01",  # Minimum
                                b"\x05\x26\x5b\xff",  # 86399999 (max valid - 23:59:59.999)
                                b"\x05\x26\x5c\x00",  # 86400000 (overflow - midnight rollover)
                                b"\x7f\xff\xff\xff",  # Max positive
                                b"\x80\x00\x00\x00",  # Sign bit
                                b"\xff\xff\xff\xff",  # Maximum
                            ],
                        ),
                        DWord("Receive_Timestamp", 0, endian=">", fuzzable=True),
                        DWord("Transmit_Timestamp", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Extended Echo boundary attacks (RFC 8335)
        extended_echo_boundary = Request(
            "ICMP_Extended_Echo_Boundary",
            children=(
                Block(
                    "ICMP_Header",
                    children=(
                        Group(
                            "Extended_Type",
                            values=[
                                b"\x2a",  # Type 42 - Extended Echo Request
                                b"\x2b",  # Type 43 - Extended Echo Reply
                            ],
                        ),
                        Group(
                            "Extended_Code",
                            values=[
                                b"\x00",  # No Error
                                b"\x01",  # Malformed Query
                                b"\x02",  # No Such Interface
                                b"\x03",  # No Such Table Entry
                                b"\x04",  # Multiple Interfaces Satisfy Query
                                b"\x05",  # Invalid (beyond spec)
                                b"\xff",  # Maximum
                            ],
                        ),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Byte("Sequence", sequence, fuzzable=True),
                        Byte("L_Reserved", 0x00, fuzzable=True),
                    ),
                ),
                Block(
                    "ICMP_Extension_Object",
                    children=(
                        Word("Length", 8, endian=">", fuzzable=True),
                        Byte("Class_Num", 1, fuzzable=True),
                        Byte("C_Type", 1, fuzzable=True),
                        Word("AFI", 1, endian=">", fuzzable=True),
                        SmartBytes("Target_Address", b"\xc0\xa8\x01\x01", size=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 5: COMPREHENSIVE COVERAGE
        # All type/code variations for complete protocol testing
        # ================================================================

        # Echo Request (Type 8)
        echo_request = Request(
            "ICMP_Echo_Request",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", icmp_type, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                        SmartString("Payload", "A" * data_size, max_len=1024, fuzzable=True)
                        if include_data
                        else Static("", ""),
                    ),
                ),
            ),
        )

        # Echo Reply (Type 0)
        echo_reply = Request(
            "ICMP_Echo_Reply",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 0, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence + 1, endian=">", fuzzable=True),
                        SmartString("Payload", "B" * data_size, max_len=1024, fuzzable=True)
                        if include_data
                        else Static("", ""),
                    ),
                ),
            ),
        )

        # Destination Unreachable (Type 3)
        dest_unreachable = Request(
            "ICMP_Dest_Unreachable",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0-15 for different unreachable reasons
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        # Include partial original packet (IP Header + 8 bytes of original data)
                        SmartBytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c"  # Version, IHL, TOS, Total Length
                            + b"\x00\x00\x00\x00"  # ID, Flags, Fragment
                            + b"\x40\x01\x00\x00"  # TTL, Protocol, Checksum
                            + b"\xc0\xa8\x01\x01"  # Source IP
                            + b"\xc0\xa8\x01\x02",  # Dest IP
                            size=20,
                            fuzzable=True,
                        ),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Time Exceeded (Type 11)
        time_exceeded = Request(
            "ICMP_Time_Exceeded",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 11, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0=TTL, 1=Fragment reassembly
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c"
                            + b"\x00\x00\x00\x00"
                            + b"\x01\x01\x00\x00"  # TTL=1
                            + b"\xc0\xa8\x01\x01"
                            + b"\xc0\xa8\x01\x02",
                            size=20,
                            fuzzable=True,
                        ),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Parameter Problem (Type 12)
        param_problem = Request(
            "ICMP_Parameter_Problem",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 12, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Byte("Pointer", 0, fuzzable=True),  # Byte offset of error
                        SmartBytes("Unused", b"\x00\x00\x00", size=3, fuzzable=False),
                        SmartBytes("IP_Header", b"\x45\x00\x00\x1c" * 5, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Source Quench (Type 4) - Deprecated but still fuzzable
        source_quench = Request(
            "ICMP_Source_Quench",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 4, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Redirect (Type 5)
        redirect = Request(
            "ICMP_Redirect",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 5, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0-3 for different redirect types
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        # Gateway IP address
                        SmartBytes("Gateway_IP", b"\xc0\xa8\x01\xfe", size=4, fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Timestamp Request (Type 13)
        timestamp_request = Request(
            "ICMP_Timestamp_Request",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 13, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                        DWord("Originate_Timestamp", 0, endian=">", fuzzable=True),
                        DWord("Receive_Timestamp", 0, endian=">", fuzzable=True),
                        DWord("Transmit_Timestamp", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Timestamp Reply (Type 14)
        timestamp_reply = Request(
            "ICMP_Timestamp_Reply",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 14, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                        DWord("Originate_Timestamp", 0, endian=">", fuzzable=True),
                        DWord("Receive_Timestamp", 0, endian=">", fuzzable=True),
                        DWord("Transmit_Timestamp", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Information Request (Type 15) - Obsolete but fuzzable
        info_request = Request(
            "ICMP_Info_Request",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 15, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Information Reply (Type 16) - Obsolete but fuzzable
        info_reply = Request(
            "ICMP_Info_Reply",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 16, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Router Advertisement (Type 9)
        router_advert = Request(
            "ICMP_Router_Advertisement",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 9, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Byte("Num_Addrs", 1, fuzzable=True),
                        Byte("Addr_Entry_Size", 2, fuzzable=True),
                        Word("Lifetime", 1800, endian=">", fuzzable=True),
                        # Router addresses
                        DWord("Router_Address_1", 0xC0A80101, endian=">", fuzzable=True),
                        DWord("Preference_Level_1", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Router Solicitation (Type 10)
        router_solicit = Request(
            "ICMP_Router_Solicitation",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 10, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Address Mask Request (Type 17) - RFC 950
        addr_mask_request = Request(
            "ICMP_Address_Mask_Request",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 17, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                        DWord("Address_Mask", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Address Mask Reply (Type 18) - RFC 950
        addr_mask_reply = Request(
            "ICMP_Address_Mask_Reply",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 18, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Word("Sequence", sequence, endian=">", fuzzable=True),
                        DWord("Address_Mask", 0xFFFFFF00, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Extended Echo Request (Type 42) - RFC 8335
        extended_echo_request = Request(
            "ICMP_Extended_Echo_Request",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 42, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Byte("Sequence", sequence, fuzzable=True),
                        # L-bit (Local), Reserved (7 bits)
                        Byte("L_Reserved", 0x00, fuzzable=True),
                        # Extension Object
                        Word("Ext_Length", 8, endian=">", fuzzable=True),
                        Byte("Class_Num", 1, fuzzable=True),  # Address Class
                        Byte("C_Type", 1, fuzzable=True),  # IPv4 Address
                        # AFI (Address Family Identifier) - IPv4
                        Word("AFI", 1, endian=">", fuzzable=True),
                        SmartBytes("Target_Address", b"\xc0\xa8\x01\x01", size=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # Extended Echo Reply (Type 43) - RFC 8335
        extended_echo_reply = Request(
            "ICMP_Extended_Echo_Reply",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 43, fuzzable=True),
                        # Code: 0=No Error, 1=Malformed Query, 2=No Such Interface, 3=No Such Table Entry, 4=Multiple Interfaces Satisfy Query
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Identifier", identifier, endian=">", fuzzable=True),
                        Byte("Sequence", sequence, fuzzable=True),
                        # State: 0=Reserved, 1=Incomplete, 2=Reachable, 3=Stale, 4=Delay, 5=Probe, 6=Failed
                        Byte("State", 2, fuzzable=True),
                        # A-bit (Active), R-bit (Router), Reserved (6 bits)
                        Byte("A_R_Reserved", 0x80, fuzzable=True),
                        Byte("Reserved", 0, fuzzable=True),
                    ),
                ),
            ),
        )

        # Destination Unreachable with all code variations (Type 3, Codes 0-15)
        # Code 0: Network Unreachable
        dest_unreach_net = Request(
            "ICMP_Dest_Unreach_Network",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x01\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02",
                            size=20,
                            fuzzable=True,
                        ),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 1: Host Unreachable
        dest_unreach_host = Request(
            "ICMP_Dest_Unreach_Host",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 1, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x45\x00\x00\x1c" * 5, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 2: Protocol Unreachable
        dest_unreach_proto = Request(
            "ICMP_Dest_Unreach_Protocol",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 2, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 3: Port Unreachable
        dest_unreach_port = Request(
            "ICMP_Dest_Unreach_Port",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 3, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 4: Fragmentation Needed and DF Set (Path MTU Discovery)
        dest_unreach_frag = Request(
            "ICMP_Dest_Unreach_Fragmentation",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 4, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Unused", 0, endian=">", fuzzable=True),
                        Word("Next_Hop_MTU", 1500, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 5: Source Route Failed
        dest_unreach_srcroute = Request(
            "ICMP_Dest_Unreach_Source_Route_Failed",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 5, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 6: Destination Network Unknown
        dest_unreach_net_unknown = Request(
            "ICMP_Dest_Unreach_Network_Unknown",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 6, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 7: Destination Host Unknown
        dest_unreach_host_unknown = Request(
            "ICMP_Dest_Unreach_Host_Unknown",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 7, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 8: Source Host Isolated
        dest_unreach_isolated = Request(
            "ICMP_Dest_Unreach_Source_Host_Isolated",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 8, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 9: Communication with Destination Network Administratively Prohibited
        dest_unreach_net_prohib = Request(
            "ICMP_Dest_Unreach_Network_Prohibited",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 9, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 10: Communication with Destination Host Administratively Prohibited
        dest_unreach_host_prohib = Request(
            "ICMP_Dest_Unreach_Host_Prohibited",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 10, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 11: Destination Network Unreachable for Type of Service
        dest_unreach_net_tos = Request(
            "ICMP_Dest_Unreach_Network_TOS",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 11, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 12: Destination Host Unreachable for Type of Service
        dest_unreach_host_tos = Request(
            "ICMP_Dest_Unreach_Host_TOS",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 12, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 13: Communication Administratively Prohibited
        dest_unreach_admin = Request(
            "ICMP_Dest_Unreach_Admin_Prohibited",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 13, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 14: Host Precedence Violation
        dest_unreach_precedence = Request(
            "ICMP_Dest_Unreach_Host_Precedence",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 14, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 15: Precedence Cutoff in Effect
        dest_unreach_cutoff = Request(
            "ICMP_Dest_Unreach_Precedence_Cutoff",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 15, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Redirect with all code variations (Type 5, Codes 0-3)
        # Code 0: Redirect for Network
        redirect_net = Request(
            "ICMP_Redirect_Network",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 5, fuzzable=True),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        SmartBytes("Gateway_IP", b"\xc0\xa8\x01\xfe", size=4, fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 1: Redirect for Host
        redirect_host = Request(
            "ICMP_Redirect_Host",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 5, fuzzable=True),
                        Byte("Code", 1, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        SmartBytes("Gateway_IP", b"\xc0\xa8\x01\xfe", size=4, fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 2: Redirect for Type of Service and Network
        redirect_tos_net = Request(
            "ICMP_Redirect_TOS_Network",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 5, fuzzable=True),
                        Byte("Code", 2, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        SmartBytes("Gateway_IP", b"\xc0\xa8\x01\xfe", size=4, fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 3: Redirect for Type of Service and Host
        redirect_tos_host = Request(
            "ICMP_Redirect_TOS_Host",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 5, fuzzable=True),
                        Byte("Code", 3, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        SmartBytes("Gateway_IP", b"\xc0\xa8\x01\xfe", size=4, fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Time Exceeded with all code variations (Type 11, Codes 0-1)
        # Code 0: TTL Exceeded in Transit
        time_exceeded_ttl = Request(
            "ICMP_Time_Exceeded_TTL",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 11, fuzzable=True),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "IP_Header",
                            b"\x45\x00\x00\x1c\x00\x00\x00\x00\x01\x01\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02",
                            size=20,
                            fuzzable=True,
                        ),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 1: Fragment Reassembly Time Exceeded
        time_exceeded_frag = Request(
            "ICMP_Time_Exceeded_Fragment",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 11, fuzzable=True),
                        Byte("Code", 1, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Parameter Problem with all code variations (Type 12, Codes 0-2)
        # Code 0: Pointer Indicates Error
        param_problem_pointer = Request(
            "ICMP_Parameter_Problem_Pointer",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 12, fuzzable=True),
                        Byte("Code", 0, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Byte("Pointer", 0, fuzzable=True),
                        SmartBytes("Unused", b"\x00\x00\x00", size=3, fuzzable=False),
                        SmartBytes("IP_Header", b"\x45\x00\x00\x1c" * 5, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 1: Missing a Required Option
        param_problem_missing = Request(
            "ICMP_Parameter_Problem_Missing_Option",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 12, fuzzable=True),
                        Byte("Code", 1, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Byte("Pointer", 0, fuzzable=True),
                        SmartBytes("Unused", b"\x00\x00\x00", size=3, fuzzable=False),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Code 2: Bad Length
        param_problem_length = Request(
            "ICMP_Parameter_Problem_Bad_Length",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 12, fuzzable=True),
                        Byte("Code", 2, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Byte("Pointer", 0, fuzzable=True),
                        SmartBytes("Unused", b"\x00\x00\x00", size=3, fuzzable=False),
                        SmartBytes("IP_Header", b"\x00" * 20, size=20, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Experimental Type 253 (Reserved for experimentation)
        experimental_253 = Request(
            "ICMP_Experimental_253",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 253, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        SmartBytes("Experimental_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Experimental Type 254 (Reserved for experimentation)
        experimental_254 = Request(
            "ICMP_Experimental_254",
            children=(
                Block(
                    "ICMP_Message",
                    children=(
                        Byte("Type", 254, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum", block_name="ICMP_Message", algorithm="ipv4", endian=">"
                        ),
                        SmartBytes("Experimental_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # ================================================================
        # OPTIMIZED REQUEST ORDERING
        # ================================================================
        # Phase 1: Quick Coverage (~30 sec) - all types once
        # Phase 2: High-Crash Tests (~2 min) - overflow, checksum attacks
        # Phase 3: CVE-Targeted (~3 min) - redirect spoofing, extension overflow
        # Phase 4: Boundary Attacks (~3 min) - type/code/timestamp boundaries
        # Phase 5: Comprehensive - all code variations
        # ================================================================

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        if self.is_request_enabled("ICMP_Quick_Coverage"):
            self.session.connect(quick_type_coverage)  # All 19 types in one request
            self.session.connect(baseline_echo)  # Simple connectivity test

        # ==================== PHASE 2: HIGH-CRASH TESTS (~2 min) ====================
        # Moved from end of session - these trigger buffer overflows and crashes
        if self.is_request_enabled("ICMP_Overflow_Tests"):
            self.session.connect(echo_oversized)  # Ping of Death variants
            self.session.connect(echo_size_boundaries)  # Specific size boundary attacks

        if self.is_request_enabled("ICMP_Checksum_Tests"):
            self.session.connect(echo_bad_checksum)  # Checksum corruption (CVE-2020-25705)

        # ==================== PHASE 3: CVE-TARGETED (~3 min) ====================
        if self.is_request_enabled("ICMP_Redirect_Attacks"):
            self.session.connect(redirect_spoofing)  # Redirect spoofing (CVE-2021-28372)

        if self.is_request_enabled("ICMP_Extension_Attacks"):
            self.session.connect(dest_unreach_rfc4884)  # RFC 4884 extension (CVE-2022-23093)
            self.session.connect(rfc4884_extension_overflow)  # Extension overflow attack
            self.session.connect(time_exceeded_rfc4884)
            self.session.connect(param_problem_rfc4884)

        # ==================== PHASE 4: BOUNDARY ATTACKS (~3 min) ====================
        if self.is_request_enabled("ICMP_Type_Code_Boundary"):
            self.session.connect(type_boundary_test)  # Type field boundaries
            self.session.connect(code_boundary_type3)  # Code field boundaries

        if self.is_request_enabled("ICMP_Timestamp_Tests"):
            self.session.connect(timestamp_attacks)  # Timestamp manipulation

        if self.is_request_enabled("ICMP_Extended_Echo"):
            self.session.connect(extended_echo_boundary)  # Extended Echo boundaries
            self.session.connect(extended_echo_request)
            self.session.connect(extended_echo_reply)

        # ==================== PHASE 5: COMPREHENSIVE COVERAGE ====================
        # All Type 3 (Destination Unreachable) code variations
        if self.is_request_enabled("ICMP_Dest_Unreachable"):
            self.session.connect(dest_unreachable)  # Generic Type 3
            self.session.connect(dest_unreach_net)  # Code 0: Network Unreachable
            self.session.connect(dest_unreach_host)  # Code 1: Host Unreachable
            self.session.connect(dest_unreach_proto)  # Code 2: Protocol Unreachable
            self.session.connect(dest_unreach_port)  # Code 3: Port Unreachable
            self.session.connect(dest_unreach_frag)  # Code 4: Fragmentation Needed
            self.session.connect(dest_unreach_srcroute)  # Code 5: Source Route Failed
            self.session.connect(dest_unreach_net_unknown)  # Code 6: Network Unknown
            self.session.connect(dest_unreach_host_unknown)  # Code 7: Host Unknown
            self.session.connect(dest_unreach_isolated)  # Code 8: Source Host Isolated
            self.session.connect(dest_unreach_net_prohib)  # Code 9: Network Admin Prohibited
            self.session.connect(dest_unreach_host_prohib)  # Code 10: Host Admin Prohibited
            self.session.connect(dest_unreach_net_tos)  # Code 11: Network TOS
            self.session.connect(dest_unreach_host_tos)  # Code 12: Host TOS
            self.session.connect(dest_unreach_admin)  # Code 13: Admin Prohibited
            self.session.connect(dest_unreach_precedence)  # Code 14: Host Precedence
            self.session.connect(dest_unreach_cutoff)  # Code 15: Precedence Cutoff

        # All Type 11 (Time Exceeded) code variations
        if self.is_request_enabled("ICMP_Time_Exceeded"):
            self.session.connect(time_exceeded)  # Generic Type 11
            self.session.connect(time_exceeded_ttl)  # Code 0: TTL Exceeded
            self.session.connect(time_exceeded_frag)  # Code 1: Fragment Reassembly

        # All Type 12 (Parameter Problem) code variations
        if self.is_request_enabled("ICMP_Parameter_Problem"):
            self.session.connect(param_problem)  # Generic Type 12
            self.session.connect(param_problem_pointer)  # Code 0: Pointer Error
            self.session.connect(param_problem_missing)  # Code 1: Missing Option
            self.session.connect(param_problem_length)  # Code 2: Bad Length

        # Router Discovery (Types 9, 10)
        if self.is_request_enabled("ICMP_Router_Discovery"):
            self.session.connect(router_advert)  # Type 9: Router Advertisement
            self.session.connect(router_solicit)  # Type 10: Router Solicitation

        # Address Mask (Types 17, 18) - RFC 950
        if self.is_request_enabled("ICMP_Address_Mask"):
            self.session.connect(addr_mask_request)  # Type 17: Address Mask Request
            self.session.connect(addr_mask_reply)  # Type 18: Address Mask Reply

        # Experimental Types (253, 254)
        if self.is_request_enabled("ICMP_Experimental"):
            self.session.connect(experimental_253)
            self.session.connect(experimental_254)

        # Obsolete/Deprecated Types
        if self.is_request_enabled("ICMP_Obsolete"):
            self.session.connect(echo_request)  # Type 8: Echo Request
            self.session.connect(echo_reply)  # Type 0: Echo Reply
            self.session.connect(source_quench)  # Type 4: Source Quench (deprecated)
            self.session.connect(redirect)  # Type 5: Redirect (generic)
            self.session.connect(timestamp_request)  # Type 13: Timestamp Request
            self.session.connect(timestamp_reply)  # Type 14: Timestamp Reply
            self.session.connect(info_request)  # Type 15: Info Request (obsolete)
            self.session.connect(info_reply)  # Type 16: Info Reply (obsolete)
            # Type 5 code variations (not in Redirect_Attacks since generic redirect is here)
            self.session.connect(redirect_net)  # Code 0: Redirect Network
            self.session.connect(redirect_host)  # Code 1: Redirect Host
            self.session.connect(redirect_tos_net)  # Code 2: Redirect TOS Network
            self.session.connect(redirect_tos_host)  # Code 3: Redirect TOS Host
