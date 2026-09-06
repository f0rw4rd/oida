"""Ethernet Frame Fuzzer

Fuzzer Optimization Strategy (Breadth-First):
==============================================
Phase 1 (0-30s): Quick_Coverage - all 12 frame types/EtherTypes once
Phase 2 (30s-3m): High-crash tests - oversized frames, buffer overflow patterns
Phase 3 (3-6m): CVE-targeted - VLAN hopping, ARP spoofing, LLDP injection
Phase 4 (6-10m): Boundary attacks - MAC addresses, EtherType boundaries
Phase 5 (10m+): Remaining tests - nested protocols, protocol-specific fields

CVE Coverage:
- CVE-2020-8597: PPPoE buffer overflow (eap_request/response handling)
- CVE-2021-27853: LLDP stack-based buffer overflow (via TLV parsing)
- CVE-2023-1255: VLAN double-tagging bypass (QinQ attacks)
- CVE-2022-20699: ARP cache poisoning via malformed frames
- CVE-2017-3881: Jumbo frame handling DoS (oversized MTU)
"""

import socket
import struct
from typing import List, Optional

from boofuzz import BitField, Byte, DWord, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import BaseMonitor
from ..primitives.dynamic import SmartString


class EthernetFuzzer(BaseFuzzer):
    """Ethernet Frame Fuzzer for Layer 2 security testing

    Supports Ethernet II, 802.3 with LLC/SNAP, VLAN tagged (802.1Q),
    QinQ double-tagged (802.1ad), jumbo frames, and various EtherTypes.

    Test Ordering (Optimized for Early Coverage):
    - Phase 1: Quick_Coverage touches all 12 frame types in ~30 seconds
    - Phase 2: Buffer overflow and oversized frame tests (high crash likelihood)
    - Phase 3: CVE-targeted injection attacks (VLAN hopping, ARP spoofing)
    - Phase 4: Boundary value attacks (MAC addresses, EtherTypes)
    - Phase 5: Nested protocol tests, discovery, LLC/SNAP
    """

    # Common EtherTypes
    ETHERTYPE_IPV4 = 0x0800
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_VLAN = 0x8100
    ETHERTYPE_IPV6 = 0x86DD
    ETHERTYPE_QINQ = 0x88A8
    ETHERTYPE_MPLS_UC = 0x8847
    ETHERTYPE_MPLS_MC = 0x8848
    ETHERTYPE_PPOE_D = 0x8863  # PPPoE Discovery
    ETHERTYPE_PPOE_S = 0x8864  # PPPoE Session
    ETHERTYPE_LLDP = 0x88CC
    ETHERTYPE_8021X = 0x888E  # 802.1X Authentication
    ETHERTYPE_LACP = 0x8809  # Link Aggregation

    PROTOCOL_OPTIONS = {
        "interface": {
            "type": str,
            "default": "eth0",
            "description": "Network interface for raw socket operations",
            "example": "eth0",
        },
        "dst_mac": {
            "type": str,
            "default": "ff:ff:ff:ff:ff:ff",
            "description": "Destination MAC address (broadcast by default)",
            "example": "00:11:22:33:44:55",
        },
        "src_mac": {
            "type": str,
            "default": None,
            "description": "Source MAC address (auto-detect if not set)",
            "example": "aa:bb:cc:dd:ee:ff",
        },
        "enable_vlan": {
            "type": bool,
            "default": False,
            "description": "Enable VLAN (802.1Q) frame fuzzing",
        },
        "vlan_id": {
            "type": int,
            "default": 100,
            "description": "VLAN ID for tagged frames (1-4094)",
            "example": "100",
        },
        "enable_qinq": {
            "type": bool,
            "default": False,
            "description": "Enable QinQ (802.1ad) double-tagged fuzzing",
        },
        "outer_vlan": {
            "type": int,
            "default": 200,
            "description": "Outer VLAN ID for QinQ frames (S-TAG)",
            "example": "200",
        },
        "enable_jumbo": {
            "type": bool,
            "default": False,
            "description": "Enable jumbo frame fuzzing (up to 9000 bytes)",
        },
        "enable_llc": {
            "type": bool,
            "default": False,
            "description": "Enable 802.3 LLC/SNAP frame fuzzing",
        },
        "fuzz_nested": {
            "type": bool,
            "default": True,
            "description": "Enable nested protocol fuzzing (IPv4, IPv6, MPLS)",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "Ethernet_Quick_Coverage",
                "Quick sweep of all 12 frame/EtherTypes (~30s)",
                "baseline",
            ),
            # Phase 2: High-crash tests
            RequestInfo(
                "Ethernet_Overflow_Tests",
                "Oversized frames and buffer overflow (CVE-2017-3881)",
                "overflow",
            ),
            RequestInfo(
                "Ethernet_Malformed", "Malformed frames with invalid structures", "overflow"
            ),
            # Phase 3: CVE-targeted operations
            RequestInfo(
                "Ethernet_VLAN_Attacks", "VLAN hopping and QinQ bypass (CVE-2023-1255)", "injection"
            ),
            RequestInfo(
                "Ethernet_ARP_Injection",
                "ARP spoofing and cache poisoning (CVE-2022-20699)",
                "injection",
            ),
            RequestInfo(
                "Ethernet_LLDP_Injection", "LLDP TLV overflow attacks (CVE-2021-27853)", "injection"
            ),
            RequestInfo(
                "Ethernet_PPPoE_Attacks", "PPPoE buffer overflow (CVE-2020-8597)", "injection"
            ),
            # Phase 4: Boundary attacks
            RequestInfo(
                "Ethernet_Boundary_Tests", "MAC address and EtherType boundary testing", "boundary"
            ),
            # Phase 5: Remaining tests
            RequestInfo("Ethernet_Basic_Frames", "Standard Ethernet II frame fuzzing", "general"),
            RequestInfo("Ethernet_LLC_SNAP", "802.3 LLC/SNAP frame testing", "general"),
            RequestInfo("Ethernet_Nested_Protocols", "IPv4, IPv6, MPLS over Ethernet", "nested"),
        ]

    def __init__(self, config: FuzzerConfig = None, connection_factory=None):
        if config:
            config.protocol_type = ProtocolType.RAW
        super().__init__(config, connection_factory)

        # Get options
        self.interface = config.get_option("interface", "eth0") if config else "eth0"
        self.dst_mac = (
            config.get_option("dst_mac", "ff:ff:ff:ff:ff:ff") if config else "ff:ff:ff:ff:ff:ff"
        )
        self.src_mac = config.get_option("src_mac", None) if config else None

        # Auto-detect source MAC if not provided
        if not self.src_mac:
            self.src_mac = self._get_interface_mac()

    def _get_interface_mac(self) -> str:
        """Get MAC address of the network interface"""
        try:
            import fcntl

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(
                s.fileno(), 0x8927, struct.pack("256s", self.interface.encode("utf-8"))
            )
            mac_bytes = info[18:24]
            return ":".join(["%02x" % b for b in mac_bytes])
        except (OSError, ImportError, struct.error) as e:
            # Default fallback MAC
            self.log.debug(f"Failed to get MAC address for interface '{self.interface}': {e}")
            return "00:11:22:33:44:55"

    def _mac_to_bytes(self, mac_str: str) -> bytes:
        """Convert MAC address string to bytes"""
        return bytes.fromhex(mac_str.replace(":", ""))

    def _define_protocol(self):
        """Define Ethernet frame structures for fuzzing

        Optimized test ordering for maximum early coverage and crash detection:
        - Phase 1: Quick_Coverage - all 12 frame types once (~30 sec)
        - Phase 2: High-crash tests - oversized frames, buffer overflows
        - Phase 3: CVE-targeted - VLAN hopping, ARP spoofing, LLDP injection
        - Phase 4: Boundary attacks - MAC addresses, EtherTypes
        - Phase 5: Remaining tests - standard frames, nested protocols
        """

        # Get protocol options
        enable_vlan = self.config.get_option("enable_vlan", False) if self.config else False
        vlan_id = self.config.get_option("vlan_id", 100) if self.config else 100
        enable_qinq = self.config.get_option("enable_qinq", False) if self.config else False
        outer_vlan = self.config.get_option("outer_vlan", 200) if self.config else 200
        enable_jumbo = self.config.get_option("enable_jumbo", False) if self.config else False
        enable_llc = self.config.get_option("enable_llc", False) if self.config else False
        fuzz_nested = self.config.get_option("fuzz_nested", True) if self.config else True

        # ================================================================
        # PHASE 1: QUICK COVERAGE (~30 sec)
        # Touch all 12 frame types/EtherTypes once for maximum breadth
        # ================================================================

        # Quick Coverage Request - all EtherTypes in one request with minimal fuzzing
        quick_coverage = Request(
            "Quick_Coverage",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                # Cycle through all 12 major EtherTypes
                Group(
                    "ethertype_sweep",
                    values=[
                        struct.pack(">H", self.ETHERTYPE_IPV4),  # 0x0800 - IPv4
                        struct.pack(">H", self.ETHERTYPE_ARP),  # 0x0806 - ARP
                        struct.pack(">H", self.ETHERTYPE_VLAN),  # 0x8100 - 802.1Q VLAN
                        struct.pack(">H", self.ETHERTYPE_IPV6),  # 0x86DD - IPv6
                        struct.pack(">H", self.ETHERTYPE_QINQ),  # 0x88A8 - QinQ
                        struct.pack(">H", self.ETHERTYPE_MPLS_UC),  # 0x8847 - MPLS Unicast
                        struct.pack(">H", self.ETHERTYPE_MPLS_MC),  # 0x8848 - MPLS Multicast
                        struct.pack(">H", self.ETHERTYPE_PPOE_D),  # 0x8863 - PPPoE Discovery
                        struct.pack(">H", self.ETHERTYPE_PPOE_S),  # 0x8864 - PPPoE Session
                        struct.pack(">H", self.ETHERTYPE_LLDP),  # 0x88CC - LLDP
                        struct.pack(">H", self.ETHERTYPE_8021X),  # 0x888E - 802.1X
                        struct.pack(">H", self.ETHERTYPE_LACP),  # 0x8809 - LACP
                    ],
                ),
                # Minimal valid payload (46 bytes for minimum frame size)
                Static("minimal_payload", b"A" * 46),
            ),
        )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (~3 min)
        # Oversized frames, buffer overflow patterns - highest crash likelihood
        # ================================================================

        # Oversized Frame Attacks (CVE-2017-3881 pattern - jumbo frame DoS)
        overflow_jumbo = Request(
            "Overflow_Jumbo_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_IPV4)),
                # Progressively larger payloads to trigger buffer overflows
                Group(
                    "overflow_payload",
                    values=[
                        b"A" * 1500,  # Standard MTU
                        b"A" * 1518,  # Maximum Ethernet frame
                        b"A" * 2000,  # Over MTU
                        b"A" * 4096,  # Page boundary
                        b"A" * 8192,  # 2x page
                        b"A" * 9000,  # Jumbo frame size
                        b"A" * 9216,  # Baby jumbo + overhead
                        b"A" * 16384,  # Large overflow
                        b"A" * 65535,  # Maximum possible (limited by IP length field)
                    ],
                ),
            ),
        )

        # Malformed Frame Attacks - structural violations
        malformed_frames = Request(
            "Malformed_Frames",
            children=(
                Group(
                    "malformed",
                    values=[
                        # Too short frame (< 64 bytes) - runt frame
                        b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00",
                        # Null MAC addresses - invalid
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00" + b"A" * 46,
                        # Broadcast src MAC (invalid)
                        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x00" + b"A" * 46,
                        # Multicast src MAC (invalid for unicast)
                        b"\xff\xff\xff\xff\xff\xff\x01\x00\x5e\x00\x00\x01\x08\x00" + b"A" * 46,
                        # Invalid EtherType in reserved range (0x0000-0x05DC are lengths)
                        self._mac_to_bytes(self.dst_mac)
                        + self._mac_to_bytes(self.src_mac)
                        + struct.pack(">H", 0x0500)
                        + b"A" * 46,
                        # Maximum EtherType boundary
                        self._mac_to_bytes(self.dst_mac)
                        + self._mac_to_bytes(self.src_mac)
                        + struct.pack(">H", 0xFFFF)
                        + b"A" * 46,
                        # Zero-length payload
                        self._mac_to_bytes(self.dst_mac)
                        + self._mac_to_bytes(self.src_mac)
                        + struct.pack(">H", 0x0800),
                    ],
                )
            ),
        )

        # Length field mismatch attacks (802.3 frames)
        length_mismatch = Request(
            "Length_Mismatch_Attack",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                # Length field values that mismatch actual payload
                Group(
                    "length_field",
                    values=[
                        struct.pack(">H", 0x0000),  # Zero length
                        struct.pack(">H", 0x0001),  # 1 byte (but payload larger)
                        struct.pack(">H", 0x05DC),  # Max 802.3 length (1500)
                        struct.pack(">H", 0x05DD),  # Just over max (invalid)
                        struct.pack(">H", 0x05FF),  # Boundary value
                    ],
                ),
                # LLC Header (SNAP)
                Byte("dsap", 0xAA),
                Byte("ssap", 0xAA),
                Byte("control", 0x03),
                Static("oui", b"\x00\x00\x00"),
                Word("snap_type", self.ETHERTYPE_IPV4, endian=">"),
                # Payload larger than length field indicates
                Static("payload", b"B" * 100),
            ),
        )

        # ================================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (~3 min)
        # VLAN hopping, ARP spoofing, LLDP injection, PPPoE attacks
        # ================================================================

        # VLAN Hopping Attack (CVE-2023-1255 pattern - double tagging bypass)
        vlan_hopping = Request(
            "VLAN_Hopping_Attack",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                # Multiple VLAN tags for hopping attacks
                Group(
                    "vlan_attack",
                    values=[
                        # Single tag with boundary VLAN IDs
                        struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0001)  # VLAN 1
                        + struct.pack(">H", 0x0800),
                        struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0FFE)  # VLAN 4094
                        + struct.pack(">H", 0x0800),
                        struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0FFF)  # VLAN 4095 (reserved)
                        + struct.pack(">H", 0x0800),
                        # Double tagging (QinQ hopping)
                        struct.pack(">H", self.ETHERTYPE_QINQ)
                        + struct.pack(">H", 0x00C8)  # Outer VLAN 200
                        + struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0064)  # Inner VLAN 100
                        + struct.pack(">H", 0x0800),
                        # Triple tagging (stack overflow attempt)
                        struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0064)
                        + struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0065)
                        + struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0x0066)
                        + struct.pack(">H", 0x0800),
                        # Priority field manipulation
                        struct.pack(">H", self.ETHERTYPE_VLAN)
                        + struct.pack(">H", 0xE064)  # Priority 7, VLAN 100
                        + struct.pack(">H", 0x0800),
                    ],
                ),
                Static("payload", b"VLAN_HOP" * 6),
            ),
        )

        # ARP Spoofing Attack (CVE-2022-20699 pattern - cache poisoning)
        arp_spoofing = Request(
            "ARP_Spoofing_Attack",
            children=(
                Static("dst_mac", self._mac_to_bytes("ff:ff:ff:ff:ff:ff")),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_ARP)),
                # ARP operation types
                Word("hw_type", 0x0001, endian=">"),  # Ethernet
                Word("proto_type", 0x0800, endian=">"),  # IPv4
                Byte("hw_len", 6),
                Byte("proto_len", 4),
                Group(
                    "arp_operation",
                    values=[
                        struct.pack(">H", 0x0001),  # ARP Request
                        struct.pack(">H", 0x0002),  # ARP Reply (for spoofing)
                        struct.pack(">H", 0x0003),  # RARP Request
                        struct.pack(">H", 0x0004),  # RARP Reply
                        struct.pack(">H", 0x0008),  # InARP Request
                        struct.pack(">H", 0x0009),  # InARP Reply
                        struct.pack(">H", 0xFFFF),  # Invalid operation
                    ],
                ),
                # Spoofed sender info
                Group(
                    "sender_mac",
                    values=[
                        self._mac_to_bytes(self.src_mac),
                        b"\x00\x00\x00\x00\x00\x00",  # Zero MAC
                        b"\xff\xff\xff\xff\xff\xff",  # Broadcast MAC
                    ],
                ),
                Group(
                    "sender_ip",
                    values=[
                        struct.pack(">I", 0xC0A80001),  # 192.168.0.1
                        struct.pack(">I", 0xC0A800FE),  # 192.168.0.254 (gateway)
                        struct.pack(">I", 0x7F000001),  # 127.0.0.1 (loopback)
                        struct.pack(">I", 0x00000000),  # 0.0.0.0
                        struct.pack(">I", 0xFFFFFFFF),  # 255.255.255.255
                    ],
                ),
                Static("target_mac", b"\x00" * 6),
                DWord("target_ip", 0xC0A80002, endian=">"),
                Static("padding", b"\x00" * 18),
            ),
        )

        # LLDP Injection Attack (CVE-2021-27853 pattern - TLV overflow)
        lldp_injection = Request(
            "LLDP_Injection_Attack",
            children=(
                Static("dst_mac", self._mac_to_bytes("01:80:c2:00:00:0e")),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_LLDP)),
                # Malformed TLV attacks
                Group(
                    "lldp_tlv_attack",
                    values=[
                        # Oversized Chassis ID TLV (type 1, length 255 but data longer)
                        b"\x02\xff" + b"A" * 300,
                        # Oversized Port ID TLV (type 2)
                        b"\x04\xff" + b"B" * 300,
                        # Invalid TLV type (type 127, reserved)
                        b"\xfe\x10" + b"C" * 16,
                        # Zero-length TLV with data
                        b"\x02\x00" + b"D" * 50,
                        # Nested End TLVs
                        b"\x00\x00\x00\x00\x00\x00",
                        # Maximum length TLV
                        b"\x02\xff" + b"E" * 255 + b"\x00\x00",
                    ],
                ),
            ),
        )

        # PPPoE Attack (CVE-2020-8597 pattern - buffer overflow in EAP)
        pppoe_attack = Request(
            "PPPoE_Attack",
            children=(
                Static("dst_mac", self._mac_to_bytes("ff:ff:ff:ff:ff:ff")),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_PPOE_D)),
                BitField("version", 1, width=4),
                BitField("type", 1, width=4),
                Group(
                    "pppoe_code",
                    values=[
                        b"\x09",  # PADI
                        b"\x07",  # PADO
                        b"\x19",  # PADR
                        b"\x65",  # PADS
                        b"\xa7",  # PADT
                        b"\x00",  # Session data
                        b"\xff",  # Invalid
                    ],
                ),
                Group(
                    "session_id",
                    values=[
                        struct.pack(">H", 0x0000),
                        struct.pack(">H", 0x0001),
                        struct.pack(">H", 0xFFFF),
                    ],
                ),
                # Length field attacks
                Group(
                    "pppoe_length",
                    values=[
                        struct.pack(">H", 0x0000),  # Zero length
                        struct.pack(">H", 0x0010),  # Normal length
                        struct.pack(">H", 0x05DC),  # Max MTU
                        struct.pack(">H", 0xFFFF),  # Overflow attempt
                    ],
                ),
                # PPPoE tags with overflow potential
                SmartString("tags", "PPPoE-tag-overflow", max_len=1500),
            ),
        )

        # ================================================================
        # PHASE 4: BOUNDARY ATTACKS (~3 min)
        # MAC address and EtherType boundary testing
        # ================================================================

        # MAC Address Boundary Testing
        mac_boundary = Request(
            "MAC_Address_Boundary",
            children=(
                Group(
                    "dst_mac_boundary",
                    values=[
                        b"\x00\x00\x00\x00\x00\x00",  # Null MAC
                        b"\x00\x00\x00\x00\x00\x01",  # Minimum unicast
                        b"\x01\x00\x5e\x00\x00\x01",  # IPv4 multicast
                        b"\x33\x33\x00\x00\x00\x01",  # IPv6 multicast
                        b"\x01\x80\xc2\x00\x00\x00",  # STP multicast
                        b"\xff\xff\xff\xff\xff\xfe",  # Almost broadcast
                        b"\xff\xff\xff\xff\xff\xff",  # Broadcast
                    ],
                ),
                Group(
                    "src_mac_boundary",
                    values=[
                        b"\x00\x00\x00\x00\x00\x00",  # Null (invalid src)
                        self._mac_to_bytes(self.src_mac),  # Normal
                        b"\x01\x00\x00\x00\x00\x00",  # Multicast bit set (invalid src)
                        b"\xff\xff\xff\xff\xff\xff",  # Broadcast (invalid src)
                    ],
                ),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_IPV4)),
                Static("payload", b"MAC_BOUNDARY" * 4),
            ),
        )

        # EtherType Boundary Testing
        ethertype_boundary = Request(
            "EtherType_Boundary",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Group(
                    "ethertype_boundary",
                    values=[
                        struct.pack(">H", 0x0000),  # Zero (invalid)
                        struct.pack(">H", 0x0001),  # Minimum
                        struct.pack(">H", 0x05DC),  # 1500 - max 802.3 length
                        struct.pack(">H", 0x05DD),  # 1501 - transition to EtherType
                        struct.pack(">H", 0x05FF),  # Boundary area
                        struct.pack(">H", 0x0600),  # Minimum EtherType (Xerox NS IDP)
                        struct.pack(">H", 0x0800),  # IPv4
                        struct.pack(">H", 0x7FFF),  # Mid-range
                        struct.pack(">H", 0x8000),  # Sign bit boundary
                        struct.pack(">H", 0xFFFE),  # Almost maximum
                        struct.pack(">H", 0xFFFF),  # Maximum
                    ],
                ),
                Static("payload", b"ETHERTYPE_BOUNDARY" * 3),
            ),
        )

        # ================================================================
        # PHASE 5: REMAINING TESTS
        # Standard frames, LLC/SNAP, nested protocols
        # ================================================================

        # Basic Ethernet II Frame
        ethernet_ii = Request(
            "Ethernet_II_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Group(
                    "ethertype",
                    values=[
                        struct.pack(">H", self.ETHERTYPE_IPV4),
                        struct.pack(">H", self.ETHERTYPE_IPV6),
                        struct.pack(">H", self.ETHERTYPE_ARP),
                        struct.pack(">H", self.ETHERTYPE_LLDP),
                    ],
                ),
                SmartString(
                    "payload", "ethernet-payload", max_len=1500 if not enable_jumbo else 9000
                ),
            ),
        )

        # VLAN Tagged Frame (802.1Q) - standard fuzzing
        vlan_frame = Request(
            "VLAN_Tagged_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("vlan_ethertype", struct.pack(">H", self.ETHERTYPE_VLAN)),
                BitField("priority", 0, width=3),
                BitField("dei", 0, width=1),
                BitField("vlan_id", vlan_id, width=12),
                Word("inner_ethertype", self.ETHERTYPE_IPV4, endian=">"),
                SmartString("vlan_payload", "VLAN", max_len=1496),
            ),
        )

        # QinQ Double-Tagged Frame (802.1ad)
        qinq_frame = Request(
            "QinQ_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("stag_ethertype", struct.pack(">H", self.ETHERTYPE_QINQ)),
                BitField("outer_priority", 0, width=3),
                BitField("outer_dei", 0, width=1),
                BitField("outer_vlan_id", outer_vlan, width=12),
                Static("ctag_ethertype", struct.pack(">H", self.ETHERTYPE_VLAN)),
                BitField("inner_priority", 0, width=3),
                BitField("inner_dei", 0, width=1),
                BitField("inner_vlan_id", vlan_id, width=12),
                Word("payload_ethertype", self.ETHERTYPE_IPV4, endian=">"),
                SmartString("qinq_payload", "QinQ", max_len=1492),
            ),
        )

        # 802.3 Frame with LLC/SNAP
        llc_snap_frame = Request(
            "LLC_SNAP_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Word("length", 64, endian=">"),
                Byte("dsap", 0xAA),
                Byte("ssap", 0xAA),
                Byte("control", 0x03),
                Static("oui", b"\x00\x00\x00"),
                Word("snap_type", self.ETHERTYPE_IPV4, endian=">"),
                SmartString("llc_payload", "LLC", max_len=1492),
            ),
        )

        # ARP Frame - standard fuzzing
        arp_frame = Request(
            "ARP_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes("ff:ff:ff:ff:ff:ff")),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_ARP)),
                Word("hw_type", 0x0001, endian=">"),
                Word("proto_type", 0x0800, endian=">"),
                Byte("hw_len", 6),
                Byte("proto_len", 4),
                Word("operation", 1, endian=">"),
                Static("sender_mac", self._mac_to_bytes(self.src_mac)),
                DWord("sender_ip", 0xC0A80001, endian=">"),
                Static("target_mac", b"\x00" * 6),
                DWord("target_ip", 0xC0A80002, endian=">"),
                Static("padding", b"\x00" * 18),
            ),
        )

        # LLDP Frame - standard fuzzing
        lldp_frame = Request(
            "LLDP_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes("01:80:c2:00:00:0e")),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_LLDP)),
                BitField("chassis_type", 1, width=7),
                BitField("chassis_len", 7, width=9),
                Byte("chassis_subtype", 4),
                Static("chassis_id", self._mac_to_bytes(self.src_mac)),
                BitField("port_type", 2, width=7),
                BitField("port_len", 7, width=9),
                Byte("port_subtype", 3),
                SmartString("port_id", "eth0"),
                BitField("ttl_type", 3, width=7),
                BitField("ttl_len", 2, width=9),
                Word("ttl_value", 120, endian=">"),
                Word("end_tlv", 0x0000, endian=">"),
            ),
        )

        # PPPoE Discovery Frame - standard fuzzing
        pppoe_frame = Request(
            "PPPoE_Discovery_Frame",
            children=(
                Static("dst_mac", self._mac_to_bytes("ff:ff:ff:ff:ff:ff")),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_PPOE_D)),
                BitField("version", 1, width=4),
                BitField("type", 1, width=4),
                Byte("code", 0x09),
                Word("session_id", 0x0000, endian=">"),
                Word("length", 12, endian=">"),
                Word("service_name_tag", 0x0101, endian=">"),
                Word("service_name_len", 0, endian=">"),
                Word("ac_name_tag", 0x0102, endian=">"),
                Word("ac_name_len", 4, endian=">"),
                SmartString("ac_name", "TEST"),
            ),
        )

        # IPv4 in Ethernet
        ipv4_frame = Request(
            "Ethernet_IPv4",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_IPV4)),
                BitField("ip_version", 4, width=4),
                BitField("ip_ihl", 5, width=4),
                Byte("ip_tos", 0),
                Word("ip_length", 64, endian=">"),
                Word("ip_id", 0x1234, endian=">"),
                BitField("ip_flags", 0, width=3),
                BitField("ip_frag_offset", 0, width=13),
                Byte("ip_ttl", 64),
                Byte("ip_protocol", 6),
                Word("ip_checksum", 0, endian=">"),
                DWord("ip_src", 0xC0A80001, endian=">"),
                DWord("ip_dst", 0xC0A80002, endian=">"),
                SmartString("tcp_payload", "TCP", max_len=1460),
            ),
        )

        # IPv6 in Ethernet
        ipv6_frame = Request(
            "Ethernet_IPv6",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_IPV6)),
                BitField("ipv6_version", 6, width=4),
                BitField("ipv6_traffic_class", 0, width=8),
                BitField("ipv6_flow_label", 0, width=20),
                Word("ipv6_payload_length", 64, endian=">"),
                Byte("ipv6_next_header", 6),
                Byte("ipv6_hop_limit", 64),
                Static("ipv6_src", b"\x20\x01\x0d\xb8" + b"\x00" * 12),
                Static("ipv6_dst", b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"),
                SmartString("ipv6_payload", "IPv6", max_len=1440),
            ),
        )

        # MPLS in Ethernet
        mpls_frame = Request(
            "Ethernet_MPLS",
            children=(
                Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
                Static("src_mac", self._mac_to_bytes(self.src_mac)),
                Static("ethertype", struct.pack(">H", self.ETHERTYPE_MPLS_UC)),
                BitField("mpls_label", 100, width=20),
                BitField("mpls_exp", 0, width=3),
                BitField("mpls_bottom", 1, width=1),
                Byte("mpls_ttl", 64),
                BitField("ip_version", 4, width=4),
                BitField("ip_ihl", 5, width=4),
                SmartString("mpls_payload", "MPLS", max_len=1480),
            ),
        )

        # ================================================================
        # OPTIMIZED REQUEST ORDERING
        # Connect requests in optimal order for early coverage + crash detection
        # ================================================================

        # PHASE 1: Quick Coverage (~30 sec) - touch all frame types immediately
        if self.is_request_enabled("Ethernet_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # PHASE 2: High-Crash Tests (~3 min) - overflow and malformed frames first
        if self.is_request_enabled("Ethernet_Overflow_Tests"):
            self.session.connect(overflow_jumbo)
            self.session.connect(length_mismatch)

        if self.is_request_enabled("Ethernet_Malformed"):
            self.session.connect(malformed_frames)

        # PHASE 3: CVE-Targeted Operations (~3 min)
        if self.is_request_enabled("Ethernet_VLAN_Attacks"):
            self.session.connect(vlan_hopping)

        if self.is_request_enabled("Ethernet_ARP_Injection"):
            self.session.connect(arp_spoofing)

        if self.is_request_enabled("Ethernet_LLDP_Injection"):
            self.session.connect(lldp_injection)

        if self.is_request_enabled("Ethernet_PPPoE_Attacks"):
            self.session.connect(pppoe_attack)

        # PHASE 4: Boundary Attacks (~3 min)
        if self.is_request_enabled("Ethernet_Boundary_Tests"):
            self.session.connect(mac_boundary)
            self.session.connect(ethertype_boundary)

        # PHASE 5: Remaining Tests
        if self.is_request_enabled("Ethernet_Basic_Frames"):
            self.session.connect(ethernet_ii)
            self.session.connect(arp_frame)
            self.session.connect(lldp_frame)
            self.session.connect(pppoe_frame)

        if self.is_request_enabled("Ethernet_LLC_SNAP") or enable_llc:
            self.session.connect(llc_snap_frame)

        # VLAN/QinQ frames (conditionally enabled or always for attacks)
        if enable_vlan:
            self.session.connect(vlan_frame)

        if enable_qinq:
            self.session.connect(qinq_frame)

        # Nested protocols
        if self.is_request_enabled("Ethernet_Nested_Protocols") and fuzz_nested:
            self.session.connect(ipv4_frame)
            self.session.connect(ipv6_frame)
            self.session.connect(mpls_frame)

    def _get_monitors(self) -> List[BaseMonitor]:
        """Return list of monitors for Ethernet fuzzing"""
        # For raw Ethernet fuzzing, we typically don't have traditional monitors
        # Could implement packet capture based monitoring
        return []

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup Ethernet-specific monitors"""
        return self._get_monitors()
