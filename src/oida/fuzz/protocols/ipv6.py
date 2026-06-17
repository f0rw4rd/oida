"""IPv6 Protocol Fuzzer"""

import socket

from boofuzz import Block, Byte, DWord, Group, Request, Size, Static, Word

from typing import List

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..primitives.dynamic import SmartBytes, SmartString


class IPv6Fuzzer(BaseFuzzer):
    """IPv6 Protocol Fuzzer for IP layer security testing"""

    PROTOCOL_OPTIONS = {
        "hop_limit": {
            "type": int,
            "default": 64,
            "description": "Hop limit (IPv6 TTL)",
            "example": "255",
        },
        "next_header": {
            "type": int,
            "default": 6,
            "description": "Next header protocol (6=TCP, 17=UDP, 58=ICMPv6)",
            "choices": [0, 6, 17, 41, 43, 44, 50, 51, 58, 59, 60],
            "example": "58",
        },
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
        "source_mac": {
            "type": str,
            "default": "00:11:22:33:44:55",
            "description": "Source MAC address",
            "example": "aa:bb:cc:dd:ee:ff",
        },
        "dest_mac": {
            "type": str,
            "default": None,
            "description": "Destination MAC (auto-calculated for multicast)",
            "example": "33:33:00:00:00:01",
        },
        "include_ethernet": {
            "type": bool,
            "default": True,
            "description": "Include Ethernet header for raw sockets",
            "example": "false",
        },
        "traffic_class": {
            "type": int,
            "default": 0,
            "description": "Traffic class (DSCP + ECN)",
            "example": "46",
        },
        "flow_label": {
            "type": int,
            "default": 0,
            "description": "Flow label (20 bits)",
            "example": "12345",
        },
        "include_extensions": {
            "type": bool,
            "default": False,
            "description": "Include extension headers",
            "example": "true",
        },
        "extension_type": {
            "type": str,
            "default": "hop",
            "description": "Extension header type",
            "choices": ["hop", "routing", "fragment", "dest", "chain"],
            "example": "fragment",
        },
        "vlan_id": {
            "type": int,
            "default": None,
            "description": "VLAN ID for 802.1Q tagging",
            "example": "100",
        },
        "dhcpv6_mode": {
            "type": bool,
            "default": False,
            "description": "Include DHCPv6 fuzzing patterns",
            "example": "true",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Basic headers
            RequestInfo("IPv6_Basic", "Basic IPv6 packet", "standard"),
            RequestInfo("IPv6_Hop_by_Hop", "Hop-by-hop options header", "extension"),
            RequestInfo("IPv6_Routing", "Routing header", "extension"),
            RequestInfo("IPv6_Extension_Chain", "Extension header chain", "extension"),
            RequestInfo("IPv6_Fragment", "Fragment header", "extension"),
            # Transport protocols
            RequestInfo("IPv6_TCP", "IPv6 with TCP payload", "transport"),
            RequestInfo("IPv6_UDP", "IPv6 with UDP payload", "transport"),
            RequestInfo("IPv6_ICMPv6", "IPv6 with ICMPv6", "transport"),
            # Neighbor Discovery
            RequestInfo("IPv6_ND_Router_Solicitation", "Router solicitation", "nd"),
            RequestInfo("IPv6_ND_Neighbor_Solicitation", "Neighbor solicitation", "nd"),
            RequestInfo("IPv6_Router_Advertisement_Flood", "RA flood test", "nd"),
            # Attack patterns
            RequestInfo("IPv6_Malformed", "Malformed packets", "high_crash"),
            RequestInfo("IPv6_Jumbogram", "Jumbogram handling", "high_crash"),
            RequestInfo("IPv6_DHCPv6_Solicit", "DHCPv6 solicit", "dhcp"),
            RequestInfo("IPv6_MLD_Report", "MLD report", "multicast"),
            # CVE tests
            RequestInfo("IPv6_CVE_2020_17440_Payload_Length", "CVE-2020-17440", "cve"),
            RequestInfo("IPv6_Extension_Chain_Overflow", "Extension chain overflow", "cve"),
            RequestInfo("IPv6_HopByHop_Options_Overflow", "Hop-by-hop overflow", "cve"),
            RequestInfo("IPv6_Recursive_Fragmentation", "Recursive fragmentation", "cve"),
            RequestInfo("IPv6_Option_Removal_Overflow", "Option removal overflow", "cve"),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.RAW
        super().__init__(config, connection_factory)

    def _ipv6_to_bytes(self, ipv6_string):
        """Convert IPv6 address string to bytes"""
        try:
            return socket.inet_pton(socket.AF_INET6, ipv6_string)
        except (socket.error, OSError, ValueError) as e:
            # Return link-local if parsing fails
            self.log.debug(f"Failed to parse IPv6 address '{ipv6_string}': {e}")
            return socket.inet_pton(socket.AF_INET6, "fe80::1")

    def _mac_to_bytes(self, mac_string):
        """Convert MAC address string to bytes"""
        parts = mac_string.replace(":", "").replace("-", "")
        return bytes.fromhex(parts)

    def _get_multicast_mac(self, ipv6_addr):
        """Generate IPv6 multicast MAC from IPv6 address"""
        # For IPv6 multicast, MAC starts with 33:33 followed by last 4 bytes of IPv6
        ipv6_bytes = self._ipv6_to_bytes(ipv6_addr)
        return b"\x33\x33" + ipv6_bytes[-4:]

    def _define_protocol(self):
        """Define IPv6 protocol structure"""
        # Get protocol options
        hop_limit = self.config.get_option("hop_limit", 64)
        next_header = self.config.get_option("next_header", 6)  # TCP by default
        source_ip = self.config.get_option("source_ip", "fe80::1")
        dest_ip = self.config.get_option("dest_ip", "fe80::2")
        source_mac = self.config.get_option("source_mac", "00:11:22:33:44:55")
        dest_mac = self.config.get_option("dest_mac", None)  # Auto-calculate if None
        include_ethernet = self.config.get_option("include_ethernet", True)
        traffic_class = self.config.get_option("traffic_class", 0)
        flow_label = self.config.get_option("flow_label", 0)
        include_extensions = self.config.get_option("include_extensions", False)
        extension_type = self.config.get_option("extension_type", "hop")
        vlan_id = self.config.get_option("vlan_id", None)

        # Auto-calculate destination MAC for IPv6 multicast if not specified
        if dest_mac is None:
            if dest_ip.startswith("ff"):  # Multicast address
                dest_mac_bytes = self._get_multicast_mac(dest_ip)
            else:
                dest_mac_bytes = self._mac_to_bytes("ff:ff:ff:ff:ff:ff")  # Broadcast
        else:
            dest_mac_bytes = self._mac_to_bytes(dest_mac)

        # Basic IPv6 packet with optional Ethernet header
        ipv6_basic = Request(
            "IPv6_Basic",
            children=(
                # Ethernet Header (if enabled)
                Block(
                    "Ethernet_Header_Basic",
                    children=(
                        SmartBytes("Dest_MAC", dest_mac_bytes, size=6, fuzzable=True),
                        SmartBytes(
                            "Source_MAC", self._mac_to_bytes(source_mac), size=6, fuzzable=True
                        ),
                        # VLAN tag if specified
                        Block(
                            "VLAN_Tag",
                            children=(
                                Word("TPID", 0x8100, endian=">", fuzzable=False),  # 802.1Q
                                Word("TCI", (vlan_id & 0x0FFF) | 0x2000, endian=">", fuzzable=True),
                            ),
                        )
                        if vlan_id is not None
                        else Static("VLAN_Absent", ""),
                        Word("EtherType", 0x86DD, endian=">", fuzzable=True),  # IPv6
                    ),
                )
                if include_ethernet
                else Static("Ethernet_Absent", ""),
                Block(
                    "IPv6_Header",
                    children=(
                        # Version (6), Traffic Class, and Flow Label
                        # First 4 bits = version (6), next 8 bits = traffic class, last 20 bits = flow label
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        # Payload Length (dynamically calculated, excluding IPv6 header)
                        Size(
                            "Payload_Length",
                            block_name="Payload",
                            length=2,
                            endian=">",
                            inclusive=True,
                            offset=0,
                            fuzzable=False,
                        ),
                        # Next Header
                        Byte("Next_Header", next_header, fuzzable=True),
                        # Hop Limit
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        # Source IPv6 Address (128 bits)
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        # Destination IPv6 Address (128 bits)
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                # Payload
                Block(
                    "Payload",
                    children=(
                        SmartString("Data", "ipv6-payload-data", max_len=1400, fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv6 with Hop-by-Hop Options extension header
        if include_extensions and extension_type == "hop":
            ipv6_hop_by_hop = Request(
                "IPv6_Hop_by_Hop",
                children=(
                    Block(
                        "IPv6_Header",
                        children=(
                            DWord(
                                "Version_TC_FL",
                                (6 << 28) | (traffic_class << 20) | flow_label,
                                endian=">",
                                fuzzable=True,
                            ),
                            Word("Payload_Length", 8, endian=">", fuzzable=True),
                            Byte("Next_Header", 0, fuzzable=False),  # Hop-by-Hop
                            Byte("Hop_Limit", hop_limit, fuzzable=True),
                            SmartBytes(
                                "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    # Hop-by-Hop Options Header
                    Block(
                        "Hop_by_Hop",
                        children=(
                            Byte("Next_Header", next_header, fuzzable=True),
                            Byte("Hdr_Ext_Len", 0, fuzzable=True),  # 8-byte units minus 8
                            # Router Alert option
                            Byte("Option_Type", 0x05, fuzzable=True),
                            Byte("Option_Length", 2, fuzzable=True),
                            Word("Router_Alert_Value", 0, endian=">", fuzzable=True),
                            # Padding
                            Byte("PadN_Type", 1, fuzzable=True),
                            Byte("PadN_Length", 0, fuzzable=True),
                        ),
                    ),
                    Block(
                        "Payload",
                        children=(
                            SmartString("Data", "hop-by-hop-payload", max_len=1392, fuzzable=True),
                        ),
                    ),
                ),
            )

        # IPv6 with Routing extension header
        if include_extensions and extension_type == "routing":
            ipv6_routing = Request(
                "IPv6_Routing",
                children=(
                    Block(
                        "IPv6_Header",
                        children=(
                            DWord(
                                "Version_TC_FL",
                                (6 << 28) | (traffic_class << 20) | flow_label,
                                endian=">",
                                fuzzable=True,
                            ),
                            Word("Payload_Length", 24, endian=">", fuzzable=True),
                            Byte("Next_Header", 43, fuzzable=False),  # Routing
                            Byte("Hop_Limit", hop_limit, fuzzable=True),
                            SmartBytes(
                                "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    # Routing Header (Type 0 - deprecated but fuzzable)
                    Block(
                        "Routing_Header",
                        children=(
                            Byte("Next_Header", next_header, fuzzable=True),
                            Byte("Hdr_Ext_Len", 2, fuzzable=True),  # 24 bytes total
                            Byte("Routing_Type", 0, fuzzable=True),
                            Byte("Segments_Left", 1, fuzzable=True),
                            DWord("Reserved", 0, endian=">", fuzzable=True),
                            # Intermediate address
                            SmartBytes(
                                "Address1", self._ipv6_to_bytes("fe80::3"), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    Block(
                        "Payload",
                        children=(
                            SmartString("Data", "routing-payload", max_len=1376, fuzzable=True),
                        ),
                    ),
                ),
            )

        # Extension header chain (THC-IPv6 style)
        if include_extensions and extension_type == "chain":
            ipv6_chain = Request(
                "IPv6_Extension_Chain",
                children=(
                    Block(
                        "IPv6_Header",
                        children=(
                            DWord(
                                "Version_TC_FL",
                                (6 << 28) | (traffic_class << 20) | flow_label,
                                endian=">",
                                fuzzable=True,
                            ),
                            Word("Payload_Length", 48, endian=">", fuzzable=True),
                            Byte("Next_Header", 0, fuzzable=False),  # Hop-by-Hop
                            Byte("Hop_Limit", hop_limit, fuzzable=True),
                            SmartBytes(
                                "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    # Multiple chained extension headers (THC-IPv6 technique)
                    Block(
                        "Hop_by_Hop",
                        children=(
                            Byte("Next_Header", 43, fuzzable=True),  # Routing next
                            Byte("Hdr_Ext_Len", 0, fuzzable=True),
                            SmartBytes("Options", b"\x00" * 6, size=6, fuzzable=True),
                        ),
                    ),
                    Block(
                        "Routing",
                        children=(
                            Byte("Next_Header", 44, fuzzable=True),  # Fragment next
                            Byte("Hdr_Ext_Len", 2, fuzzable=True),
                            Byte("Routing_Type", 0, fuzzable=True),
                            Byte("Segments_Left", 1, fuzzable=True),
                            DWord("Reserved", 0, endian=">", fuzzable=True),
                            SmartBytes(
                                "Address", self._ipv6_to_bytes("fe80::99"), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    Block(
                        "Fragment",
                        children=(
                            Byte("Next_Header", next_header, fuzzable=True),
                            Byte("Reserved1", 0, fuzzable=True),
                            Word("Fragment_Offset_Flags", 0x0001, endian=">", fuzzable=True),
                            DWord("Identification", 0xDEADBEEF, endian=">", fuzzable=True),
                        ),
                    ),
                ),
            )

        # IPv6 with Fragment extension header
        if include_extensions and extension_type == "fragment":
            ipv6_fragment = Request(
                "IPv6_Fragment",
                children=(
                    Block(
                        "IPv6_Header",
                        children=(
                            DWord(
                                "Version_TC_FL",
                                (6 << 28) | (traffic_class << 20) | flow_label,
                                endian=">",
                                fuzzable=True,
                            ),
                            Word("Payload_Length", 16, endian=">", fuzzable=True),
                            Byte("Next_Header", 44, fuzzable=False),  # Fragment
                            Byte("Hop_Limit", hop_limit, fuzzable=True),
                            SmartBytes(
                                "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    # Fragment Header
                    Block(
                        "Fragment_Header",
                        children=(
                            Byte("Next_Header", next_header, fuzzable=True),
                            Byte("Reserved1", 0, fuzzable=True),
                            Word(
                                "Fragment_Offset_Flags", 0x0001, endian=">", fuzzable=True
                            ),  # M flag set
                            DWord("Identification", 0x12345678, endian=">", fuzzable=True),
                        ),
                    ),
                    Block(
                        "Fragment_Data",
                        children=(SmartBytes("Data", b"FRAGMENT", size=8, fuzzable=True),),
                    ),
                ),
            )

        # IPv6 with TCP payload
        ipv6_tcp = Request(
            "IPv6_TCP",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 20, endian=">", fuzzable=True),
                        Byte("Next_Header", 6, fuzzable=False),  # TCP
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "TCP_Header",
                    children=(
                        Word("Source_Port", 12345, endian=">", fuzzable=True),
                        Word("Dest_Port", 80, endian=">", fuzzable=True),
                        DWord("Sequence", 1, endian=">", fuzzable=True),
                        DWord("Acknowledgment", 0, endian=">", fuzzable=True),
                        Byte("Data_Offset_Reserved", 0x50, fuzzable=True),
                        Byte("Flags", 0x02, fuzzable=True),  # SYN
                        Word("Window", 8192, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Urgent", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv6 with UDP payload
        ipv6_udp = Request(
            "IPv6_UDP",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 8, endian=">", fuzzable=True),
                        Byte("Next_Header", 17, fuzzable=False),  # UDP
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "UDP_Header",
                    children=(
                        Word("Source_Port", 54321, endian=">", fuzzable=True),
                        Word("Dest_Port", 53, endian=">", fuzzable=True),
                        Word("Length", 8, endian=">", fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv6 with ICMPv6 payload
        ipv6_icmp = Request(
            "IPv6_ICMPv6",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 8, endian=">", fuzzable=True),
                        Byte("Next_Header", 58, fuzzable=False),  # ICMPv6
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "ICMPv6_Header",
                    children=(
                        Byte("Type", 128, fuzzable=True),  # Echo Request
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Identifier", 1, endian=">", fuzzable=True),
                        Word("Sequence", 1, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv6 Neighbor Discovery - Router Solicitation
        ipv6_nd_rs = Request(
            "IPv6_ND_Router_Solicitation",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 8, endian=">", fuzzable=True),
                        Byte("Next_Header", 58, fuzzable=False),  # ICMPv6
                        Byte("Hop_Limit", 255, fuzzable=True),  # Must be 255 for ND
                        SmartBytes("Source_IP", self._ipv6_to_bytes("::"), size=16, fuzzable=True),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes("ff02::2"), size=16, fuzzable=True
                        ),
                    ),
                ),
                Block(
                    "ICMPv6_RS",
                    children=(
                        Byte("Type", 133, fuzzable=True),  # Router Solicitation
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv6 Neighbor Discovery - Neighbor Solicitation
        ipv6_nd_ns = Request(
            "IPv6_ND_Neighbor_Solicitation",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 24, endian=">", fuzzable=True),
                        Byte("Next_Header", 58, fuzzable=False),  # ICMPv6
                        Byte("Hop_Limit", 255, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes("ff02::1:ff00:2"), size=16, fuzzable=True
                        ),
                    ),
                ),
                Block(
                    "ICMPv6_NS",
                    children=(
                        Byte("Type", 135, fuzzable=True),  # Neighbor Solicitation
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        DWord("Reserved", 0, endian=">", fuzzable=True),
                        # Target Address
                        SmartBytes(
                            "Target_Address", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # THC-IPv6 style Router Advertisement flooding
        ipv6_router_adv_flood = Request(
            "IPv6_Router_Advertisement_Flood",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 56, endian=">", fuzzable=True),
                        Byte("Next_Header", 58, fuzzable=False),  # ICMPv6
                        Byte("Hop_Limit", 255, fuzzable=False),  # Must be 255
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes("fe80::1337"), size=16, fuzzable=True
                        ),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes("ff02::1"), size=16, fuzzable=False
                        ),
                    ),
                ),
                Block(
                    "ICMPv6_RA",
                    children=(
                        Byte("Type", 134, fuzzable=False),  # Router Advertisement
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Byte("Cur_Hop_Limit", 64, fuzzable=True),
                        Byte("Flags", 0xC0, fuzzable=True),  # Managed + Other flags
                        Word("Router_Lifetime", 1800, endian=">", fuzzable=True),
                        DWord("Reachable_Time", 0, endian=">", fuzzable=True),
                        DWord("Retrans_Timer", 0, endian=">", fuzzable=True),
                        # Prefix Information Option
                        Byte("Option_Type", 3, fuzzable=True),
                        Byte("Option_Length", 4, fuzzable=True),
                        Byte("Prefix_Length", 64, fuzzable=True),
                        Byte("LA_Flags", 0xC0, fuzzable=True),  # L + A flags
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

        # Malformed IPv6 packets
        ipv6_malformed = Request(
            "IPv6_Malformed",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        # Invalid version (not 6)
                        DWord(
                            "Version_TC_FL",
                            (4 << 28) | (0xFF << 20) | 0xFFFFF,  # Version 4 with max values
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 0xFFFF, endian=">", fuzzable=True),
                        Byte("Next_Header", 255, fuzzable=True),  # Reserved
                        Byte("Hop_Limit", 0, fuzzable=True),
                        SmartBytes("Source_IP", b"\x00" * 16, size=16, fuzzable=True),
                        SmartBytes("Dest_IP", b"\xff" * 16, size=16, fuzzable=True),
                    ),
                ),
            ),
        )

        # IPv6 with Jumbogram (Payload > 65535 bytes)
        ipv6_jumbogram = Request(
            "IPv6_Jumbogram",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word(
                            "Payload_Length", 0, endian=">", fuzzable=True
                        ),  # 0 indicates jumbogram
                        Byte("Next_Header", 0, fuzzable=False),  # Hop-by-hop for jumbogram
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                # Hop-by-Hop with Jumbo Payload option
                Block(
                    "Hop_by_Hop_Jumbo",
                    children=(
                        Byte("Next_Header", next_header, fuzzable=True),
                        Byte("Hdr_Ext_Len", 0, fuzzable=True),
                        # Jumbo Payload option
                        Byte("Option_Type", 0xC2, fuzzable=True),
                        Byte("Option_Length", 4, fuzzable=True),
                        DWord("Jumbo_Length", 65536, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # THC-IPv6 style DHCPv6 fuzzing
        dhcpv6_mode = self.config.get_option("dhcpv6_mode", False)
        if dhcpv6_mode:
            ipv6_dhcpv6 = Request(
                "IPv6_DHCPv6_Solicit",
                children=(
                    Block(
                        "IPv6_Header",
                        children=(
                            DWord(
                                "Version_TC_FL",
                                (6 << 28) | (traffic_class << 20) | flow_label,
                                endian=">",
                                fuzzable=True,
                            ),
                            Word("Payload_Length", 48, endian=">", fuzzable=True),
                            Byte("Next_Header", 17, fuzzable=False),  # UDP
                            Byte("Hop_Limit", hop_limit, fuzzable=True),
                            SmartBytes(
                                "Source_IP", self._ipv6_to_bytes("fe80::1"), size=16, fuzzable=True
                            ),
                            SmartBytes(
                                "Dest_IP", self._ipv6_to_bytes("ff02::1:2"), size=16, fuzzable=True
                            ),
                        ),
                    ),
                    Block(
                        "UDP_Header",
                        children=(
                            Word("Source_Port", 546, endian=">", fuzzable=True),
                            Word("Dest_Port", 547, endian=">", fuzzable=False),
                            Word("Length", 40, endian=">", fuzzable=True),
                            Word("Checksum", 0, endian=">", fuzzable=True),
                        ),
                    ),
                    Block(
                        "DHCPv6_Message",
                        children=(
                            Byte("Message_Type", 1, fuzzable=True),  # Solicit
                            # Transaction ID
                            Byte("Transaction_ID_1", 0x12, fuzzable=True),
                            Byte("Transaction_ID_2", 0x34, fuzzable=True),
                            Byte("Transaction_ID_3", 0x56, fuzzable=True),
                            # Client Identifier Option
                            Word("Option_Code_DUID", 1, endian=">", fuzzable=True),
                            Word("Option_Length_DUID", 14, endian=">", fuzzable=True),
                            Word("DUID_Type", 3, endian=">", fuzzable=True),  # Link-layer
                            Word("Hardware_Type", 1, endian=">", fuzzable=True),
                            SmartBytes(
                                "Link_Layer_Address",
                                self._mac_to_bytes(source_mac),
                                size=6,
                                fuzzable=True,
                            ),
                            # Option Request Option
                            Word("Option_Code_ORO", 6, endian=">", fuzzable=True),
                            Word("Option_Length_ORO", 4, endian=">", fuzzable=True),
                            Word(
                                "Requested_Option_1", 23, endian=">", fuzzable=True
                            ),  # DNS servers
                            Word(
                                "Requested_Option_2", 24, endian=">", fuzzable=True
                            ),  # Domain list
                            # Elapsed Time Option
                            Word("Option_Code_Elapsed", 8, endian=">", fuzzable=True),
                            Word("Option_Length_Elapsed", 2, endian=">", fuzzable=True),
                            Word("Elapsed_Time", 0, endian=">", fuzzable=True),
                        ),
                    ),
                ),
            )

        # THC-IPv6 style MLD fuzzing
        ipv6_mld = Request(
            "IPv6_MLD_Report",
            children=(
                Block(
                    "IPv6_Header",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 36, endian=">", fuzzable=True),
                        Byte("Next_Header", 0, fuzzable=False),  # Hop-by-Hop
                        Byte("Hop_Limit", 1, fuzzable=False),  # Must be 1 for MLD
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes("ff02::16"), size=16, fuzzable=True
                        ),
                    ),
                ),
                # Hop-by-Hop with Router Alert
                Block(
                    "Hop_by_Hop_MLD",
                    children=(
                        Byte("Next_Header", 58, fuzzable=False),  # ICMPv6
                        Byte("Hdr_Ext_Len", 0, fuzzable=True),
                        Byte("Router_Alert_Type", 0x05, fuzzable=True),
                        Byte("Router_Alert_Length", 2, fuzzable=True),
                        Word("Router_Alert_Value", 0, endian=">", fuzzable=True),
                        Byte("PadN_Type", 1, fuzzable=True),
                        Byte("PadN_Length", 0, fuzzable=True),
                    ),
                ),
                Block(
                    "MLDv2_Report",
                    children=(
                        Byte("Type", 143, fuzzable=True),  # MLDv2 Report
                        Byte("Code", 0, fuzzable=True),
                        Word("Checksum", 0, endian=">", fuzzable=True),
                        Word("Reserved", 0, endian=">", fuzzable=True),
                        Word("Number_of_Records", 1, endian=">", fuzzable=True),
                        # Multicast Address Record
                        Byte("Record_Type", 4, fuzzable=True),  # ALLOW_NEW_SOURCES
                        Byte("Aux_Data_Len", 0, fuzzable=True),
                        Word("Number_of_Sources", 0, endian=">", fuzzable=True),
                        SmartBytes(
                            "Multicast_Address",
                            self._ipv6_to_bytes("ff02::1:3"),
                            size=16,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # Embedded Stack IPv6 Vulnerability Patterns

        # CVE-2020-17440 - picoTCP IPv6 payload length unchecked
        ipv6_payload_length_vuln = Request(
            "IPv6_CVE_2020_17440_Payload_Length",
            children=(
                Block(
                    "IPv6_Header_Payload_Vuln",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        # Critical: Payload length doesn't match actual data
                        Group(
                            "Payload_Length_Mismatch",
                            values=[
                                b"\xff\xff",
                                b"\xff\xfe",
                                b"\xff\xfd",  # Max values
                                b"\x80\x00",
                                b"\x7f\xff",
                                b"\x40\x00",  # Sign boundary
                                b"\x00\x01",
                                b"\x00\x00",  # Minimal values
                                b"\xff\xff",
                                b"\xff\xfe",
                                b"\x80\x00",
                                b"\x00\x01",
                                b"\x00\x00",  # Boundary testing
                            ],
                        ),
                        Byte("Next_Header", 6, fuzzable=False),  # TCP
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "Payload_Mismatch_Data",
                    children=(
                        # Actual payload much smaller/larger than claimed
                        SmartString(
                            "Mismatched_Payload", "test-payload", max_len=8192, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # Extension header chain length validation bypass
        ipv6_ext_chain_overflow = Request(
            "IPv6_Extension_Chain_Overflow",
            children=(
                Block(
                    "IPv6_Header_Chain",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 1000, endian=">", fuzzable=True),
                        Byte("Next_Header", 0, fuzzable=False),  # Hop-by-Hop (start chain)
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                # Critical: Long chain of extension headers to exhaust parsing
                Block(
                    "Extension_Chain_1",
                    children=(
                        Byte("Next_Header", 60, fuzzable=False),  # Destination Options
                        Byte("Hdr_Ext_Len", 250, fuzzable=True),  # Large extension header
                        SmartString("Chain_Data_1", "chain-data-1", max_len=1024, fuzzable=True),
                    ),
                ),
                Block(
                    "Extension_Chain_2",
                    children=(
                        Byte("Next_Header", 43, fuzzable=False),  # Routing
                        Byte("Hdr_Ext_Len", 250, fuzzable=True),
                        SmartString("Chain_Data_2", "chain-data-2", max_len=1024, fuzzable=True),
                    ),
                ),
                Block(
                    "Extension_Chain_3",
                    children=(
                        Byte("Next_Header", 6, fuzzable=False),  # Finally TCP
                        Byte("Hdr_Ext_Len", 250, fuzzable=True),
                        SmartString("Chain_Data_3", "chain-data-3", max_len=1024, fuzzable=True),
                    ),
                ),
            ),
        )

        # Hop-by-hop options parsing integer overflow
        ipv6_hopbyhop_overflow = Request(
            "IPv6_HopByHop_Options_Overflow",
            children=(
                Block(
                    "IPv6_Header_HopOpt",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 200, endian=">", fuzzable=True),
                        Byte("Next_Header", 0, fuzzable=False),  # Hop-by-Hop
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "HopByHop_Options_Overflow",
                    children=(
                        Byte("Next_Header", 6, fuzzable=False),  # TCP
                        # Critical: Extension length causing integer overflow
                        Group(
                            "Hdr_Ext_Len_Overflow",
                            values=[
                                b"\xff",
                                b"\xfe",
                                b"\xfd",
                                b"\xfc",  # Max 8-bit values
                                b"\x7f",
                                b"\x80",
                                b"\x81",  # Sign bit boundary
                                b"\xff",
                                b"\xfe",
                                b"\xfd",  # Overflow conditions
                            ],
                        ),
                        # Option that could cause parsing overflow
                        Byte("Option_Type", 0x01, fuzzable=True),  # PadN
                        Group(
                            "Option_Length_Overflow",
                            values=[
                                b"\xff",
                                b"\xfe",
                                b"\xfd",
                                b"\xfc",
                                b"\xc8",
                                b"\x64",
                                b"\x32",
                                b"\x7f",
                                b"\x80",
                                b"\xff",
                                b"\xfe",
                            ],
                        ),
                        SmartString(
                            "Option_Data_Overflow", "option-data", max_len=2048, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # Recursive fragmentation attack
        ipv6_recursive_fragment = Request(
            "IPv6_Recursive_Fragmentation",
            children=(
                Block(
                    "IPv6_Header_RecFrag",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 100, endian=">", fuzzable=True),
                        Byte("Next_Header", 44, fuzzable=False),  # Fragment
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "Fragment_Header_Recursive",
                    children=(
                        Byte(
                            "Next_Header", 44, fuzzable=False
                        ),  # Another Fragment header (recursive)
                        Byte("Reserved", 0, fuzzable=True),
                        # Critical: Fragment offset arithmetic overflow
                        Group(
                            "Fragment_Offset_Overflow",
                            values=[
                                b"\xff\xff",
                                b"\xff\xfe",
                                b"\xff\xf8",  # Max offset values
                                b"\x7f\xff",
                                b"\x80\x00",
                                b"\x80\x01",  # Sign boundary
                                b"\x00\x01",
                                b"\x00\x08",
                                b"\x00\x10",  # Minimal values
                            ],
                        ),
                        DWord("Identification", 0x12345678, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Second_Fragment_Header",
                    children=(
                        Byte("Next_Header", 6, fuzzable=False),  # TCP (finally)
                        Byte("Reserved", 0, fuzzable=True),
                        Word(
                            "Fragment_Offset_Flags", 0x0000, endian=">", fuzzable=True
                        ),  # Last fragment
                        DWord("Identification", 0x12345678, endian=">", fuzzable=True),
                    ),
                ),
                Block(
                    "Fragment_Data_Recursive",
                    children=(
                        SmartString(
                            "Fragmented_Data", "fragment-data", max_len=2048, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # Integer overflow in IPv6 option removal (FreeRTOS+TCP pattern)
        ipv6_option_removal_overflow = Request(
            "IPv6_Option_Removal_Overflow",
            children=(
                Block(
                    "IPv6_Header_OptRem",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=True,
                        ),
                        Word("Payload_Length", 150, endian=">", fuzzable=True),
                        Byte("Next_Header", 60, fuzzable=False),  # Destination Options
                        Byte("Hop_Limit", hop_limit, fuzzable=True),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=True
                        ),
                        SmartBytes("Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=True),
                    ),
                ),
                Block(
                    "Destination_Options_Removal",
                    children=(
                        Byte("Next_Header", 6, fuzzable=False),  # TCP
                        # Critical: Header length that causes underflow when removed
                        Group(
                            "Hdr_Ext_Len_Underflow",
                            values=[
                                b"\x00",
                                b"\x01",
                                b"\x02",
                                b"\x03",  # Very small values
                                b"\xff",
                                b"\xfe",
                                b"\xfd",  # Values that wrap when subtracted
                            ],
                        ),
                        # Multiple options that trigger removal logic
                        Byte("Option1_Type", 0x00, fuzzable=True),  # Pad1
                        Byte("Option2_Type", 0x01, fuzzable=True),  # PadN
                        Byte("Option2_Length", 4, fuzzable=True),
                        DWord("Option2_Data", 0x41414141, endian=">", fuzzable=True),
                        # More options to trigger complex removal
                        SmartString(
                            "Additional_Options", "additional-options", max_len=1024, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # Incorrect Payload Length Test - tests length field validation logic
        ipv6_incorrect_length = Request(
            "IPv6_Incorrect_Length",
            children=(
                Block(
                    "IPv6_Header_BadLength",
                    children=(
                        DWord(
                            "Version_TC_FL",
                            (6 << 28) | (traffic_class << 20) | flow_label,
                            endian=">",
                            fuzzable=False,
                        ),
                        # Intentionally incorrect payload length values
                        Group(
                            "Bad_Payload_Length",
                            values=[
                                b"\x00\x00",  # 0 bytes (too small, but not jumbogram)
                                b"\x00\x08",  # 8 bytes (smaller than actual payload)
                                b"\xff\xff",  # 65535 bytes (maximum, way too large)
                                b"\x80\x00",  # 32768 bytes (sign boundary)
                                b"\x00\x01",  # 1 byte (way too small)
                            ],
                        ),
                        Byte("Next_Header", next_header, fuzzable=False),
                        Byte("Hop_Limit", hop_limit, fuzzable=False),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=False
                        ),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=False
                        ),
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

        # Quick-coverage requests: single pass through all packet types with
        # minimal mutations so every code path is touched early.
        ipv6_quick_coverage = Request(
            "IPv6_Quick_Coverage",
            children=(
                # Quick sweep: One packet for each major type with fuzzable=False
                # This ensures all code paths are touched within first 30 seconds
                # Basic IPv6 Header (minimal)
                Block(
                    "Quick_IPv6_Header",
                    children=(
                        DWord("Version_TC_FL", (6 << 28), endian=">", fuzzable=False),
                        Word("Payload_Length", 8, endian=">", fuzzable=False),
                        # Cycle through all major Next Header values
                        Group(
                            "Quick_Next_Headers",
                            values=[
                                b"\x06",  # TCP
                                b"\x11",  # UDP
                                b"\x3a",  # ICMPv6
                                b"\x00",  # Hop-by-Hop
                                b"\x2b",  # Routing
                                b"\x2c",  # Fragment
                                b"\x32",  # ESP
                                b"\x33",  # AH
                                b"\x3b",  # No Next Header
                                b"\x3c",  # Destination Options
                                b"\x29",  # IPv6 encapsulation
                                b"\xff",  # Reserved (malformed)
                            ],
                        ),
                        Byte("Hop_Limit", hop_limit, fuzzable=False),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=False
                        ),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes(dest_ip), size=16, fuzzable=False
                        ),
                    ),
                ),
                Block(
                    "Quick_Payload",
                    children=(SmartBytes("Data", b"QUICKCOV", size=8, fuzzable=False),),
                ),
            ),
        )

        # Quick ICMPv6 type sweep (ND, MLD, Echo, etc.)
        ipv6_quick_icmpv6_types = Request(
            "IPv6_Quick_ICMPv6_Types",
            children=(
                Block(
                    "Quick_ICMPv6_Header",
                    children=(
                        DWord("Version_TC_FL", (6 << 28), endian=">", fuzzable=False),
                        Word("Payload_Length", 8, endian=">", fuzzable=False),
                        Byte("Next_Header", 58, fuzzable=False),
                        Byte("Hop_Limit", 255, fuzzable=False),
                        SmartBytes(
                            "Source_IP", self._ipv6_to_bytes(source_ip), size=16, fuzzable=False
                        ),
                        SmartBytes(
                            "Dest_IP", self._ipv6_to_bytes("ff02::1"), size=16, fuzzable=False
                        ),
                    ),
                ),
                Block(
                    "Quick_ICMPv6_Payload",
                    children=(
                        # Cycle through all major ICMPv6 types
                        Group(
                            "Quick_ICMPv6_Type",
                            values=[
                                b"\x80",  # Echo Request
                                b"\x81",  # Echo Reply
                                b"\x85",  # Router Solicitation
                                b"\x86",  # Router Advertisement
                                b"\x87",  # Neighbor Solicitation
                                b"\x88",  # Neighbor Advertisement
                                b"\x89",  # Redirect
                                b"\x8f",  # MLDv2 Report
                                b"\x82",  # MLD Query
                                b"\x83",  # MLD Report
                                b"\x84",  # MLD Done
                                b"\x01",  # Destination Unreachable
                                b"\x02",  # Packet Too Big
                                b"\x03",  # Time Exceeded
                                b"\x04",  # Parameter Problem
                            ],
                        ),
                        Byte("Code", 0, fuzzable=False),
                        Word("Checksum", 0, endian=">", fuzzable=False),
                        DWord("Reserved", 0, endian=">", fuzzable=False),
                    ),
                ),
            ),
        )

        # =============================================================
        # Connect requests in mutation order. boofuzz fuzzes requests in
        # connect() order, so earlier groups are exercised first; the
        # group labels below are ordering buckets, not a wall-clock schedule.
        # =============================================================

        # Quick coverage first (broad, shallow)
        self.session.connect(ipv6_quick_coverage)
        self.session.connect(ipv6_quick_icmpv6_types)

        # High-crash tests next - CVE and overflow patterns
        # These have highest probability of finding crashes
        if self.is_request_enabled("IPv6_CVE_2020_17440_Payload_Length"):
            self.session.connect(ipv6_payload_length_vuln)  # CVE-2020-17440
        if self.is_request_enabled("IPv6_Extension_Chain_Overflow"):
            self.session.connect(ipv6_ext_chain_overflow)  # Extension chain overflow
        if self.is_request_enabled("IPv6_HopByHop_Options_Overflow"):
            self.session.connect(ipv6_hopbyhop_overflow)  # Hop-by-hop overflow
        if self.is_request_enabled("IPv6_Recursive_Fragmentation"):
            self.session.connect(ipv6_recursive_fragment)  # Recursive fragment attack
        if self.is_request_enabled("IPv6_Option_Removal_Overflow"):
            self.session.connect(ipv6_option_removal_overflow)  # Option removal overflow
        if self.is_request_enabled("IPv6_Malformed"):
            self.session.connect(ipv6_malformed)  # Malformed packets

        # CVE-targeted operations: length validation, jumbograms, RA flooding
        self.session.connect(ipv6_incorrect_length)  # Length validation bypass
        if self.is_request_enabled("IPv6_Jumbogram"):
            self.session.connect(ipv6_jumbogram)  # Jumbogram handling
        if self.is_request_enabled("IPv6_Router_Advertisement_Flood"):
            self.session.connect(ipv6_router_adv_flood)  # RA flooding (THC-IPv6 style)

        # Boundary attacks: extension-header fuzzing with full mutation
        if include_extensions:
            if extension_type == "fragment" and self.is_request_enabled("IPv6_Fragment"):
                self.session.connect(ipv6_fragment)
            elif extension_type == "hop" and self.is_request_enabled("IPv6_Hop_by_Hop"):
                self.session.connect(ipv6_hop_by_hop)
            elif extension_type == "routing" and self.is_request_enabled("IPv6_Routing"):
                self.session.connect(ipv6_routing)
            elif extension_type == "chain" and self.is_request_enabled("IPv6_Extension_Chain"):
                self.session.connect(ipv6_chain)

        # Standard protocol tests last: lower crash probability but important
        # for coverage of the basic packet types
        if self.is_request_enabled("IPv6_Basic"):
            self.session.connect(ipv6_basic)
        if self.is_request_enabled("IPv6_TCP"):
            self.session.connect(ipv6_tcp)
        if self.is_request_enabled("IPv6_UDP"):
            self.session.connect(ipv6_udp)
        if self.is_request_enabled("IPv6_ICMPv6"):
            self.session.connect(ipv6_icmp)
        if self.is_request_enabled("IPv6_ND_Router_Solicitation"):
            self.session.connect(ipv6_nd_rs)
        if self.is_request_enabled("IPv6_ND_Neighbor_Solicitation"):
            self.session.connect(ipv6_nd_ns)
        if self.is_request_enabled("IPv6_MLD_Report"):
            self.session.connect(ipv6_mld)
        if dhcpv6_mode and self.is_request_enabled("IPv6_DHCPv6_Solicit"):
            self.session.connect(ipv6_dhcpv6)
