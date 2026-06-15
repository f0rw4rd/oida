"""DHCP Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.
Test ordering follows the 5-phase optimization strategy:
- Phase 1: Quick message type sweep (all 8 types in ~30 sec)
- Phase 2: High-crash tests (overflow, buffer attacks, option chain)
- Phase 3: CVE-targeted operations (option parsing, refcount attacks)
- Phase 4: Boundary attacks (length fields, option limits)
- Phase 5: Remaining tests (vendor, extended, resource exhaustion)

CVE Coverage:
- CVE-2004-0460: DHCPD logging buffer overflow (Phase 2)
- CVE-2022-2928: Option refcount overflow (Phase 3)
- CVE-2020-25681/25682: dnsmasq heap overflow via DNS (Phase 2)
- CVE-2011-0997: dhclient script_write_params overflow (Phase 2)

Message Types Covered (Phase 1 Quick Coverage):
- DISCOVER (1), OFFER (2), REQUEST (3), DECLINE (4)
- ACK (5), NAK (6), RELEASE (7), INFORM (8)
"""

from typing import List

from boofuzz import Block, Byte, DWord, Group, QWord, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import UDPSocketConnection
from ..primitives.dynamic import SmartString


class DHCPFuzzer(BaseFuzzer):
    """DHCP Protocol Fuzzer for network configuration security testing

    Targets DHCP vulnerabilities including option parsing, message type
    confusion, buffer overflows, and resource exhaustion attacks.

    Test Ordering (Optimized for Early Coverage):
    - Phase 1: Quick_Coverage touches all 8 message types in ~30 seconds
    - Phase 2: Buffer overflow and malformed option tests (high crash likelihood)
    - Phase 3: CVE-targeted option parsing (CVE-2022-2928, CVE-2004-0460)
    - Phase 4: Boundary value attacks (length fields, limits)
    - Phase 5: Vendor, extended options, resource exhaustion

    DHCP uses UDP port 67 (server) / port 68 (client) by default.
    """

    # Protocol-specific monitor: DHCP discover check every 50 tests
    DEFAULT_MONITORS = "dhcp:50"

    PROTOCOL_OPTIONS = {
        "timeout": {
            "type": float,
            "default": 5.0,
            "description": "Response timeout in seconds",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage (~30 sec)
            RequestInfo("DHCP_Quick_Coverage", "Quick sweep of all 8 message types", "baseline"),
            RequestInfo("DHCP_DISCOVER", "DHCP discovery request", "baseline"),
            # Phase 2: High-crash tests (~3 min)
            RequestInfo(
                "DHCP_MALFORMED_OPTIONS",
                "Malformed options buffer overflow (CVE-2004-0460)",
                "overflow",
            ),
            RequestInfo("DHCP_OPTION_CHAIN", "Option chain parser overflow attack", "overflow"),
            RequestInfo(
                "DHCP_MALFORMED_EXTENDED", "Malformed extended options (CVE-2022-2928)", "overflow"
            ),
            RequestInfo("DHCP_Hostname_Overflow", "Hostname option buffer overflow", "overflow"),
            # Phase 3: CVE-targeted operations (~3 min)
            RequestInfo("DHCP_OPTION_INJECTION", "Option value injection attacks", "cve"),
            RequestInfo(
                "DHCP_INVALID_MESSAGE_TYPE", "Invalid message type protocol confusion", "cve"
            ),
            RequestInfo("DHCP_Option_Refcount", "Option refcount overflow (CVE-2022-2928)", "cve"),
            # Phase 4: Boundary attacks (~3 min)
            RequestInfo(
                "DHCP_Length_Boundary", "Option length boundary testing (0, 255, 256)", "boundary"
            ),
            RequestInfo("DHCP_Field_Boundary", "Header field boundary values", "boundary"),
            # Phase 5: Remaining tests
            RequestInfo("DHCP_REQUEST", "DHCP configuration request", "standard"),
            RequestInfo("DHCP_RELEASE", "DHCP IP release", "standard"),
            RequestInfo("DHCP_VENDOR_SPECIFIC", "Vendor-specific information fuzzing", "vendor"),
            RequestInfo(
                "DHCP_EXTENDED_OPTIONS",
                "Extended option fuzzing (RFC 3046, 4702, 3118)",
                "extended",
            ),
            RequestInfo("DHCP_RESOURCE_EXHAUSTION", "Resource exhaustion attacks", "dos"),
        ]

    def _create_socket(self):
        # DHCP clients need to bind to a local port to receive responses
        # Using port 0 lets the OS assign an ephemeral port, or use port 68 (standard DHCP client port)
        # Also set recv_timeout to ensure we wait for responses
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),
            **self._timeout_overrides(recv_default=5.0),
        )

    def setup_custom_monitors(self) -> list:
        """Setup DHCP-specific monitoring with DISCOVER/OFFER validation"""
        from ..monitors import DHCPDiscoverMonitor

        dhcp_monitor = DHCPDiscoverMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            timeout=2,
            check_interval=3,  # Check every 3 test cases
        )

        return [dhcp_monitor]

    def _create_dhcp_header(self, name_suffix="", xid=0x12345678, ciaddr=0, flags=0x8000):
        """Create common DHCP header block to reduce code duplication"""
        return Block(
            f"DHCP_Header{name_suffix}",
            children=(
                Byte("op", 0x01),  # Boot request
                Byte("htype", 0x01),  # Ethernet hardware type
                Byte("hlen", 0x06),  # Hardware address length
                Byte("hops", 0x00),  # Hops
                DWord("xid", xid, endian=">"),  # Transaction ID
                Word("secs", 0x0000, endian=">"),  # Seconds
                Word("flags", flags, endian=">"),  # Broadcast flag
                DWord("ciaddr", ciaddr, endian=">"),  # Client IP
                DWord("yiaddr", 0x00000000, endian=">"),  # Your IP
                DWord("siaddr", 0x00000000, endian=">"),  # Server IP
                DWord("giaddr", 0x00000000, endian=">"),  # Gateway IP
                # Client hardware address (16 bytes, padded)
                Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                # Server name (64 bytes)
                Static("sname", b"\x00" * 64),
                # Boot filename (128 bytes)
                Static("file", b"\x00" * 128),
                # DHCP Magic Cookie
                DWord("magic_cookie", 0x63825363, endian=">"),
            ),
        )

    def _define_protocol(self) -> None:
        """Define DHCP protocol structure with optimized test ordering.

        Test ordering follows the 5-phase optimization strategy:
        - Phase 1: Quick_Coverage + DISCOVER (all 8 message types)
        - Phase 2: High-crash tests (overflow, buffer, option chain)
        - Phase 3: CVE-targeted operations (injection, refcount)
        - Phase 4: Boundary attacks
        - Phase 5: Standard operations, vendor, extended, exhaustion
        """

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Quick sweep of all 8 DHCP message types in one request
        # Goal: Touch every message type in first 30 seconds for maximum breadth

        dhcp_quick_coverage = Request(
            "DHCP_Quick_Coverage",
            children=(
                self._create_dhcp_header("_Quick"),
                Block(
                    "DHCP_Quick_Options",
                    children=(
                        # Message Type Option (53) - cycles through all 8 types
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Group(
                            "message_type_sweep",
                            values=[
                                b"\x01",  # DISCOVER
                                b"\x02",  # OFFER (server response, tests client code path)
                                b"\x03",  # REQUEST
                                b"\x04",  # DECLINE
                                b"\x05",  # ACK (server response)
                                b"\x06",  # NAK (server response)
                                b"\x07",  # RELEASE
                                b"\x08",  # INFORM
                            ],
                        ),
                        # Minimal options to keep tests fast
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 1. DHCP Discover - Client requesting IP configuration
        dhcp_discover = Request(
            "DHCP_DISCOVER",
            children=(
                Block(
                    "DHCP_Header",
                    children=(
                        Byte("op", 0x01),  # Boot request
                        Byte("htype", 0x01),  # Ethernet hardware type
                        Byte("hlen", 0x06),  # Hardware address length
                        Byte("hops", 0x00),  # Hops
                        DWord("xid", 0x12345678, endian=">"),  # Transaction ID
                        Word("secs", 0x0000, endian=">"),  # Seconds
                        Word("flags", 0x8000, endian=">"),  # Broadcast flag
                        DWord("ciaddr", 0x00000000, endian=">"),  # Client IP
                        DWord("yiaddr", 0x00000000, endian=">"),  # Your IP
                        DWord("siaddr", 0x00000000, endian=">"),  # Server IP
                        DWord("giaddr", 0x00000000, endian=">"),  # Gateway IP
                        # Client hardware address (16 bytes, padded)
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        # Server name (64 bytes)
                        Static("sname", b"\x00" * 64),
                        # Boot filename (128 bytes)
                        Static("file", b"\x00" * 128),
                        # DHCP Magic Cookie
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Options",
                    children=(
                        # Message Type Option (53)
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),  # DHCPDISCOVER
                        # Parameter Request List Option (55)
                        Byte("option_55_code", 55),
                        Byte("option_55_length", 4),
                        Byte("subnet_mask", 1),  # Subnet Mask
                        Byte("router", 3),  # Router
                        Byte("dns_server", 6),  # DNS Server
                        Byte("domain_name", 15),  # Domain Name
                        # Client Identifier Option (61)
                        Byte("option_61_code", 61),
                        Byte("option_61_length", 7),
                        Byte("hw_type", 1),  # Ethernet
                        Static("client_id", b"\x00\x11\x22\x33\x44\x55"),
                        # End Option (255)
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 2. DHCP Request - Client requesting specific configuration
        dhcp_request = Request(
            "DHCP_REQUEST",
            children=(
                Block(
                    "DHCP_Header_Request",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Options_Request",
                    children=(
                        # Message Type (DHCPREQUEST)
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 3),  # DHCPREQUEST
                        # Requested IP Address Option (50)
                        Byte("option_50_code", 50),
                        Byte("option_50_length", 4),
                        DWord("requested_ip", 0xC0A80164, endian=">"),  # 192.168.1.100
                        # Server Identifier Option (54)
                        Byte("option_54_code", 54),
                        Byte("option_54_length", 4),
                        DWord("server_id", 0xC0A80101, endian=">"),  # 192.168.1.1
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 3. DHCP Release - Client releasing IP
        dhcp_release = Request(
            "DHCP_RELEASE",
            children=(
                Block(
                    "DHCP_Header_Release",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        DWord("ciaddr", 0xC0A80164, endian=">"),  # Client IP to release
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Options_Release",
                    children=(
                        # Message Type (DHCPRELEASE)
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 7),  # DHCPRELEASE
                        # Server Identifier
                        Byte("option_54_code", 54),
                        Byte("option_54_length", 4),
                        DWord("server_id", 0xC0A80101, endian=">"),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 4. DHCP Malformed Options - Buffer overflow testing
        dhcp_malformed = Request(
            "DHCP_MALFORMED_OPTIONS",
            children=(
                Block(
                    "DHCP_Header_Malformed",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Malformed_Options",
                    children=(
                        # Oversized option length
                        Byte("hostname_option", 12),
                        Byte("oversized_length", 255),  # Invalid length
                        SmartString("oversized_hostname", "dhcp-oversized-hostname", max_len=1000),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 5. DHCP Option Injection - Malicious option values
        dhcp_injection = Request(
            "DHCP_OPTION_INJECTION",
            children=(
                Block(
                    "DHCP_Header_Injection",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Injection_Options",
                    children=(
                        # Message Type
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        # Hostname Option (12) - SmartString will fuzz this
                        Byte("hostname_option", 12),
                        Byte("hostname_length", 20),
                        SmartString("hostname", "testhost", max_len=100, fuzzable=True),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 6. DHCP Vendor Specific Information - Option 43 fuzzing
        dhcp_vendor = Request(
            "DHCP_VENDOR_SPECIFIC",
            children=(
                Block(
                    "DHCP_Header_Vendor",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Vendor_Options",
                    children=(
                        # Message Type
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        # Vendor Class Identifier (60)
                        Byte("option_60_code", 60),
                        Byte("option_60_length", 12),
                        SmartString("vendor_class", "MSFT 5.0", max_len=12),
                        # Vendor Specific Information (43)
                        Byte("option_43_code", 43),
                        Byte("option_43_length", 50),
                        SmartString(
                            "vendor_specific_data", "dhcp-vendor-specific", max_len=50
                        ),  # Potential overflow
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 7. DHCP Invalid Message Types - Protocol confusion
        dhcp_invalid = Request(
            "DHCP_INVALID_MESSAGE_TYPE",
            children=(
                Block(
                    "DHCP_Header_Invalid",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Invalid_Options",
                    children=(
                        # Invalid Message Type
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Group(
                            "invalid_message_types",
                            values=[
                                b"\x00",  # Invalid
                                b"\x09",  # Reserved
                                b"\xff",  # Invalid
                                b"\x64",  # Out of range
                                b"\xff",  # Max value (was -1, wraps to 255)
                            ],
                        ),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 8. DHCP Resource Exhaustion - Multiple requests
        dhcp_exhaustion = Request(
            "DHCP_RESOURCE_EXHAUSTION",
            children=(
                Block(
                    "DHCP_Header_Exhaustion",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        # Different MAC addresses for each request
                        SmartString("mac_prefix", "\x00\x11\x22\x33\x44", max_len=5),
                        Byte("mac_suffix", 0x00),  # Will be fuzzed
                        Static("chaddr_padding", b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Exhaustion_Options",
                    children=(
                        # Message Type (DHCPDISCOVER)
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        # Client Identifier with varying values
                        Byte("option_61_code", 61),
                        Byte("option_61_length", 7),
                        Byte("hw_type", 1),
                        SmartString("client_mac_prefix", "\x00\x11\x22\x33\x44", max_len=5),
                        Byte("client_mac_suffix", 0x00),  # Will be fuzzed
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 9. DHCP with Additional Options - Extended option fuzzing
        dhcp_extended_options = Request(
            "DHCP_EXTENDED_OPTIONS",
            children=(
                Block(
                    "DHCP_Header_Extended",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Extended_Options",
                    children=(
                        # Message Type
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        # Maximum DHCP Message Size (57)
                        Byte("option_57_code", 57),
                        Byte("option_57_length", 2),
                        Word("max_message_size", 1500, endian=">"),
                        # Renewal (T1) Time Value (58)
                        Byte("option_58_code", 58),
                        Byte("option_58_length", 4),
                        DWord("renewal_time", 3600, endian=">"),
                        # Rebinding (T2) Time Value (59)
                        Byte("option_59_code", 59),
                        Byte("option_59_length", 4),
                        DWord("rebinding_time", 6300, endian=">"),
                        # Relay Agent Information (82) - RFC 3046
                        Byte("option_82_code", 82),
                        Byte("option_82_length", 20),
                        # Agent Circuit ID Sub-option
                        Byte("circuit_id_subopt", 1),
                        Byte("circuit_id_length", 8),
                        SmartString("circuit_id", "switch01", max_len=8, fuzzable=True),
                        # Agent Remote ID Sub-option
                        Byte("remote_id_subopt", 2),
                        Byte("remote_id_length", 8),
                        SmartString("remote_id", "port001", max_len=8, fuzzable=True),
                        # Client FQDN (81) - RFC 4702
                        Byte("option_81_code", 81),
                        Byte("option_81_length", 20),
                        Byte("fqdn_flags", 0x03),  # S and O flags
                        Byte("rcode1", 0),
                        Byte("rcode2", 0),
                        SmartString("fqdn", "client.example.com", max_len=17, fuzzable=True),
                        # Authentication (90) - RFC 3118
                        Byte("option_90_code", 90),
                        Byte("option_90_length", 16),
                        Byte("auth_protocol", 1),  # Delayed authentication
                        Byte("auth_algorithm", 1),  # HMAC-MD5
                        Byte("rdm", 0),
                        QWord("replay_detection", 0x123456789ABCDEF0, endian=">"),
                        Byte("auth_info_length", 4),
                        DWord("auth_info", 0xDEADBEEF, endian=">"),
                        # PXE Options (93-97)
                        Byte("option_93_code", 93),  # Client System Architecture
                        Byte("option_93_length", 2),
                        Word("arch_type", 0x0007, endian=">"),  # EFI x86-64
                        Byte("option_94_code", 94),  # Client Network Interface
                        Byte("option_94_length", 3),
                        Byte("undi_major", 3),
                        Byte("undi_minor", 1),
                        Byte("undi_type", 1),
                        # Auto-Configure (116) - RFC 2563
                        Byte("option_116_code", 116),
                        Byte("option_116_length", 1),
                        Byte("auto_configure", 1),  # DoNotAutoConfigure
                        # Captive Portal (160) - RFC 7710
                        Byte("option_160_code", 160),
                        Byte("option_160_length", 20),
                        SmartString(
                            "captive_portal_uri", "http://portal.local", max_len=20, fuzzable=True
                        ),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # 10. DHCP with Malformed Extended Options
        dhcp_malformed_extended = Request(
            "DHCP_MALFORMED_EXTENDED",
            children=(
                Block(
                    "DHCP_Header_Mal_Ext",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0x12345678, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Malformed_Ext_Options",
                    children=(
                        # Message Type
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        # Malformed Relay Agent Information (82)
                        Byte("option_82_code", 82),
                        Byte("option_82_length", 255, fuzzable=True),  # Oversized length
                        SmartString(
                            "malformed_relay_data", "relay-agent-info", max_len=1000, fuzzable=True
                        ),
                        # Invalid Option Code
                        Byte("invalid_option_code", 254, fuzzable=True),
                        Byte("invalid_option_length", 100, fuzzable=True),
                        SmartString(
                            "invalid_option_data", "invalid-option", max_len=500, fuzzable=True
                        ),
                        # Option with Zero Length
                        Byte("zero_length_option", 119),
                        Byte("zero_length", 0),
                        # Option without End
                        Byte("no_end_option", 120),
                        Byte("no_end_length", 10),
                        SmartString("no_end_data", "dhcp-option-data", max_len=10),
                        # No end option here
                    ),
                ),
            ),
        )

        # DHCP Option Chaining - Tests option parser with excessive options (exploitdb pattern)
        # Generates packets with 100+ options to trigger parser overflow vulnerabilities
        dhcp_option_chain = Request(
            "DHCP_OPTION_CHAIN",
            children=(
                Block(
                    "DHCP_Header_Chain",
                    children=(
                        Byte("op", 0x01),
                        Byte("htype", 0x01),
                        Byte("hlen", 0x06),
                        Byte("hops", 0x00),
                        DWord("xid", 0xABCDEF00, endian=">"),
                        Word("secs", 0x0000, endian=">"),
                        Word("flags", 0x8000, endian=">"),
                        DWord("ciaddr", 0x00000000, endian=">"),
                        DWord("yiaddr", 0x00000000, endian=">"),
                        DWord("siaddr", 0x00000000, endian=">"),
                        DWord("giaddr", 0x00000000, endian=">"),
                        Static("chaddr", b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10),
                        Static("sname", b"\x00" * 64),
                        Static("file", b"\x00" * 128),
                        DWord("magic_cookie", 0x63825363, endian=">"),
                    ),
                ),
                Block(
                    "DHCP_Options_Chained",
                    children=(
                        # Message Type
                        Byte("opt_53_code", 53),
                        Byte("opt_53_len", 1),
                        Byte("opt_53_val", 1),
                        # Generate many option chains to stress parser (200+ options)
                        # Using repeating patterns of valid option codes with varying lengths
                        Group(
                            "option_chain",
                            values=[
                                # Chain 1: 50 options (option code 119-224 are private/reserved)
                                b"".join(
                                    [bytes([i, 1, 0xFF]) for i in range(119, 169)]
                                ),  # 50 opts * 3 bytes = 150 bytes
                                # Chain 2: 100 options (duplicate option codes - parser stress test)
                                b"".join(
                                    [bytes([12, 4, 192, 168, 1, 1]) for _ in range(100)]
                                ),  # 100 * 6 bytes = 600 bytes
                                # Chain 3: Mixed length options
                                b"".join(
                                    [
                                        bytes([150 + i % 20, (i % 10) + 1] + [0xFF] * (i % 10 + 1))
                                        for i in range(80)
                                    ]
                                ),  # 80 varied opts
                                # Chain 4: Option 82 sub-option nesting (relay agent)
                                bytes([82, 200])
                                + bytes(range(200)),  # Option 82 with 200 byte payload
                                # Chain 5: Duplicate standard options (e.g., multiple DNS servers)
                                b"".join(
                                    [bytes([6, 4, 8, 8, 8, 8]) for _ in range(50)]
                                ),  # 50 DNS option duplicates
                            ],
                        ),
                        # End option
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # ==================== PHASE 2 ADDITIONS: HIGH-CRASH TESTS ====================

        # Hostname Option Buffer Overflow (CVE-2004-0460 pattern)
        # Tests logging buffer overflow via hostname option
        dhcp_hostname_overflow = Request(
            "DHCP_Hostname_Overflow",
            children=(
                self._create_dhcp_header("_Hostname"),
                Block(
                    "DHCP_Hostname_Options",
                    children=(
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),  # DISCOVER
                        # Hostname Option (12) with oversized values
                        Byte("hostname_option", 12),
                        Group(
                            "hostname_lengths",
                            values=[
                                # Length/data combinations to trigger buffer overflow
                                b"\xff" + b"A" * 255,  # Max length with data
                                b"\x00",  # Zero length
                                b"\x01" + b"A" * 500,  # Short length, long data (mismatch)
                                b"\xff" + b"A" * 1000,  # Extreme overflow attempt
                                b"\x80" + b"%" * 128,  # Format string + length
                            ],
                        ),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # ==================== PHASE 3 ADDITIONS: CVE-TARGETED ====================

        # Option Refcount Overflow (CVE-2022-2928 pattern)
        # Repeated lease queries can overflow option refcount
        dhcp_option_refcount = Request(
            "DHCP_Option_Refcount",
            children=(
                self._create_dhcp_header("_Refcount", xid=0xDEADBEEF),
                Block(
                    "DHCP_Refcount_Options",
                    children=(
                        # Message Type - INFORM triggers different code path
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 8),  # INFORM - used in lease queries
                        # Client identifier to enable tracking
                        Byte("option_61_code", 61),
                        Byte("option_61_length", 7),
                        Byte("hw_type", 1),
                        Static("client_id", b"\x00\x11\x22\x33\x44\x55"),
                        # Parameter Request List - triggers option copying
                        Byte("option_55_code", 55),
                        Group(
                            "param_list_sizes",
                            values=[
                                # Varying sizes to stress refcount handling
                                bytes([1, 3, 6, 15]),  # Normal (4 params)
                                bytes(range(1, 100)),  # Large (99 params)
                                bytes([1] * 255),  # Max with duplicates
                                bytes(range(1, 256)),  # All possible params
                            ],
                        ),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # ==================== PHASE 4 ADDITIONS: BOUNDARY TESTS ====================

        # Option Length Boundary Tests
        dhcp_length_boundary = Request(
            "DHCP_Length_Boundary",
            children=(
                self._create_dhcp_header("_LenBound"),
                Block(
                    "DHCP_Length_Options",
                    children=(
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        # Test various option code + length combinations
                        Group(
                            "boundary_options",
                            values=[
                                # Hostname with boundary lengths
                                bytes([12, 0]),  # Zero length
                                bytes([12, 1, 0x41]),  # Min length
                                bytes([12, 254]) + b"A" * 254,  # Near max
                                bytes([12, 255]) + b"A" * 255,  # Max length
                                # Domain name with boundary lengths
                                bytes([15, 0]),  # Zero length domain
                                bytes([15, 255]) + b"." * 255,  # Max domain
                                # Client ID with boundary lengths
                                bytes([61, 0]),  # Zero length
                                bytes([61, 255]) + b"\x01" + b"\xff" * 254,  # Max client ID
                                # Vendor class with boundary
                                bytes([60, 0]),  # Zero vendor class
                                bytes([60, 255]) + b"X" * 255,  # Max vendor class
                            ],
                        ),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # Header Field Boundary Tests
        dhcp_field_boundary = Request(
            "DHCP_Field_Boundary",
            children=(
                Block(
                    "DHCP_Header_Boundary",
                    children=(
                        Group(
                            "op_values",
                            values=[
                                b"\x00",  # Invalid op
                                b"\x01",  # Boot request (valid)
                                b"\x02",  # Boot reply (valid)
                                b"\x03",  # Invalid
                                b"\xff",  # Max value
                            ],
                        ),
                        Group(
                            "htype_values",
                            values=[
                                b"\x00",  # Reserved
                                b"\x01",  # Ethernet (valid)
                                b"\x06",  # IEEE 802
                                b"\xff",  # Max value
                            ],
                        ),
                        Group(
                            "hlen_values",
                            values=[
                                b"\x00",  # Zero length (invalid)
                                b"\x06",  # Ethernet (valid)
                                b"\x10",  # Max hardware addr (16)
                                b"\xff",  # Overflow
                            ],
                        ),
                        Byte("hops", 0xFF),  # Max hops
                        DWord("xid", 0xFFFFFFFF, endian=">"),  # Max transaction ID
                        Word("secs", 0xFFFF, endian=">"),  # Max seconds
                        Word("flags", 0xFFFF, endian=">"),  # All flags set
                        DWord("ciaddr", 0xFFFFFFFF, endian=">"),  # Broadcast IP
                        DWord("yiaddr", 0xFFFFFFFF, endian=">"),
                        DWord("siaddr", 0xFFFFFFFF, endian=">"),
                        DWord("giaddr", 0xFFFFFFFF, endian=">"),
                        Static("chaddr", b"\xff" * 16),
                        Static("sname", b"\xff" * 64),
                        Static("file", b"\xff" * 128),
                        # Invalid magic cookie values
                        Group(
                            "magic_cookie_values",
                            values=[
                                b"\x63\x82\x53\x63",  # Valid
                                b"\x00\x00\x00\x00",  # Zero
                                b"\xff\xff\xff\xff",  # Max
                                b"\x63\x82\x53\x00",  # Corrupted last byte
                            ],
                        ),
                    ),
                ),
                Block(
                    "DHCP_Boundary_Options",
                    children=(
                        Byte("option_53_code", 53),
                        Byte("option_53_length", 1),
                        Byte("message_type", 1),
                        Byte("end_option", 255),
                    ),
                ),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Reordered for fast coverage + early crash detection:
        # - PHASE 1: Quick message type sweep (all 8 types in ~30 sec)
        # - PHASE 2: High-crash tests (overflow, buffer attacks)
        # - PHASE 3: CVE-targeted operations (injection, refcount)
        # - PHASE 4: Boundary attacks
        # - PHASE 5: Remaining tests (standard ops, vendor, extended)
        #
        # Use --enable or --disable CLI flags to select specific request groups

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Touch all 8 message types once for maximum breadth coverage
        if self.is_request_enabled("DHCP_Baseline"):
            self.session.connect(dhcp_quick_coverage)
            self.session.connect(dhcp_discover)

        # ==================== PHASE 2: HIGH-CRASH TESTS (~3 min) ====================
        # Moved up from late session - these trigger buffer overflows and crashes
        if self.is_request_enabled("DHCP_Overflow"):
            self.session.connect(dhcp_malformed)  # CVE-2004-0460 pattern
            self.session.connect(dhcp_option_chain)  # Parser overflow
            self.session.connect(dhcp_malformed_extended)  # CVE-2022-2928 pattern
            self.session.connect(dhcp_hostname_overflow)  # Hostname buffer overflow

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS (~3 min) ====================
        if self.is_request_enabled("DHCP_CVE"):
            self.session.connect(dhcp_injection)  # Option injection
            self.session.connect(dhcp_invalid)  # Invalid message types
            self.session.connect(dhcp_option_refcount)  # CVE-2022-2928 refcount

        # ==================== PHASE 4: BOUNDARY ATTACKS (~3 min) ====================
        if self.is_request_enabled("DHCP_Boundary"):
            self.session.connect(dhcp_length_boundary)  # Option length boundaries
            self.session.connect(dhcp_field_boundary)  # Header field boundaries

        # ==================== PHASE 5: REMAINING TESTS ====================
        if self.is_request_enabled("DHCP_Standard"):
            self.session.connect(dhcp_request)
            self.session.connect(dhcp_release)

        if self.is_request_enabled("DHCP_Vendor"):
            self.session.connect(dhcp_vendor)

        if self.is_request_enabled("DHCP_Extended"):
            self.session.connect(dhcp_extended_options)

        if self.is_request_enabled("DHCP_DoS"):
            self.session.connect(dhcp_exhaustion)


class DHCPv6Fuzzer(BaseFuzzer):
    """DHCPv6 Protocol Fuzzer for IPv6 network configuration security testing

    Targets DHCPv6 vulnerabilities including option parsing, message type
    confusion, buffer overflows, relay message attacks, and resource exhaustion.

    Test Ordering (Optimized for Early Coverage):
    - Phase 1: Baseline SOLICIT touches core message path (~30 sec)
    - Phase 2: Standard message types: REQUEST, RELEASE, RENEW, REBIND, CONFIRM,
               DECLINE, INFORMATION-REQUEST, Rapid Commit (~3 min)
    - Phase 3: Overflow and buffer attacks (high crash likelihood) (~3 min)
    - Phase 4: Boundary value attacks (option lengths, msg types, transaction IDs)
    - Phase 5: Relay message fuzzing (RELAY-FORW, RELAY-REPL)

    CVE Coverage:
    - CVE-2020-25681: dnsmasq heap overflow via DHCPv6 DNS options (Phase 3)
    - DHCPv6 option length overflow patterns (Phase 3)
    - Relay message encapsulation attacks (Phase 5)

    DHCPv6 uses UDP port 547 (server) / port 546 (client) by default.
    """

    # Protocol-specific monitor: DHCPv6 solicit check every 50 tests
    DEFAULT_MONITORS = "dhcp:50"

    PROTOCOL_OPTIONS = {
        "timeout": {
            "type": float,
            "default": 5.0,
            "description": "Response timeout in seconds",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests"""
        return [
            # Phase 1: Baseline
            RequestInfo("DHCPv6_SOLICIT", "Client solicitation for IPv6 config", "baseline"),
            # Phase 2: Standard message types
            RequestInfo("DHCPv6_REQUEST", "DHCPv6 address request", "standard"),
            RequestInfo("DHCPv6_RELEASE", "DHCPv6 address release", "standard"),
            RequestInfo("DHCPv6_RENEW", "DHCPv6 address renew (msg_type=5)", "standard"),
            RequestInfo("DHCPv6_REBIND", "DHCPv6 address rebind (msg_type=6)", "standard"),
            RequestInfo("DHCPv6_CONFIRM", "DHCPv6 address confirm (msg_type=4)", "standard"),
            RequestInfo("DHCPv6_DECLINE", "DHCPv6 address decline (msg_type=9)", "standard"),
            RequestInfo(
                "DHCPv6_INFORMATION_REQUEST",
                "Stateless DHCPv6 info request (msg_type=11)",
                "standard",
            ),
            RequestInfo(
                "DHCPv6_Rapid_Commit",
                "Solicit with rapid commit option (14)",
                "standard",
            ),
            RequestInfo("DHCPv6_ADVANCED_OPTIONS", "Advanced option nesting", "standard"),
            RequestInfo("DHCPv6_PREFIX_DELEGATION", "Prefix delegation request", "standard"),
            # Phase 3: Overflow and buffer attacks
            RequestInfo("DHCPv6_MALFORMED_OPTIONS", "Malformed option overflow", "overflow"),
            RequestInfo(
                "DHCPv6_DNS_Overflow",
                "DNS option heap overflow (CVE-2020-25681 pattern)",
                "overflow",
            ),
            # Phase 4: Boundary value attacks
            RequestInfo(
                "DHCPv6_Boundary",
                "Boundary tests for option lengths, msg types, transaction IDs",
                "boundary",
            ),
            # Phase 5: Relay message fuzzing
            RequestInfo(
                "DHCPv6_RELAY_FORWARD",
                "Relay-forward message (msg_type=12) with encapsulated client message",
                "relay",
            ),
            RequestInfo(
                "DHCPv6_RELAY_REPLY",
                "Relay-reply message (msg_type=13) with encapsulated server message",
                "relay",
            ),
        ]

    def _create_socket(self):
        # DHCPv6 clients need to bind to a local port to receive responses
        # Using port 0 lets the OS assign an ephemeral port
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),
            **self._timeout_overrides(recv_default=5.0),
        )

    def setup_custom_monitors(self) -> list:
        """Setup DHCPv6-specific monitoring with SOLICIT validation"""
        from ..monitors import DHCPDiscoverMonitor

        # Reuse DHCP discover monitor -- DHCPv6 servers often coexist with DHCPv4
        dhcp_monitor = DHCPDiscoverMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            timeout=2,
            check_interval=3,
        )

        return [dhcp_monitor]

    def _create_dhcpv6_header(self, name_suffix="", msg_type=1, txid=(0x12, 0x34, 0x56)):
        """Create common DHCPv6 header block to reduce code duplication.

        Args:
            name_suffix: Suffix for block name uniqueness
            msg_type: DHCPv6 message type (1=SOLICIT, 3=REQUEST, etc.)
            txid: 3-byte transaction ID tuple
        """
        return Block(
            f"DHCPv6_Header{name_suffix}",
            children=(
                Byte("msg_type", msg_type),
                Byte("transaction_id_1", txid[0]),
                Byte("transaction_id_2", txid[1]),
                Byte("transaction_id_3", txid[2]),
            ),
        )

    def _create_client_id_option(self, name_suffix=""):
        """Create Client Identifier option (1) with DUID-LLT.

        Returns a tuple of primitives for embedding in a Block's children.
        """
        return (
            Word(f"option_1_code{name_suffix}", 1, endian=">"),
            Word(f"option_1_length{name_suffix}", 14, endian=">"),
            Word(f"duid_type{name_suffix}", 1, endian=">"),  # DUID-LLT
            Word(f"hw_type{name_suffix}", 1, endian=">"),  # Ethernet
            DWord(f"time{name_suffix}", 0x12345678, endian=">"),
            SmartString(f"link_layer_addr{name_suffix}", "\x00\x11\x22\x33\x44\x55", max_len=6),
        )

    def _create_server_id_option(self, name_suffix=""):
        """Create Server Identifier option (2) with DUID-LLT."""
        return (
            Word(f"option_2_code{name_suffix}", 2, endian=">"),
            Word(f"option_2_length{name_suffix}", 14, endian=">"),
            Word(f"server_duid_type{name_suffix}", 1, endian=">"),
            Word(f"server_hw_type{name_suffix}", 1, endian=">"),
            DWord(f"server_time{name_suffix}", 0x87654321, endian=">"),
            SmartString(
                f"server_link_layer_addr{name_suffix}", "\x00\xaa\xbb\xcc\xdd\xee", max_len=6
            ),
        )

    def _create_ia_na_with_address(
        self, name_suffix="", t1=3600, t2=7200, preferred=7200, valid=14400
    ):
        """Create IA_NA option (3) with embedded IA Address option (5)."""
        return (
            Word(f"option_3_code{name_suffix}", 3, endian=">"),
            Word(f"option_3_length{name_suffix}", 40, endian=">"),
            DWord(f"iaid{name_suffix}", 0x12345678, endian=">"),
            DWord(f"t1{name_suffix}", t1, endian=">"),
            DWord(f"t2{name_suffix}", t2, endian=">"),
            # IA Address Option (5)
            Word(f"option_5_code{name_suffix}", 5, endian=">"),
            Word(f"option_5_length{name_suffix}", 24, endian=">"),
            SmartString(
                f"ipv6_address{name_suffix}",
                "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                max_len=16,
            ),
            DWord(f"preferred_lifetime{name_suffix}", preferred, endian=">"),
            DWord(f"valid_lifetime{name_suffix}", valid, endian=">"),
        )

    def _define_protocol(self) -> None:
        """Define DHCPv6 protocol structure with optimized test ordering.

        Test ordering follows the 5-phase optimization strategy:
        - Phase 1: Baseline SOLICIT (~30 sec)
        - Phase 2: Standard message types (REQUEST, RELEASE, RENEW, REBIND, etc.)
        - Phase 3: Overflow and buffer attacks (high crash likelihood)
        - Phase 4: Boundary value attacks
        - Phase 5: Relay message fuzzing
        """

        # ==================== PHASE 1: BASELINE (~30 sec) ====================
        # Core SOLICIT for initial breadth coverage

        # 1. DHCPv6 Solicit - Client requesting IPv6 configuration
        dhcpv6_solicit = Request(
            "DHCPv6_SOLICIT",
            children=(
                Block(
                    "DHCPv6_Header",
                    children=(
                        Byte("msg_type", 1),  # SOLICIT
                        Byte("transaction_id_1", 0x12),
                        Byte("transaction_id_2", 0x34),
                        Byte("transaction_id_3", 0x56),
                    ),
                ),
                Block(
                    "DHCPv6_Options",
                    children=(
                        # Client Identifier Option (1)
                        Word("option_1_code", 1, endian=">"),
                        Word("option_1_length", 14, endian=">"),
                        Word("duid_type", 1, endian=">"),  # DUID-LLT
                        Word("hw_type", 1, endian=">"),  # Ethernet
                        DWord("time", 0x12345678, endian=">"),
                        SmartString("link_layer_addr", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # Option Request Option (6)
                        Word("option_6_code", 6, endian=">"),
                        Word("option_6_length", 8, endian=">"),
                        Word("requested_option_1", 23, endian=">"),  # DNS Recursive Name Server
                        Word("requested_option_2", 24, endian=">"),  # Domain Search List
                        Word("requested_option_3", 3, endian=">"),  # IA_NA (Non-temporary Address)
                        Word("requested_option_4", 39, endian=">"),  # FQDN
                        # IA_NA Option (3)
                        Word("option_3_code", 3, endian=">"),
                        Word("option_3_length", 12, endian=">"),
                        DWord("iaid", 0x12345678, endian=">"),
                        DWord("t1", 3600, endian=">"),
                        DWord("t2", 7200, endian=">"),
                        # Elapsed Time Option (8)
                        Word("option_8_code", 8, endian=">"),
                        Word("option_8_length", 2, endian=">"),
                        Word("elapsed_time", 100, endian=">"),
                    ),
                ),
            ),
        )

        # ==================== PHASE 2: STANDARD MESSAGE TYPES (~3 min) ====================
        # All standard DHCPv6 message types for protocol state machine coverage

        # 2. DHCPv6 Request - Client requesting specific configuration
        dhcpv6_request = Request(
            "DHCPv6_REQUEST",
            children=(
                Block(
                    "DHCPv6_Header_Request",
                    children=(
                        Byte("msg_type", 3),  # REQUEST
                        Byte("transaction_id_1", 0x12),
                        Byte("transaction_id_2", 0x34),
                        Byte("transaction_id_3", 0x56),
                    ),
                ),
                Block(
                    "DHCPv6_Options_Request",
                    children=(
                        # Client Identifier
                        Word("option_1_code", 1, endian=">"),
                        Word("option_1_length", 14, endian=">"),
                        Word("duid_type", 1, endian=">"),
                        Word("hw_type", 1, endian=">"),
                        DWord("time", 0x12345678, endian=">"),
                        SmartString("link_layer_addr", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # Server Identifier Option (2)
                        Word("option_2_code", 2, endian=">"),
                        Word("option_2_length", 14, endian=">"),
                        Word("server_duid_type", 1, endian=">"),
                        Word("server_hw_type", 1, endian=">"),
                        DWord("server_time", 0x87654321, endian=">"),
                        SmartString(
                            "server_link_layer_addr", "\x00\xaa\xbb\xcc\xdd\xee", max_len=6
                        ),
                        # IA_NA with IA Address
                        Word("option_3_code", 3, endian=">"),
                        Word("option_3_length", 40, endian=">"),
                        DWord("iaid", 0x12345678, endian=">"),
                        DWord("t1", 3600, endian=">"),
                        DWord("t2", 7200, endian=">"),
                        # IA Address Option (5)
                        Word("option_5_code", 5, endian=">"),
                        Word("option_5_length", 24, endian=">"),
                        SmartString(
                            "ipv6_address",
                            "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                            max_len=16,
                        ),
                        DWord("preferred_lifetime", 7200, endian=">"),
                        DWord("valid_lifetime", 14400, endian=">"),
                    ),
                ),
            ),
        )

        # 3. DHCPv6 Release - Client releasing IPv6 addresses
        dhcpv6_release = Request(
            "DHCPv6_RELEASE",
            children=(
                Block(
                    "DHCPv6_Header_Release",
                    children=(
                        Byte("msg_type", 8),  # RELEASE
                        Byte("transaction_id_1", 0x12),
                        Byte("transaction_id_2", 0x34),
                        Byte("transaction_id_3", 0x56),
                    ),
                ),
                Block(
                    "DHCPv6_Options_Release",
                    children=(
                        # Client Identifier
                        Word("option_1_code", 1, endian=">"),
                        Word("option_1_length", 14, endian=">"),
                        Word("duid_type", 1, endian=">"),
                        Word("hw_type", 1, endian=">"),
                        DWord("time", 0x12345678, endian=">"),
                        SmartString("link_layer_addr", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # Server Identifier
                        Word("option_2_code", 2, endian=">"),
                        Word("option_2_length", 14, endian=">"),
                        Word("server_duid_type", 1, endian=">"),
                        Word("server_hw_type", 1, endian=">"),
                        DWord("server_time", 0x87654321, endian=">"),
                        SmartString(
                            "server_link_layer_addr", "\x00\xaa\xbb\xcc\xdd\xee", max_len=6
                        ),
                        # IA_NA with address to release
                        Word("option_3_code", 3, endian=">"),
                        Word("option_3_length", 40, endian=">"),
                        DWord("iaid", 0x12345678, endian=">"),
                        DWord("t1", 0, endian=">"),
                        DWord("t2", 0, endian=">"),
                        # IA Address
                        Word("option_5_code", 5, endian=">"),
                        Word("option_5_length", 24, endian=">"),
                        SmartString(
                            "ipv6_address",
                            "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                            max_len=16,
                        ),
                        DWord("preferred_lifetime", 0, endian=">"),
                        DWord("valid_lifetime", 0, endian=">"),
                    ),
                ),
            ),
        )

        # 4. DHCPv6 Renew - Client renewing existing address (msg_type=5)
        dhcpv6_renew = Request(
            "DHCPv6_RENEW",
            children=(
                self._create_dhcpv6_header("_Renew", msg_type=5, txid=(0xAB, 0xCD, 0x01)),
                Block(
                    "DHCPv6_Options_Renew",
                    children=(
                        *self._create_client_id_option("_renew"),
                        *self._create_server_id_option("_renew"),
                        *self._create_ia_na_with_address("_renew", t1=3600, t2=7200),
                        # Elapsed Time Option (8)
                        Word("option_8_code", 8, endian=">"),
                        Word("option_8_length", 2, endian=">"),
                        Word("elapsed_time", 500, endian=">"),
                    ),
                ),
            ),
        )

        # 5. DHCPv6 Rebind - Client rebinding after server unreachable (msg_type=6)
        dhcpv6_rebind = Request(
            "DHCPv6_REBIND",
            children=(
                self._create_dhcpv6_header("_Rebind", msg_type=6, txid=(0xAB, 0xCD, 0x02)),
                Block(
                    "DHCPv6_Options_Rebind",
                    children=(
                        # No server ID in rebind -- client broadcasts to any server
                        *self._create_client_id_option("_rebind"),
                        *self._create_ia_na_with_address("_rebind", t1=3600, t2=7200),
                        # Elapsed Time Option (8)
                        Word("option_8_code_rb", 8, endian=">"),
                        Word("option_8_length_rb", 2, endian=">"),
                        Word("elapsed_time_rb", 1000, endian=">"),
                    ),
                ),
            ),
        )

        # 6. DHCPv6 Confirm - Client confirming address after link change (msg_type=4)
        dhcpv6_confirm = Request(
            "DHCPv6_CONFIRM",
            children=(
                self._create_dhcpv6_header("_Confirm", msg_type=4, txid=(0xAB, 0xCD, 0x03)),
                Block(
                    "DHCPv6_Options_Confirm",
                    children=(
                        *self._create_client_id_option("_confirm"),
                        *self._create_ia_na_with_address("_confirm", t1=0, t2=0),
                        # Elapsed Time Option (8)
                        Word("option_8_code_cf", 8, endian=">"),
                        Word("option_8_length_cf", 2, endian=">"),
                        Word("elapsed_time_cf", 0, endian=">"),
                    ),
                ),
            ),
        )

        # 7. DHCPv6 Decline - Client declining offered address (msg_type=9)
        dhcpv6_decline = Request(
            "DHCPv6_DECLINE",
            children=(
                self._create_dhcpv6_header("_Decline", msg_type=9, txid=(0xAB, 0xCD, 0x04)),
                Block(
                    "DHCPv6_Options_Decline",
                    children=(
                        *self._create_client_id_option("_decline"),
                        *self._create_server_id_option("_decline"),
                        *self._create_ia_na_with_address(
                            "_decline", t1=0, t2=0, preferred=0, valid=0
                        ),
                    ),
                ),
            ),
        )

        # 8. DHCPv6 Information-Request - Stateless DHCPv6 (msg_type=11)
        # No IA_NA -- client only wants configuration parameters, not addresses
        dhcpv6_information_request = Request(
            "DHCPv6_INFORMATION_REQUEST",
            children=(
                self._create_dhcpv6_header("_InfoReq", msg_type=11, txid=(0xAB, 0xCD, 0x05)),
                Block(
                    "DHCPv6_Options_InfoReq",
                    children=(
                        *self._create_client_id_option("_inforeq"),
                        # Option Request Option (6) - request DNS and domain info
                        Word("option_6_code_ir", 6, endian=">"),
                        Word("option_6_length_ir", 6, endian=">"),
                        Word("requested_opt_dns", 23, endian=">"),  # DNS servers
                        Word("requested_opt_domain", 24, endian=">"),  # Domain search list
                        Word("requested_opt_sntp", 31, endian=">"),  # SNTP servers
                        # Elapsed Time Option (8)
                        Word("option_8_code_ir", 8, endian=">"),
                        Word("option_8_length_ir", 2, endian=">"),
                        Word("elapsed_time_ir", 0, endian=">"),
                    ),
                ),
            ),
        )

        # 9. DHCPv6 Rapid Commit - Solicit with rapid commit option (14)
        # Allows 2-message exchange (SOLICIT/REPLY) instead of 4-message
        dhcpv6_rapid_commit = Request(
            "DHCPv6_Rapid_Commit",
            children=(
                self._create_dhcpv6_header("_RapidCommit", msg_type=1, txid=(0xAB, 0xCD, 0x06)),
                Block(
                    "DHCPv6_Options_RapidCommit",
                    children=(
                        *self._create_client_id_option("_rapid"),
                        # IA_NA Option (3)
                        Word("option_3_code_rapid", 3, endian=">"),
                        Word("option_3_length_rapid", 12, endian=">"),
                        DWord("iaid_rapid", 0x12345678, endian=">"),
                        DWord("t1_rapid", 3600, endian=">"),
                        DWord("t2_rapid", 7200, endian=">"),
                        # Rapid Commit Option (14) - zero-length option
                        Word("option_14_code", 14, endian=">"),
                        Word("option_14_length", 0, endian=">"),
                        # Option Request Option (6)
                        Word("option_6_code_rapid", 6, endian=">"),
                        Word("option_6_length_rapid", 4, endian=">"),
                        Word("requested_opt_dns_rapid", 23, endian=">"),
                        Word("requested_opt_domain_rapid", 24, endian=">"),
                        # Elapsed Time Option (8)
                        Word("option_8_code_rapid", 8, endian=">"),
                        Word("option_8_length_rapid", 2, endian=">"),
                        Word("elapsed_time_rapid", 0, endian=">"),
                    ),
                ),
            ),
        )

        # 10. DHCPv6 with Advanced Options
        dhcpv6_advanced = Request(
            "DHCPv6_ADVANCED_OPTIONS",
            children=(
                Block(
                    "DHCPv6_Header_Advanced",
                    children=(
                        Byte("msg_type", 1),  # SOLICIT
                        Byte("transaction_id_1", 0x12),
                        Byte("transaction_id_2", 0x34),
                        Byte("transaction_id_3", 0x56),
                    ),
                ),
                Block(
                    "DHCPv6_Advanced_Options",
                    children=(
                        # Client Identifier
                        Word("option_1_code", 1, endian=">"),
                        Word("option_1_length", 14, endian=">"),
                        Word("duid_type", 1, endian=">"),
                        Word("hw_type", 1, endian=">"),
                        DWord("time", 0x12345678, endian=">"),
                        SmartString("link_layer_addr", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # DNS Recursive Name Server Option (23)
                        Word("option_23_code", 23, endian=">"),
                        Word("option_23_length", 32, endian=">"),
                        SmartString(
                            "dns_server_1",
                            "\x20\x01\x48\x60\x48\x60\x00\x00\x00\x00\x00\x00\x00\x00\x88\x88",
                            max_len=16,
                        ),
                        SmartString(
                            "dns_server_2",
                            "\x20\x01\x48\x60\x48\x60\x00\x00\x00\x00\x00\x00\x00\x00\x88\x44",
                            max_len=16,
                        ),
                        # Domain Search List Option (24)
                        Word("option_24_code", 24, endian=">"),
                        Word("option_24_length", 20, endian=">"),
                        SmartString(
                            "domain_search",
                            "\x07example\x03com\x00\x04test\x03org\x00",
                            max_len=20,
                            fuzzable=True,
                        ),
                        # Information Refresh Time Option (32)
                        Word("option_32_code", 32, endian=">"),
                        Word("option_32_length", 4, endian=">"),
                        DWord("refresh_time", 86400, endian=">"),
                        # FQDN Option (39)
                        Word("option_39_code", 39, endian=">"),
                        Word("option_39_length", 20, endian=">"),
                        Byte("fqdn_flags", 0x01),  # S flag
                        SmartString(
                            "client_fqdn",
                            "\x06client\x07example\x03com\x00",
                            max_len=19,
                            fuzzable=True,
                        ),
                        # Authentication Option (11)
                        Word("option_11_code", 11, endian=">"),
                        Word("option_11_length", 20, endian=">"),
                        Byte("auth_protocol", 1),
                        Byte("auth_algorithm", 1),
                        Byte("rdm", 0),
                        QWord("replay_detection", 0x123456789ABCDEF0, endian=">"),
                        SmartString("auth_info", "\xde\xad\xbe\xef\xca\xfe\xba\xbe", max_len=8),
                        # Remote Identifier Option (37)
                        Word("option_37_code", 37, endian=">"),
                        Word("option_37_length", 8, endian=">"),
                        DWord("enterprise_number", 9, endian=">"),
                        SmartString("remote_id", "port01", max_len=4, fuzzable=True),
                    ),
                ),
            ),
        )

        # 11. DHCPv6 Prefix Delegation
        dhcpv6_prefix_delegation = Request(
            "DHCPv6_PREFIX_DELEGATION",
            children=(
                Block(
                    "DHCPv6_Header_PD",
                    children=(
                        Byte("msg_type", 1),  # SOLICIT
                        Byte("transaction_id_1", 0x12),
                        Byte("transaction_id_2", 0x34),
                        Byte("transaction_id_3", 0x56),
                    ),
                ),
                Block(
                    "DHCPv6_PD_Options",
                    children=(
                        # Client Identifier
                        Word("option_1_code", 1, endian=">"),
                        Word("option_1_length", 14, endian=">"),
                        Word("duid_type", 1, endian=">"),
                        Word("hw_type", 1, endian=">"),
                        DWord("time", 0x12345678, endian=">"),
                        SmartString("link_layer_addr", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # IA_PD Option (25) - Identity Association for Prefix Delegation
                        Word("option_25_code", 25, endian=">"),
                        Word("option_25_length", 41, endian=">"),
                        DWord("pd_iaid", 0x87654321, endian=">"),
                        DWord("pd_t1", 3600, endian=">"),
                        DWord("pd_t2", 7200, endian=">"),
                        # IA Prefix Option (26)
                        Word("option_26_code", 26, endian=">"),
                        Word("option_26_length", 25, endian=">"),
                        DWord("prefix_preferred_lifetime", 7200, endian=">"),
                        DWord("prefix_valid_lifetime", 14400, endian=">"),
                        Byte("prefix_length", 64),
                        SmartString(
                            "prefix",
                            "\x20\x01\x0d\xb8\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                            max_len=16,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # ==================== PHASE 3: OVERFLOW AND BUFFER ATTACKS (~3 min) ====================
        # High-crash-likelihood tests targeting option parsing vulnerabilities

        # 12. DHCPv6 Malformed Options - Buffer overflow testing
        dhcpv6_malformed = Request(
            "DHCPv6_MALFORMED_OPTIONS",
            children=(
                Block(
                    "DHCPv6_Header_Malformed",
                    children=(
                        Byte("msg_type", 1),
                        Byte("transaction_id_1", 0x12),
                        Byte("transaction_id_2", 0x34),
                        Byte("transaction_id_3", 0x56),
                    ),
                ),
                Block(
                    "DHCPv6_Malformed_Options",
                    children=(
                        # Oversized FQDN Option (39)
                        Word("option_39_code", 39, endian=">"),
                        Word("option_39_length", 1000, endian=">", fuzzable=True),  # Oversized
                        Byte("fqdn_flags", 0x01),
                        SmartString("oversized_fqdn", "example.com", max_len=2000, fuzzable=True),
                        # Invalid Option Code
                        Word("invalid_option_code", 65535, endian=">", fuzzable=True),
                        Word("invalid_option_length", 500, endian=">", fuzzable=True),
                        SmartString(
                            "invalid_option_data", "dhcpv6-option", max_len=1000, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # 13. DHCPv6 DNS Option Heap Overflow (CVE-2020-25681 pattern)
        # dnsmasq heap overflow via crafted DNS-related DHCPv6 options
        # Targets option 23 (DNS servers) and option 24 (domain search list) with
        # oversized payloads that can trigger heap buffer overflows in dnsmasq
        dhcpv6_dns_overflow = Request(
            "DHCPv6_DNS_Overflow",
            children=(
                self._create_dhcpv6_header("_DNSOverflow", msg_type=1, txid=(0xDE, 0xAD, 0x01)),
                Block(
                    "DHCPv6_DNS_Overflow_Options",
                    children=(
                        *self._create_client_id_option("_dnsovf"),
                        # Oversized DNS Recursive Name Server Option (23)
                        # CVE-2020-25681: heap overflow via large DNS option payload
                        Word("option_23_code_ovf", 23, endian=">"),
                        Word("option_23_length_ovf", 4096, endian=">", fuzzable=True),
                        SmartString(
                            "dns_overflow_payload",
                            "\x20\x01\x0d\xb8" + "\x41" * 252,
                            max_len=4096,
                            fuzzable=True,
                        ),
                        # Oversized Domain Search List Option (24)
                        Word("option_24_code_ovf", 24, endian=">"),
                        Word("option_24_length_ovf", 2048, endian=">", fuzzable=True),
                        SmartString(
                            "domain_overflow_payload",
                            "\x3f" + "A" * 63 + "\x3f" + "B" * 63 + "\x00",
                            max_len=2048,
                            fuzzable=True,
                        ),
                        # Nested FQDN with excessive label lengths
                        Word("option_39_code_ovf", 39, endian=">"),
                        Word("option_39_length_ovf", 1024, endian=">", fuzzable=True),
                        Byte("fqdn_flags_ovf", 0x01),
                        SmartString(
                            "fqdn_overflow_payload",
                            "\xff" + "C" * 255 + "\xff" + "D" * 255 + "\x00",
                            max_len=1024,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # ==================== PHASE 4: BOUNDARY VALUE ATTACKS ====================
        # Tests edge cases in option lengths, message types, and transaction IDs

        # 14. DHCPv6 Boundary Tests
        dhcpv6_boundary = Request(
            "DHCPv6_Boundary",
            children=(
                Block(
                    "DHCPv6_Header_Boundary",
                    children=(
                        # Fuzz message type with boundary values
                        Group(
                            "msg_type_boundary",
                            values=[
                                b"\x00",  # Invalid (0)
                                b"\x01",  # SOLICIT (valid)
                                b"\x0d",  # RELAY-REPL (13, max standard)
                                b"\x0e",  # Above max standard type
                                b"\x7f",  # Mid-range
                                b"\xff",  # Max byte value
                            ],
                        ),
                        # Fuzz transaction ID with boundary values
                        Group(
                            "txid_boundary",
                            values=[
                                b"\x00\x00\x00",  # All zeros
                                b"\xff\xff\xff",  # All ones
                                b"\x80\x00\x00",  # High bit set
                                b"\x7f\xff\xff",  # Max positive
                                b"\x00\x00\x01",  # Minimum non-zero
                            ],
                        ),
                    ),
                ),
                Block(
                    "DHCPv6_Boundary_Options",
                    children=(
                        # Test option length boundary values
                        Group(
                            "option_boundary_values",
                            values=[
                                # Client ID option (1) with zero length
                                b"\x00\x01\x00\x00",
                                # Client ID option (1) with max 16-bit length
                                b"\x00\x01\xff\xff" + b"\x41" * 100,
                                # Option code 0 (reserved) with data
                                b"\x00\x00\x00\x04\xde\xad\xbe\xef",
                                # Option code 65535 with zero length
                                b"\xff\xff\x00\x00",
                                # Option code 65535 with max length
                                b"\xff\xff\xff\xff" + b"\x42" * 200,
                                # IA_NA (3) with zero length (missing IAID, T1, T2)
                                b"\x00\x03\x00\x00",
                                # IA_NA (3) with truncated length (only 4 bytes for 12-byte option)
                                b"\x00\x03\x00\x04\x12\x34\x56\x78",
                                # Elapsed Time (8) with zero length
                                b"\x00\x08\x00\x00",
                                # Elapsed Time (8) with oversized length
                                b"\x00\x08\x00\xff" + b"\x00" * 255,
                                # Multiple zero-length options in sequence
                                b"\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00",
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ==================== PHASE 5: RELAY MESSAGE FUZZING ====================
        # Tests relay agent encapsulation/decapsulation vulnerabilities

        # 15. DHCPv6 Relay Forward (msg_type=12)
        # Relay agents use this to forward client messages to servers
        # Encapsulates a full client message inside a Relay Message option (9)
        dhcpv6_relay_forward = Request(
            "DHCPv6_RELAY_FORWARD",
            children=(
                Block(
                    "DHCPv6_Relay_Header",
                    children=(
                        Byte("msg_type", 12),  # RELAY-FORW
                        Byte("hop_count", 0),  # Hop count
                        # Link-address (16 bytes) - relay agent's address on link
                        SmartString(
                            "link_address",
                            "\x20\x01\x0d\xb8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                            max_len=16,
                        ),
                        # Peer-address (16 bytes) - client's address
                        SmartString(
                            "peer_address",
                            "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x11\x22\xff\xfe\x33\x44\x55",
                            max_len=16,
                        ),
                    ),
                ),
                Block(
                    "DHCPv6_Relay_Options",
                    children=(
                        # Interface-Id Option (18) - identifies the relay interface
                        Word("option_18_code", 18, endian=">"),
                        Word("option_18_length", 4, endian=">"),
                        SmartString("interface_id", "eth0", max_len=4, fuzzable=True),
                        # Relay Message Option (9) - encapsulated client SOLICIT
                        Word("option_9_code", 9, endian=">"),
                        Word("option_9_length", 50, endian=">", fuzzable=True),
                        # Encapsulated DHCPv6 SOLICIT message
                        Byte("inner_msg_type", 1),  # SOLICIT
                        Byte("inner_txid_1", 0xCA),
                        Byte("inner_txid_2", 0xFE),
                        Byte("inner_txid_3", 0x01),
                        # Inner Client Identifier
                        Word("inner_opt_1_code", 1, endian=">"),
                        Word("inner_opt_1_length", 14, endian=">"),
                        Word("inner_duid_type", 1, endian=">"),
                        Word("inner_hw_type", 1, endian=">"),
                        DWord("inner_time", 0xAABBCCDD, endian=">"),
                        SmartString("inner_link_layer", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # Inner IA_NA Option
                        Word("inner_opt_3_code", 3, endian=">"),
                        Word("inner_opt_3_length", 12, endian=">"),
                        DWord("inner_iaid", 0x11223344, endian=">"),
                        DWord("inner_t1", 3600, endian=">"),
                        DWord("inner_t2", 7200, endian=">"),
                        # Remote ID Option (37) - relay agent remote ID
                        Word("option_37_code_relay", 37, endian=">"),
                        Word("option_37_length_relay", 10, endian=">"),
                        DWord("enterprise_num", 9, endian=">"),
                        SmartString("remote_id_relay", "relay1", max_len=6, fuzzable=True),
                    ),
                ),
            ),
        )

        # 16. DHCPv6 Relay Reply (msg_type=13)
        # Tests server-side relay reply processing
        dhcpv6_relay_reply = Request(
            "DHCPv6_RELAY_REPLY",
            children=(
                Block(
                    "DHCPv6_Relay_Reply_Header",
                    children=(
                        Byte("msg_type", 13),  # RELAY-REPL
                        Byte("hop_count", 0),
                        SmartString(
                            "link_address",
                            "\x20\x01\x0d\xb8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                            max_len=16,
                        ),
                        SmartString(
                            "peer_address",
                            "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x11\x22\xff\xfe\x33\x44\x55",
                            max_len=16,
                        ),
                    ),
                ),
                Block(
                    "DHCPv6_Relay_Reply_Options",
                    children=(
                        # Interface-Id Option (18)
                        Word("option_18_code", 18, endian=">"),
                        Word("option_18_length", 4, endian=">"),
                        SmartString("interface_id", "eth0", max_len=4, fuzzable=True),
                        # Relay Message Option (9) - encapsulated server ADVERTISE
                        Word("option_9_code", 9, endian=">"),
                        Word("option_9_length", 60, endian=">", fuzzable=True),
                        # Encapsulated DHCPv6 ADVERTISE (msg_type=2)
                        Byte("inner_msg_type", 2),  # ADVERTISE
                        Byte("inner_txid_1", 0xCA),
                        Byte("inner_txid_2", 0xFE),
                        Byte("inner_txid_3", 0x01),
                        # Inner Server Identifier
                        Word("inner_opt_2_code", 2, endian=">"),
                        Word("inner_opt_2_length", 14, endian=">"),
                        Word("inner_srv_duid_type", 1, endian=">"),
                        Word("inner_srv_hw_type", 1, endian=">"),
                        DWord("inner_srv_time", 0x87654321, endian=">"),
                        SmartString("inner_srv_link_layer", "\x00\xaa\xbb\xcc\xdd\xee", max_len=6),
                        # Inner Client Identifier
                        Word("inner_opt_1_code", 1, endian=">"),
                        Word("inner_opt_1_length", 14, endian=">"),
                        Word("inner_clt_duid_type", 1, endian=">"),
                        Word("inner_clt_hw_type", 1, endian=">"),
                        DWord("inner_clt_time", 0xAABBCCDD, endian=">"),
                        SmartString("inner_clt_link_layer", "\x00\x11\x22\x33\x44\x55", max_len=6),
                        # Preference Option (7)
                        Word("inner_opt_7_code", 7, endian=">"),
                        Word("inner_opt_7_length", 1, endian=">"),
                        Byte("preference", 255),
                    ),
                ),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Reordered for fast coverage + early crash detection:
        # - PHASE 1: Baseline SOLICIT (~30 sec)
        # - PHASE 2: Standard message types (all DHCPv6 message types)
        # - PHASE 3: Overflow and buffer attacks (high crash likelihood)
        # - PHASE 4: Boundary value attacks
        # - PHASE 5: Relay message fuzzing
        #
        # Use --enable or --disable CLI flags to select specific request groups

        # ==================== PHASE 1: BASELINE (~30 sec) ====================
        if self.is_request_enabled("DHCPv6_Baseline"):
            self.session.connect(dhcpv6_solicit)

        # ==================== PHASE 2: STANDARD MESSAGE TYPES (~3 min) ====================
        if self.is_request_enabled("DHCPv6_Standard"):
            self.session.connect(dhcpv6_request)
            self.session.connect(dhcpv6_release)
            self.session.connect(dhcpv6_renew)
            self.session.connect(dhcpv6_rebind)
            self.session.connect(dhcpv6_confirm)
            self.session.connect(dhcpv6_decline)
            self.session.connect(dhcpv6_information_request)
            self.session.connect(dhcpv6_rapid_commit)
            self.session.connect(dhcpv6_advanced)
            self.session.connect(dhcpv6_prefix_delegation)

        # ==================== PHASE 3: OVERFLOW AND BUFFER ATTACKS (~3 min) ====================
        if self.is_request_enabled("DHCPv6_Overflow"):
            self.session.connect(dhcpv6_malformed)
            self.session.connect(dhcpv6_dns_overflow)  # CVE-2020-25681 pattern

        # ==================== PHASE 4: BOUNDARY VALUE ATTACKS ====================
        if self.is_request_enabled("DHCPv6_Boundary"):
            self.session.connect(dhcpv6_boundary)

        # ==================== PHASE 5: RELAY MESSAGE FUZZING ====================
        if self.is_request_enabled("DHCPv6_Relay"):
            self.session.connect(dhcpv6_relay_forward)
            self.session.connect(dhcpv6_relay_reply)


# For backward compatibility and explicit exports
__all__ = ["DHCPFuzzer", "DHCPv6Fuzzer"]
