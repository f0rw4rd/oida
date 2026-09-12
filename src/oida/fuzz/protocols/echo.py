"""Echo Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.
Test ordering follows the optimization phases:
- Phase 1: Quick feature sweep (all operations once)
- Phase 2: High-crash tests (overflow, buffer attacks)
- Phase 3: CVE-targeted operations (path traversal, format strings)
- Phase 4: Boundary attacks (line endings, unicode)
- Phase 5: Standard fuzzing (text, numeric, binary)
"""

from typing import List

from boofuzz import Delim, Group, RandomData, Request

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import TCPSocketConnection, UDPSocketConnection
from ..monitors import BaseMonitor
from ..primitives.dynamic import SmartString


class EchoFuzzer(BaseFuzzer):
    """Echo Protocol Fuzzer for TCP variant

    Test ordering optimized for:
    1. Maximum early coverage - touch all operations in first 30 seconds
    2. High-crash tests early - overflow, boundary, buffer attacks
    3. CVE-relevant operations tested early
    4. Redundant test cases removed
    """

    PROTOCOL_OPTIONS = {
        "use_udp": {
            "type": bool,
            "default": False,
            "description": "Use UDP instead of TCP",
            "example": "true",
        },
        "max_payload_size": {
            "type": int,
            "default": 4096,
            "description": "Maximum payload size for fuzzing",
            "example": 65535,
        },
        "include_binary": {
            "type": bool,
            "default": True,
            "description": "Include binary payloads in fuzzing",
            "example": "true",
        },
        "test_fragmentation": {
            "type": bool,
            "default": False,
            "description": "Test with fragmented packets",
            "example": "true",
        },
        "test_amplification": {
            "type": bool,
            "default": True,
            "description": "Test amplification attack vectors (UDP only)",
            "example": "true",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "Echo_Quick_Coverage", "Quick sweep of all echo operations (~30 sec)", "baseline"
            ),
            # Phase 2: High-Crash Tests
            RequestInfo(
                "Echo_Buffer_Overflow",
                "Buffer overflow attacks (long strings, deep nesting)",
                "overflow",
            ),
            RequestInfo("Echo_Format_String", "Format string injection attacks", "overflow"),
            # Phase 3: CVE-Targeted
            RequestInfo(
                "Echo_Path_Traversal", "Path traversal attacks (CVE-2016-1897 pattern)", "cve"
            ),
            RequestInfo("Echo_Injection", "Command and null injection patterns", "cve"),
            # Phase 4: Boundary
            RequestInfo("Echo_Line_Endings", "Line ending variations (parser bugs)", "boundary"),
            RequestInfo("Echo_Unicode", "Unicode and encoding edge cases", "boundary"),
            # Phase 5: Standard
            RequestInfo("Echo_Text", "Standard text fuzzing", "standard"),
            RequestInfo("Echo_Binary", "Binary data fuzzing", "standard"),
            RequestInfo("Echo_Fragmented", "Fragmented packet testing", "standard", slow=True),
            # UDP-mode requests (only connected when use_udp): listed so they are
            # visible to --list-requests and honor --enable/--disable.
            RequestInfo("UDP_Fragmentation_Attack", "UDP fragmentation attack", "boundary"),
            RequestInfo("UDP_Amplification", "UDP amplification probe", "boundary"),
            RequestInfo("UDP_MTU_Boundary", "UDP MTU boundary datagrams", "boundary"),
            RequestInfo("UDP_Zero_Length", "UDP zero-length / single-byte datagrams", "boundary"),
        ]

    def _create_socket(self):
        """Create TCP or UDP socket connection on port 7"""
        if self.config.get_option("use_udp", False):
            return UDPSocketConnection(
                self.config.target_ip,
                self.config.target_port or 7,
                bind=("0.0.0.0", 0),
                **self._timeout_overrides(recv_default=2.0),
            )
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port or 7,
            **self._timeout_overrides(),
        )

    def setup_custom_monitors(self) -> List[BaseMonitor]:
        """No special monitoring needed for Echo"""
        return []

    def _define_protocol(self) -> None:
        """Define Echo protocol fuzzing structure

        Optimized ordering:
        - Phase 1 (0-30 sec): Quick coverage sweep
        - Phase 2 (30-90 sec): High-crash overflow/format string tests
        - Phase 3 (90-150 sec): CVE-targeted path traversal/injection
        - Phase 4 (150-210 sec): Boundary tests (line endings, unicode)
        - Phase 5 (210+ sec): Standard fuzzing (text, binary)
        """

        max_size = self.config.get_option("max_payload_size", 4096)
        include_binary = self.config.get_option("include_binary", True)

        # ============================================================
        # PHASE 1: QUICK COVERAGE SWEEP (~30 sec)
        # Touch all echo operations once for maximum breadth
        # ============================================================

        quick_coverage = Request(
            "Quick_Coverage",
            children=(
                Group(
                    "quick_sweep",
                    values=[
                        # Basic text
                        b"Hello Echo",
                        # Numeric
                        b"1234567890",
                        # Special chars
                        b"!@#$%^&*()",
                        # Path pattern
                        b"../test",
                        # Unicode (UTF-8)
                        b"\xc4\x80test",  # Latin Extended A
                        # Binary pattern
                        b"\x00\x01\x02\x03",
                        # Line endings
                        b"test\r\n",
                        # Long string (boundary)
                        b"A" * 256,
                        # Format string
                        b"%s%s%s%n",
                        # Null injection
                        b"test\x00hidden",
                    ],
                ),
            ),
        )

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS - BUFFER OVERFLOW (~60 sec)
        # These patterns commonly trigger crashes in echo implementations
        # ============================================================

        # 2a. Long string overflow attacks
        buffer_overflow = Request(
            "Buffer_Overflow",
            children=(
                Group(
                    "overflow_patterns",
                    values=[
                        b"A" * 256,  # 256 bytes - common buffer boundary
                        b"A" * 512,  # 512 bytes
                        b"A" * 1024,  # 1KB
                        b"A" * 2048,  # 2KB
                        b"A" * 4096,  # 4KB - page boundary
                        b"A" * 8192,  # 8KB
                        b"A" * 16384,  # 16KB
                        b"A" * 32768,  # 32KB
                        b"A" * 65535,  # 64KB - max uint16
                        b"\x41" * 100 + b"\x42" * 100 + b"\x43" * 100,  # Pattern for crash analysis
                    ],
                ),
            ),
        )

        # 2b. Format string attacks (can crash or leak memory)
        format_string = Request(
            "Format_String",
            children=(
                Group(
                    "format_patterns",
                    values=[
                        b"%s" * 20,  # String format
                        b"%x" * 20,  # Hex dump
                        b"%n" * 10,  # Write count (dangerous)
                        b"%s%s%s%s%n",  # Classic format string
                        b"AAAA%08x.%08x.%08x.%08x",  # Stack leak
                        b"%p" * 20,  # Pointer dump
                        b"%.9999999s",  # Long precision
                        b"%99999999d",  # Long width
                        b"%-99999999d",  # Left-aligned long width
                        b"%*.*s" * 10,  # Variable width/precision
                    ],
                ),
            ),
        )

        # ============================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (~60 sec)
        # Path traversal and injection attacks
        # ============================================================

        # 3a. Deep Path Traversal (CVE-2016-1897 pattern - buffer overflow via path)
        path_traversal = Request(
            "Path_Traversal",
            children=(
                Group(
                    "path_patterns",
                    values=[
                        b"../" * 50,  # Deep Unix traversal
                        b"..\\" * 50,  # Deep Windows traversal
                        b"/.." * 50,  # Alternate pattern
                        b"../" * 100,  # Very deep (300 chars)
                        b"....//....//",  # Double dot bypass
                        b"..%2f" * 20,  # URL encoded
                        b"..%5c" * 20,  # URL encoded backslash
                        b"..%252f" * 20,  # Double encoded
                        b"/etc/passwd",  # Direct path
                        b"C:\\Windows\\System32\\config\\SAM",  # Windows path
                    ],
                ),
            ),
        )

        # 3b. Injection patterns (null byte, command injection)
        injection = Request(
            "Injection",
            children=(
                Group(
                    "injection_patterns",
                    values=[
                        b"test\x00hidden",  # Null byte injection
                        b"\x00" * 100,  # Null flood
                        b"test\x00\x00\x00hidden",  # Multiple nulls
                        b"`id`",  # Backtick command
                        b"$(id)",  # Subshell command
                        b"; id",  # Semicolon injection
                        b"| id",  # Pipe injection
                        b"&& id",  # AND injection
                        b"|| id",  # OR injection
                        b"\nid\n",  # Newline injection
                    ],
                ),
            ),
        )

        # ============================================================
        # PHASE 4: BOUNDARY TESTS (~60 sec)
        # Line endings and unicode edge cases
        # ============================================================

        # 4a. Line Ending Variations (parser bugs)
        line_endings = Request(
            "Line_Endings",
            children=(
                Group(
                    "line_ending_data",
                    values=[
                        b"Line1\r\nLine2\r\nLine3",  # Windows CRLF
                        b"Line1\nLine2\nLine3",  # Unix LF
                        b"Line1\rLine2\rLine3",  # Old Mac CR
                        b"Line1\r\n\r\nLine2",  # Double CRLF
                        b"Line1\n\nLine2",  # Double LF
                        b"Mixed\r\nEndings\nHere\r",  # Mixed endings
                        b"\r\n" * 100,  # CRLF flood
                        b"\n" * 1000,  # LF flood
                        b"test\r\n\x00\r\n",  # CRLF with null
                        b"\x0d\x0a" * 50 + b"\x0a" * 50,  # Binary line endings
                    ],
                ),
            ),
        )

        # 4b. UTF-8 and Unicode (encoding edge cases)
        unicode_echo = Request(
            "Unicode_Echo",
            children=(
                Group(
                    "unicode_data",
                    values=[
                        ("A" * 100).encode("utf-8"),  # ASCII baseline
                        ("\xc0\x80" * 50).encode("latin-1"),  # Overlong null (invalid UTF-8)
                        b"\xef\xbf\xbf" * 50,  # U+FFFF (noncharacter)
                        b"\xed\xa0\x80" * 30,  # Surrogate half (invalid)
                        b"\xf4\x90\x80\x80" * 20,  # Beyond U+10FFFF (invalid)
                        ("A" * 100).encode("utf-8"),  # Latin Extended
                        b"\xe4\xb8\xad" * 100,  # Chinese (3-byte UTF-8)
                        b"\xf0\x9f\x94\xa5" * 100,  # Emoji (4-byte UTF-8)
                        b"\x00" + b"\xef\xbf\xbf" * 50,  # Null + unicode boundary
                        b"\xfe\xff" + b"test",  # BOM (UTF-16 BE marker)
                    ],
                ),
            ),
        )

        # ============================================================
        # PHASE 5: STANDARD FUZZING
        # Comprehensive text and binary fuzzing
        # ============================================================

        # 5a. Text fuzzing (SmartString provides mutation library)
        text_echo = Request(
            "Text_Echo",
            children=(
                SmartString("text_data", "Hello Echo Service!", max_len=max_size, fuzzable=True),
            ),
        )

        # 5b. Binary Data Echo
        binary_echo = Request(
            "Binary_Echo",
            children=(
                RandomData("binary_data", min_length=1, max_length=max_size, max_mutations=100),
            ),
        )

        # 5c. Fragmented Data (optional - slow)
        fragmented = Request(
            "Fragmented_Data",
            children=(
                SmartString("frag1", "PART", max_len=64),
                Delim("delim1", " ", fuzzable=False),
                SmartString("frag2", "ONE", max_len=64),
                Delim("delim2", "-", fuzzable=False),
                SmartString("frag3", "PART", max_len=64),
                Delim("delim3", " ", fuzzable=False),
                SmartString("frag4", "TWO", max_len=64),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Connect requests in crash-priority order
        # Use --enable or --disable CLI flags to select specific request groups

        # PHASE 1: Quick coverage sweep (~30 sec)
        if self.is_request_enabled("Echo_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # PHASE 2: High-crash overflow tests (~60 sec)
        if self.is_request_enabled("Echo_Buffer_Overflow"):
            self.session.connect(buffer_overflow)

        if self.is_request_enabled("Echo_Format_String"):
            self.session.connect(format_string)

        # PHASE 3: CVE-targeted operations (~60 sec)
        if self.is_request_enabled("Echo_Path_Traversal"):
            self.session.connect(path_traversal)

        if self.is_request_enabled("Echo_Injection"):
            self.session.connect(injection)

        # PHASE 4: Boundary tests (~60 sec)
        if self.is_request_enabled("Echo_Line_Endings"):
            self.session.connect(line_endings)

        if self.is_request_enabled("Echo_Unicode"):
            self.session.connect(unicode_echo)

        # PHASE 5: Standard fuzzing
        if self.is_request_enabled("Echo_Text"):
            self.session.connect(text_echo)

        if include_binary and self.is_request_enabled("Echo_Binary"):
            self.session.connect(binary_echo)

        if self.config.get_option("test_fragmentation", False) and self.is_request_enabled(
            "Echo_Fragmented"
        ):
            self.session.connect(fragmented)

        # UDP-specific tests
        if self.config.get_option("use_udp", False):
            self._define_udp_protocol()

    def _define_udp_protocol(self) -> None:
        """Define UDP-specific echo tests (MTU, amplification, fragmentation)"""
        # IP fragmentation attacks
        fragmentation = Request(
            "UDP_Fragmentation_Attack",
            children=(
                Group(
                    "frag_patterns",
                    values=[
                        b"F" * 1473,  # Just over MTU (forces fragmentation)
                        b"F" * 1500,  # Ethernet MTU
                        b"F" * 2000,  # 2 fragments
                        b"F" * 4000,  # 3 fragments
                        b"F" * 8000,  # 6 fragments
                        b"F" * 16000,  # 11 fragments
                        b"F" * 32000,  # 22 fragments
                        b"F" * 65000,  # 45 fragments (near max)
                        b"\x00" * 1500 + b"\xff" * 1500,  # Teardrop-style
                    ],
                ),
            ),
        )

        # Amplification attack vectors (DDoS reflection)
        amplification = Request(
            "UDP_Amplification",
            children=(
                Group(
                    "amp_patterns",
                    values=[
                        b"A",  # Single byte (high amplification factor)
                        b"",  # Zero-length
                        b"LIST",  # Command-like
                        b"HELP",  # Help command
                        b"STATUS",  # Status query
                        b"VERSION",  # Version query
                    ],
                ),
            ),
        )

        # MTU boundary testing
        mtu_boundary = Request(
            "UDP_MTU_Boundary",
            children=(
                Group(
                    "mtu_patterns",
                    values=[
                        b"M" * 576,  # Minimum MTU
                        b"M" * 1280,  # IPv6 minimum MTU
                        b"M" * 1472,  # Max unfragmented
                        b"M" * 1473,  # Forces fragmentation
                        b"M" * 1500,  # Ethernet MTU
                        b"M" * 9000,  # Jumbo frame
                    ],
                ),
            ),
        )

        # Zero-length and edge case datagrams
        zero_length = Request(
            "UDP_Zero_Length",
            children=(
                Group(
                    "zero_edge_patterns",
                    values=[
                        b"",  # Empty datagram
                        b"\x00",  # Single null
                        b"\xff",  # Single 0xff
                        b" ",  # Single space
                    ],
                ),
            ),
        )

        if self.is_request_enabled("UDP_Fragmentation_Attack"):
            self.session.connect(fragmentation)
        if self.config.get_option("test_amplification", True) and self.is_request_enabled(
            "UDP_Amplification"
        ):
            self.session.connect(amplification)
        if self.is_request_enabled("UDP_MTU_Boundary"):
            self.session.connect(mtu_boundary)
        if self.is_request_enabled("UDP_Zero_Length"):
            self.session.connect(zero_length)
