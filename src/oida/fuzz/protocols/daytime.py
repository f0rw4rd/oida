"""Daytime Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (5 Phases):
    Phase 1 (0-10s): Quick_Coverage - One request per input type
    Phase 2 (10-30s): High-crash tests - Buffer overflow, large payloads
    Phase 3 (30-60s): Boundary attacks - Integer boundaries, format strings
    Phase 4 (60-120s): Input variations - Commands, unicode, encodings
    Phase 5 (120s+): Deep fuzzing - Full mutation of all fields

Security Notes:
    - RFC 867 Daytime protocol is simple (connect -> receive time string)
    - However, implementations have had buffer overflows in response parsing
    - Some implementations accept input before sending time (triggers Phase 2)
    - Format string vulnerabilities possible in logging implementations
"""

from typing import List

from boofuzz import Group, RandomData, Request, Static

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.connections import TCPSocketConnection
from oida.fuzz.core.connections import CountingUDPConnection as UDPSocketConnection
from oida.fuzz.monitors import BaseMonitor
from oida.fuzz.primitives.dynamic import SmartString


class DaytimeFuzzer(BaseFuzzer):
    """Daytime Protocol Fuzzer for TCP variant (RFC 867)

    Optimized for breadth-first coverage with high-crash tests early.
    """

    PROTOCOL_OPTIONS = {
        "use_udp": {
            "type": bool,
            "default": False,
            "description": "Use UDP instead of TCP",
            "example": "true",
        },
        "send_requests": {
            "type": bool,
            "default": False,
            "description": "Send data to trigger responses (some implementations)",
            "example": "true",
        },
        "test_commands": {
            "type": bool,
            "default": True,
            "description": "Test with command-like inputs",
            "example": "true",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick coverage
            RequestInfo("Daytime_Baseline", "Quick sweep of all input types (~10 sec)", "baseline"),
            # Phase 2: High-crash tests
            RequestInfo(
                "Daytime_Overflow", "Buffer overflow and large payload attacks", "overflow"
            ),
            # Phase 3: Boundary attacks
            RequestInfo(
                "Daytime_Boundary", "Integer boundary and format string attacks", "boundary"
            ),
            # Phase 4: Input variations
            RequestInfo("Daytime_Commands", "Command-like inputs (TIME, DATE, etc.)", "input"),
            RequestInfo("Daytime_Unicode", "Unicode and encoding variations", "input"),
            RequestInfo("Daytime_HTTP", "HTTP-wrapped requests", "input"),
            # Phase 5: Deep fuzzing
            RequestInfo("Daytime_Binary", "Random binary data fuzzing", "deep"),
            RequestInfo("Daytime_LineEndings", "Line ending variations", "deep"),
            # UDP-mode requests (only connected when use_udp): listed so they are
            # visible to --list-requests and honor --enable/--disable.
            RequestInfo("UDP_MTU_Boundary", "UDP MTU boundary datagrams", "boundary"),
            RequestInfo("UDP_Oversized", "UDP oversized datagrams", "boundary"),
        ]

    def _create_socket(self):
        """Create TCP or UDP socket connection on port 13"""
        if self.config.get_option("use_udp", False):
            return UDPSocketConnection(
                self.config.target_ip,
                self.config.target_port or 13,
                bind=("0.0.0.0", 0),
                **self._timeout_overrides(recv_default=2.0),
            )
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port or 13,
            **self._timeout_overrides(),
        )

    def setup_custom_monitors(self) -> List[BaseMonitor]:
        """No special monitoring needed for Daytime"""
        return []

    def _define_protocol(self) -> None:
        """Define Daytime protocol fuzzing structure

        Optimized test ordering:
        - Phase 1: Quick feature sweep (all input types once)
        - Phase 2: High-crash tests (overflow, buffer attacks)
        - Phase 3: Boundary attacks (integer limits, format strings)
        - Phase 4: Input variations (commands, unicode, HTTP-wrapped)
        - Phase 5: Deep fuzzing (binary, line endings)
        """

        send_requests = self.config.get_option("send_requests", False)
        test_commands = self.config.get_option("test_commands", True)

        # ============================================================
        # PHASE 1: QUICK COVERAGE (~10 sec)
        # Touch all input types in one request for maximum breadth
        # ============================================================

        # Quick_Coverage: Single request cycling through all input types
        # This ensures we hit empty, text, binary, unicode, and oversized in first pass
        quick_coverage = Request(
            "Quick_Coverage",
            children=(
                Group(
                    "all_input_types",
                    values=[
                        b"",  # Empty (standard daytime)
                        b"\r\n",  # Simple trigger
                        b"TIME\r\n",  # Text command
                        b"\x00\xff\x7f\x80",  # Binary boundaries
                        "时间".encode("utf-8"),  # Unicode
                        b"A" * 256,  # Small overflow
                        b"%s%s%s%s\r\n",  # Format string
                        b"GET / HTTP/1.0\r\n\r\n",  # HTTP-like
                    ],
                ),
            ),
        )

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS (~20 sec)
        # Buffer overflow and large payload attacks
        # ============================================================

        # Large payload overflow attacks
        overflow_small = Request(
            "Overflow_Small",
            children=(
                SmartString("payload", "A" * 1024, max_len=1024, fuzzable=True),
                Static("crlf", b"\r\n"),
            ),
        )

        overflow_medium = Request(
            "Overflow_Medium",
            children=(
                SmartString("payload", "B" * 4096, max_len=4096, fuzzable=True),
                Static("crlf", b"\r\n"),
            ),
        )

        overflow_large = Request(
            "Overflow_Large",
            children=(
                SmartString("payload", "C" * 65535, max_len=65535, fuzzable=True),
                Static("crlf", b"\r\n"),
            ),
        )

        # Binary data with potential crash triggers
        binary_crash = Request(
            "Binary_Crash",
            children=(
                Group(
                    "crash_patterns",
                    values=[
                        b"\x00" * 256,  # Null bytes (string termination)
                        b"\xff" * 256,  # All 0xFF bytes
                        b"\x00\x00\x00\x00" * 64,  # Aligned nulls
                        b"\x41\x41\x41\x41" * 1024,  # Stack overflow pattern (AAAA)
                        b"\xcc\xcc\xcc\xcc" * 256,  # INT3 pattern (debug)
                        b"\x90" * 1024 + b"\xcc" * 4,  # NOP sled + INT3
                    ],
                ),
                Static("crlf", b"\r\n"),
            ),
        )

        # ============================================================
        # PHASE 3: BOUNDARY ATTACKS (~30 sec)
        # Integer boundaries and format string attacks
        # ============================================================

        # Integer boundary values in data
        boundary_values = Request(
            "Boundary_Values",
            children=(
                Group(
                    "boundaries",
                    values=[
                        b"\x00",  # Minimum byte
                        b"\x7f",  # Max signed byte
                        b"\x80",  # Min negative signed
                        b"\xff",  # Max byte
                        b"\x00\x00",  # Zero word
                        b"\xff\xff",  # Max word
                        b"\x7f\xff\xff\xff",  # Max signed 32-bit
                        b"\x80\x00\x00\x00",  # Min negative signed 32-bit
                        b"\xff\xff\xff\xff",  # Max 32-bit
                    ],
                ),
                Static("crlf", b"\r\n"),
            ),
        )

        # Format string attacks (for implementations with logging)
        format_strings = Request(
            "Format_Strings",
            children=(
                Group(
                    "format_patterns",
                    values=[
                        b"%s%s%s%s%s%s%s%s",  # String format
                        b"%x%x%x%x%x%x%x%x",  # Hex dump
                        b"%n%n%n%n%n%n%n%n",  # Write format (dangerous)
                        b"%p%p%p%p%p%p%p%p",  # Pointer leak
                        b"%.10000s",  # Long format
                        b"%99999$n",  # Direct parameter
                        b"AAAA%08x.%08x.%08x.%08x",  # Stack dump
                    ],
                ),
                Static("crlf", b"\r\n"),
            ),
        )

        # ============================================================
        # PHASE 4: INPUT VARIATIONS (~60 sec)
        # Commands, Unicode, HTTP-wrapped
        # ============================================================

        # Standard daytime behavior - just connect (no data sent)
        empty_request = Request("Empty_Request", children=(Static("empty", b""),))

        # Simple trigger (some servers wait for input)
        simple_request = Request(
            "Simple_Request", children=(SmartString("request", "\r\n", fuzzable=False),)
        )

        # Text request with fuzzing
        text_request = Request(
            "Text_Request",
            children=(
                SmartString("text", "TIME", max_len=10, fuzzable=True),
                Static("crlf", b"\r\n"),
            ),
        )

        # Command-like inputs (for non-standard implementations)
        protocol_commands = Request(
            "Protocol_Commands",
            children=(
                Group(
                    "commands",
                    values=[
                        b"GET TIME",
                        b"HELP",
                        b"STATUS",
                        b"VERSION",
                        b"DATE",
                        b"TIME",
                        b"UTC",
                        b"GMT",
                        b"LOCAL",
                        b"TZ=UTC",
                    ],
                ),
                Static("crlf", b"\r\n"),
            ),
        )

        # Unicode and UTF-8 encoding tests
        unicode_request = Request(
            "Unicode_Request",
            children=(
                Group(
                    "unicode",
                    values=[
                        "时间".encode("utf-8"),  # Chinese for "time"
                        "الوقت".encode("utf-8"),  # Arabic for "time"
                        "🕐🕑🕒".encode("utf-8"),  # Clock emojis
                        ("\U0001f600" * 10).encode("utf-8"),
                        b"\x00" + b"\xef\xbf\xbf",  # Unicode boundaries
                        b"\xc0\x80",  # Overlong null
                        b"\xed\xa0\x80",  # Surrogate (invalid UTF-8)
                    ],
                ),
                Static("crlf", b"\r\n"),
            ),
        )

        # HTTP-like request (some implementations might be HTTP-wrapped)
        http_request = Request(
            "HTTP_Request",
            children=(
                Static("method", b"GET / HTTP/1.1\r\n"),
                Static("host", b"Host: "),
                SmartString("hostname", "localhost", max_len=50, fuzzable=True),
                Static("crlf1", b"\r\n"),
                Static("user_agent", b"User-Agent: DaytimeFuzzer\r\n"),
                Static("crlf2", b"\r\n"),
            ),
        )

        # ============================================================
        # PHASE 5: DEEP FUZZING (remaining time)
        # Full mutation of binary and line endings
        # ============================================================

        # Binary random data with full mutation
        binary_request = Request(
            "Binary_Request",
            children=(
                RandomData("binary", min_length=1, max_length=100, max_mutations=25),
                Static("crlf", b"\r\n"),
            ),
        )

        # Line ending variations
        line_endings = Request(
            "Line_Endings",
            children=(
                SmartString("data", "REQUEST", max_len=20, fuzzable=True),
                Group(
                    "endings",
                    values=[
                        b"\r\n",  # Windows
                        b"\n",  # Unix
                        b"\r",  # Old Mac
                        b"\r\n\r\n",  # Double Windows
                        b"\n\n",  # Double Unix
                        b"\r\r",  # Double Mac
                        b"\x00",  # Null termination
                    ],
                ),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Phase 1: Quick coverage (all types once)
        # Phase 2: High-crash tests (overflow, binary attacks)
        # Phase 3: Boundary attacks (integers, format strings)
        # Phase 4: Input variations (commands, unicode, HTTP)
        # Phase 5: Deep fuzzing (binary, line endings)

        # PHASE 1: Quick Coverage (~10 sec)
        if self.is_request_enabled("Daytime_Baseline"):
            self.session.connect(quick_coverage)

        # PHASE 2: High-Crash Tests (~20 sec)
        if self.is_request_enabled("Daytime_Overflow"):
            self.session.connect(overflow_small)
            self.session.connect(overflow_medium)
            self.session.connect(overflow_large)
            self.session.connect(binary_crash)

        # PHASE 3: Boundary Attacks (~30 sec)
        if self.is_request_enabled("Daytime_Boundary"):
            self.session.connect(boundary_values)
            self.session.connect(format_strings)

        # PHASE 4: Input Variations (~60 sec)
        if self.is_request_enabled("Daytime_Commands"):
            if not send_requests:
                self.session.connect(empty_request)
            else:
                self.session.connect(simple_request)
                self.session.connect(text_request)

            if test_commands:
                self.session.connect(protocol_commands)

        if self.is_request_enabled("Daytime_Unicode"):
            self.session.connect(unicode_request)

        if self.is_request_enabled("Daytime_HTTP"):
            self.session.connect(http_request)

        # PHASE 5: Deep Fuzzing (remaining time)
        if self.is_request_enabled("Daytime_Binary"):
            self.session.connect(binary_request)

        if self.is_request_enabled("Daytime_LineEndings"):
            self.session.connect(line_endings)

        # UDP-specific tests
        if self.config.get_option("use_udp", False):
            self._define_udp_protocol()

    def _define_udp_protocol(self) -> None:
        """Define UDP-specific daytime tests"""
        # MTU boundary testing
        mtu_boundary = Request(
            "UDP_MTU_Boundary",
            children=(
                Group(
                    "mtu_patterns",
                    values=[
                        b"",  # Empty datagram
                        b"M" * 576,  # Minimum MTU
                        b"M" * 1472,  # Max unfragmented
                        b"M" * 1500,  # Ethernet MTU
                    ],
                ),
            ),
        )

        # Oversized datagrams
        oversized = Request(
            "UDP_Oversized",
            children=(
                Group(
                    "oversized_patterns",
                    values=[
                        b"O" * 2048,
                        b"O" * 4096,
                        b"O" * 8192,
                        b"O" * 65507,  # Max UDP payload
                    ],
                ),
            ),
        )

        if self.is_request_enabled("UDP_MTU_Boundary"):
            self.session.connect(mtu_boundary)
        if self.is_request_enabled("UDP_Oversized"):
            self.session.connect(oversized)
