"""TFTP Protocol Fuzzer

Optimized for breadth-first coverage and early crash detection.

Test ordering phases:
- Phase 1: Quick opcode sweep (all 5 opcodes in ~30 sec)
- Phase 2: High-crash tests (overflow, buffer attacks)
- Phase 3: CVE-targeted path traversal
- Phase 4: Boundary attacks
- Phase 5: Everything else (standard tests, malformed packets)
"""

from typing import List

from boofuzz import Block, Byte, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import UDPSocketConnection
from ..primitives.dynamic import SmartString
from ..primitives.smart_string import StringContext


class TFTPFuzzer(BaseFuzzer):
    """TFTP Protocol Fuzzer for file transfer server security testing

    Targets TFTP vulnerabilities including buffer overflows in filename/mode
    fields, malformed packet structures, and path traversal attacks.

    Optimized test ordering:
    - All 5 opcodes tested within first 30 seconds
    - Buffer overflow and oversized payload tests early
    - CVE-targeted path traversal patterns (CVE-2011-4722, CVE-2017-6805)
    - Boundary value testing for block numbers and error codes
    """

    # Protocol-specific monitor: TFTP read check every 50 tests
    DEFAULT_MONITORS = "tftp:50"

    PROTOCOL_OPTIONS: dict = {}

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "TFTP_Quick_Coverage", "Quick opcode sweep (all 5 opcodes once)", "baseline"
            ),
            # Phase 2: High-crash tests
            RequestInfo("TFTP_Overflow", "Oversized filename/data buffer overflows", "overflow"),
            RequestInfo(
                "TFTP_Deep_Traversal", "Deep path traversal attacks (CVE patterns)", "traversal"
            ),
            # Phase 3: CVE-targeted
            RequestInfo("TFTP_CVE_Traversal", "CVE-specific traversal patterns", "cve"),
            # Phase 4: Boundary testing
            RequestInfo("TFTP_Boundary", "Block number and error code boundaries", "boundary"),
            # Phase 5: Standard operations
            RequestInfo(
                "TFTP_Standard_Ops", "Standard RRQ/WRQ/DATA/ACK/ERROR operations", "standard"
            ),
            RequestInfo("TFTP_Invalid_Mode", "Invalid transfer mode testing", "protocol"),
            RequestInfo("TFTP_Malformed", "Malformed packets and invalid opcodes", "malformed"),
            RequestInfo(
                "TFTP_Short_Datagram",
                "Runt datagrams shorter than the fixed header (0-3 bytes)",
                "malformed",
            ),
            RequestInfo(
                "TFTP_Unterminated",
                "RRQ/WRQ strings without null termination (decode-walk)",
                "malformed",
            ),
        ]

    def _create_socket(self):
        # TFTP requires binding to a local port to receive responses
        # The bind tuple (host, port) specifies where to listen for responses
        # Using port 0 lets the OS pick an available ephemeral port
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),  # Bind to any interface, ephemeral port
            **self._timeout_overrides(recv_default=2.0),  # Wait up to 2 seconds for response
        )

    def setup_custom_monitors(self) -> list:
        """Setup TFTP-specific monitoring with RRQ/response validation"""
        from ..monitors import TFTPReadMonitor

        tftp_monitor = TFTPReadMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            timeout=2,
            check_interval=3,  # Check every 3 test cases
        )

        return [tftp_monitor]

    def _define_protocol(self) -> None:
        """Define TFTP protocol structure for fuzzing

        Optimized ordering for breadth-first coverage:
        - Phase 1: Quick opcode sweep (all 5 opcodes in ~30 sec)
        - Phase 2: High-crash tests (oversized, deep traversal)
        - Phase 3: CVE-targeted path traversal
        - Phase 4: Boundary attacks (block numbers, error codes)
        - Phase 5: Standard operations and malformed packets
        """

        # ================================================================
        # PHASE 1: QUICK OPCODE SWEEP (~30 sec)
        # Touch all 5 TFTP opcodes once with minimal params for breadth coverage
        # ================================================================

        quick_coverage = Request(
            "Quick_Opcode_Coverage",
            children=(
                Block(
                    "Quick_Coverage_Packet",
                    children=(
                        # Cycle through all 5 opcodes
                        Group(
                            "opcode",
                            values=[
                                b"\x00\x01",  # RRQ (1)
                                b"\x00\x02",  # WRQ (2)
                                b"\x00\x03",  # DATA (3)
                                b"\x00\x04",  # ACK (4)
                                b"\x00\x05",  # ERROR (5)
                            ],
                        ),
                        # Minimal valid payload that works for all opcodes
                        Static("filename", "test.txt"),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 2: HIGH-CRASH TESTS (buffer overflows, oversized payloads)
        # Moved early - these trigger crashes in vulnerable implementations
        # ================================================================

        # 2a. Oversized Filename - Buffer overflow in filename parsing
        # CVE-2011-4722, CVE-2017-6805 patterns
        oversized_filename_rrq = Request(
            "TFTP_Oversized_Filename_RRQ",
            children=(
                Block(
                    "Oversized_Filename_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        # Large filenames to overflow stack buffers
                        Group(
                            "overflow_filename",
                            values=[
                                "A" * 256,  # Common buffer size
                                "A" * 512,  # Standard TFTP filename max
                                "A" * 1024,  # Double standard max
                                "A" * 2048,  # Large overflow
                                "A" * 4096,  # Very large overflow
                                "/" + "A" * 500,  # Path prefix
                                "../" + "A" * 500,  # Traversal + overflow combo
                            ],
                        ),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 2b. Oversized Filename WRQ - Write request buffer overflow
        oversized_filename_wrq = Request(
            "TFTP_Oversized_Filename_WRQ",
            children=(
                Block(
                    "Oversized_Filename_WRQ",
                    children=(
                        Word("opcode", 2, endian=">"),
                        Group(
                            "overflow_filename",
                            values=[
                                "B" * 256,
                                "B" * 512,
                                "B" * 1024,
                                "B" * 2048,
                                "../" + "B" * 500,
                            ],
                        ),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 2c. Oversized DATA Packets - Heap overflow in data handling
        oversized_data = Request(
            "TFTP_Oversized_Data",
            children=(
                Block(
                    "Oversized_DATA",
                    children=(
                        Word("opcode", 3, endian=">"),
                        Word("block_number", 1, endian=">"),
                        # TFTP standard is 512 bytes, test beyond
                        Group(
                            "oversized_payload",
                            values=[
                                b"X" * 512,  # Standard max
                                b"X" * 513,  # Off-by-one
                                b"X" * 1024,  # Double
                                b"X" * 2000,  # Large overflow
                                b"X" * 4096,  # Very large overflow
                                b"\xff" * 512,  # High bytes
                                b"\x00" * 512 + b"X" * 512,  # Null padding + overflow
                            ],
                        ),
                    ),
                ),
            ),
        )

        # 2d. Oversized Error Message - Error message buffer overflow
        oversized_error_msg = Request(
            "TFTP_Oversized_Error_Msg",
            children=(
                Block(
                    "Oversized_ERROR",
                    children=(
                        Word("opcode", 5, endian=">"),
                        Word("error_code", 1, endian=">"),
                        Group(
                            "oversized_errmsg",
                            values=[
                                "Error: " + "E" * 256,
                                "Error: " + "E" * 512,
                                "Error: " + "E" * 1024,
                                "Error: " + "E" * 2048,
                            ],
                        ),
                        Byte("null_terminator", 0x00),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 3: CVE-TARGETED PATH TRAVERSAL
        # Specific patterns from CVE-2011-4722, CVE-2017-6805, CVE-2012-6664
        # ================================================================

        # 3a. Deep path traversal - crash parser testing
        deep_path_rrq = Request(
            "TFTP_Deep_Path_RRQ",
            children=(
                Block(
                    "Deep_Path_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        Group(
                            "deep_paths",
                            values=[
                                "../" * 100,  # Deep traversal to crash path parsers
                                "/.." * 100,
                                ".\\" * 100,
                                "\\\\*",
                                "\\\\?\\",
                                "....//....//....//....//....//....//",
                                "%2e%2e%2f" * 50,  # URL encoded traversal
                                "..%c0%af" * 50,  # UTF-8 overlong encoding
                                "..%252f" * 50,  # Double URL encoding
                            ],
                        ),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 3b. CVE-specific traversal patterns - targeting real vulnerabilities
        cve_traversal_rrq = Request(
            "TFTP_CVE_Traversal_RRQ",
            children=(
                Block(
                    "CVE_Traversal_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        Group(
                            "cve_paths",
                            values=[
                                # CVE-2011-4722 - Ipswitch WhatsUp Gold pattern
                                "../../../etc/passwd",
                                "..\\..\\..\\boot.ini",
                                "../../../windows/system32/config/sam",
                                # CVE-2017-6805 - MobaXterm pattern
                                "..\\..\\..\\..\\..\\..\\windows\\win.ini",
                                "../../../../../../../etc/shadow",
                                # CVE-2012-6664 - Distinct TFTP Server write traversal
                                "..\\..\\..\\..\\inetpub\\wwwroot\\shell.php",
                                "../../../../../tmp/evil.sh",
                                # Null byte injection for path truncation
                                "../../../etc/passwd\x00.txt",
                                "..\\..\\..\\boot.ini\x00.jpg",
                                # Mixed slash patterns
                                "..\\../..\\../etc/passwd",
                                "../..\\../..\\windows\\system.ini",
                            ],
                        ),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 3c. Write traversal for code execution (CVE-2012-6664 pattern)
        cve_traversal_wrq = Request(
            "TFTP_CVE_Traversal_WRQ",
            children=(
                Block(
                    "CVE_Traversal_WRQ",
                    children=(
                        Word("opcode", 2, endian=">"),
                        Group(
                            "cve_write_paths",
                            values=[
                                # Distinct TFTP Server 3.10 pattern
                                "..\\..\\..\\inetpub\\scripts\\shell.exe",
                                "../../../var/www/html/backdoor.php",
                                "..\\..\\windows\\system32\\config\\sam",
                                # Startup folder persistence
                                "..\\..\\..\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe",
                                "../../../etc/cron.d/evil",
                                # Web shell drops
                                "..\\..\\..\\wwwroot\\cmd.aspx",
                                "../../../htdocs/shell.php",
                            ],
                        ),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 4: BOUNDARY VALUE TESTING
        # Block numbers, error codes, opcode boundaries
        # ================================================================

        # 4a. Block Number Boundary Testing
        block_number_boundary = Request(
            "TFTP_Block_Number_Boundary",
            children=(
                Block(
                    "Block_Boundary_DATA",
                    children=(
                        Word("opcode", 3, endian=">"),
                        Group(
                            "block_boundary",
                            values=[
                                b"\x00\x00",  # Zero (often invalid)
                                b"\x00\x01",  # Minimum valid
                                b"\x7f\xff",  # Mid-range (32767)
                                b"\x80\x00",  # Sign bit flip (32768)
                                b"\xff\xfe",  # Maximum - 1 (65534)
                                b"\xff\xff",  # Maximum (65535)
                            ],
                        ),
                        Static("data", "test_data"),
                    ),
                ),
            ),
        )

        # 4b. ACK Block Number Boundary
        ack_block_boundary = Request(
            "TFTP_ACK_Block_Boundary",
            children=(
                Block(
                    "ACK_Block_Boundary",
                    children=(
                        Word("opcode", 4, endian=">"),
                        Group(
                            "ack_block_boundary",
                            values=[
                                b"\x00\x00",  # Zero
                                b"\x00\x01",  # First block
                                b"\x7f\xff",  # Mid-range
                                b"\x80\x00",  # Sign bit
                                b"\xff\xff",  # Maximum
                            ],
                        ),
                    ),
                ),
            ),
        )

        # 4c. Error Code Boundary Testing
        error_code_boundary = Request(
            "TFTP_Error_Code_Boundary",
            children=(
                Block(
                    "Error_Code_Boundary",
                    children=(
                        Word("opcode", 5, endian=">"),
                        Group(
                            "error_code_boundary",
                            values=[
                                b"\x00\x00",  # Not defined (0)
                                b"\x00\x01",  # File not found (1)
                                b"\x00\x02",  # Access violation (2)
                                b"\x00\x03",  # Disk full (3)
                                b"\x00\x04",  # Illegal operation (4)
                                b"\x00\x05",  # Unknown transfer ID (5)
                                b"\x00\x06",  # File already exists (6)
                                b"\x00\x07",  # No such user (7)
                                b"\x00\x08",  # Terminate transfer (8) - RFC 2347
                                b"\x00\xff",  # Invalid error code
                                b"\xff\xff",  # Maximum
                            ],
                        ),
                        Static("error_message", "Test error"),
                        Byte("null_terminator", 0x00),
                    ),
                ),
            ),
        )

        # 4d. Opcode Boundary Testing
        opcode_boundary = Request(
            "TFTP_Opcode_Boundary",
            children=(
                Block(
                    "Opcode_Boundary",
                    children=(
                        Group(
                            "opcode_boundary",
                            values=[
                                b"\x00\x00",  # Zero (invalid)
                                b"\x00\x01",  # RRQ (valid)
                                b"\x00\x05",  # ERROR (valid max)
                                b"\x00\x06",  # OACK - RFC 2347 option acknowledgment
                                b"\x00\x07",  # Invalid
                                b"\x00\xff",  # High byte
                                b"\xff\x00",  # Swapped
                                b"\xff\xff",  # Maximum
                            ],
                        ),
                        Static("filename", "test.txt"),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # ================================================================
        # PHASE 5: STANDARD OPERATIONS
        # Full fuzzing of each opcode with SmartString mutations
        # ================================================================

        # 5a. Standard Read Request (RRQ)
        read_request = Request(
            "TFTP_RRQ",
            children=(
                Block(
                    "RRQ_Packet",
                    children=(
                        Word("opcode", 1, endian=">"),
                        SmartString(
                            "filename",
                            "test.txt",
                            max_len=512,
                            fuzzable=True,
                            context=StringContext.FILENAME,
                        ),
                        Byte("null1", 0x00),
                        Group("mode", values=["netascii", "octet", "mail"]),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 5b. Standard Write Request (WRQ)
        write_request = Request(
            "TFTP_WRQ",
            children=(
                Block(
                    "WRQ_Packet",
                    children=(
                        Word("opcode", 2, endian=">"),
                        SmartString(
                            "filename",
                            "upload.txt",
                            max_len=512,
                            fuzzable=True,
                            context=StringContext.FILENAME,
                        ),
                        Byte("null1", 0x00),
                        Group("mode", values=["netascii", "octet", "mail"]),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 5c. Standard DATA Packet
        data_packet = Request(
            "TFTP_DATA",
            children=(
                Block(
                    "DATA_Packet",
                    children=(
                        Word("opcode", 3, endian=">"),
                        Word("block_number", 1, endian=">", fuzzable=True),
                        SmartString("data", "Hello TFTP World!", max_len=512, fuzzable=True),
                    ),
                ),
            ),
        )

        # 5d. Standard ACK Packet
        ack_packet = Request(
            "TFTP_ACK",
            children=(
                Block(
                    "ACK_Packet",
                    children=(
                        Word("opcode", 4, endian=">"),
                        Word("block_number", 1, endian=">", fuzzable=True),
                    ),
                ),
            ),
        )

        # 5e. Standard ERROR Packet
        error_packet = Request(
            "TFTP_ERROR",
            children=(
                Block(
                    "ERROR_Packet",
                    children=(
                        Word("opcode", 5, endian=">"),
                        Word("error_code", 1, endian=">", fuzzable=True),
                        SmartString("error_message", "File not found", max_len=512, fuzzable=True),
                        Byte("null_terminator", 0x00),
                    ),
                ),
            ),
        )

        # 5f. Invalid Mode Strings
        invalid_mode_rrq = Request(
            "TFTP_Invalid_Mode_RRQ",
            children=(
                Block(
                    "Invalid_Mode_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        Static("filename", "test.txt"),
                        Byte("null1", 0x00),
                        Group(
                            "invalid_modes",
                            values=[
                                "invalid_mode",
                                "A" * 100,
                                "netascii\x00extra_data",
                                "octet\r\ninjected",
                                "\x00\x01\x02\x03",
                                "mode_with_nulls\x00\x00\x00",
                                "",  # Empty mode
                                "binary",  # Non-standard mode
                                "ascii",  # Non-standard mode
                            ],
                        ),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # 5g. Malformed Packets with Invalid Opcodes
        malformed_packets = Request(
            "TFTP_Malformed",
            children=(
                Block(
                    "Malformed_Packet",
                    children=(
                        Word("invalid_opcode", 99, endian=">", fuzzable=True),
                        SmartString("random_data", "AAAA", max_len=1000, fuzzable=True),
                    ),
                ),
            ),
        )

        # 5h. RFC 2347 Options (OACK testing)
        options_request = Request(
            "TFTP_Options_RRQ",
            children=(
                Block(
                    "Options_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        Static("filename", "test.txt"),
                        Byte("null1", 0x00),
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                        # RFC 2347/2348/2349 options
                        Group(
                            "option_name",
                            values=[
                                "blksize",  # RFC 2348
                                "tsize",  # RFC 2349
                                "timeout",  # RFC 2349
                                "multicast",  # RFC 2090
                                "windowsize",  # RFC 7440
                            ],
                        ),
                        Byte("null3", 0x00),
                        Group(
                            "option_value",
                            values=[
                                "0",  # Zero
                                "1",  # Minimum
                                "512",  # Default block size
                                "1024",  # Double block size
                                "65464",  # Maximum block size
                                "65535",  # Over maximum
                                "-1",  # Negative
                                "AAAA",  # Non-numeric
                            ],
                        ),
                        Byte("null4", 0x00),
                    ),
                ),
            ),
        )

        # 5i. Short / runt datagrams (shorter than the fixed TFTP header)
        # Cut the length-bearing field into the last 1-6 bytes: exercises
        # servers that index opcode/block/error-code without a length check.
        short_datagram = Request(
            "TFTP_Short_Datagram",
            children=(
                Block(
                    "Short_Datagram",
                    children=(
                        Group(
                            "runt_bytes",
                            values=[
                                b"",  # 0-byte datagram
                                b"\x00",  # 1-byte partial opcode
                                b"\x00\x03",  # 2-byte opcode-only DATA (block absent)
                                b"\x00\x04",  # 2-byte opcode-only ACK (block absent)
                                b"\x00\x05",  # 2-byte opcode-only ERROR (code absent)
                                b"\x00\x03\x00",  # 3-byte DATA: opcode + 1 of 2 block bytes
                                b"\x00\x04\x00",  # 3-byte ACK: opcode + 1 of 2 block bytes
                            ],
                        ),
                    ),
                ),
            ),
        )

        # 5j. Unterminated strings (fixed-buffer decode-walk class)
        # RRQ with a long filename and NO trailing null before the mode:
        # a naive strlen/strcpy walks off the end of the field.
        unterminated_filename_rrq = Request(
            "TFTP_Malformed_Unterminated_Filename_RRQ",
            children=(
                Block(
                    "Unterminated_Filename_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        Static("filename", "A" * 300),
                        # NO null terminator here -> filename runs into mode
                        Static("mode", "octet"),
                        Byte("null2", 0x00),
                    ),
                ),
            ),
        )

        # RRQ with filename+null but the mode NOT null-terminated: the packet
        # ends mid-mode, so a mode-string decode walks past the datagram end.
        unterminated_mode_rrq = Request(
            "TFTP_Malformed_Unterminated_Mode_RRQ",
            children=(
                Block(
                    "Unterminated_Mode_RRQ",
                    children=(
                        Word("opcode", 1, endian=">"),
                        Static("filename", "test.txt"),
                        Byte("null1", 0x00),
                        Static("mode", "netascii"),
                        # NO trailing null -> packet ends mid-mode
                    ),
                ),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Reordered for fast coverage + early crash detection

        # ==================== PHASE 1: QUICK OPCODE SWEEP (~30 sec) ====================
        if self.is_request_enabled("TFTP_Quick_Coverage"):
            self.session.connect(quick_coverage)

        # ==================== PHASE 2: HIGH-CRASH TESTS (~2 min) ====================
        if self.is_request_enabled("TFTP_Overflow"):
            self.session.connect(oversized_filename_rrq)
            self.session.connect(oversized_filename_wrq)
            self.session.connect(oversized_data)
            self.session.connect(oversized_error_msg)

        if self.is_request_enabled("TFTP_Deep_Traversal"):
            self.session.connect(deep_path_rrq)

        # ==================== PHASE 3: CVE-TARGETED (~2 min) ====================
        if self.is_request_enabled("TFTP_CVE_Traversal"):
            self.session.connect(cve_traversal_rrq)
            self.session.connect(cve_traversal_wrq)

        # ==================== PHASE 4: BOUNDARY TESTS (~2 min) ====================
        if self.is_request_enabled("TFTP_Boundary"):
            self.session.connect(block_number_boundary)
            self.session.connect(ack_block_boundary)
            self.session.connect(error_code_boundary)
            self.session.connect(opcode_boundary)

        # ==================== PHASE 5: STANDARD OPERATIONS ====================
        if self.is_request_enabled("TFTP_Standard_Ops"):
            self.session.connect(read_request)
            self.session.connect(write_request)
            self.session.connect(data_packet)
            self.session.connect(ack_packet)
            self.session.connect(error_packet)
            self.session.connect(options_request)

        if self.is_request_enabled("TFTP_Invalid_Mode"):
            self.session.connect(invalid_mode_rrq)

        if self.is_request_enabled("TFTP_Malformed"):
            self.session.connect(malformed_packets)

        if self.is_request_enabled("TFTP_Short_Datagram"):
            self.session.connect(short_datagram)

        if self.is_request_enabled("TFTP_Unterminated"):
            self.session.connect(unterminated_filename_rrq)
            self.session.connect(unterminated_mode_rrq)

        return self.session
