"""ASTM E1381 / E1394 Clinical Lab (LIS) Protocol Fuzzer

Targets the low-level framing (ASTM E1381) and record layer (ASTM E1394,
a.k.a. CLSI LIS1-A / LIS2-A2) spoken by clinical laboratory instruments and
Laboratory Information Systems (LIS). These parsers are almost always legacy
firmware / vendor middleware with minimal input validation, so the same crash
shapes that plague HL7/MLLP receivers apply here: fixed-buffer record fields,
sloppy frame framing, and delimiter injection.

E1381 low-level frame layout:

    <STX> frame# <text> <ETX|ETB> C1 C2 <CR> <LF>

    STX  = 0x02   frame start
    frame# = one ASCII digit 0-7 (mod 8 frame counter)
    text = one E1394 record (or record fragment)
    ETX  = 0x03   last frame of the record
    ETB  = 0x17   intermediate frame (more to follow)
    C1C2 = two uppercase-hex ASCII chars, mod-256 sum of frame#..ETX/ETB
    CR LF = 0x0D 0x0A   frame terminator

E1381 link-layer handshake bytes:

    ENQ 0x05   ACK 0x06   NAK 0x15   EOT 0x04

E1394 records carried in <text> (first char is the record type):

    H = header   P = patient   O = order   R = result
    C = comment  Q = query     L = terminator

    Fields delimited by  |   components by  ^   repeats by  \\   escape by  &
    The H record's second field declares the delimiters, e.g.  "H|\\^&|||..."

Fuzzing categories (mirrors the HL7/MLLP framing fuzzer):
    baseline  - a valid, correctly-checksummed H-record frame
    overflow  - oversized record fields overflowing fixed instrument buffers
    boundary  - frame-number and record-type edge values
    malformed - checksum corruption, delimiter injection, truncated framing
"""

from typing import List

from boofuzz import Bytes, Group, Request

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.connections import TCPSocketConnection
from oida.fuzz.primitives.dynamic import SmartString, StringContext

# ASTM E1381 low-level control bytes
STX = b"\x02"
ETX = b"\x03"
ETB = b"\x17"
CR = b"\x0d"
LF = b"\x0a"
ENQ = b"\x05"
ACK = b"\x06"
NAK = b"\x15"
EOT = b"\x04"

# ASTM E1381 over TCP is commonly exposed on 12000 by instrument gateways.
DEFAULT_PORT = 12000


def astm_checksum(body: bytes) -> bytes:
    """ASTM E1381 frame checksum: mod-256 sum of the framed body, 2 upper-hex ASCII.

    The body spans the frame-number digit through the ETX/ETB terminator
    (inclusive) but excludes the leading STX. Represented as two uppercase
    hexadecimal ASCII characters.
    """
    return f"{sum(body) & 0xFF:02X}".encode("ascii")


def astm_frame(frame_num: bytes, text: bytes, end: bytes = ETX) -> bytes:
    """Assemble a complete, correctly-checksummed E1381 frame."""
    body = frame_num + text + end
    return STX + body + astm_checksum(body) + CR + LF


class ASTMFuzzer(BaseFuzzer):
    """ASTM E1381/E1394 clinical-lab (LIS) protocol fuzzer.

    Exercises the E1381 framing layer (STX/frame#/checksum/ETX-ETB/CRLF) and the
    E1394 record/field layer (| ^ \\ & delimiters) of laboratory instruments and
    LIS middleware over TCP. Analogous to the HL7/MLLP framing fuzzer.

    ASTM-over-TCP instruments typically listen on port 12000.
    """

    # Mirror the HL7 framing fuzzer's monitor cadence (healthcare TCP framing).
    DEFAULT_MONITORS = "hl7:20"

    # A representative valid E1394 header record. Second field declares the
    # delimiters: repeat=\  component=^  escape=&  (field separator is '|').
    H_RECORD = b"H|\\^&|||OIDA_LIS^1.0|||||||P|LIS2-A2|20260101120000"

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests (strict 1:1 gating)."""
        return [
            RequestInfo(
                "ASTM_Baseline",
                "Valid framed H record with a correct E1381 checksum",
                "baseline",
            ),
            RequestInfo(
                "ASTM_Checksum_Corrupt",
                "Valid frame carrying a wrong 2-byte checksum",
                "malformed",
            ),
            RequestInfo(
                "ASTM_Oversized_Record",
                "H/O/R record with an oversized field (256/1024/4096 'A') overflowing fixed buffers",
                "overflow",
            ),
            RequestInfo(
                "ASTM_Delimiter_Injection",
                "Inject | ^ \\ & and embedded CR/STX/null into record fields",
                "malformed",
            ),
            RequestInfo(
                "ASTM_Frame_Number_Boundary",
                "Frame-number byte across 0-9, non-digit and 0xFF",
                "boundary",
            ),
            RequestInfo(
                "ASTM_Missing_Terminator",
                "Frame missing ETX/checksum/CRLF so the receiver reads past the frame",
                "malformed",
            ),
            RequestInfo(
                "ASTM_Record_Type_Boundary",
                "Record-type char across H/P/O/R/C/Q/L, invalid and empty",
                "boundary",
            ),
        ]

    def _create_socket(self):
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port or DEFAULT_PORT,
            **self._timeout_overrides(),
        )

    def _define_protocol(self) -> None:
        """Define the ASTM E1381/E1394 fuzzing structure."""
        h_record = self.H_RECORD
        # frame#..ETX body of the baseline H-record frame (STX excluded from sum).
        base_body = b"1" + h_record + ETX

        # =====================================================================
        # BASELINE: a valid ENQ / framed H record / EOT exchange
        # =====================================================================
        baseline = Request(
            "ASTM_Baseline",
            children=(
                Bytes("ENQ", ENQ, fuzzable=False),
                Bytes("Frame", astm_frame(b"1", h_record, ETX), fuzzable=False),
                Bytes("EOT", EOT, fuzzable=False),
            ),
        )

        # =====================================================================
        # MALFORMED: correct frame body, wrong checksum group
        # =====================================================================
        checksum_corrupt = Request(
            "ASTM_Checksum_Corrupt",
            children=(
                Bytes("STX", STX, fuzzable=False),
                # frame# + text + ETX (a well-formed body; only the checksum lies)
                Bytes("Body", base_body, fuzzable=False),
                Group(
                    "Bad_Checksum",
                    values=[
                        b"00",  # zeroed
                        b"FF",  # all bits set
                        b"ZZ",  # non-hex
                        b"XY",  # non-hex
                        b"0",  # too short
                        b"000",  # too long
                        b"ff",  # lowercase (spec mandates uppercase)
                        b"\x00\x00",  # binary NULs where hex ASCII is expected
                    ],
                ),
                Bytes("CRLF", CR + LF, fuzzable=False),
            ),
        )

        # =====================================================================
        # OVERFLOW: oversized record field (SmartString variable field + A-run)
        # =====================================================================
        oversized_record = Request(
            "ASTM_Oversized_Record",
            children=(
                Bytes("STX", STX, fuzzable=False),
                Bytes("Frame_Number", b"2", fuzzable=False),
                Group("Record_Type", values=[b"H", b"O", b"R"]),
                Bytes("Sep1", b"|", fuzzable=False),
                # E1394 sender-name/ID record field: a VisibleString identifier.
                # CREDENTIAL adds identifier-injection payloads (NULL truncation,
                # homoglyph, control/whitespace) that confuse sender matching in
                # the LIS record layer, on top of the SmartString length testing.
                SmartString(
                    "Sender",
                    "OIDA_LIS",
                    max_len=256,
                    fuzzable=True,
                    context=StringContext.CREDENTIAL,
                ),
                Bytes("Sep2", b"|", fuzzable=False),
                # Oversized field overflowing fixed instrument parse buffers.
                Group("Oversized", values=[b"A" * 256, b"A" * 1024, b"A" * 4096]),
                Bytes("ETX", ETX, fuzzable=False),
                Bytes("Checksum", b"00", fuzzable=False),
                Bytes("CRLF", CR + LF, fuzzable=False),
            ),
        )

        # =====================================================================
        # MALFORMED: E1394 delimiter injection into a P (patient) record
        # =====================================================================
        delimiter_injection = Request(
            "ASTM_Delimiter_Injection",
            children=(
                Bytes("STX", STX, fuzzable=False),
                Bytes("Prefix", b"3P|1|", fuzzable=False),
                Group(
                    "Injected_Field",
                    values=[
                        b"DOE^JOHN",  # well-formed component (control)
                        b"DOE|JOHN",  # extra field separator
                        b"DOE||JOHN",  # empty field
                        b"DOE^^JOHN",  # extra component separator
                        b"DOE\\JOHN",  # repeat delimiter
                        b"DOE&JOHN",  # escape / subcomponent delimiter
                        b"DOE^JOHN^\\&|",  # every delimiter at once
                        b"|" * 64,  # field-separator flood
                        b"^" * 64,  # component-separator flood
                        b"\\" * 64,  # repeat-delimiter flood
                        b"&" * 64,  # escape-delimiter flood
                        b"DOE" + CR + b"H|\\^&",  # embedded CR -> premature record/frame break
                        b"DOE" + STX + b"INJECT",  # embedded STX -> false frame start
                        b"DOE\x00NULL",  # embedded NUL -> C-string truncation
                        b"DOE" + ETX + b"00",  # embedded ETX + fake checksum
                    ],
                ),
                Bytes("Rest", b"|||||", fuzzable=False),
                Bytes("ETX", ETX, fuzzable=False),
                Bytes("Checksum", b"00", fuzzable=False),
                Bytes("CRLF", CR + LF, fuzzable=False),
            ),
        )

        # =====================================================================
        # BOUNDARY: frame-number byte edge values
        # =====================================================================
        frame_number_boundary = Request(
            "ASTM_Frame_Number_Boundary",
            children=(
                Bytes("STX", STX, fuzzable=False),
                Group(
                    "Frame_Number",
                    values=[str(d).encode("ascii") for d in range(10)]
                    + [
                        b"A",  # non-digit ASCII
                        b" ",  # space
                        b"\xff",  # high byte
                        b"",  # missing frame number
                        b"10",  # two digits
                    ],
                ),
                Bytes("Record", h_record, fuzzable=False),
                Bytes("ETX", ETX, fuzzable=False),
                Bytes("Checksum", b"00", fuzzable=False),
                Bytes("CRLF", CR + LF, fuzzable=False),
            ),
        )

        # =====================================================================
        # MALFORMED: truncated framing (missing ETX / checksum / CRLF)
        # =====================================================================
        missing_terminator = Request(
            "ASTM_Missing_Terminator",
            children=(
                Bytes("STX", STX, fuzzable=False),
                Bytes("Frame_Number", b"4", fuzzable=False),
                Bytes("Record", h_record, fuzzable=False),
                Group(
                    "Truncation",
                    values=[
                        b"",  # nothing after text: no ETX, checksum or CRLF
                        ETX,  # ETX only, no checksum / CRLF
                        ETX + b"00",  # ETX + checksum, no CRLF
                        ETX + CR,  # missing trailing LF
                        CR + LF,  # CRLF but no ETX / checksum
                        ETB,  # intermediate ETB with no following frame
                        ETX + b"0",  # single (truncated) checksum nibble
                    ],
                ),
            ),
        )

        # =====================================================================
        # BOUNDARY: record-type character edge values
        # =====================================================================
        record_type_boundary = Request(
            "ASTM_Record_Type_Boundary",
            children=(
                Bytes("STX", STX, fuzzable=False),
                Bytes("Frame_Number", b"5", fuzzable=False),
                Group(
                    "Record_Type",
                    values=[
                        b"H",  # header
                        b"P",  # patient
                        b"O",  # order
                        b"R",  # result
                        b"C",  # comment
                        b"Q",  # query
                        b"L",  # terminator
                        b"Z",  # invalid / vendor
                        b"9",  # numeric
                        b"",  # empty record type
                        b"HH",  # two-char record type
                    ],
                ),
                Bytes("Rest", b"|\\^&|||", fuzzable=False),
                Bytes("ETX", ETX, fuzzable=False),
                Bytes("Checksum", b"00", fuzzable=False),
                Bytes("CRLF", CR + LF, fuzzable=False),
            ),
        )

        # =====================================================================
        # Wire requests to the session (strict 1:1 gating on RequestInfo.name)
        # =====================================================================
        if self.is_request_enabled("ASTM_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("ASTM_Checksum_Corrupt"):
            self.session.connect(checksum_corrupt)
        if self.is_request_enabled("ASTM_Oversized_Record"):
            self.session.connect(oversized_record)
        if self.is_request_enabled("ASTM_Delimiter_Injection"):
            self.session.connect(delimiter_injection)
        if self.is_request_enabled("ASTM_Frame_Number_Boundary"):
            self.session.connect(frame_number_boundary)
        if self.is_request_enabled("ASTM_Missing_Terminator"):
            self.session.connect(missing_terminator)
        if self.is_request_enabled("ASTM_Record_Type_Boundary"):
            self.session.connect(record_type_boundary)
