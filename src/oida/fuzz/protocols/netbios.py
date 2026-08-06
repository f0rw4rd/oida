"""NetBIOS Name Service (NBNS) Protocol Fuzzer

NBNS runs over UDP 137 and carries a DNS-like 12-byte header followed by a
QUESTION whose owner name uses NetBIOS "first-level encoding": each of the 16
raw NetBIOS name bytes is split into two nibbles and every nibble is mapped to
a printable char via ``nibble + 0x41`` (so bytes 'A'..'P'). The encoded label
is exactly 32 bytes, prefixed by a 0x20 length byte and followed by a 0x00
label terminator, an optional scope-id label, QTYPE and QCLASS.

The historical bug class here is the name-decode over-read: a decoder that
walks the first-level-encoded label without honoring the length byte / null
terminator reads past the packet buffer. This drives Samba nmbd
(CVE-2007-5398) and the Windows NBNS name-decode over-reads (CVE-2003-0661),
among ~14 NetBIOS name-decode CVEs OIDA otherwise cannot reach.
"""

from typing import List

from boofuzz import Block, Byte, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import UDPSocketConnection
from ..primitives.dynamic import SmartString
from ..primitives.smart_string import StringContext

# NBNS QTYPEs (RFC 1002)
NB = 0x0020  # general Name query
NBSTAT = 0x0021  # Node status query
IN_CLASS = 0x0001  # Internet class


def _first_level_encode(name16: bytes) -> bytes:
    """First-level-encode a 16-byte NetBIOS name into its 32-byte label.

    Each raw byte is split into two nibbles; each nibble is mapped to a
    printable character with ``nibble + 0x41`` (0x41 == 'A'), so the output
    alphabet is 'A'..'P'. The input is truncated/padded to exactly 16 bytes.
    """
    raw = (name16 + b"\x00" * 16)[:16]
    out = bytearray()
    for b in raw:
        out.append((b >> 4) + 0x41)
        out.append((b & 0x0F) + 0x41)
    return bytes(out)


# Wildcard name "*" padded with 15 nulls  -> "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
WILDCARD_NAME = _first_level_encode(b"*")
# A normal workstation name "OIDA" (15 chars space-padded) + 0x00 suffix.
NORMAL_NAME = _first_level_encode(b"OIDA" + b" " * 11 + b"\x00")


class NetBIOSFuzzer(BaseFuzzer):
    """NetBIOS Name Service (NBNS, UDP 137) fuzzer.

    Targets the NetBIOS first-level name-decode path: unterminated labels,
    illegal label-length bytes, oversized encoded names, second-level
    (scope-id) length lies, and inflated record counts. These reproduce the
    classic name-decode over-read CVEs (Samba nmbd CVE-2007-5398, Windows
    NBNS CVE-2003-0661, and related).
    """

    DEFAULT_MONITORS = "ping"

    PROTOCOL_OPTIONS: dict = {}

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests and audit tests."""
        return [
            RequestInfo(
                "NetBIOS_Baseline",
                "Valid NBSTAT query for wildcard name (well-formed 32-byte label)",
                "baseline",
            ),
            RequestInfo(
                "NetBIOS_Name_Unterminated",
                "First-level label with no 0x00 terminator (decode-walk over-read; "
                "CVE-2007-5398 / CVE-2003-0661)",
                "malformed",
            ),
            RequestInfo(
                "NetBIOS_Label_Length_Boundary",
                "First label-length byte swept across legal/illegal values (miscount)",
                "boundary",
            ),
            RequestInfo(
                "NetBIOS_Name_Oversized",
                "Encoded name far longer than 32 bytes with matching length byte (overflow)",
                "overflow",
            ),
            RequestInfo(
                "NetBIOS_SecondLevel_Length_Lie",
                "Scope-id (second-level) length byte larger than the bytes present",
                "malformed",
            ),
            RequestInfo(
                "NetBIOS_Count_Lies",
                "QDCOUNT/ANCOUNT inflated far beyond the records actually present",
                "malformed",
            ),
            RequestInfo(
                "NetBIOS_NBSTAT_Wildcard",
                "NBSTAT (0x0021) node-status query for the '*' wildcard name",
                "boundary",
            ),
        ]

    def _create_socket(self):
        # NBNS is request/response over UDP; bind an ephemeral local port so
        # replies (name-query responses, node-status) can be received.
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),
            **self._timeout_overrides(recv_default=2.0, send_default=2.0),
        )

    def setup_custom_monitors(self) -> list:
        """NBNS has no reliable data-plane liveness probe here; rely on ping."""
        return []

    def _define_protocol(self) -> None:
        """Define NBNS requests. Every Request is gated 1:1 by its registered
        name so --enable/--disable select exactly one request each."""

        # 1. Baseline: well-formed NBSTAT query for the wildcard name.
        baseline = Request(
            "NetBIOS_Baseline",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        # Keep txid fuzzable so the baseline has >=1 mutation and
                        # actually emits a packet: boofuzz skips a request whose
                        # every field is fuzzable=False (0 test cases).
                        Word("txid", 0x1337, endian=">", fuzzable=True),
                        Word("flags", 0x0000, endian=">", fuzzable=False),
                        Word("qdcount", 0x0001, endian=">", fuzzable=False),
                        Word("ancount", 0x0000, endian=">", fuzzable=False),
                        Word("nscount", 0x0000, endian=">", fuzzable=False),
                        Word("arcount", 0x0000, endian=">", fuzzable=False),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        Byte("label_length", 0x20, fuzzable=False),
                        Static("encoded_name", WILDCARD_NAME),
                        Byte("name_terminator", 0x00, fuzzable=False),
                        Word("qtype", NBSTAT, endian=">", fuzzable=False),
                        Word("qclass", IN_CLASS, endian=">", fuzzable=False),
                    ),
                ),
            ),
        )

        # 2. Unterminated name: 32-byte encoded label with NO 0x00 terminator
        #    and no second-level length -> a naive decoder walks off the end.
        name_unterminated = Request(
            "NetBIOS_Name_Unterminated",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        Word("txid", 0x0002, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        Word("qdcount", 0x0001, endian=">"),
                        Word("ancount", 0x0000, endian=">"),
                        Word("nscount", 0x0000, endian=">"),
                        Word("arcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        Byte("label_length", 0x20),
                        # All first-level-encoding chars 'A'..'P', 32 bytes.
                        Static("encoded_name", b"ABCDEFGHIJKLMNOP" * 2),
                        # NO name_terminator / second-level length -> runs into QTYPE.
                        Word("qtype", NB, endian=">"),
                        Word("qclass", IN_CLASS, endian=">"),
                    ),
                ),
            ),
        )

        # 3. Label-length boundary: first length byte swept. 0x20 (=32) is the
        #    only legal first-level length; all others drive a miscount.
        label_length_boundary = Request(
            "NetBIOS_Label_Length_Boundary",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        Word("txid", 0x0003, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        Word("qdcount", 0x0001, endian=">"),
                        Word("ancount", 0x0000, endian=">"),
                        Word("nscount", 0x0000, endian=">"),
                        Word("arcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        Group(
                            "label_length",
                            values=[
                                b"\x00",  # empty label
                                b"\x20",  # legal first-level length (32)
                                b"\x21",  # off-by-one over
                                b"\x3f",  # DNS max label (63) - illegal here
                                b"\x40",  # compression-pointer high bits set
                                b"\xff",  # maximum
                            ],
                        ),
                        Static("encoded_name", WILDCARD_NAME),
                        Byte("name_terminator", 0x00),
                        Word("qtype", NBSTAT, endian=">"),
                        Word("qclass", IN_CLASS, endian=">"),
                    ),
                ),
            ),
        )

        # 4. Oversized name: encoded label far longer than 32 bytes with a
        #    length byte claiming it -> overflow of fixed 16/33-byte name buffers.
        name_oversized = Request(
            "NetBIOS_Name_Oversized",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        Word("txid", 0x0004, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        Word("qdcount", 0x0001, endian=">"),
                        Word("ancount", 0x0000, endian=">"),
                        Word("nscount", 0x0000, endian=">"),
                        Word("arcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        # length byte claims the (illegally large) label size
                        Group(
                            "label_length",
                            values=[b"\x40", b"\x80", b"\xff"],
                        ),
                        Group(
                            "encoded_name",
                            values=[
                                b"A" * 64,
                                b"A" * 128,
                                b"A" * 256,
                            ],
                        ),
                        Byte("name_terminator", 0x00),
                        Word("qtype", NB, endian=">"),
                        Word("qclass", IN_CLASS, endian=">"),
                    ),
                ),
            ),
        )

        # 5. Second-level length lie: valid 32-byte first-level name, then a
        #    scope-id label whose length byte overstates the bytes present,
        #    truncated at the packet tail.
        secondlevel_length_lie = Request(
            "NetBIOS_SecondLevel_Length_Lie",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        Word("txid", 0x0005, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        Word("qdcount", 0x0001, endian=">"),
                        Word("ancount", 0x0000, endian=">"),
                        Word("nscount", 0x0000, endian=">"),
                        Word("arcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        Byte("label_length", 0x20),
                        Static("encoded_name", WILDCARD_NAME),
                        # scope-id label: length byte >> actual bytes present
                        Group(
                            "scope_length",
                            values=[b"\x3f", b"\x7f", b"\xff"],
                        ),
                        # Scope-id (second-level) label. It is a DNS-domain-class
                        # identifier, so tag it HOSTNAME: the corpus adds
                        # NULL-injection / IDN-homograph / label-length payloads on
                        # top of length testing. Only 5 bytes are actually present
                        # while scope_length above overstates them, so the
                        # framing lie that defines this request is preserved (no
                        # length field references this value -> nothing to recompute).
                        SmartString(
                            "scope_label",
                            "LOCAL",
                            context=StringContext.HOSTNAME,
                            max_len=64,
                            fuzzable=True,
                        ),
                        # packet ends here: no 0x00 terminator, no QTYPE/QCLASS
                    ),
                ),
            ),
        )

        # 6. Count lies: QDCOUNT / ANCOUNT inflated with only one record present.
        count_lies = Request(
            "NetBIOS_Count_Lies",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        Word("txid", 0x0006, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        Word("qdcount", 0x00FF, endian=">"),  # claims 255 questions
                        Word("ancount", 0x00FF, endian=">"),  # claims 255 answers
                        Word("nscount", 0x0000, endian=">"),
                        Word("arcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        Byte("label_length", 0x20),
                        Static("encoded_name", WILDCARD_NAME),
                        Byte("name_terminator", 0x00),
                        Word("qtype", NB, endian=">"),
                        Word("qclass", IN_CLASS, endian=">"),
                    ),
                ),
            ),
        )

        # 7. NBSTAT wildcard: node-status decode path for the "*" name.
        nbstat_wildcard = Request(
            "NetBIOS_NBSTAT_Wildcard",
            children=(
                Block(
                    "NBNS_Header",
                    children=(
                        Word("txid", 0x0007, endian=">"),
                        Word("flags", 0x0000, endian=">"),
                        Word("qdcount", 0x0001, endian=">"),
                        Word("ancount", 0x0000, endian=">"),
                        Word("nscount", 0x0000, endian=">"),
                        Word("arcount", 0x0000, endian=">"),
                    ),
                ),
                Block(
                    "NBNS_Question",
                    children=(
                        Byte("label_length", 0x20),
                        Static("encoded_name", WILDCARD_NAME),
                        Byte("name_terminator", 0x00),
                        Word("qtype", NBSTAT, endian=">"),
                        Word("qclass", IN_CLASS, endian=">"),
                    ),
                ),
            ),
        )

        # STRICT 1:1 gating: each RequestInfo name == Request node name.
        if self.is_request_enabled("NetBIOS_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("NetBIOS_Name_Unterminated"):
            self.session.connect(name_unterminated)
        if self.is_request_enabled("NetBIOS_Label_Length_Boundary"):
            self.session.connect(label_length_boundary)
        if self.is_request_enabled("NetBIOS_Name_Oversized"):
            self.session.connect(name_oversized)
        if self.is_request_enabled("NetBIOS_SecondLevel_Length_Lie"):
            self.session.connect(secondlevel_length_lie)
        if self.is_request_enabled("NetBIOS_Count_Lies"):
            self.session.connect(count_lies)
        if self.is_request_enabled("NetBIOS_NBSTAT_Wildcard"):
            self.session.connect(nbstat_wildcard)

        return self.session
