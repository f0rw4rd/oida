"""HART-IP Protocol Fuzzer

HART-IP (IEC 62138 / FieldComm HART over IP) server security fuzzer,
UDP/TCP port 5094. This module targets the UDP transport.

CVE coverage:
- CVE-2020-16209: FieldComm hipserver oversized-message stack overflow
  (CWE-121). An inbound HART-IP message whose declared ByteCount / actual
  payload exceeds a fixed internal buffer overruns the stack. Exercised by
  HARTIP_Payload_Overflow (and, obliquely, HARTIP_ByteCount_Lie).
- CVE-2013-2476: short-header infinite loop. A datagram shorter than the
  fixed HART-IP header lets a length-blind parse loop run away. Exercised by
  HARTIP_Short_Header.

HART-IP framing used here:
    byte  0     Version        (0x01)
    byte  1     MessageType    (0=Request, 1=Response, 2=Publish)
    byte  2     MessageID      (0=Session-Init, 1=Session-Close,
                                2=Keep-Alive, 3=Token-Passing PDU)
    byte  3     Status
    bytes 4-5   SequenceNumber (Word, big-endian)
    bytes 6-7   ByteCount      (Word, big-endian) -- length of the payload
    bytes 8+    payload

For a Token-Passing message (MessageID 3) the payload is a HART PDU:
    delimiter, address, command, byte-count, data..., checksum (XOR).
"""

from typing import List

from boofuzz import Block, Byte, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import UDPSocketConnection
from ..primitives.dynamic import SmartBytes


class HARTIPFuzzer(BaseFuzzer):
    """HART-IP Protocol Fuzzer (UDP/TCP 5094).

    Strict 1:1 request gating: every boofuzz Request name matches its
    RequestInfo name, and each session.connect() is wrapped in
    self.is_request_enabled(<name>).
    """

    # HART-IP servers have no application-layer read probe here; a liveness
    # ping is the most reliable crash oracle for an oversized/short datagram.
    DEFAULT_MONITORS = "ping"

    PROTOCOL_OPTIONS: dict = {}

    # Valid HART-IP header field values reused across requests.
    _VERSION = 0x01
    _MSGTYPE_REQUEST = 0x00
    _MSGID_SESSION_INIT = 0x00
    _MSGID_TOKEN_PASSING = 0x03

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests."""
        return [
            RequestInfo(
                "HARTIP_Baseline",
                "Valid HART-IP Session-Initiate request",
                "baseline",
            ),
            RequestInfo(
                "HARTIP_Payload_Overflow",
                "Oversized payload vs fixed buffer (256/512/1024/4096) (CVE-2020-16209)",
                "overflow",
            ),
            RequestInfo(
                "HARTIP_Short_Header",
                "Runt datagram shorter than the 5-byte header (0/1/3/5) (CVE-2013-2476)",
                "malformed",
            ),
            RequestInfo(
                "HARTIP_ByteCount_Lie",
                "ByteCount Word {0x0000,0x0005,0xFFFF} disagreeing with real payload length",
                "boundary",
            ),
            RequestInfo(
                "HARTIP_MessageType_ID_Boundary",
                "MessageType + MessageID bytes over valid + reserved/invalid values",
                "boundary",
            ),
            RequestInfo(
                "HARTIP_TokenPassing_PDU_Malformed",
                "MessageID 3 Token-Passing HART PDU with bad byte-count/command and wrong checksum",
                "malformed",
            ),
            RequestInfo(
                "HARTIP_Version_Boundary",
                "Version byte Group {0x00,0x01,0x02,0xFF}",
                "boundary",
            ),
        ]

    def _create_socket(self):
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),
            **self._timeout_overrides(recv_default=2.0),
        )

    def _define_protocol(self) -> None:
        """Define HART-IP request structures with strict 1:1 gating."""

        # 1. Baseline -- a well-formed Session-Initiate request.
        # Session-Init payload: master type (1) + inactivity timeout (Dword).
        baseline = Request(
            "HARTIP_Baseline",
            children=(
                Block(
                    "HARTIP_Baseline_Msg",
                    children=(
                        Byte("version", self._VERSION),
                        Byte("msg_type", self._MSGTYPE_REQUEST),
                        Byte("msg_id", self._MSGID_SESSION_INIT),
                        Byte("status", 0x00),
                        Word("sequence", 0x0001, endian=">"),
                        # HART-IP ByteCount = total message length INCLUDING the
                        # 8-byte header (payload_len = byte_count - 8). Payload is
                        # 5 bytes (master_type + 4-byte timeout) -> 13. Was 5,
                        # which a conformant server reads as payload_len 0.
                        Word("byte_count", 13, endian=">"),
                        # Session-Init payload: primary master + 4-byte timeout
                        Byte("master_type", 0x01),
                        Static("inactivity_timeout", b"\x00\x00\x75\x30"),  # 30000 ms
                    ),
                ),
            ),
        )

        # 2. Payload_Overflow -- oversized payload vs a fixed internal buffer.
        # CVE-2020-16209: hipserver copies the message body into a stack buffer
        # without bounding it against ByteCount. SmartBytes carries the variable
        # oversized body; byte_count is set large to match the declared length.
        payload_overflow = Request(
            "HARTIP_Payload_Overflow",
            children=(
                Block(
                    "HARTIP_Overflow_Msg",
                    children=(
                        Byte("version", self._VERSION),
                        Byte("msg_type", self._MSGTYPE_REQUEST),
                        Byte("msg_id", self._MSGID_TOKEN_PASSING),
                        Byte("status", 0x00),
                        Word("sequence", 0x0001, endian=">"),
                        Word("byte_count", 0xFFFF, endian=">"),  # claim a huge body
                        Group(
                            "overflow_size",
                            values=[
                                b"A" * 256,  # small fixed buffer
                                b"A" * 512,  # common stack buffer
                                b"A" * 1024,  # double
                                b"A" * 4096,  # large overrun
                            ],
                        ),
                        # Variable overflow tail (SmartBytes mutation engine).
                        SmartBytes("overflow_tail", b"B" * 512, fuzzable=True),
                    ),
                ),
            ),
        )

        # 3. Short_Header -- datagram shorter than the fixed 5-byte header.
        # CVE-2013-2476: a length-blind header parse loops forever on a runt.
        short_header = Request(
            "HARTIP_Short_Header",
            children=(
                Block(
                    "HARTIP_Short_Header_Msg",
                    children=(
                        Group(
                            "runt_bytes",
                            values=[
                                b"",  # 0-byte datagram
                                b"\x01",  # 1 byte: version only
                                b"\x01\x00\x00",  # 3 bytes: version+type+id
                                b"\x01\x00\x00\x00\x00",  # 5 bytes: header minus ByteCount
                            ],
                        ),
                    ),
                ),
            ),
        )

        # 4. ByteCount_Lie -- declared ByteCount disagrees with real payload.
        bytecount_lie = Request(
            "HARTIP_ByteCount_Lie",
            children=(
                Block(
                    "HARTIP_ByteCount_Lie_Msg",
                    children=(
                        Byte("version", self._VERSION),
                        Byte("msg_type", self._MSGTYPE_REQUEST),
                        Byte("msg_id", self._MSGID_SESSION_INIT),
                        Byte("status", 0x00),
                        Word("sequence", 0x0001, endian=">"),
                        Group(
                            "byte_count",
                            values=[
                                b"\x00\x00",  # claims 0 bytes
                                b"\x00\x05",  # claims 5 bytes
                                b"\xff\xff",  # claims 65535 bytes
                            ],
                        ),
                        # Actual payload is fixed and short: mismatches all above.
                        Static("actual_payload", b"\x01\x00\x00\x75\x30"),
                    ),
                ),
            ),
        )

        # 5. MessageType_ID_Boundary -- valid + reserved/invalid type/id bytes.
        msgtype_id_boundary = Request(
            "HARTIP_MessageType_ID_Boundary",
            children=(
                Block(
                    "HARTIP_MsgType_ID_Msg",
                    children=(
                        Byte("version", self._VERSION),
                        Group(
                            "msg_type",
                            values=[
                                b"\x00",  # Request (valid)
                                b"\x01",  # Response (valid)
                                b"\x02",  # Publish (valid)
                                b"\x03",  # reserved
                                b"\xff",  # invalid
                            ],
                        ),
                        Group(
                            "msg_id",
                            values=[
                                b"\x00",  # Session-Init (valid)
                                b"\x01",  # Session-Close (valid)
                                b"\x02",  # Keep-Alive (valid)
                                b"\x03",  # Token-Passing (valid)
                                b"\x04",  # reserved
                                b"\xff",  # invalid
                            ],
                        ),
                        Byte("status", 0x00),
                        Word("sequence", 0x0001, endian=">"),
                        Word("byte_count", 8, endian=">"),  # header-only message = 8 bytes
                    ),
                ),
            ),
        )

        # 6. TokenPassing_PDU_Malformed -- MessageID 3 with a broken HART PDU.
        # The embedded PDU byte-count and command are inconsistent with the data
        # actually present, and the trailing checksum is deliberately wrong.
        token_passing_malformed = Request(
            "HARTIP_TokenPassing_PDU_Malformed",
            children=(
                Block(
                    "HARTIP_TokenPassing_Msg",
                    children=(
                        Byte("version", self._VERSION),
                        Byte("msg_type", self._MSGTYPE_REQUEST),
                        Byte("msg_id", self._MSGID_TOKEN_PASSING),
                        Byte("status", 0x00),
                        Word("sequence", 0x0001, endian=">"),
                        # Outer frame = 8-byte header + 7-byte embedded PDU = 15.
                        # The intended malformation is the inner pdu_byte_count
                        # (0xFF) below, so the outer ByteCount must stay valid or
                        # the datagram is dropped at HART-IP framing first.
                        Word("byte_count", 15, endian=">"),
                        # Embedded HART short-frame PDU:
                        Byte("pdu_delimiter", 0x02),  # STX short frame
                        Byte("pdu_address", 0x00),
                        Group(
                            "pdu_command",
                            values=[
                                b"\x00",  # cmd 0
                                b"\xfe",  # undefined command
                                b"\xff",  # invalid command
                            ],
                        ),
                        # Byte-count claims more data than is present.
                        Byte("pdu_byte_count", 0xFF),
                        Static("pdu_data", b"\x01\x02"),  # only 2 bytes present
                        Byte("pdu_checksum", 0x00),  # wrong XOR checksum
                    ),
                ),
            ),
        )

        # 7. Version_Boundary -- version byte over valid + out-of-range values.
        version_boundary = Request(
            "HARTIP_Version_Boundary",
            children=(
                Block(
                    "HARTIP_Version_Msg",
                    children=(
                        Group(
                            "version",
                            values=[
                                b"\x00",  # invalid (below 1)
                                b"\x01",  # valid HART-IP v1
                                b"\x02",  # future/unknown
                                b"\xff",  # invalid
                            ],
                        ),
                        Byte("msg_type", self._MSGTYPE_REQUEST),
                        Byte("msg_id", self._MSGID_SESSION_INIT),
                        Byte("status", 0x00),
                        Word("sequence", 0x0001, endian=">"),
                        # 8-byte header + 5-byte payload = 13 (see Baseline).
                        Word("byte_count", 13, endian=">"),
                        Byte("master_type", 0x01),
                        Static("inactivity_timeout", b"\x00\x00\x75\x30"),
                    ),
                ),
            ),
        )

        # Strict 1:1 gating: one connect per advertised request.
        if self.is_request_enabled("HARTIP_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("HARTIP_Payload_Overflow"):
            self.session.connect(payload_overflow)
        if self.is_request_enabled("HARTIP_Short_Header"):
            self.session.connect(short_header)
        if self.is_request_enabled("HARTIP_ByteCount_Lie"):
            self.session.connect(bytecount_lie)
        if self.is_request_enabled("HARTIP_MessageType_ID_Boundary"):
            self.session.connect(msgtype_id_boundary)
        if self.is_request_enabled("HARTIP_TokenPassing_PDU_Malformed"):
            self.session.connect(token_passing_malformed)
        if self.is_request_enabled("HARTIP_Version_Boundary"):
            self.session.connect(version_boundary)

        return self.session
