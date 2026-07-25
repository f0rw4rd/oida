"""IGMP Protocol Fuzzer

IGMP (Internet Group Management Protocol, IPv4 multicast, IP protocol 2).

Targets count-trust / parse bugs in embedded IGMPv3 stacks. Motivating gap:
the VxWorks IPnet IGMPv3 flaws that OIDA previously could not reach with any
existing raw-L3 fuzzer:

- CVE-2019-12259 - IGMPv3 array-index / NULL-pointer dereference driven by a
  Membership Query whose number_of_sources is trusted without bounds-checking
  the sources actually present.
- CVE-2019-12265 - out-of-bounds read from a length field on IGMP input.
- CVE-2020-10664 - IGMP buffer-overread / parse bug.

Framing (RFC 2236 / RFC 3376):
- IGMPv2 (8 bytes): type(1), max_resp_time(1), checksum(Word), group_address(4).
- IGMPv3 Membership Query (type 0x11, >=12 bytes): type, max_resp_code,
  checksum, group_address(4), resv/S/QRV(1), QQIC(1), number_of_sources(Word),
  then N x source_address(4).
- IGMPv3 Membership Report (type 0x22): type, reserved(1), checksum,
  reserved(Word), number_of_group_records(Word), then group records:
  record_type(1), aux_data_len(1), number_of_sources(Word),
  multicast_address(4), sources..., aux data.

IGMP has no dedicated raw-socket ProtocolType (it is IP protocol 2, kernel does
not expose an IPPROTO_IGMP cooked socket the way it does for ICMP), so this
fuzzer uses ProtocolType.RAW. The 16-bit ones-complement checksum over the IGMP
message is computed with boofuzz Checksum(algorithm="ipv4"), exactly like the
ICMP fuzzer.

Note: Requires root/admin privileges for raw socket access.
"""

from typing import List

from boofuzz import Block, Byte, Bytes, Checksum, Group, Request, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..primitives.dynamic import SmartBytes


class IGMPFuzzer(BaseFuzzer):
    """IGMP Protocol Fuzzer for IPv4 multicast group-management security testing.

    Strict 1:1 request convention: every RequestInfo name in
    get_request_definitions() matches exactly one boofuzz Request node name and
    is individually gated by is_request_enabled(), so --enable / --disable work.
    """

    # Ping monitor - IGMP is a layer-3 protocol, a TCP socket monitor is meaningless.
    DEFAULT_MONITORS = "ping"

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests (strict 1:1 with nodes)."""
        return [
            RequestInfo(
                "IGMP_Baseline",
                "Valid IGMPv2 General Query (type 0x11, group 0.0.0.0)",
                "baseline",
            ),
            RequestInfo(
                "IGMPv3_Query_NumSources_Lie",
                "IGMPv3 Query whose number_of_sources is far larger than sources "
                "present (count-trust loop; VxWorks CVE-2019-12259 array-index class)",
                "malformed",
            ),
            RequestInfo(
                "IGMPv3_Report_NumRecords_Lie",
                "IGMPv3 Report with number_of_group_records inflated vs records present",
                "malformed",
            ),
            RequestInfo(
                "IGMPv3_GroupRecord_AuxDataLen_Overflow",
                "Group record whose aux_data_len claims more 32-bit words than present, "
                "truncated at the tail",
                "overflow",
            ),
            RequestInfo(
                "IGMP_Type_Boundary",
                "Type byte boundary sweep {0x11,0x12,0x16,0x17,0x22,0x00,0x23,0xFF}",
                "boundary",
            ),
            RequestInfo(
                "IGMP_Truncated",
                "IGMPv3 query/report cut mid group-record / mid source-list",
                "malformed",
            ),
            RequestInfo(
                "IGMP_MaxRespCode_Boundary",
                "max_resp_code sweep {0x00,0x7F,0x80,0x81,0xFF} across the v3 "
                "float-encoding boundary (>=0x80 switches to mantissa/exp encoding)",
                "boundary",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # Use an IPPROTO_IGMP raw socket so the kernel builds the IP header and
        # we supply only the IGMP message (mirrors the ICMP fuzzer). A plain
        # ProtocolType.RAW socket is IPPROTO_RAW/IP_HDRINCL and would parse the
        # IGMP Type byte as an IP header -> the message never reaches the target.
        config.protocol_type = ProtocolType.IGMP
        super().__init__(config, connection_factory)

    def _define_protocol(self):
        """Define IGMP protocol structure with per-request enable/disable gating."""

        # ================================================================
        # 1. Baseline - valid IGMPv2 General Query
        # ================================================================
        # Type field fuzzable=True guarantees at least one packet is emitted
        # (mirrors the ICMP baseline echo convention).
        baseline = Request(
            "IGMP_Baseline",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Byte("Type", 0x11, fuzzable=True),  # Membership Query
                        Byte("Max_Resp_Time", 0x64, fuzzable=False),  # 100 -> 10.0s
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        # General Query -> group address 0.0.0.0
                        Bytes("Group_Address", b"\x00\x00\x00\x00", size=4, fuzzable=False),
                    ),
                ),
            ),
        )

        # ================================================================
        # 2. IGMPv3 Query with a lying number_of_sources (CVE-2019-12259 class)
        # ================================================================
        # number_of_sources claims 255 / 32767 / 65535 sources, but only ONE
        # source address is actually present in the packet. A stack that trusts
        # the count and iterates it will index off the end of the array.
        query_numsrc_lie = Request(
            "IGMPv3_Query_NumSources_Lie",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Byte("Type", 0x11, fuzzable=False),  # Membership Query
                        Byte("Max_Resp_Code", 0x64, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Bytes("Group_Address", b"\xe0\x00\x00\x01", size=4, fuzzable=False),
                        Byte("Resv_S_QRV", 0x02, fuzzable=False),  # S=0, QRV=2
                        Byte("QQIC", 0x64, fuzzable=False),
                        # Big-endian Word count, wildly larger than sources present:
                        Group(
                            "Number_Of_Sources",
                            values=[
                                b"\x00\xff",  # 255
                                b"\x7f\xff",  # 32767
                                b"\xff\xff",  # 65535
                            ],
                        ),
                        # One 4-byte source present by default; SmartBytes lets
                        # Radamsa vary the actual source list against the lying count.
                        SmartBytes(
                            "Source_Address", b"\xc0\xa8\x01\x01", max_len=64, fuzzable=True
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # 3. IGMPv3 Report with a lying number_of_group_records
        # ================================================================
        # Declares up to 65535 group records but ships only one; a count-trusting
        # report parser walks past the buffer.
        report_numrec_lie = Request(
            "IGMPv3_Report_NumRecords_Lie",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Byte("Type", 0x22, fuzzable=False),  # Version 3 Membership Report
                        Byte("Reserved1", 0x00, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Reserved2", 0, endian=">", fuzzable=False),
                        Group(
                            "Number_Of_Group_Records",
                            values=[
                                b"\x00\xff",  # 255
                                b"\x7f\xff",  # 32767
                                b"\xff\xff",  # 65535
                            ],
                        ),
                        # Exactly one group record present.
                        Byte("Record_Type", 0x01, fuzzable=False),  # MODE_IS_INCLUDE
                        Byte("Aux_Data_Len", 0x00, fuzzable=False),
                        Word("Record_Num_Sources", 0, endian=">", fuzzable=False),
                        Bytes("Multicast_Address", b"\xe0\x00\x00\x01", size=4, fuzzable=False),
                    ),
                ),
            ),
        )

        # ================================================================
        # 4. Group record aux_data_len overflow (truncated tail)
        # ================================================================
        # aux_data_len is expressed in 32-bit words. Here it claims 16 / 64 / 127
        # / 255 words of auxiliary data that are NOT present - the record is cut
        # off immediately after the multicast address.
        auxlen_overflow = Request(
            "IGMPv3_GroupRecord_AuxDataLen_Overflow",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Byte("Type", 0x22, fuzzable=False),  # Version 3 Membership Report
                        Byte("Reserved1", 0x00, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Reserved2", 0, endian=">", fuzzable=False),
                        Word("Number_Of_Group_Records", 1, endian=">", fuzzable=False),
                        Byte("Record_Type", 0x01, fuzzable=False),
                        Group(
                            "Aux_Data_Len",
                            values=[
                                b"\x10",  # 16 words = 64 bytes claimed, 0 present
                                b"\x40",  # 64 words = 256 bytes
                                b"\x7f",  # 127 words = 508 bytes
                                b"\xff",  # 255 words = 1020 bytes
                            ],
                        ),
                        Word("Record_Num_Sources", 0, endian=">", fuzzable=False),
                        Bytes("Multicast_Address", b"\xe0\x00\x00\x01", size=4, fuzzable=False),
                        # Aux data deliberately absent (truncated tail).
                    ),
                ),
            ),
        )

        # ================================================================
        # 5. Type field boundary sweep
        # ================================================================
        type_boundary = Request(
            "IGMP_Type_Boundary",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Group(
                            "Type",
                            values=[
                                b"\x11",  # Membership Query (v1/v2/v3)
                                b"\x12",  # v1 Membership Report
                                b"\x16",  # v2 Membership Report
                                b"\x17",  # v2 Leave Group
                                b"\x22",  # v3 Membership Report
                                b"\x00",  # invalid / null
                                b"\x23",  # unassigned (just past v3 report)
                                b"\xff",  # max
                            ],
                        ),
                        Byte("Max_Resp_Code", 0x64, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Bytes("Group_Address", b"\x00\x00\x00\x00", size=4, fuzzable=False),
                    ),
                ),
            ),
        )

        # ================================================================
        # 6. Truncated IGMPv3 message (cut mid group-record / mid source-list)
        # ================================================================
        # The header promises 4 group records; the tail is chopped at progressively
        # deeper offsets inside the first record (nothing, record_type only,
        # + aux_data_len, + num_sources promising 2 sources, partial multicast addr).
        truncated = Request(
            "IGMP_Truncated",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Byte("Type", 0x22, fuzzable=False),  # Version 3 Membership Report
                        Byte("Reserved1", 0x00, fuzzable=False),
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Word("Reserved2", 0, endian=">", fuzzable=False),
                        Word("Number_Of_Group_Records", 4, endian=">", fuzzable=False),  # lies
                        Group(
                            "Truncated_Tail",
                            values=[
                                b"",  # nothing after the count
                                b"\x01",  # record_type only
                                b"\x01\x00",  # + aux_data_len
                                b"\x01\x00\x00\x02",  # + num_sources=2, no addr/sources
                                b"\x01\x00\x00\x02\xe0\x00",  # partial multicast address
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # 7. max_resp_code boundary (v3 float-encoding switch at 0x80)
        # ================================================================
        # For code < 0x80 the value is the literal; for code >= 0x80 IGMPv3
        # decodes it as a floating-point mantissa/exponent. Straddle that edge.
        maxresp_boundary = Request(
            "IGMP_MaxRespCode_Boundary",
            children=(
                Block(
                    "IGMP_Message",
                    children=(
                        Byte("Type", 0x11, fuzzable=False),  # Membership Query
                        Group(
                            "Max_Resp_Code",
                            values=[
                                b"\x00",  # zero
                                b"\x7f",  # max literal
                                b"\x80",  # first float-encoded value
                                b"\x81",  # just past the switch
                                b"\xff",  # max float-encoded value
                            ],
                        ),
                        Checksum(
                            "Checksum", block_name="IGMP_Message", algorithm="ipv4", endian=">"
                        ),
                        Bytes("Group_Address", b"\xe0\x00\x00\x01", size=4, fuzzable=False),
                        Byte("Resv_S_QRV", 0x02, fuzzable=False),
                        Byte("QQIC", 0x64, fuzzable=False),
                        Word("Number_Of_Sources", 0, endian=">", fuzzable=False),
                    ),
                ),
            ),
        )

        # ================================================================
        # Gated wiring (strict 1:1: each node name == its RequestInfo name)
        # ================================================================
        if self.is_request_enabled("IGMP_Baseline"):
            self.session.connect(baseline)

        if self.is_request_enabled("IGMPv3_Query_NumSources_Lie"):
            self.session.connect(query_numsrc_lie)

        if self.is_request_enabled("IGMPv3_Report_NumRecords_Lie"):
            self.session.connect(report_numrec_lie)

        if self.is_request_enabled("IGMPv3_GroupRecord_AuxDataLen_Overflow"):
            self.session.connect(auxlen_overflow)

        if self.is_request_enabled("IGMP_Type_Boundary"):
            self.session.connect(type_boundary)

        if self.is_request_enabled("IGMP_Truncated"):
            self.session.connect(truncated)

        if self.is_request_enabled("IGMP_MaxRespCode_Boundary"):
            self.session.connect(maxresp_boundary)
