"""EtherCAT (EtherCAT-over-Ethernet, EtherType 0x88A4) Frame Fuzzer.

Raw-L2 fuzzer for the EtherCAT wire protocol. EtherCAT rides directly on top
of an Ethernet II frame (EtherType 0x88A4); it is NOT IP/UDP based on a real
segment, so it uses the raw-L2 socket approach (ProtocolType.RAW, MAC
helpers, gated connects).

Wire framing (EtherCAT is LITTLE-ENDIAN for its own fields; the Ethernet
EtherType stays network byte order):

    Ethernet:  dst(6) | src(6) | EtherType 0x88A4 (2, big-endian)
    EtherCAT header (1 Word, little-endian):
        bits 0..10  = Length (of all datagrams that follow)
        bit  11     = Reserved
        bits 12..15 = Type (1 = EtherCAT command datagrams)
    Datagram (repeatable):
        Cmd(1)   - 0x01 APRD, 0x02 APWR, 0x0A LRD, 0x0C LRW, ...
        Index(1)
        ADP(2, LE)   - slave address / position
        ADO(2, LE)   - offset
        Flags(1 Word, LE):
            bits 0..10  = LenBits (length of Data[])
            bits 11..13 = Reserved
            bit  14     = Circulating (C)
            bit  15     = More datagrams follow (M)
        IRQ(2, LE)
        Data[LenBits]
        WKC(2, LE)   - working counter
    Mailbox (CoE/FoE) carried in an LRW datagram's Data:
        Length(2, LE) | Address(2, LE) | Prio/Type(1) | ...

CVE coverage (server-side EtherCAT parsing, OOB write / read classes):
- CVE-2023-7242 / CVE-2023-7243 / CVE-2023-7244: out-of-bounds write in
  EtherCAT datagram parsing (attacker-controlled datagram length walked past
  the received buffer).
- CVE-2012-4293: EtherCAT mailbox dissector length field trusted beyond the
  actual mailbox payload.
"""

import struct
from typing import List, Optional

from boofuzz import Byte, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import BaseMonitor
from ..primitives.dynamic import SmartBytes


class EtherCATFuzzer(BaseFuzzer):
    """EtherCAT-over-Ethernet (0x88A4) raw-L2 fuzzer.

    Targets the server/slave-side datagram and mailbox parsers with
    length-lie, boundary and malformed-walk mutations that reproduce the
    OOB-write / OOB-read CVE classes above.
    """

    ETHERTYPE_ECAT = 0x88A4

    # EtherCAT datagram commands
    CMD_APRD = 0x01  # Auto-increment physical read
    CMD_APWR = 0x02  # Auto-increment physical write
    CMD_LRD = 0x0A  # Logical read
    CMD_LRW = 0x0C  # Logical read/write (used for mailbox / PDO)

    # EtherCAT header type nibble (1 = command datagrams)
    ECAT_TYPE_CMD = 0x1

    PROTOCOL_OPTIONS = {
        "interface": {
            "type": str,
            "default": "eth0",
            "description": "Network interface for raw socket operations",
            "example": "eth0",
        },
        "dst_mac": {
            "type": str,
            "default": "ff:ff:ff:ff:ff:ff",
            "description": "Destination MAC address (broadcast by default)",
            "example": "00:11:22:33:44:55",
        },
        "src_mac": {
            "type": str,
            "default": None,
            "description": "Source MAC address (auto-detect if not set)",
            "example": "aa:bb:cc:dd:ee:ff",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests.

        The advertised name equals the boofuzz Request node name for every
        request, so advertised set == connected set under default flags.
        """
        return [
            RequestInfo(
                "EtherCAT_Baseline",
                "Valid single APRD datagram (well-formed reference frame)",
                "baseline",
            ),
            RequestInfo(
                "EtherCAT_Datagram_Length_Overflow",
                "Datagram LenBits larger than the Data present (CVE-2023-7244 OOB write)",
                "overflow",
            ),
            RequestInfo(
                "EtherCAT_Header_Length_Lie",
                "EtherCAT header 11-bit Length {0, 0x7FF, > frame} vs actual",
                "boundary",
            ),
            RequestInfo(
                "EtherCAT_Mailbox_Length_Overflow",
                "CoE/FoE mailbox Length Word larger than mailbox payload (CVE-2012-4293)",
                "overflow",
            ),
            RequestInfo(
                "EtherCAT_Cmd_Boundary",
                "Datagram Cmd byte over valid + reserved + 0xFF",
                "boundary",
            ),
            RequestInfo(
                "EtherCAT_More_Datagrams_Lie",
                "More-datagrams (M) bit set but no following datagram (walk past end)",
                "malformed",
            ),
            RequestInfo(
                "EtherCAT_Datagram_ZeroLen",
                "Zero-length datagram in a multi-datagram walk (non-advancing loop)",
                "malformed",
            ),
        ]

    def __init__(self, config: FuzzerConfig = None, connection_factory=None):
        if config:
            config.protocol_type = ProtocolType.RAW
        super().__init__(config, connection_factory)

        self.interface = config.get_option("interface", "eth0") if config else "eth0"
        self.dst_mac = (
            config.get_option("dst_mac", "ff:ff:ff:ff:ff:ff") if config else "ff:ff:ff:ff:ff:ff"
        )
        self.src_mac = config.get_option("src_mac", None) if config else None

        if not self.src_mac:
            self.src_mac = self._get_interface_mac()

    # ------------------------------------------------------------------ #
    # MAC / socket helpers (raw-L2 ProtocolType.RAW connection)
    # ------------------------------------------------------------------ #
    def _get_interface_mac(self) -> str:
        """Get MAC address of the network interface (fallback on failure)."""
        try:
            import fcntl
            import socket

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

    # ------------------------------------------------------------------ #
    # EtherCAT little-endian field builders
    # ------------------------------------------------------------------ #
    def _ecat_header(self, length: int, ecat_type: int = None) -> bytes:
        """Build the little-endian EtherCAT header Word.

        11-bit Length | 1-bit Reserved | 4-bit Type.
        """
        if ecat_type is None:
            ecat_type = self.ECAT_TYPE_CMD
        val = (length & 0x7FF) | ((ecat_type & 0xF) << 12)
        return struct.pack("<H", val)

    def _dgram_flags(self, len_bits: int, more: int = 0, circulating: int = 0) -> bytes:
        """Build the little-endian datagram flags Word.

        11-bit LenBits | reserved | Circulating (bit 14) | More (bit 15).
        """
        val = (len_bits & 0x7FF) | ((circulating & 1) << 14) | ((more & 1) << 15)
        return struct.pack("<H", val)

    def _datagram(
        self,
        cmd: int,
        data: bytes,
        len_bits: int = None,
        more: int = 0,
        index: int = 0,
        adp: int = 0,
        ado: int = 0,
        irq: int = 0,
    ) -> bytes:
        """Assemble one raw EtherCAT datagram (Cmd..WKC), little-endian."""
        if len_bits is None:
            len_bits = len(data)
        return (
            struct.pack("<B", cmd & 0xFF)
            + struct.pack("<B", index & 0xFF)
            + struct.pack("<H", adp & 0xFFFF)
            + struct.pack("<H", ado & 0xFFFF)
            + self._dgram_flags(len_bits, more=more)
            + struct.pack("<H", irq & 0xFFFF)
            + data
            + struct.pack("<H", 0x0000)  # WKC
        )

    def _eth_hdr(self) -> bytes:
        """Ethernet header up to and including the EtherCAT EtherType."""
        return (
            self._mac_to_bytes(self.dst_mac)
            + self._mac_to_bytes(self.src_mac)
            + struct.pack(">H", self.ETHERTYPE_ECAT)  # EtherType is network byte order
        )

    # ------------------------------------------------------------------ #
    # Protocol definition
    # ------------------------------------------------------------------ #
    def _define_protocol(self):
        eth = self._eth_hdr()

        # ---- 1. Baseline: one valid APRD datagram --------------------- #
        base_data = b"\x00\x00\x00\x00"
        base_dgram_static = self._datagram(self.CMD_APRD, base_data, len_bits=len(base_data))
        baseline = Request(
            "EtherCAT_Baseline",
            children=(
                Static("eth", eth),
                Static("ecat_hdr", self._ecat_header(len(base_dgram_static))),
                Static("cmd", struct.pack("<B", self.CMD_APRD)),
                Byte("index", 0x00),
                Word("adp", 0x0000, endian="<"),
                Word("ado", 0x0000, endian="<"),
                Static("flags", self._dgram_flags(4)),  # LenBits = 4 (matches data)
                Word("irq", 0x0000, endian="<"),
                SmartBytes("data", base_data, max_len=64),  # variable Data[] field
                Word("wkc", 0x0000, endian="<"),
            ),
        )

        # ---- 2. Datagram LenBits > data present (OOB write) ----------- #
        # Data present is 4 bytes but the flags word advertises a much larger
        # LenBits, so a parser that trusts it walks past the received buffer.
        overflow_data = b"\x41\x41\x41\x41"
        dgram_len_overflow = Request(
            "EtherCAT_Datagram_Length_Overflow",
            children=(
                Static("eth", eth),
                Static("ecat_hdr", self._ecat_header(16)),
                Static("cmd", struct.pack("<B", self.CMD_APRD)),
                Byte("index", 0x00),
                Word("adp", 0x0000, endian="<"),
                Word("ado", 0x0000, endian="<"),
                Group(
                    "flags_len",
                    values=[
                        self._dgram_flags(0x7FF),  # 2047 >> 4 present
                        self._dgram_flags(0x400),
                        self._dgram_flags(0x100),
                        self._dgram_flags(0x040),
                        self._dgram_flags(0x005),  # just over the 4 present
                    ],
                ),
                Word("irq", 0x0000, endian="<"),
                Static("data", overflow_data),
                Word("wkc", 0x0000, endian="<"),
            ),
        )

        # ---- 3. EtherCAT header 11-bit Length lie --------------------- #
        hdr_dgram = self._datagram(self.CMD_APRD, base_data, len_bits=len(base_data))
        header_len_lie = Request(
            "EtherCAT_Header_Length_Lie",
            children=(
                Static("eth", eth),
                Group(
                    "ecat_hdr_len",
                    values=[
                        self._ecat_header(0x000),  # claims empty
                        self._ecat_header(0x001),  # 1 octet
                        self._ecat_header(0x7FF),  # max 11-bit, >> frame
                        self._ecat_header(len(hdr_dgram) + 0x100),  # > actual frame
                    ],
                ),
                Static("dgram", hdr_dgram),
            ),
        )

        # ---- 4. Mailbox (CoE/FoE) Length > payload (CVE-2012-4293) ---- #
        # CoE SDO-ish payload of 4 bytes carried in an LRW datagram; the
        # mailbox header Length word is inflated far beyond it.
        mbx_payload = b"\x2f\x00\x10\x00"  # 4-byte CoE payload
        mbx_len_group = Group(
            "mbx_length",
            values=[
                struct.pack("<H", 0xFFFF),
                struct.pack("<H", 0x0FFF),
                struct.pack("<H", 0x0100),
                struct.pack("<H", 0x0005),  # just over the 4 present
            ],
        )
        # Datagram wrapping the mailbox: LenBits = mailbox on-wire size.
        mbx_full = (
            struct.pack("<H", 0x0004)  # placeholder length (overwritten by group render)
            + struct.pack("<H", 0x0000)
            + struct.pack("<B", 0x03)
            + struct.pack("<B", 0x00)
            + mbx_payload
        )
        mailbox_overflow = Request(
            "EtherCAT_Mailbox_Length_Overflow",
            children=(
                Static("eth", eth),
                Static("ecat_hdr", self._ecat_header(12 + len(mbx_full))),
                Static("cmd", struct.pack("<B", self.CMD_LRW)),
                Byte("index", 0x00),
                Word("adp", 0x0000, endian="<"),
                Word("ado", 0x0000, endian="<"),
                Static("flags", self._dgram_flags(len(mbx_full))),
                Word("irq", 0x0000, endian="<"),
                # Mailbox header with the mutable Length word first.
                mbx_len_group,
                Static("mbx_address", struct.pack("<H", 0x0000)),
                Static("mbx_type", struct.pack("<B", 0x03)),  # CoE
                Static("mbx_counter", struct.pack("<B", 0x00)),
                Static("mbx_payload", mbx_payload),
                Word("wkc", 0x0000, endian="<"),
            ),
        )

        # ---- 5. Cmd byte boundary ------------------------------------- #
        cmd_dgram_tail = (
            struct.pack("<B", 0x00)  # index
            + struct.pack("<H", 0x0000)  # adp
            + struct.pack("<H", 0x0000)  # ado
            + self._dgram_flags(4)
            + struct.pack("<H", 0x0000)  # irq
            + base_data
            + struct.pack("<H", 0x0000)  # wkc
        )
        cmd_boundary = Request(
            "EtherCAT_Cmd_Boundary",
            children=(
                Static("eth", eth),
                Static("ecat_hdr", self._ecat_header(1 + len(cmd_dgram_tail))),
                Group(
                    "cmd",
                    values=[
                        b"\x00",  # NOP
                        b"\x01",  # APRD (valid)
                        b"\x02",  # APWR (valid)
                        b"\x0a",  # LRD (valid)
                        b"\x0c",  # LRW (valid)
                        b"\x0d",  # reserved
                        b"\x0e",  # reserved
                        b"\x0f",  # reserved
                        b"\xff",  # max / invalid
                    ],
                ),
                Static("dgram_tail", cmd_dgram_tail),
            ),
        )

        # ---- 6. More-datagrams (M) bit set, nothing follows ----------- #
        # One datagram with the More bit set but no following datagram: a
        # parser that loops "while more" walks past the end of the frame.
        more_dgram = (
            struct.pack("<B", self.CMD_APRD)
            + struct.pack("<B", 0x00)
            + struct.pack("<H", 0x0000)
            + struct.pack("<H", 0x0000)
            + self._dgram_flags(4, more=1)  # M = 1, but no next datagram
            + struct.pack("<H", 0x0000)
            + base_data
            + struct.pack("<H", 0x0000)
        )
        more_lie = Request(
            "EtherCAT_More_Datagrams_Lie",
            children=(
                Static("eth", eth),
                Static("ecat_hdr", self._ecat_header(len(more_dgram))),
                Static("dgram", more_dgram),
            ),
        )

        # ---- 7. Zero-length datagram in a multi-datagram walk --------- #
        # First datagram: LenBits = 0 with More set; second datagram follows.
        # A non-advancing parser (adds header+len each step) can spin because
        # the zero-length body does not move the cursor as expected.
        zero_dgram = (
            struct.pack("<B", self.CMD_APRD)
            + struct.pack("<B", 0x00)
            + struct.pack("<H", 0x0000)
            + struct.pack("<H", 0x0000)
            + self._dgram_flags(0, more=1)  # LenBits = 0, More = 1
            + struct.pack("<H", 0x0000)
            + b""  # zero-length data
            + struct.pack("<H", 0x0000)  # wkc
        )
        second_dgram = self._datagram(self.CMD_APRD, base_data, len_bits=len(base_data))
        zero_len = Request(
            "EtherCAT_Datagram_ZeroLen",
            children=(
                Static("eth", eth),
                Static("ecat_hdr", self._ecat_header(len(zero_dgram) + len(second_dgram))),
                Static("dgram_zero", zero_dgram),
                Static("dgram_second", second_dgram),
            ),
        )

        # ------------------------------------------------------------------ #
        # Gated connects (STRICT 1:1; node name == advertised name).
        # ------------------------------------------------------------------ #
        if self.is_request_enabled("EtherCAT_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("EtherCAT_Datagram_Length_Overflow"):
            self.session.connect(dgram_len_overflow)
        if self.is_request_enabled("EtherCAT_Header_Length_Lie"):
            self.session.connect(header_len_lie)
        if self.is_request_enabled("EtherCAT_Mailbox_Length_Overflow"):
            self.session.connect(mailbox_overflow)
        if self.is_request_enabled("EtherCAT_Cmd_Boundary"):
            self.session.connect(cmd_boundary)
        if self.is_request_enabled("EtherCAT_More_Datagrams_Lie"):
            self.session.connect(more_lie)
        if self.is_request_enabled("EtherCAT_Datagram_ZeroLen"):
            self.session.connect(zero_len)

    def _get_monitors(self) -> List[BaseMonitor]:
        return []

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        return self._get_monitors()
