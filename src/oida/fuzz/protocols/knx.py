"""KNXnet/IP Protocol Fuzzer (UDP/3671)

Targets the KNXnet/IP tunnelling/routing stack used by KNX building-automation
gateways and IP routers.

CVE coverage motivating this fuzzer:
  - CVE-2021-37740: KNXnet/IP Secure SESSION_REQUEST with an inconsistent
    KNXnet/IP header TotalLength field wedges the router (length-lie DoS class).
  - CVE-2019-6840: KNX server format-string / malformed-body handling (RCE),
    reachable through malformed CONNECT_REQUEST / cEMI bodies.

Framing (every KNXnet/IP datagram):
    Byte  HeaderLength      (must be 0x06)
    Byte  ProtocolVersion   (must be 0x10)
    Word  ServiceType       (big-endian, e.g. 0x0201 SEARCH_REQUEST)
    Word  TotalLength       (big-endian, header + body length)
    ...   service body      (HPAI blocks / CRIs / cEMI frames)

HPAI (Host Protocol Address Information), 8 bytes:
    Byte  structure length  (0x08)
    Byte  host protocol     (0x01 IPV4_UDP, 0x02 IPV4_TCP)
    4B    IPv4 address
    Word  port
"""

from typing import List

from boofuzz import Block, Byte, Group, Request, Static, Word

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import ProtocolType
from oida.fuzz.core.connections import CountingUDPConnection as UDPSocketConnection
from oida.fuzz.primitives.dynamic import SmartBytes

# KNXnet/IP header constants
_HEADER_LEN = 0x06
_PROTO_VERSION = 0x10

# ServiceType identifiers (big-endian words)
_SEARCH_REQUEST = b"\x02\x01"
_DESCRIPTION_REQUEST = b"\x02\x03"
_CONNECT_REQUEST = b"\x02\x05"
_CONNECTIONSTATE_REQUEST = b"\x02\x07"
_TUNNELING_REQUEST = b"\x04\x20"
_ROUTING_INDICATION = b"\x05\x30"
_SESSION_REQUEST = b"\x09\x51"  # KNXnet/IP Secure


def _hpai(host_protocol: int = 0x01) -> tuple:
    """A well-formed 8-byte HPAI block (structure len + proto + IP + port)."""
    return (
        Byte("hpai_struct_len", 0x08),
        Byte("hpai_host_protocol", host_protocol),
        Static("hpai_ip", b"\xc0\xa8\x00\x0a"),  # 192.168.0.10
        Static("hpai_port", b"\x0e\x57"),  # 3671
    )


class KNXFuzzer(BaseFuzzer):
    """KNXnet/IP Protocol Fuzzer for KNX gateways and IP routers.

    Exercises the KNXnet/IP header (length/version/service-type consistency),
    HPAI structure-length handling, CONNECT_REQUEST CRI parsing, and cEMI frame
    truncation - the code paths behind CVE-2021-37740 and CVE-2019-6840.
    """

    # Liveness via ICMP echo: a length-lie DoS wedges the router, ping detects it.
    DEFAULT_MONITORS = "ping"

    PROTOCOL_OPTIONS: dict = {}

    def __init__(self, config, connection_factory=None):
        # KNXnet/IP runs over UDP/3671
        config.protocol_type = ProtocolType.UDP
        super().__init__(config, connection_factory)

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Static request definitions for --list-requests (strict 1:1 gating)."""
        return [
            RequestInfo(
                "KNX_Baseline",
                "Valid SEARCH_REQUEST with a well-formed HPAI",
                "baseline",
            ),
            RequestInfo(
                "KNX_TotalLength_Lie",
                "KNXnet/IP header TotalLength inconsistent with datagram "
                "length (CVE-2021-37740 SESSION_REQUEST DoS class)",
                "malformed",
            ),
            RequestInfo(
                "KNX_HPAI_StructLen_Overflow",
                "HPAI structure-length byte over/under the 8-byte HPAI present",
                "overflow",
            ),
            RequestInfo(
                "KNX_ServiceType_Boundary",
                "ServiceType word over valid + reserved/invalid identifiers",
                "boundary",
            ),
            RequestInfo(
                "KNX_Connect_CRI_Malformed",
                "CONNECT_REQUEST with a malformed CRI struct-length / "
                "tunnel-layer byte (CVE-2019-6840 class)",
                "malformed",
            ),
            RequestInfo(
                "KNX_cEMI_Truncated",
                "TUNNELING_REQUEST carrying a cEMI frame truncated after the message-code byte",
                "malformed",
            ),
            RequestInfo(
                "KNX_HeaderLength_Boundary",
                "HeaderLength byte boundary (must be 0x06) + ProtocolVersion variations",
                "boundary",
            ),
        ]

    def _create_socket(self):
        """UDP socket bound to an ephemeral local port for KNXnet/IP replies."""
        return UDPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            bind=("0.0.0.0", 0),
            **self._timeout_overrides(recv_default=2.0),
        )

    def setup_custom_monitors(self) -> list:
        """No protocol-specific monitor; rely on DEFAULT_MONITORS (ping)."""
        return []

    def _define_protocol(self) -> None:
        """Define KNXnet/IP request structures (strict 1:1 gating)."""

        # ================================================================
        # 1. KNX_Baseline - valid SEARCH_REQUEST + well-formed HPAI
        # header(6) + HPAI(8) = 14 = 0x000E
        # ================================================================
        baseline = Request(
            "KNX_Baseline",
            children=(
                Block(
                    "KNX_Baseline_Packet",
                    children=(
                        Byte("header_len", _HEADER_LEN),
                        Byte("protocol_version", _PROTO_VERSION),
                        Static("service_type", _SEARCH_REQUEST),
                        Word("total_length", 14, endian=">"),
                        *_hpai(),
                    ),
                ),
            ),
        )

        # ================================================================
        # 2. KNX_TotalLength_Lie - SESSION_REQUEST (KNXnet/IP Secure) whose
        # header TotalLength disagrees with the real datagram length.
        # CVE-2021-37740 length-inconsistency DoS class.
        # Body: control-endpoint HPAI(8) + 32-byte DH client public value.
        # Real datagram length = 6 + 8 + 32 = 46, but TotalLength lies.
        # ================================================================
        total_length_lie = Request(
            "KNX_TotalLength_Lie",
            children=(
                Block(
                    "KNX_TotalLength_Lie_Packet",
                    children=(
                        Byte("header_len", _HEADER_LEN),
                        Byte("protocol_version", _PROTO_VERSION),
                        Static("service_type", _SESSION_REQUEST),
                        Group(
                            "total_length",
                            values=[
                                b"\x00\x00",  # claims empty datagram
                                b"\x00\x06",  # claims header-only (body ignored)
                                b"\xff\xff",  # claims 65535 bytes (over-read)
                            ],
                        ),
                        *_hpai(),
                        # Diffie-Hellman client public value (32 bytes)
                        Static("dh_public", b"\x41" * 32),
                    ),
                ),
            ),
        )

        # ================================================================
        # 3. KNX_HPAI_StructLen_Overflow - HPAI structure-length byte lies
        # about the 8-byte HPAI that follows.
        # ================================================================
        hpai_structlen = Request(
            "KNX_HPAI_StructLen_Overflow",
            children=(
                Block(
                    "KNX_HPAI_StructLen_Packet",
                    children=(
                        Byte("header_len", _HEADER_LEN),
                        Byte("protocol_version", _PROTO_VERSION),
                        Static("service_type", _SEARCH_REQUEST),
                        Word("total_length", 14, endian=">"),
                        Group(
                            "hpai_struct_len",
                            values=[
                                b"\x00",  # zero-length structure
                                b"\xff",  # 255, far past the 8 bytes present
                                b"\x40",  # 64, > frame remaining (over-read)
                            ],
                        ),
                        Byte("hpai_host_protocol", 0x01),
                        Static("hpai_ip", b"\xc0\xa8\x00\x0a"),
                        Static("hpai_port", b"\x0e\x57"),
                    ),
                ),
            ),
        )

        # ================================================================
        # 4. KNX_ServiceType_Boundary - ServiceType word over valid +
        # reserved/invalid identifiers.
        # ================================================================
        servicetype_boundary = Request(
            "KNX_ServiceType_Boundary",
            children=(
                Block(
                    "KNX_ServiceType_Packet",
                    children=(
                        Byte("header_len", _HEADER_LEN),
                        Byte("protocol_version", _PROTO_VERSION),
                        Group(
                            "service_type",
                            values=[
                                _SEARCH_REQUEST,
                                _DESCRIPTION_REQUEST,
                                _CONNECT_REQUEST,
                                _CONNECTIONSTATE_REQUEST,
                                _TUNNELING_REQUEST,
                                _ROUTING_INDICATION,
                                _SESSION_REQUEST,
                                b"\x00\x00",  # reserved / invalid
                                b"\x02\x02",  # SEARCH_RESPONSE sent as request
                                b"\xff\xff",  # out-of-range service type
                            ],
                        ),
                        Word("total_length", 14, endian=">"),
                        *_hpai(),
                    ),
                ),
            ),
        )

        # ================================================================
        # 5. KNX_Connect_CRI_Malformed - CONNECT_REQUEST with a malformed CRI.
        # Body: control HPAI(8) + data HPAI(8) + CRI.
        # CRI (tunnelling) = struct_len(0x04) + conn_type(0x04) +
        #                    KNX layer(0x02 LinkLayer) + reserved(0x00).
        # SmartBytes carries a variable CRI tail (extra/absent option bytes).
        # ================================================================
        connect_cri = Request(
            "KNX_Connect_CRI_Malformed",
            children=(
                Block(
                    "KNX_Connect_CRI_Packet",
                    children=(
                        Byte("header_len", _HEADER_LEN),
                        Byte("protocol_version", _PROTO_VERSION),
                        Static("service_type", _CONNECT_REQUEST),
                        Word("total_length", 26, endian=">"),
                        # control endpoint HPAI
                        Byte("ctrl_hpai_len", 0x08),
                        Byte("ctrl_hpai_proto", 0x01),
                        Static("ctrl_hpai_ip", b"\xc0\xa8\x00\x0a"),
                        Static("ctrl_hpai_port", b"\x0e\x57"),
                        # data endpoint HPAI
                        Byte("data_hpai_len", 0x08),
                        Byte("data_hpai_proto", 0x01),
                        Static("data_hpai_ip", b"\xc0\xa8\x00\x0a"),
                        Static("data_hpai_port", b"\x0e\x57"),
                        # CRI - malformed structure length
                        Group(
                            "cri_struct_len",
                            values=[
                                b"\x00",  # zero-length CRI
                                b"\x02",  # too short for the fields present
                                b"\xff",  # over-long CRI
                            ],
                        ),
                        Byte("cri_conn_type", 0x04),  # TUNNEL_CONNECTION
                        # KNX tunnel layer - invalid layer selectors
                        Group(
                            "cri_tunnel_layer",
                            values=[
                                b"\x00",  # reserved
                                b"\x02",  # LINK_LAYER (valid)
                                b"\x80",  # BUSMONITOR (privileged) / invalid
                                b"\xff",  # out-of-range layer
                            ],
                        ),
                        # variable CRI tail (option bytes / padding)
                        SmartBytes(
                            name="cri_tail",
                            default_value=b"\x00",
                            max_len=64,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # ================================================================
        # 6. KNX_cEMI_Truncated - TUNNELING_REQUEST carrying a cEMI frame that
        # ends right after the message-code byte (no additional-info /
        # control fields), so a naive cEMI parser reads past the datagram.
        # Connection header: struct_len(0x04) + channel + seq + reserved.
        # ================================================================
        cemi_truncated = Request(
            "KNX_cEMI_Truncated",
            children=(
                Block(
                    "KNX_cEMI_Truncated_Packet",
                    children=(
                        Byte("header_len", _HEADER_LEN),
                        Byte("protocol_version", _PROTO_VERSION),
                        Static("service_type", _TUNNELING_REQUEST),
                        Word("total_length", 11, endian=">"),
                        # connection header (4 bytes)
                        Byte("conn_struct_len", 0x04),
                        Byte("channel_id", 0x01),
                        Byte("seq_counter", 0x00),
                        Byte("conn_reserved", 0x00),
                        # cEMI frame truncated right after the message code
                        Group(
                            "cemi_message_code",
                            values=[
                                b"\x11",  # L_Data.req
                                b"\x29",  # L_Data.ind
                                b"\x2e",  # L_Data.con
                                b"\xfc",  # M_PropRead.req
                                b"\x00",  # invalid message code
                            ],
                        ),
                        # nothing follows: frame ends mid-cEMI
                    ),
                ),
            ),
        )

        # ================================================================
        # 7. KNX_HeaderLength_Boundary - HeaderLength byte must be 0x06;
        # sweep boundary values plus ProtocolVersion variations.
        # ================================================================
        headerlen_boundary = Request(
            "KNX_HeaderLength_Boundary",
            children=(
                Block(
                    "KNX_HeaderLength_Packet",
                    children=(
                        Group(
                            "header_len",
                            values=[
                                b"\x00",  # zero header length
                                b"\x05",  # one short of spec
                                b"\x06",  # correct
                                b"\xff",  # over-long header
                            ],
                        ),
                        Group(
                            "protocol_version",
                            values=[
                                b"\x10",  # correct (1.0)
                                b"\x00",  # zero
                                b"\x11",  # unknown minor
                                b"\xff",  # out-of-range
                            ],
                        ),
                        Static("service_type", _SEARCH_REQUEST),
                        Word("total_length", 14, endian=">"),
                        *_hpai(),
                    ),
                ),
            ),
        )

        # ---------------- strict 1:1 gating ----------------
        if self.is_request_enabled("KNX_Baseline"):
            self.session.connect(baseline)
        if self.is_request_enabled("KNX_TotalLength_Lie"):
            self.session.connect(total_length_lie)
        if self.is_request_enabled("KNX_HPAI_StructLen_Overflow"):
            self.session.connect(hpai_structlen)
        if self.is_request_enabled("KNX_ServiceType_Boundary"):
            self.session.connect(servicetype_boundary)
        if self.is_request_enabled("KNX_Connect_CRI_Malformed"):
            self.session.connect(connect_cri)
        if self.is_request_enabled("KNX_cEMI_Truncated"):
            self.session.connect(cemi_truncated)
        if self.is_request_enabled("KNX_HeaderLength_Boundary"):
            self.session.connect(headerlen_boundary)

        return self.session
