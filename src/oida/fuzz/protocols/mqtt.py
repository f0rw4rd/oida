"""MQTT Protocol Fuzzer

Refactored to use the StatefulFuzzer framework with:
- MQTTConnection: Stateful connection (TCP only, no banner)
- MQTTAuthenticator: CONNECT/CONNACK authentication

State Machine V2 Integration:
- StateContext: Carries response data between state transitions
- Response storage: Stores CONNACK, session state for cross-state access
- Context-aware callbacks: State callbacks can access shared context

Optimized for breadth-first coverage and early crash detection.

Test Ordering Strategy (5 Phases):
    Phase 1 (0-30s): Quick_Coverage - All 14 MQTT packet types once
    Phase 2 (30s-3m): High-crash tests - Malformed length, buffer overflow, protocol errors
    Phase 3 (3-6m): CVE-targeted - CONNECT auth bypass, QoS 2 memory leak, large properties
    Phase 4 (6-10m): Boundary attacks - Field boundary tests, Will message, topic limits
    Phase 5 (10m+): Deep fuzzing - Standard requests with full mutation

CVE Coverage:
    - CVE-2023-28366: QoS 2 message memory leak (Phase 2/3)
    - CVE-2023-3592: Large properties causing CPU exhaustion (Phase 2)
    - CVE-2021-28166: Malformed CONNECT packet crash (Phase 2)
    - CVE-2017-7653: Large payload/topic length (Phase 2)
    - CVE-2024-6786: Crafted MQTT packets exploitation (Phase 2)
    - CVE-2021-34432: SUBSCRIBE topic filter DoS (Phase 4)

References:
    - https://blog.compass-security.com/2023/09/from-mqtt-fundamentals-to-cve/
    - https://arxiv.org/pdf/2309.03547 (Security assessment of MQTT brokers)
    - Eclipse Mosquitto security advisories

Integration Pattern Example:
    This fuzzer demonstrates the StateContext integration pattern:

    1. Create StateContext in __init__:
        self._state_context = StateContext()

    2. Store responses for cross-state data access:
        ctx.set_response("CONNACK", ResponseData(raw=response, parsed={"return_code": 0}))

    3. Access previous responses in later states:
        connack = ctx.get_response("CONNACK")
        if connack and connack.parsed.get("return_code") == 0:
            # Connection accepted, ready to publish
"""

from typing import List, Optional

from boofuzz import Block, Byte, Group, Request, Size, Static, Word
from boofuzz.monitors import BaseMonitor

from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo
from oida.fuzz.core.stateful_fuzzer import StatefulFuzzer
from oida.fuzz.core.auth import MQTTAuthenticator, ProtocolAuthenticator
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.core.session import StateContext, ResponseData
from oida.fuzz.core.session.sequence import SequenceConfig, SequenceDirection
from oida.fuzz.core.session.state_machine import StateTransitionError
from oida.fuzz.monitors import MQTTMonitor
from oida.fuzz.primitives.dynamic import DynamicWord, SmartString
from oida.fuzz.primitives.smart_string import StringContext

import logging

logger = logging.getLogger(__name__)


class MQTTRemainingLength(Size):
    """Size primitive that renders the MQTT Remaining Length as a variable-length
    integer (1-4 bytes, 7 bits per byte with a continuation bit), per MQTT 3.1.1
    §2.2.3 / MQTT 5.0 §1.5.5.

    A fixed-width ``Size`` cannot encode this field: ``length=1`` is correct only
    for payloads < 128 bytes, and ``length=2`` corrupts small payloads (the high
    byte 0x00 decodes as Remaining Length 0). So once a fuzzed field pushed the
    payload >= 128 bytes the broker desynced before deeper parsing -- a coverage
    gap. The DEFAULT (non-fuzzed) rendering now emits a correct varint; fuzzing
    the length field itself still yields the inner bit-field mutations, so the
    deliberately-malformed-length coverage is unchanged.
    """

    @staticmethod
    def _encode_varint(n: int) -> bytes:
        # MQTT Remaining Length is at most 4 bytes (max 268,435,455). Clamp
        # defensively so a pathological computed length can't loop unbounded.
        if n < 0:
            n = 0
        n = min(n, 268435455)
        out = bytearray()
        while True:
            byte = n % 128
            n //= 128
            if n > 0:
                byte |= 0x80
            out.append(byte)
            if n == 0 or len(out) >= 4:
                break
        return bytes(out)

    def encode(self, value, mutation_context):
        if value is None:  # default (not fuzzing this field): real MQTT varint
            if self._recursion_flag:
                return self._get_dummy_value()
            return self._encode_varint(self._calculated_length(mutation_context=mutation_context))
        # Fuzzing the length field itself: keep the inner bit-field mutations
        # (the malformed-length coverage the tests rely on).
        return self.bit_field.encode(value=value, mutation_context=mutation_context)

    def _get_dummy_value(self):
        # One-byte placeholder used only to break the size-of-self recursion.
        return b"\x00"


class MQTTFuzzer(StatefulFuzzer):
    """MQTT Protocol Fuzzer for IoT/IIoT messaging protocol testing.

    Uses StatefulFuzzer framework with MQTTAuthenticator for CONNECT/CONNACK.

    Optimized test ordering ensures:
    - All 14 MQTT packet types tested within first 30 seconds
    - High-crash tests (malformed, overflow) run in first 3 minutes
    - CVE-relevant operations tested within first 6 minutes
    - Boundary attacks complete within first 10 minutes

    Phase breakdown:
    - Phase 1: Quick_Coverage - all packet types once (~30 sec)
    - Phase 2: High-crash tests - malformed packets, length attacks (~3 min)
    - Phase 3: CVE-targeted - QoS 2 leak, large properties, auth bypass (~3 min)
    - Phase 4: Boundary attacks - field limits, topic/payload boundaries (~4 min)
    - Phase 5: Deep fuzzing - standard requests with full mutation
    """

    # StatefulFuzzer configuration
    PROTOCOL_NAME = "mqtt"
    CONNECTION_CLASS = None  # MQTT uses plain TCP (no banner/handshake)
    AUTHENTICATOR_CLASS = MQTTAuthenticator

    # The MQTT state machine's connected/authenticated state is named "READY"
    # (not the generic CommonState.AUTHENTICATED). Requests without an explicit
    # requires_state default to it so the matcher recognises the already-
    # established connection instead of re-sending a second CONNECT — which MQTT
    # brokers reject (one CONNECT per connection), closing the socket.
    DEFAULT_REQUEST_STATE = "READY"

    # Use MQTT-specific monitor for protocol-aware health checks
    DEFAULT_MONITORS = "mqtt"

    # Packet types (high nibble of byte 0) that a broker answers on success:
    # CONNECT->CONNACK, PUBREL->PUBCOMP, SUBSCRIBE->SUBACK,
    # UNSUBSCRIBE->UNSUBACK, PINGREQ->PINGRESP, AUTH(0xF)->AUTH.
    # PUBLISH depends on the QoS flags (low nibble): QoS1/2 are acked,
    # QoS0 is fire-and-forget. Everything else (PUBLISH QoS0, PUBACK, PUBREC,
    # PUBCOMP, DISCONNECT 0xE, and the client-only half of any handshake) gets
    # no reply, so waiting the full recv timeout per case was pure dead time.
    # Mutated bytes may of course still elicit a reply (e.g. a corrupted QoS0
    # PUBLISH parsed as a SUBSCRIBE); the fast path still polls briefly for
    # queued data and surfaces RSTs, so a reply or crash signal is never
    # lost — just not waited for.
    _REPLY_TYPES = {0x1, 0x6, 0x8, 0xA, 0xC, 0xF}

    @classmethod
    def _reply_expected_for_payload(cls, data: bytes) -> bool:
        """Reply-expectation policy: MQTT packet type byte -> wait or skip.

        Non-MQTT-looking bytes (empty) conservatively wait.
        """
        if not data:
            return True
        first = data[0]
        packet_type = first >> 4
        if packet_type == 0x3:  # PUBLISH: acked only at QoS 1/2
            qos = (first >> 1) & 0x3
            return qos in (1, 2)
        return packet_type in cls._REPLY_TYPES

    reply_policy = _reply_expected_for_payload

    # Brokers answer a parseable CONNECT/SUBSCRIBE/PINGREQ in ~1ms (p99 2.9ms
    # measured in calibration against the docker mock); malformed ones are
    # silently dropped, so waiting the full calibrated recv timeout (~0.5s)
    # per mutated case was dead time. 0.15s bounds the wait for
    # reply-expected-but-mutated-into-silence packets while leaving two
    # orders of magnitude of headroom for real answers.
    reply_wait_cap = 0.15

    PROTOCOL_OPTIONS = {
        "mqtt_username": {
            "type": str,
            "default": None,
            "description": "MQTT username for authentication",
            "example": "mqttuser",
        },
        "mqtt_password": {
            "type": str,
            "default": None,
            "description": "MQTT password for authentication",
            "example": "secret123",
        },
        "mqtt_client_id": {
            "type": str,
            "default": "fuzzclient",
            "description": "MQTT client identifier",
            "example": "client001",
        },
        "use_auth": {
            "type": bool,
            "default": False,
            "description": "Enable MQTT authentication and state validation",
        },
        "mqtt_protocol_version": {
            "type": int,
            "default": 4,
            "description": "MQTT protocol version (3=3.1, 4=3.1.1, 5=5.0)",
            "choices": [3, 4, 5],
        },
    }

    def __init__(self, config: FuzzerConfig = None, connection_factory=None, command_runner=None):
        self.port = config.target_port or 1883
        self.protocol_name = "MQTT"

        # Authentication credentials - use options if not provided
        self.username = config.get_option("mqtt_username", None) if config else None
        self.password = config.get_option("mqtt_password", None) if config else None
        self.client_id = (
            config.get_option("mqtt_client_id", "fuzzclient") if config else "fuzzclient"
        )
        self.use_auth = config.get_option("use_auth", False) if config else False
        self.protocol_version = config.get_option("mqtt_protocol_version", 4) if config else 4

        # State Machine V2: Create shared StateContext for MQTT protocol
        # This context carries data between state transitions (CONNECT -> CONNACK -> READY)
        self._state_context = StateContext()

        # Sequence manager for packet_id tracking (16-bit, 1-65535)
        seq_mgr = self._state_context.get_sequence_manager("mqtt")
        seq_mgr.add_sequence(
            SequenceConfig(
                name="packet_id",
                initial=1,
                min_value=1,
                max_value=0xFFFF,
                increment=1,
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

        super().__init__(config, connection_factory)

    @property
    def context(self) -> StateContext:
        """Get the StateContext for data propagation.

        State Machine V2 Pattern:
        Protocols can use this to access shared state:
            ctx = fuzzer.context
            connack = ctx.get_response("CONNACK")
            session_present = ctx.get("session_present")
        """
        return self._state_context

    def store_connack_response(
        self, response: bytes, return_code: int, session_present: bool = False
    ) -> None:
        """Store MQTT CONNACK response for later reference.

        State Machine V2 Pattern:
        Store the CONNACK response for cross-state access.

        Args:
            response: Raw CONNACK bytes
            return_code: CONNACK return code (0=accepted)
            session_present: Session Present flag from CONNACK
        """
        self._state_context.set_response(
            "CONNACK",
            ResponseData(
                raw=response,
                parsed={
                    "return_code": return_code,
                    "session_present": session_present,
                    "accepted": return_code == 0,
                },
                response_code=return_code,
            ),
        )
        self._state_context.set("mqtt_connected", return_code == 0)
        self._state_context.set("session_present", session_present)

    def _create_authenticator(self, config: FuzzerConfig) -> Optional[ProtocolAuthenticator]:
        """Create MQTT authenticator from config options."""
        if not self.use_auth:
            return None

        return MQTTAuthenticator(
            client_id=self.client_id,
            username=self.username,
            password=self.password,
            protocol_version=self.protocol_version,
            clean_session=True,
            protocol_name="MQTT",
        )

    def _next_packet_id(self) -> int:
        """Get current packet ID and increment for next use."""
        seq_mgr = self._state_context.get_sequence_manager("mqtt")
        return seq_mgr.get_and_increment("packet_id")

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        Returns request groups organized by optimization phase for
        maximum early coverage and crash detection.

        State Requirements:
        - PRE_AUTH: CONNECT packet fuzzing, auth bypass (before CONNACK)
        - AUTHENTICATED: Normal operations after successful CONNECT/CONNACK
        - ANY: Protocol errors that can be sent in any state
        """
        return [
            # Phase 1: Quick Coverage (can run in any state - sends raw packets)
            RequestInfo(
                "MQTT_Quick_Coverage",
                "Quick sweep of all 14 packet types (~30s)",
                "baseline",
                requires_state=CommonState.ANY,
            ),
            # Phase 2: High-crash tests (protocol errors - any state)
            RequestInfo(
                "MQTT_Malformed_Length",
                "Malformed variable length encoding (CVE-2017-7653)",
                "protocol",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "MQTT_Buffer_Overflow",
                "Large payload/topic overflow attacks",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "MQTT_Protocol_Errors",
                "Invalid packet types and reserved bits",
                "protocol",
                requires_state=CommonState.ANY,
            ),
            # Phase 3: CVE-targeted operations
            RequestInfo(
                "MQTT_QoS2_Memory",
                "QoS 2 message handling (CVE-2023-28366 memory leak)",
                "protocol",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "MQTT_Large_Properties",
                "Large user properties (CVE-2023-3592 CPU exhaustion)",
                "boundary",
                requires_state=CommonState.PRE_AUTH,
            ),  # Part of CONNECT
            RequestInfo(
                "MQTT_Auth_Bypass",
                "CONNECT authentication bypass attempts",
                "auth",
                requires_state=CommonState.PRE_AUTH,
            ),
            # Phase 4: Boundary attacks
            RequestInfo(
                "MQTT_Connect_Boundary",
                "CONNECT field boundary tests",
                "boundary",
                requires_state=CommonState.PRE_AUTH,
            ),  # CONNECT is pre-auth
            RequestInfo(
                "MQTT_Topic_Boundary",
                "Topic name/filter boundary tests (CVE-2021-34432)",
                "boundary",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "MQTT_Will_Message",
                "Will message fuzzing",
                "protocol",
                requires_state=CommonState.PRE_AUTH,
            ),  # Will is in CONNECT
            RequestInfo(
                "MQTT_Reserved_Topic",
                "Reserved '$'-topic PUBLISH (CVE-2018-12543 assert/exit) and "
                "~65400-'/' SUBSCRIBE filter (CVE-2019-11779 stack overflow)",
                "boundary",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # Phase 5: Standard operations (requires successful CONNECT)
            RequestInfo(
                "MQTT_Standard_Ops",
                "Standard PUBLISH/SUBSCRIBE operations",
                "standard",
                requires_state=CommonState.AUTHENTICATED,
            ),
            RequestInfo(
                "MQTT_Control_Packets",
                "Control packets (PING, DISCONNECT)",
                "standard",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # Sparkplug B IIoT payload (MQTT PUBLISH wrapping fuzzed protobuf)
            RequestInfo(
                "MQTT_Sparkplug_Payload",
                "Sparkplug B protobuf payload inside MQTT PUBLISH (IIoT)",
                "protocol",
                requires_state=CommonState.AUTHENTICATED,
            ),
            # MQTT 5.0 reason code sweep — all 256 byte values
            RequestInfo(
                "MQTT_Reason_Code_Sweep",
                "MQTT 5.0 reason code sweep (all 256 byte values)",
                "protocol",
                requires_state=CommonState.ANY,
            ),
            # MQTT 5.0 property parser attacks (CVE-2026-8686 coreMQTT OOB read,
            # CVE-2026-44248 Netty unbounded alloc, CVE-2023-3592 mosquitto will-prop)
            RequestInfo(
                "MQTT_V5_Property_Length_Lie",
                "MQTT 5.0 property-length varint lies (0x00/max/over/under) "
                "vs properties present (CVE-2026-8686 OOB read, CVE-2026-44248 alloc)",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "MQTT_V5_Property_Malformed",
                "MQTT 5.0 malformed property blocks: unknown property-id, "
                "User-Property (0x26) string-length over-read, truncated/duplicate, "
                "oversized allocation vector (CVE-2026-44248, CVE-2023-3592)",
                "protocol",
                requires_state=CommonState.ANY,
            ),
        ]

    def _define_protocol(self):
        """Define MQTT protocol messages for fuzzing

        Request ordering optimized for:
        - Phase 1: Quick_Coverage - all 14 packet types in ~30 seconds
        - Phase 2: High-crash tests (malformed, overflow) in first 3 minutes
        - Phase 3: CVE-targeted operations in first 6 minutes
        - Phase 4: Boundary attacks complete within 10 minutes
        - Phase 5: Deep fuzzing with full mutation
        """

        # ==================== PHASE 1: QUICK COVERAGE (~30 sec) ====================
        # Touch all 14 MQTT packet types once with minimal params for breadth coverage
        # This ensures we hit every code path in the first 30 seconds

        quick_coverage = Request(
            "Quick_Packet_Coverage",
            children=(
                Group(
                    "Packet_Type",
                    values=[
                        # CONNECT (0x10) - Client connection request
                        b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06fuzz01",
                        # PUBLISH QoS 0 (0x30) - Basic publish
                        b"\x30\x0f\x00\x04test\x00\x01testmsg",
                        # PUBLISH QoS 1 (0x32) - Publish with ACK
                        b"\x32\x0f\x00\x04test\x00\x01testmsg",
                        # PUBLISH QoS 2 (0x34) - Publish exactly-once
                        b"\x34\x0f\x00\x04test\x00\x01testmsg",
                        # PUBACK (0x40) - Publish acknowledgment
                        b"\x40\x02\x00\x01",
                        # PUBREC (0x50) - Publish received (QoS 2 step 1)
                        b"\x50\x02\x00\x01",
                        # PUBREL (0x62) - Publish release (QoS 2 step 2)
                        b"\x62\x02\x00\x01",
                        # PUBCOMP (0x70) - Publish complete (QoS 2 step 3)
                        b"\x70\x02\x00\x01",
                        # SUBSCRIBE (0x82) - Subscribe to topics
                        b"\x82\x09\x00\x01\x00\x04test\x00",
                        # SUBACK (0x90) - Subscribe acknowledgment (server sends, but test parser)
                        b"\x90\x03\x00\x01\x00",
                        # UNSUBSCRIBE (0xA2) - Unsubscribe from topics
                        b"\xa2\x08\x00\x02\x00\x04test",
                        # UNSUBACK (0xB0) - Unsubscribe acknowledgment
                        b"\xb0\x02\x00\x02",
                        # PINGREQ (0xC0) - Ping request
                        b"\xc0\x00",
                        # PINGRESP (0xD0) - Ping response (server sends, but test parser)
                        b"\xd0\x00",
                        # DISCONNECT (0xE0) - Clean disconnect
                        b"\xe0\x00",
                    ],
                ),
            ),
        )

        # Baseline CONNECT - simple valid CONNECT to verify service responds
        baseline_connect = Request(
            "MQTT_Baseline",
            children=(
                Static(name="connect_header", default_value=b"\x10"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="connect_payload", length=1
                ),
                Block(
                    "connect_payload",
                    children=(
                        Word("protocol_name_length", 4, endian=">"),
                        Static(name="protocol_name", default_value=b"MQTT"),
                        Byte("protocol_level", 4, fuzzable=True),  # MQTT 3.1.1
                        Byte("connect_flags", 0x02),  # Clean session
                        Word("keep_alive", 60, endian=">"),
                        Word("client_id_length", 10, endian=">"),
                        Static(name="client_id", default_value=b"fuzzclient"),
                    ),
                ),
            ),
        )

        # ==================== PHASE 2: HIGH-CRASH TESTS (~3 min) ====================
        # These trigger buffer overflows, memory corruption, and parser crashes

        # CVE-2017-7653 pattern: Malformed variable length encoding
        malformed_length_1byte = Request(
            "Malformed_Length_1Byte",
            children=(
                Static(name="publish_header", default_value=b"\x30"),
                # 0x80 without continuation = incomplete length encoding
                Static(name="bad_length", default_value=b"\x80"),
                SmartString("payload", "A" * 64, max_len=128),
            ),
        )

        malformed_length_max = Request(
            "Malformed_Length_Max",
            children=(
                Static(name="publish_header", default_value=b"\x30"),
                # Maximum encoded length (268,435,455 bytes) - will cause allocation issues
                Static(name="max_length", default_value=b"\xff\xff\xff\x7f"),
                SmartString("payload", "A" * 256, max_len=512),
            ),
        )

        malformed_length_overflow = Request(
            "Malformed_Length_Overflow",
            children=(
                Static(name="publish_header", default_value=b"\x30"),
                # 5-byte length encoding (invalid - max is 4 bytes)
                Static(name="overflow_length", default_value=b"\xff\xff\xff\xff\x7f"),
                SmartString("payload", "A" * 128, max_len=256),
            ),
        )

        # Large payload buffer overflow attack
        large_payload_overflow = Request(
            "Large_Payload_Overflow",
            children=(
                Static(name="publish_header", default_value=b"\x30"),
                Group(
                    "Length_Payload",
                    values=[
                        # 64 bytes payload
                        b"\x46\x00\x04test" + b"A" * 64,
                        # 256 bytes payload
                        b"\x82\x02\x00\x04test" + b"A" * 256,
                        # 1024 bytes payload
                        b"\x88\x08\x00\x04test" + b"A" * 1024,
                        # 4096 bytes payload
                        b"\xa0\x20\x00\x04test" + b"A" * 4096,
                    ],
                ),
            ),
        )

        # Large topic name overflow (CVE-2017-7653 related)
        large_topic_overflow = Request(
            "Large_Topic_Overflow",
            children=(
                Static(name="publish_header", default_value=b"\x30"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="publish_payload", length=2, endian=">"
                ),
                Block(
                    "publish_payload",
                    children=(
                        Group(
                            "Topic_Size",
                            values=[
                                # 256 byte topic
                                (256).to_bytes(2, "big") + b"A" * 256,
                                # 1024 byte topic
                                (1024).to_bytes(2, "big") + b"A" * 1024,
                                # 65535 byte topic (maximum)
                                (65535).to_bytes(2, "big")
                                + b"A" * 4096,  # Truncated for practical reasons
                            ],
                        ),
                        SmartString("message", "test", max_len=64),
                    ),
                ),
            ),
        )

        # Invalid packet types and reserved bits
        invalid_packet_types = Request(
            "Invalid_Packet_Types",
            children=(
                Group(
                    "Invalid_Header",
                    values=[
                        b"\x00\x00",  # Reserved (0x0)
                        b"\x01\x00",  # Invalid flags on CONNECT (should be 0)
                        b"\x11\x00",  # CONNECT with wrong flags
                        b"\x21\x02\x00\x01",  # Invalid CONNACK flags
                        b"\x31\x00",  # PUBLISH with reserved bit set
                        b"\x3f\x00",  # PUBLISH with all flags
                        b"\x41\x02\x00\x01",  # PUBACK with wrong flags
                        b"\x51\x02\x00\x01",  # PUBREC with wrong flags
                        b"\x61\x02\x00\x01",  # PUBREL with wrong flags (should be 0x62)
                        b"\x71\x02\x00\x01",  # PUBCOMP with wrong flags
                        b"\x81\x00",  # SUBSCRIBE with wrong flags (should be 0x82)
                        b"\x91\x00",  # SUBACK with wrong flags
                        b"\xa1\x00",  # UNSUBSCRIBE with wrong flags
                        b"\xb1\x02\x00\x01",  # UNSUBACK with wrong flags
                        b"\xc1\x00",  # PINGREQ with wrong flags
                        b"\xd1\x00",  # PINGRESP with wrong flags
                        b"\xe1\x00",  # DISCONNECT with wrong flags
                        b"\xf0\x00",  # AUTH (MQTT 5.0 only) on v3.1.1
                    ],
                ),
            ),
        )

        # Zero-length fields (common parser crash trigger)
        zero_length_fields = Request(
            "Zero_Length_Fields",
            children=(
                Group(
                    "Zero_Fields",
                    values=[
                        # CONNECT with zero-length client ID
                        b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
                        # PUBLISH with zero-length topic
                        b"\x30\x04\x00\x00test",
                        # SUBSCRIBE with zero-length topic filter
                        b"\x82\x05\x00\x01\x00\x00\x00",
                        # Empty payload after valid header
                        b"\x30\x02\x00\x00",
                    ],
                ),
            ),
        )

        # Reserved '$'-prefixed PUBLISH topic (CVE-2018-12543).
        # Mosquitto 1.5.0-1.5.2: publishing to a topic that starts with '$' but is
        # not '$SYS' (e.g. "$test/test") reaches an assert() that is otherwise
        # unreachable, and the broker exits. These are pre-crafted QoS-0 PUBLISH
        # packets (fixed header 0x30, topic-length word, topic, empty payload).
        dollar_topic_publish = Request(
            "Dollar_Topic_Publish",
            children=(
                Group(
                    "Dollar_Topics",
                    values=[
                        b"\x30\x0c\x00\x0a$test/test",  # canonical PoC topic
                        b"\x30\x06\x00\x04$foo",
                        b"\x30\x03\x00\x01$",
                        b"\x30\x08\x00\x06$test/",
                        b"\x30\x0a\x00\x08$share/x",  # another reserved '$' prefix, not $SYS
                    ],
                ),
            ),
        )

        # SUBSCRIBE topic filter of ~65400 '/' separators (CVE-2019-11779).
        # Mosquitto 1.5.0-1.6.5: sub_topic_tokenise recurses once per hierarchy
        # separator, so a filter of ~65400 '/' chars overflows the stack. The
        # remaining-length varint and topic-filter-length are rendered correctly
        # so the packet is well-formed apart from its pathological depth.
        subscribe_slash_overflow = Request(
            "Subscribe_Slash_Overflow",
            children=(
                Static(name="subscribe_header", default_value=b"\x82"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="slash_payload", length=2, endian=">"
                ),
                Block(
                    "slash_payload",
                    children=(
                        DynamicWord("packet_id", lambda: self._next_packet_id(), endian=">"),
                        Word("topic_filter_length", 65400, endian=">"),
                        Static(name="slash_topic", default_value=b"/" * 65400),
                        Byte("qos", 0),
                    ),
                ),
            ),
        )

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS (~3 min) ====================

        # CVE-2023-28366: QoS 2 message handling causing memory leak
        # Send many QoS 2 messages with duplicate packet IDs without completing handshake
        qos2_memory_leak = Request(
            "QoS2_Memory_Leak",
            children=(
                Static(name="publish_qos2", default_value=b"\x34"),  # PUBLISH QoS 2
                MQTTRemainingLength(name="remaining_length", block_name="qos2_payload", length=1),
                Block(
                    "qos2_payload",
                    children=(
                        Word("topic_length", 4, endian=">"),
                        Static(name="topic", default_value=b"test"),
                        # Same packet ID repeated - triggers CVE-2023-28366
                        DynamicWord("packet_id", lambda: self._next_packet_id(), endian=">"),
                        SmartString("message", "QoS2 test message", max_len=256),
                    ),
                ),
            ),
        )

        # Incomplete QoS 2 handshake sequences
        qos2_incomplete = Request(
            "QoS2_Incomplete_Handshake",
            children=(
                Group(
                    "QoS2_Sequence",
                    values=[
                        # PUBLISH QoS 2 followed by nothing (wait for PUBREC)
                        b"\x34\x0c\x00\x04test\x00\x0aqos2data",
                        # PUBREC without prior PUBLISH
                        b"\x50\x02\x00\x01",
                        # PUBREL without PUBREC
                        b"\x62\x02\x00\x01",
                        # PUBCOMP without PUBREL
                        b"\x70\x02\x00\x01",
                        # Duplicate PUBREL
                        b"\x62\x02\x00\x01\x62\x02\x00\x01",
                    ],
                ),
            ),
        )

        # CVE-2023-3592: Large number of user properties (MQTT 5.0 CPU exhaustion)
        large_properties = Request(
            "Large_User_Properties",
            children=(
                Static(name="connect_v5", default_value=b"\x10"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="v5_payload", length=2, endian=">"
                ),
                Block(
                    "v5_payload",
                    children=(
                        # MQTT 5.0 header
                        Word("protocol_name_length", 4, endian=">"),
                        Static(name="protocol_name", default_value=b"MQTT"),
                        Byte("protocol_level", 5),  # MQTT 5.0
                        Byte("connect_flags", 0x02),
                        Word("keep_alive", 60, endian=">"),
                        # Properties section with many user properties
                        Group(
                            "Properties",
                            values=[
                                # 10 user properties
                                b"\x50" + (b"\x26\x00\x04key1\x00\x04val1" * 10),
                                # 50 user properties
                                b"\x96\x02" + (b"\x26\x00\x04key1\x00\x04val1" * 50),
                                # 100 user properties (triggers CPU exhaustion)
                                b"\xac\x05" + (b"\x26\x00\x04key1\x00\x04val1" * 100),
                            ],
                        ),
                        Word("client_id_length", 6, endian=">"),
                        Static(name="client_id", default_value=b"fuzz01"),
                    ),
                ),
            ),
        )

        # Authentication bypass attempts
        auth_bypass = Request(
            "Auth_Bypass",
            children=(
                Static(name="connect_header", default_value=b"\x10"),
                MQTTRemainingLength(name="remaining_length", block_name="auth_payload", length=1),
                Block(
                    "auth_payload",
                    children=(
                        Word("protocol_name_length", 4, endian=">"),
                        Static(name="protocol_name", default_value=b"MQTT"),
                        Byte("protocol_level", 4),
                        Group(
                            "Connect_Flags",
                            values=[
                                b"\xc2",  # Username + Password flags set, but no credentials
                                b"\x82",  # Username flag only, no username
                                b"\x42",  # Password flag only (invalid without username)
                                b"\xc0",  # Auth flags without clean session
                                b"\xfe",  # All flags except reserved bit
                            ],
                        ),
                        Word("keep_alive", 60, endian=">"),
                        Word("client_id_length", 6, endian=">"),
                        Static(name="client_id", default_value=b"bypass"),
                    ),
                ),
            ),
        )

        # ==================== PHASE 4: BOUNDARY ATTACKS (~4 min) ====================

        # CONNECT field boundaries
        connect_boundary = Request(
            "Connect_Field_Boundaries",
            children=(
                Static(name="connect_header", default_value=b"\x10"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="connect_payload", length=2, endian=">"
                ),
                Block(
                    "connect_payload",
                    children=(
                        # Protocol name length boundary
                        Group(
                            "Protocol_Name_Boundary",
                            values=[
                                b"\x00\x00",  # Zero length
                                b"\x00\x01X",  # 1 char
                                b"\x00\x04MQTT",  # Valid
                                b"\x00\x06MQIsdp",  # MQTT 3.1 name
                                b"\xff\xff" + b"X" * 256,  # Oversized (truncated)
                            ],
                        ),
                        Byte("protocol_level", 4),
                        Byte("connect_flags", 0x02),
                        # Keep alive boundaries
                        Group(
                            "Keep_Alive_Boundary",
                            values=[
                                b"\x00\x00",  # Zero (immediate timeout)
                                b"\x00\x01",  # 1 second
                                b"\xff\xff",  # Maximum (65535 seconds)
                            ],
                        ),
                        Word("client_id_length", 6, endian=">"),
                        Static(name="client_id", default_value=b"fuzz01"),
                    ),
                ),
            ),
        )

        # Client ID boundaries
        client_id_boundary = Request(
            "Client_ID_Boundaries",
            children=(
                Static(name="connect_header", default_value=b"\x10"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="clientid_payload", length=2, endian=">"
                ),
                Block(
                    "clientid_payload",
                    children=(
                        Word("protocol_name_length", 4, endian=">"),
                        Static(name="protocol_name", default_value=b"MQTT"),
                        Byte("protocol_level", 4),
                        Byte("connect_flags", 0x02),
                        Word("keep_alive", 60, endian=">"),
                        Group(
                            "Client_ID",
                            values=[
                                b"\x00\x00",  # Zero length (allowed with clean session)
                                b"\x00\x01X",  # 1 char
                                b"\x00\x17" + b"X" * 23,  # Max recommended (23 chars)
                                b"\x00\x40" + b"X" * 64,  # 64 chars
                                b"\x01\x00" + b"X" * 256,  # 256 chars
                                b"\xff\xff" + b"X" * 1024,  # Oversized (truncated)
                            ],
                        ),
                    ),
                ),
            ),
        )

        # Topic name/filter boundaries (CVE-2021-34432 related)
        topic_boundary = Request(
            "Topic_Boundaries",
            children=(
                Static(name="subscribe_header", default_value=b"\x82"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="topic_payload", length=2, endian=">"
                ),
                Block(
                    "topic_payload",
                    children=(
                        DynamicWord("packet_id", lambda: self._next_packet_id(), endian=">"),
                        Group(
                            "Topic_Filter",
                            values=[
                                # Zero length
                                b"\x00\x00\x00",
                                # Single char
                                b"\x00\x01X\x00",
                                # Wildcards
                                b"\x00\x01#\x00",  # Multi-level wildcard
                                b"\x00\x01+\x00",  # Single-level wildcard
                                b"\x00\x05+/+/+\x00",  # Multiple wildcards
                                # Deep nesting
                                b"\x00\x0f" + b"a/b/c/d/e/f/g/h\x00",
                                # Very deep nesting
                                b"\x00\x1f" + b"/".join([b"x"] * 16) + b"\x00",
                                # Long topic
                                b"\x01\x00" + b"X" * 256 + b"\x00",
                                # Invalid wildcards
                                b"\x00\x02a#\x00",  # # not at end
                                b"\x00\x03+a/\x00",  # + not alone in level
                            ],
                        ),
                    ),
                ),
            ),
        )

        # Packet ID boundaries
        packet_id_boundary = Request(
            "Packet_ID_Boundaries",
            children=(
                Static(name="subscribe_header", default_value=b"\x82"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="packetid_payload", length=1
                ),
                Block(
                    "packetid_payload",
                    children=(
                        Group(
                            "Packet_ID",
                            values=[
                                b"\x00\x00",  # Zero (invalid for SUBSCRIBE)
                                b"\x00\x01",  # Minimum valid
                                b"\x7f\xff",  # Mid-range
                                b"\x80\x00",  # Sign bit boundary
                                b"\xff\xfe",  # Near maximum
                                b"\xff\xff",  # Maximum
                            ],
                        ),
                        Word("topic_filter_length", 4, endian=">"),
                        Static(name="topic", default_value=b"test"),
                        Byte("qos", 0),
                    ),
                ),
            ),
        )

        # Will message fuzzing
        will_message = Request(
            "Will_Message_Fuzzing",
            children=(
                Static(name="connect_header", default_value=b"\x10"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="will_payload", length=2, endian=">"
                ),
                Block(
                    "will_payload",
                    children=(
                        Word("protocol_name_length", 4, endian=">"),
                        Static(name="protocol_name", default_value=b"MQTT"),
                        Byte("protocol_level", 4),
                        Group(
                            "Will_Flags",
                            values=[
                                b"\x04",  # Will flag only
                                b"\x06",  # Will flag + clean session
                                b"\x0e",  # Will flag + QoS 1 + clean session
                                b"\x16",  # Will flag + QoS 2 + clean session
                                b"\x26",  # Will flag + retain + clean session
                                b"\x3e",  # Will flag + QoS 3 (invalid) + retain + clean session
                            ],
                        ),
                        Word("keep_alive", 60, endian=">"),
                        Word("client_id_length", 6, endian=">"),
                        Static(name="client_id", default_value=b"fuzz01"),
                        # Will topic
                        Group(
                            "Will_Topic",
                            values=[
                                b"\x00\x00",  # Zero length
                                b"\x00\x09will/test",  # Valid
                                b"\x01\x00" + b"X" * 256,  # Long topic
                            ],
                        ),
                        # Will message
                        Group(
                            "Will_Message",
                            values=[
                                b"\x00\x00",  # Zero length
                                b"\x00\x0cwill message",  # Valid
                                b"\x04\x00" + b"X" * 1024,  # Long message
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ==================== PHASE 5: STANDARD OPERATIONS ====================

        # Standard CONNECT
        mqtt_connect = Request(
            "mqtt_connect",
            children=(
                Static(name="connect_header", default_value=b"\x10"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="connect_payload", length=1
                ),
                Block(
                    "connect_payload",
                    children=(
                        Word("protocol_name_length", 4, endian=">"),
                        Static(name="protocol_name", default_value=b"MQTT"),
                        Byte("protocol_level", 4),
                        Byte("connect_flags", 0x02),
                        Word("keep_alive", 60, endian=">"),
                        Word("client_id_length", 10, endian=">"),
                        SmartString(
                            "client_id", "fuzzclient", max_len=256, context=StringContext.CREDENTIAL
                        ),
                    ),
                ),
            ),
        )

        # Standard PUBLISH
        mqtt_publish = Request(
            "mqtt_publish",
            children=(
                Static(name="publish_header", default_value=b"\x30"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="publish_payload", length=1
                ),
                Block(
                    "publish_payload",
                    children=(
                        Word("topic_length", 10, endian=">"),
                        SmartString(
                            "topic", "test/topic", max_len=65535, context=StringContext.PATH
                        ),
                        DynamicWord("packet_id", lambda: self._next_packet_id(), endian=">"),
                        SmartString("message", "Test message", max_len=1024),
                    ),
                ),
            ),
        )

        # Standard SUBSCRIBE
        mqtt_subscribe = Request(
            "mqtt_subscribe",
            children=(
                Static(name="subscribe_header", default_value=b"\x82"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="subscribe_payload", length=1
                ),
                Block(
                    "subscribe_payload",
                    children=(
                        DynamicWord("packet_id", lambda: self._next_packet_id(), endian=">"),
                        Word("topic_filter_length", 11, endian=">"),
                        SmartString(
                            "topic_filter", "test/+/data", max_len=256, context=StringContext.PATH
                        ),
                        Byte("qos", 0),
                    ),
                ),
            ),
        )

        # Standard UNSUBSCRIBE
        mqtt_unsubscribe = Request(
            "mqtt_unsubscribe",
            children=(
                Static(name="unsubscribe_header", default_value=b"\xa2"),
                MQTTRemainingLength(
                    name="remaining_length", block_name="unsubscribe_payload", length=1
                ),
                Block(
                    "unsubscribe_payload",
                    children=(
                        DynamicWord("packet_id", lambda: self._next_packet_id(), endian=">"),
                        Word("topic_filter_length", 11, endian=">"),
                        SmartString(
                            "topic_filter", "test/+/data", max_len=256, context=StringContext.PATH
                        ),
                    ),
                ),
            ),
        )

        # Control packets
        mqtt_pingreq = Request(
            "mqtt_pingreq",
            children=(
                Static(name="pingreq_header", default_value=b"\xc0"),
                Static(name="pingreq_length", default_value=b"\x00"),
            ),
        )

        mqtt_disconnect = Request(
            "mqtt_disconnect",
            children=(
                Static(name="disconnect_header", default_value=b"\xe0"),
                Static(name="disconnect_length", default_value=b"\x00"),
            ),
        )

        # MQTT 5.0 AUTH packet
        mqtt_auth = Request(
            "mqtt_auth",
            children=(
                Static(name="auth_header", default_value=b"\xf0"),
                MQTTRemainingLength(name="remaining_length", block_name="auth_payload", length=1),
                Block(
                    "auth_payload",
                    children=(
                        Byte("reason_code", 0x00),  # Success
                        # Properties (simplified)
                        Byte("properties_length", 0x00),
                    ),
                ),
            ),
        )

        # ==================== SPARKPLUG B PAYLOAD (IIoT) ====================
        # Sparkplug B wraps a Google protobuf "Payload" message inside MQTT PUBLISH.
        # Topic format: spBv1.0/<group_id>/<msg_type>/<edge_node>[/<device>]
        # The protobuf body uses standard wire-format tags:
        #   Field 1 (timestamp) tag=0x08 varint
        #   field 2 (metrics)   tag=0x12 length-delimited
        #   field 3 (seq)       tag=0x18 varint
        # A submessage Metric contains name (tag=0x0a), alias (tag=0x10),
        # timestamp (tag=0x18), datatype (tag=0x20), and a typed value field.
        # Fuzzing the inner protobuf framing exercises Sparkplug parsers
        # (Eclipse Tahu, Cirrus Link, Ignition) for varint / length / tag bugs.
        mqtt_sparkplug_payload = Request(
            "MQTT_Sparkplug_Payload",
            children=(
                # PUBLISH QoS 0 (Sparkplug NDATA / DDATA are typically QoS 0)
                Static(name="publish_header", default_value=b"\x30"),
                # MQTT remaining length is a varint; the default payload is < 128
                # bytes so it must be a single octet. A fixed 2-byte Size emits a
                # leading 0x00 that MQTT reads as remaining-length 0.
                MQTTRemainingLength(
                    name="remaining_length", block_name="sparkplug_publish", length=1
                ),
                Block(
                    "sparkplug_publish",
                    children=(
                        # Sparkplug B topic — spBv1.0/<group>/NDATA/<edge> (25 bytes)
                        Word("topic_length", 25, endian=">"),
                        Static(
                            name="sparkplug_topic",
                            default_value=b"spBv1.0/grp1/NDATA/node01",
                        ),
                        # Protobuf payload — fuzz the inner framing
                        Group(
                            "Protobuf_Payload",
                            values=[
                                # Minimal valid Sparkplug B payload:
                                #   timestamp=0x42, seq=0
                                b"\x08\x42\x18\x00",
                                # One metric: name="t", alias=1, timestamp=1,
                                #   datatype=3 (Int32), int_value=0x2a
                                b"\x08\x01\x12\x10"
                                b"\x0a\x01t\x10\x01\x18\x01 \x03(\x80\x01R\x04\x2a\x00\x00\x00"
                                b"\x18\x00",
                                # Malformed: oversized varint (10 bytes 0xff)
                                b"\x08" + b"\xff" * 10 + b"\x01",
                                # Malformed: length-delimited field with length>>actual
                                b"\x12\xff\x7fAB",
                                # Unknown wire-type 6 (reserved -> parser error)
                                b"\x0e\x00",
                                # Unknown wire-type 7 (reserved -> parser error)
                                b"\x0f\x00",
                                # Truncated submessage tag with no length byte
                                b"\x12",
                                # Recursive/nested Metric submessages (depth abuse)
                                b"\x12\x10" + (b"\x12\x02\x08\x01" * 4),
                                # Metric with datatype=0 (Unknown) — Tahu rejects
                                b"\x12\x06\x0a\x01x \x00",
                                # Metric with very large alias (varint 64-bit max)
                                b"\x12\x0b\x10\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
                                # All zeros — empty protobuf message
                                b"",
                                # Single 0xFF byte — invalid tag
                                b"\xff",
                            ],
                        ),
                    ),
                ),
            ),
        )

        # ==================== MQTT 5.0 REASON CODE SWEEP ====================
        # MQTT 5.0 introduced 1-byte reason codes on CONNACK, PUBACK, PUBREC,
        # PUBREL, PUBCOMP, SUBACK, UNSUBACK, DISCONNECT, and AUTH. Each packet
        # type defines a sparse set of legal values; brokers that don't
        # validate the byte map crash, misroute, or leak state. Sweep all
        # 256 byte values via Group(). The carrier here is DISCONNECT
        # (0xE0), which in MQTT 5.0 is "fixed header + reason code + props".
        mqtt_reason_code_sweep = Request(
            "MQTT_Reason_Code_Sweep",
            children=(
                # DISCONNECT fixed header
                Static(name="disconnect_header", default_value=b"\xe0"),
                # Remaining length = 2 (1 byte reason code + 1 byte property len)
                Static(name="remaining_length", default_value=b"\x02"),
                # Reason code sweep — all 256 values (0x00..0xFF)
                Group(
                    "Reason_Code",
                    values=[bytes([rc]) for rc in range(256)],
                ),
                # Empty property length (MQTT 5.0)
                Static(name="properties_length", default_value=b"\x00"),
            ),
        )

        # ==================== MQTT 5.0 PROPERTY PARSER ATTACKS ====================
        # MQTT 5.0 packets carry a property section = a property-length (variable
        # byte integer) followed by a sequence of {property-identifier, value}.
        # Parsers that trust the declared property-length, or that read a
        # property's embedded string/binary length without bounds-checking it
        # against the bytes actually present, over-read or over-allocate.
        #   CVE-2026-8686  - coreMQTT property parser out-of-bounds read
        #   CVE-2026-44248 - Netty unbounded MQTT 5.0 property allocation
        #   CVE-2023-3592  - mosquitto will-property handling
        #
        # Carrier packets (topic "test", one Payload-Format-Indicator property
        # 0x01 0x01 present, payload "hi") where the property-length VARINT is
        # made to lie about how many property bytes follow.
        mqtt_v5_property_length_lie = Request(
            "MQTT_V5_Property_Length_Lie",
            children=(
                Group(
                    "Property_Length_Lie",
                    values=[
                        # PUBLISH v5, property-length = max varint (268,435,455)
                        # but only 4 property bytes present -> unbounded read/alloc.
                        b"\x30\x0e\x00\x04test\xff\xff\xff\x7f\x01\x01hi",
                        # PUBLISH v5, property-length = 0x00 but 2 property bytes
                        # present -> parser desync (props consumed as payload).
                        b"\x30\x0b\x00\x04test\x00\x01\x01hi",
                        # PUBLISH v5, declared property-length (0x0a=10) > actual
                        # (2 bytes present) -> read past the property section.
                        b"\x30\x0b\x00\x04test\x0a\x01\x01hi",
                        # PUBLISH v5, declared property-length (0x01=1) < actual
                        # (2 bytes present) -> trailing property byte mis-parsed.
                        b"\x30\x0b\x00\x04test\x01\x01\x01hi",
                        # CONNECT v5, property-length = max varint but only a
                        # 5-byte Session-Expiry (0x11) property present.
                        b"\x10\x1b\x00\x04MQTT\x05\x02\x00\x3c"
                        b"\xff\xff\xff\x7f\x11\x00\x00\x00\x3c\x00\x06fuzz01",
                    ],
                ),
            ),
        )

        mqtt_v5_property_malformed = Request(
            "MQTT_V5_Property_Malformed",
            children=(
                Group(
                    "Property_Malformed",
                    values=[
                        # PUBLISH v5, User-Property (0x26) whose name string-length
                        # (0xffff=65535) is far larger than the 2 bytes present
                        # -> string over-read (CVE-2026-8686 class).
                        b"\x30\x0c\x00\x04test\x05\x26\xff\xffAB",
                        # PUBLISH v5, unknown property identifier 0x99 (not defined
                        # for any MQTT 5.0 packet) with a trailing byte.
                        b"\x30\x0a\x00\x04test\x02\x99\x00hi",
                        # PUBLISH v5, truncated property: identifier 0x03
                        # (Content-Type) declares a 0xffff string but no bytes.
                        b"\x30\x09\x00\x04test\x03\x03\xff\xff",
                        # PUBLISH v5, duplicate Payload-Format-Indicator (0x01)
                        # -> some parsers reject/leak on duplicate scalar props.
                        b"\x30\x0c\x00\x04test\x04\x01\x01\x01\x01hi",
                        # CONNECT v5, oversized allocation vector: property-length
                        # 0xff 0xff 0xff 0x7f then a User-Property (0x26) whose
                        # value string-length is the 64-bit-ish max the encoder
                        # allows (CVE-2026-44248 unbounded property allocation).
                        b"\x10\x1c\x00\x04MQTT\x05\x02\x00\x3c"
                        b"\xff\xff\xff\x7f\x26\x00\x01k\xff\xffV\x00\x06fuzz01",
                    ],
                ),
            ),
        )

        # ==================== OPTIMIZED REQUEST ORDERING ====================
        # Phase 1: Quick Coverage (~30 sec)
        if self.is_request_enabled("MQTT_Quick_Coverage"):
            self.session.connect(quick_coverage)
            self.session.connect(baseline_connect)

        # Phase 2: High-crash tests (~3 min)
        if self.is_request_enabled("MQTT_Malformed_Length"):
            self.session.connect(malformed_length_1byte)
            self.session.connect(malformed_length_max)
            self.session.connect(malformed_length_overflow)

        if self.is_request_enabled("MQTT_Buffer_Overflow"):
            self.session.connect(large_payload_overflow)
            self.session.connect(large_topic_overflow)

        if self.is_request_enabled("MQTT_Protocol_Errors"):
            self.session.connect(invalid_packet_types)
            self.session.connect(zero_length_fields)

        # Phase 3: CVE-targeted operations (~3 min)
        if self.is_request_enabled("MQTT_QoS2_Memory"):
            self.session.connect(qos2_memory_leak)
            self.session.connect(qos2_incomplete)

        if self.is_request_enabled("MQTT_Large_Properties"):
            self.session.connect(large_properties)

        if self.is_request_enabled("MQTT_Auth_Bypass"):
            self.session.connect(auth_bypass)

        # Phase 4: Boundary attacks (~4 min)
        if self.is_request_enabled("MQTT_Connect_Boundary"):
            self.session.connect(connect_boundary)
            self.session.connect(client_id_boundary)

        if self.is_request_enabled("MQTT_Topic_Boundary"):
            self.session.connect(topic_boundary)
            self.session.connect(packet_id_boundary)

        if self.is_request_enabled("MQTT_Will_Message"):
            self.session.connect(will_message)

        if self.is_request_enabled("MQTT_Reserved_Topic"):
            self.session.connect(dollar_topic_publish)
            self.session.connect(subscribe_slash_overflow)

        # Phase 5: Standard operations
        if self.is_request_enabled("MQTT_Standard_Ops"):
            self.session.connect(mqtt_connect)
            self.session.connect(mqtt_publish)
            self.session.connect(mqtt_subscribe)
            self.session.connect(mqtt_unsubscribe)

        if self.is_request_enabled("MQTT_Control_Packets"):
            self.session.connect(mqtt_pingreq)
            self.session.connect(mqtt_disconnect)
            self.session.connect(mqtt_auth)

        # Sparkplug B IIoT payload — fuzzed protobuf wrapped in PUBLISH
        if self.is_request_enabled("MQTT_Sparkplug_Payload"):
            self.session.connect(mqtt_sparkplug_payload)

        # MQTT 5.0 reason code sweep — all 256 byte values
        if self.is_request_enabled("MQTT_Reason_Code_Sweep"):
            self.session.connect(mqtt_reason_code_sweep)

        # MQTT 5.0 property parser attacks (property-length lies + malformed props)
        if self.is_request_enabled("MQTT_V5_Property_Length_Lie"):
            self.session.connect(mqtt_v5_property_length_lie)

        if self.is_request_enabled("MQTT_V5_Property_Malformed"):
            self.session.connect(mqtt_v5_property_malformed)

    def _define_state_machine(self) -> None:
        """
        Define MQTT state machine for connection and authentication validation

        States:
        - DISCONNECTED: Initial state, no connection
        - CONNECTED: TCP connection established
        - CONNECT_SENT: MQTT CONNECT packet sent
        - CONNACK_RECEIVED: CONNACK received from broker
        - READY: Ready to publish/receive messages
        """
        if not self.use_auth:
            self.log.display("MQTT state machine disabled (no authentication)")
            return

        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
            TransitionRule,
        )

        # Define states
        disconnected = ProtocolState(
            name="DISCONNECTED",
            state_type=StateType.CONNECTION,
            description="No connection to MQTT broker",
        )

        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            requires=["DISCONNECTED"],
            description="TCP connection established",
        )

        connect_sent = ProtocolState(
            name="CONNECT_SENT",
            state_type=StateType.SESSION,
            setup=self._send_mqtt_connect,
            requires=["CONNECTED"],
            timeout=2.0,
            timeout_callback=lambda: self.log.warning("MQTT CONNECT timeout"),
            description="MQTT CONNECT packet sent, awaiting CONNACK",
        )

        connack_received = ProtocolState(
            name="CONNACK_RECEIVED",
            state_type=StateType.AUTHENTICATION,
            setup=self._receive_connack,
            validation=self._validate_mqtt_connection,
            requires=["CONNECT_SENT"],
            description="CONNACK received, connection accepted",
        )

        ready = ProtocolState(
            name="READY",
            state_type=StateType.SESSION,
            requires=["CONNACK_RECEIVED"],
            description="Ready to publish/subscribe",
        )

        # Define transition rules
        transitions = [
            TransitionRule("DISCONNECTED", "CONNECTED", description="Establish TCP connection"),
            TransitionRule("CONNECTED", "CONNECT_SENT", description="Send MQTT CONNECT packet"),
            TransitionRule(
                "CONNECT_SENT", "CONNACK_RECEIVED", description="Receive and validate CONNACK"
            ),
            TransitionRule("CONNACK_RECEIVED", "READY", description="Transition to ready state"),
        ]

        # Create state machine with StateContext
        # State Machine V2: Pass context for response data propagation
        self.state_machine = StateMachine(
            initial_state=disconnected,
            states=[disconnected, connected, connect_sent, connack_received, ready],
            transitions=transitions,
            allow_invalid_transitions=False,
            context=self._state_context,
        )

        # Auth is deferred until connection is established in fuzz_all()
        self.log.display(
            "MQTT state machine created with StateContext (auth deferred until connection ready)"
        )

    # =========================================================================
    # Legacy helper methods (now handled by MQTTAuthenticator in core/auth.py)
    # Kept for backwards compatibility with state machine approach
    # =========================================================================

    def _get_auth_socket(self):
        """Get or create socket for state machine authentication."""
        if not hasattr(self, "_auth_sock") or self._auth_sock is None:
            import socket

            self._auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._auth_sock.settimeout(2.0)
            self._auth_sock.connect((self.config.target_ip, self.config.target_port))
        return self._auth_sock

    def _close_auth_socket(self):
        """Close the authentication socket."""
        if hasattr(self, "_auth_sock") and self._auth_sock:
            try:
                self._auth_sock.close()
            except Exception as e:
                logger.debug(f"self._auth_sock.close(): {e}")
            self._auth_sock = None

    class _SocketWrapper:
        """Adapt a raw socket to the authenticator's send/recv interface
        while capturing the CONNACK bytes returned by recv()."""

        def __init__(self, s):
            self._sock = s
            self.last_recv = b""

        def send(self, data):
            return self._sock.send(data)

        def recv(self, n):
            data = self._sock.recv(n)
            self.last_recv = data
            return data

    def _send_mqtt_connect(self) -> bool:
        """Send MQTT CONNECT and read CONNACK (CONNECT_SENT setup callback).

        Performs the real CONNECT/CONNACK handshake on the auth socket via
        MQTTAuthenticator and stores the raw CONNACK in the StateContext so
        later states (and tests) can access it via ctx.get_response("CONNACK").
        """
        if not self.authenticator:
            return False

        sock = self._get_auth_socket()
        wrapper = self._SocketWrapper(sock)
        accepted = self.authenticator.authenticate(wrapper)

        # Persist the CONNACK so it propagates through the state machine.
        connack = wrapper.last_recv or b""
        if len(connack) >= 4:
            return_code = connack[3]
            self.store_connack_response(connack, return_code)
        return accepted

    def _receive_connack(self) -> bool:
        """CONNACK_RECEIVED setup callback.

        The CONNACK was already read and stored during _send_mqtt_connect();
        confirm it was accepted (return code 0) before advancing.
        """
        connack = self._state_context.get_response("CONNACK")
        if connack is None:
            return False
        return bool(connack.parsed.get("accepted", False))

    def _validate_mqtt_connection(self) -> bool:
        """Validate MQTT connection (for state machine use)."""
        if self.authenticator:
            sock = self._get_auth_socket()
            return self.authenticator.validate(self._SocketWrapper(sock))
        return True

    def _get_monitors(self) -> List[BaseMonitor]:
        """Return list of monitors for MQTT service"""
        monitors = []

        # MQTT protocol monitor using CONNECT/CONNACK
        mqtt_monitor = MQTTMonitor(
            host=self.config.target_ip,
            port=self.port,
            timeout=2.0,
            check_interval=10,
            retry_count=2,
            failure_threshold=2,
        )
        monitors.append(mqtt_monitor)

        return monitors

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup MQTT-specific monitors"""
        return self._get_monitors()

    def _drive_state_machine(self) -> None:
        """Walk the MQTT state machine through its real connection sequence.

        DISCONNECTED -> CONNECTED -> CONNECT_SENT -> CONNACK_RECEIVED -> READY

        Each transition runs the corresponding setup callback, which performs
        the real CONNECT/CONNACK handshake on the auth socket (see
        _send_mqtt_connect). This mirrors how the MMS/VNC fuzzers drive their
        state machines during connection setup so that state_history and the
        StateContext reflect the handshake the fuzzer actually performed.

        The handshake runs on a dedicated preflight socket; boofuzz manages
        its own fuzzing connections separately, so we close the socket after.
        """
        if not (self.use_auth and self.state_machine):
            return

        try:
            self.state_machine.traverse_to_state("READY")
            self.log.display(
                f"MQTT state machine advanced to {self.state_machine.get_current_state_name()}"
            )
        except StateTransitionError as e:
            self.log.fail(f"MQTT state machine could not reach READY: {e}")
            raise
        finally:
            self._close_auth_socket()

    def fuzz_all(self) -> None:
        """
        Override fuzz_all to use StatefulFuzzer's authentication framework.

        MQTT can work in two modes:
        1. With authentication (use_auth=True): Uses MQTTAuthenticator for CONNECT/CONNACK
        2. Without authentication: Sends raw MQTT packets without connection setup

        Note: For MQTT, "authentication" means the CONNECT/CONNACK handshake,
        which may or may not include username/password credentials.
        """
        # Access session to trigger lazy state-machine initialization.
        _ = self.session

        if self.use_auth:
            self.log.display("MQTT fuzzing with CONNECT/CONNACK handshake enabled")
            # Drive the state machine through the real handshake before fuzzing
            # so DISCONNECTED -> ... -> READY is reflected in state_history.
            self._drive_state_machine()

        # Use StatefulFuzzer's authentication framework
        # The MQTTAuthenticator will send CONNECT and validate CONNACK
        super().fuzz_all()
