"""Regression tests for the MQTT Remaining Length varints in the fuzzer.

The ``Large_Payload_Overflow`` request carries a Group of hand-encoded PUBLISH
bodies whose Remaining Length is meant to be *valid* (the malformed-length
coverage lives in its own request). Three of the four literals were
miscalculated -- e.g. ``\\x82\\x02`` decodes to 258 for a body of 262 -- which
desyncs the broker's parser for every following packet on the stateful TCP
connection, so the "large but well-formed payload" path was never reached.
"""

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

# Fixed header 0x30 (PUBLISH, QoS 0 -> no packet identifier), then the body:
# 2-byte topic length + "test" + N payload bytes.
_TOPIC_OVERHEAD = 2 + len("test")
_PAYLOAD_SIZES = (64, 256, 1024, 4096)


def _decode_varint(data: bytes) -> tuple[int, int]:
    """Decode an MQTT Remaining Length; returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    consumed = 0
    for byte in data[:4]:
        value += (byte & 0x7F) * multiplier
        multiplier *= 128
        consumed += 1
        if not byte & 0x80:
            return value, consumed
    raise AssertionError("malformed varint: no terminating byte in 4 octets")


def _walk(node):
    yield node
    for child in getattr(node, "stack", []) or []:
        yield from _walk(child)


@pytest.fixture(scope="module")
def length_payload_values():
    """Render the fuzzer's request tree and pull the Length_Payload group."""
    from oida.fuzz.core.config import FuzzerConfig, ProtocolType
    from oida.fuzz.core.connections.base import MockConnectionFactory
    from oida.fuzz.protocols.mqtt import MQTTFuzzer

    config = FuzzerConfig(
        target_ip="192.0.2.10",
        target_port=1883,
        protocol_type=ProtocolType.TCP,
    )
    fuzzer = MQTTFuzzer(config, connection_factory=MockConnectionFactory())

    captured = {}

    def _connect(request, *args, **kwargs):
        captured[request.name] = request

    session = MagicMock()
    session.connect.side_effect = _connect
    fuzzer._session = session
    fuzzer._define_protocol()

    request = captured.get("Large_Payload_Overflow")
    assert request is not None, f"request not defined; saw {sorted(captured)}"

    for node in _walk(request):
        if "Length_Payload" in getattr(node, "name", "") and hasattr(node, "values"):
            # boofuzz keeps the first entry as the Group's default value and
            # only the remaining mutations in .values.
            values = list(node.values)
            default = node._default_value
            if default not in values:
                values.insert(0, default)
            return values
    raise AssertionError("no Length_Payload group found in Large_Payload_Overflow")


def test_group_covers_the_documented_payload_sizes(length_payload_values):
    assert len(length_payload_values) == len(_PAYLOAD_SIZES)


@pytest.mark.parametrize("index,payload_size", list(enumerate(_PAYLOAD_SIZES)))
def test_remaining_length_matches_the_body(length_payload_values, index, payload_size):
    value = length_payload_values[index]
    remaining, consumed = _decode_varint(value)
    assert remaining == _TOPIC_OVERHEAD + payload_size
    # And it must describe every byte that actually follows it.
    assert remaining == len(value) - consumed


def test_literals_match_the_fuzzer_own_varint_encoder(length_payload_values):
    """Cross-check the hand-written bytes against MQTTRemainingLength."""
    from oida.fuzz.protocols.mqtt import MQTTRemainingLength

    for value, payload_size in zip(length_payload_values, _PAYLOAD_SIZES):
        expected = MQTTRemainingLength._encode_varint(_TOPIC_OVERHEAD + payload_size)
        assert value[: len(expected)] == expected
