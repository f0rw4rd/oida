"""
Offline tests for MQTT 5.0 property-parser fuzzer coverage.

The MQTT fuzzer previously only varied the *count* of v5 user properties
(Large_User_Properties) and never fuzzed the property-length variable byte
integer or the embedded property string/binary lengths. This adds two
requests that attack the v5 property parser directly:

  MQTT_V5_Property_Length_Lie  - property-length varint lies (0x00, max,
      declared>actual, declared<actual) vs the property bytes present.
      Targets CVE-2026-8686 (coreMQTT OOB read) and CVE-2026-44248
      (Netty unbounded property allocation).
  MQTT_V5_Property_Malformed   - malformed property blocks: unknown
      property-id, User-Property (0x26) string-length over-read, truncated /
      duplicate props, oversized allocation vector. Targets CVE-2023-3592
      (mosquitto will-property) / CVE-2026-44248.

The session is built offline (no live broker) via MockConnectionFactory;
the lazy `.session` property runs _define_protocol() and wires the boofuzz
nodes. Request objects are named to match their registered names, so a
connected node name equals its --enable/--disable key.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

NEW_REQUESTS = {
    "MQTT_V5_Property_Length_Lie",
    "MQTT_V5_Property_Malformed",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=1883,
        protocol_type=ProtocolType.TCP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build(config):
    fuzzer_class = PROTOCOL_FUZZERS["mqtt"]
    if fuzzer_class is None:
        require_service("mqtt fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["mqtt"].get_request_definitions()}


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _render(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node.render()
    raise AssertionError(f"request {name!r} not connected")


def test_new_requests_are_advertised():
    """Both v5 property-parser requests appear in --list-requests."""
    assert NEW_REQUESTS <= _advertised_names()


def test_new_requests_connected_by_default():
    """Both requests are wired into the session under default flags."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_disableable(name):
    """--disable <name> removes it while leaving other requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert len(connected) > 1


def test_property_length_lie_renders_max_varint_after_topic():
    """Default render carries the max property-length varint (0xff ff ff 7f)
    directly after the topic - the coreMQTT OOB-read vector."""
    rendered = _render(_build(_make_config()), "MQTT_V5_Property_Length_Lie")
    # topic "test" immediately followed by the maximum 4-byte varint.
    assert b"\x00\x04test\xff\xff\xff\x7f" in rendered


def test_property_malformed_renders_userprop_string_overread():
    """Default render carries a User-Property (0x26) whose name string-length
    (0xffff) is far larger than the bytes present - the string over-read."""
    rendered = _render(_build(_make_config()), "MQTT_V5_Property_Malformed")
    assert b"\x26\xff\xff" in rendered
