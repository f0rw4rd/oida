"""Offline tests for the CAN fuzzer (socketcand + J1939 TP surfaces).

The CAN fuzzer's _define_protocol() wires every session.connect() behind
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable actually
take effect. These tests build the boofuzz session offline with
MockConnectionFactory and inspect session.nodes - no network I/O. The fuzzer is
imported directly (not via the PROTOCOL_FUZZERS registry) so this test touches
no shared files.

Coverage targets:
- socketcand < open <bus> > bus-name overflow (CVE-2026-37538, CWE-121)
- J1939 TP.DT sequence-number underflow (CVE-2026-37534 / CVE-2026-37537)
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.can import CANFuzzer

pytestmark = pytest.mark.core

EXPECTED_NAMES = {
    "CAN_Baseline",
    "CAN_SocketCAND_BusName_Overflow",
    "CAN_SocketCAND_Malformed_Command",
    "J1939_TPDT_SeqNum_Underflow",
    "J1939_TPCM_Size_Lie",
    "CAN_ID_Boundary",
    "CAN_DLC_Boundary",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=29536,
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
    return CANFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in CANFuzzer.get_request_definitions()}


def _node(fuzzer, node_name):
    for node in fuzzer.session.nodes.values():
        if node.name == node_name:
            return node
    raise AssertionError(f"node {node_name!r} not connected")


def test_all_seven_requests_are_advertised():
    """--list-requests exposes exactly the seven documented requests."""
    assert _advertised() == EXPECTED_NAMES


def test_seven_request_definitions():
    """Sanity: get_request_definitions() returns exactly seven entries."""
    assert len(CANFuzzer.get_request_definitions()) == 7


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags (all seven wired)."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    # No request is connected without being advertised.
    assert connected <= _advertised()


def test_categories_cover_the_four_axes():
    """Every request carries one of the four documented categories."""
    cats = {d.category for d in CANFuzzer.get_request_definitions()}
    assert cats == {"baseline", "overflow", "boundary", "malformed"}


@pytest.mark.parametrize("name", sorted(EXPECTED_NAMES))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(EXPECTED_NAMES))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving other requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    # Sanity: the rest survive the disable.
    assert connected == EXPECTED_NAMES - {name}


def test_busname_overflow_renders_long_a_run_inside_open():
    """The bus-name overflow renders a long 'A' run inside < open ... >.

    This is the CVE-2026-37538 sink: the oversized bus name flows straight into
    socketcand main()'s fixed stack buffer.
    """
    fuzzer = _build(_make_config(enabled_requests=["CAN_SocketCAND_BusName_Overflow"]))
    rendered = _node(fuzzer, "CAN_SocketCAND_BusName_Overflow").render()

    assert rendered.startswith(b"< open ")
    assert rendered.endswith(b" >")
    # Default SmartString value is 256 'A'; require a clearly-long run.
    assert b"A" * 256 in rendered


def test_tpdt_underflow_declares_size_then_ships_one_frame():
    """The TP.DT underflow request declares a multi-packet TP.CM then ships a
    single TP.DT whose sequence byte (default 0x00) lies about its position."""
    fuzzer = _build(_make_config(enabled_requests=["J1939_TPDT_SeqNum_Underflow"]))
    rendered = _node(fuzzer, "J1939_TPDT_SeqNum_Underflow").render()

    # TP.CM control frame (PGN 0xEC00) declaring the transfer precedes the
    # single TP.DT (PGN 0xEB00) data frame.
    assert b"18ECFF00" in rendered
    assert b"18EBFF00" in rendered
    # Default sequence-number Group value is 0x00 -> the underflow trigger.
    assert b"18EBFF00 8 00" in rendered
