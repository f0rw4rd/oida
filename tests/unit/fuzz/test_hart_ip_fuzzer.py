"""Offline tests for the HART-IP UDP fuzzer request gating and framing.

HARTIPFuzzer._define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")` with strict 1:1 gating (each
boofuzz Request name matches its RequestInfo name). These tests build the
boofuzz session offline via MockConnectionFactory and inspect session.nodes,
without any network I/O.

Covers CVE-2020-16209 (oversized-payload overflow) and CVE-2013-2476
(short-header loop) request wiring.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.hart_ip import HARTIPFuzzer

pytestmark = pytest.mark.core

ALL_REQUESTS = {
    "HARTIP_Baseline",
    "HARTIP_Payload_Overflow",
    "HARTIP_Short_Header",
    "HARTIP_ByteCount_Lie",
    "HARTIP_MessageType_ID_Boundary",
    "HARTIP_TokenPassing_PDU_Malformed",
    "HARTIP_Version_Boundary",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=5094,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _build(config):
    return HARTIPFuzzer(config=config, connection_factory=MockConnectionFactory())


def _advertised():
    return {d.name for d in HARTIPFuzzer.get_request_definitions()}


def test_all_seven_requests_advertised():
    """--list-requests exposes exactly the seven HART-IP requests."""
    assert _advertised() == ALL_REQUESTS
    assert len(HARTIPFuzzer.get_request_definitions()) == 7


def test_default_run_advertised_equals_connected():
    """Under default flags the connected set equals the advertised set (1:1)."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected <= _advertised()


def test_default_monitor_is_ping():
    assert HARTIPFuzzer.DEFAULT_MONITORS == "ping"


def test_categories_present():
    """Each advertised request carries one of the expected categories."""
    cats = {d.name: d.category for d in HARTIPFuzzer.get_request_definitions()}
    assert cats["HARTIP_Baseline"] == "baseline"
    assert cats["HARTIP_Payload_Overflow"] == "overflow"
    assert cats["HARTIP_Short_Header"] == "malformed"
    assert cats["HARTIP_ByteCount_Lie"] == "boundary"
    assert cats["HARTIP_MessageType_ID_Boundary"] == "boundary"
    assert cats["HARTIP_TokenPassing_PDU_Malformed"] == "malformed"
    assert cats["HARTIP_Version_Boundary"] == "boundary"


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_individually_selectable(name):
    """--enable <name> connects exactly that request, proving strict gating."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while other requests stay connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == ALL_REQUESTS - {name}


def test_short_header_renders_below_header_length():
    """Short_Header default mutation renders a runt shorter than the 5-byte header."""
    fuzzer = _build(_make_config(enabled_requests=["HARTIP_Short_Header"]))
    request = next(
        node for node in fuzzer.session.nodes.values() if node.name == "HARTIP_Short_Header"
    )
    rendered = request.render()
    assert len(rendered) < 5, f"default render was {len(rendered)} bytes: {rendered!r}"
