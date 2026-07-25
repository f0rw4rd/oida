"""
Offline tests for the IGMP fuzzer's per-request enable/disable gating.

IGMP is IPv4 multicast (IP protocol 2). The fuzzer targets count-trust / parse
bugs in embedded IGMPv3 stacks (VxWorks CVE-2019-12259 / CVE-2019-12265 /
CVE-2020-10664). Every session.connect() in _define_protocol() is wrapped in
is_request_enabled("<RegisteredName>") so --enable / --disable take effect.

These tests build the boofuzz session offline with MockConnectionFactory and
inspect session.nodes - no network I/O. The IGMP fuzzer is imported directly
(central registration in protocols/__init__.py is intentionally out of scope).
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.igmp import IGMPFuzzer

pytestmark = pytest.mark.core

EXPECTED_NAMES = {
    "IGMP_Baseline",
    "IGMPv3_Query_NumSources_Lie",
    "IGMPv3_Report_NumRecords_Lie",
    "IGMPv3_GroupRecord_AuxDataLen_Overflow",
    "IGMP_Type_Boundary",
    "IGMP_Truncated",
    "IGMP_MaxRespCode_Boundary",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=0,
        protocol_type=ProtocolType.RAW,
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
    return IGMPFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of Request nodes actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in IGMPFuzzer.get_request_definitions()}


def _node(fuzzer, node_name):
    for node in fuzzer.session.nodes.values():
        if node.name == node_name:
            return node
    raise AssertionError(f"node {node_name!r} not connected")


def test_all_seven_requests_are_advertised():
    """--list-requests exposes exactly the seven documented requests."""
    assert _advertised() == EXPECTED_NAMES


def test_request_categories_are_valid():
    """Every request declares a category from the allowed set."""
    allowed = {"baseline", "overflow", "boundary", "malformed"}
    cats = {d.category for d in IGMPFuzzer.get_request_definitions()}
    assert cats <= allowed


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags (all build unconditionally)."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == EXPECTED_NAMES


@pytest.mark.parametrize("name", sorted(EXPECTED_NAMES))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(EXPECTED_NAMES))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving the other requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == EXPECTED_NAMES - {name}


def test_numsources_lie_renders_inflated_count():
    """The IGMPv3 Query renders an inflated number_of_sources count byte-pair
    while carrying only a single 4-byte source address (CVE-2019-12259 class)."""
    fuzzer = _build(_make_config(enabled_requests=["IGMPv3_Query_NumSources_Lie"]))
    req = _node(fuzzer, "IGMPv3_Query_NumSources_Lie")
    rendered = req.render()

    # Default Group value is the first entry: number_of_sources = 0x00FF (255).
    assert b"\x00\xff" in rendered
    # The declared source address is present exactly once...
    assert rendered.count(b"\xc0\xa8\x01\x01") == 1
    # ...so the packet claims 255 sources but ships only one (12-byte IGMPv3
    # query fixed header + 4-byte source = 16 bytes, far short of 12 + 255*4).
    assert len(rendered) == 16
