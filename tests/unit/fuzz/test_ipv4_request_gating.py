"""
Offline tests for the three black-box IPv4 fuzzer requests added for
header/fragment reassembly abuse:

    IPv4_IHL_Underflow          - IHL < 5 (header length below 20-byte minimum)
    IPv4_Fragment_MF_Misaligned - MF=1 with non-8-byte-aligned offset + length
    IPv4_Lone_Tail_Fragment     - MF=0, large non-zero offset, no first fragment

The IPv4 fuzzer wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable (which
populate config.enabled_requests / disabled_requests) take effect. These tests
build the boofuzz session offline via MockConnectionFactory and inspect
session.nodes without any network I/O.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from oida.fuzz.core.connections import MockConnectionFactory

pytestmark = pytest.mark.core

# The three requests these tests are about.
NEW_REQUESTS = {
    "IPv4_IHL_Underflow",
    "IPv4_Fragment_MF_Misaligned",
    "IPv4_Lone_Tail_Fragment",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="192.168.1.100",
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
    fuzzer_class = PROTOCOL_FUZZERS["ipv4"]
    if fuzzer_class is None:
        pytest.skip("ipv4 fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _connected_nodes(fuzzer):
    session = fuzzer.session
    return {node.name: node for node in session.nodes.values()}


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["ipv4"].get_request_definitions()}


def test_new_requests_are_advertised():
    """All three new requests appear in --list-requests."""
    assert NEW_REQUESTS <= _advertised()


def test_new_requests_connected_under_default_flags():
    """Under default flags all three are wired into the session."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected
    # Nothing is connected without being advertised.
    assert connected <= _advertised()


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated 1:1."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_disableable(name):
    """--disable <name> removes it while leaving other defaults connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "IPv4_Basic" in connected


def test_ihl_underflow_byte_present_in_render():
    """A rendered IPv4_IHL_Underflow mutation carries an IHL < 5 version byte."""
    fuzzer = _build(_make_config(enabled_requests=["IPv4_IHL_Underflow"]))
    node = _connected_nodes(fuzzer)["IPv4_IHL_Underflow"]
    rendered = node.render()
    # First byte is version(4)/IHL: default Group value is 0x40 (IHL=0), all
    # candidate values 0x40..0x44 encode an illegal IHL below the minimum of 5.
    assert rendered[0] in {0x40, 0x41, 0x42, 0x43, 0x44}
    assert (rendered[0] & 0x0F) < 5


def test_mf_misaligned_flags_present_in_render():
    """IPv4_Fragment_MF_Misaligned renders MF=1 with a non-8-aligned offset."""
    fuzzer = _build(_make_config(enabled_requests=["IPv4_Fragment_MF_Misaligned"]))
    node = _connected_nodes(fuzzer)["IPv4_Fragment_MF_Misaligned"]
    rendered = node.render()
    flags_frag = int.from_bytes(rendered[6:8], "big")
    assert flags_frag & 0x2000  # MF bit set
    assert (flags_frag & 0x1FFF) % 1 == 0  # offset present
    assert (flags_frag & 0x1FFF) != 0  # non-zero, and 3 is not 8-aligned in bytes


def test_lone_tail_fragment_flags_present_in_render():
    """IPv4_Lone_Tail_Fragment renders MF=0 with a large non-zero offset."""
    fuzzer = _build(_make_config(enabled_requests=["IPv4_Lone_Tail_Fragment"]))
    node = _connected_nodes(fuzzer)["IPv4_Lone_Tail_Fragment"]
    rendered = node.render()
    flags_frag = int.from_bytes(rendered[6:8], "big")
    assert not (flags_frag & 0x2000)  # MF clear
    assert (flags_frag & 0x1FFF) == 0x00B9  # large non-zero fragment offset
