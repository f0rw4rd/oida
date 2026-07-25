"""
Offline tests for the two ARP length/truncation black-box techniques added to
the Ethernet fuzzer.

The Ethernet fuzzer gates every session.connect() behind
`self.is_request_enabled("<AdvertisedName>")`, where the advertised RequestInfo
name (e.g. "Ethernet_ARP_HwLen_ProtoLen_Mutation") differs from the boofuzz
Request node name it connects (e.g. "ARP_HwLen_ProtoLen_Mutation"). These tests
build the boofuzz session offline with MockConnectionFactory and inspect
session.nodes to verify the new requests are advertised AND individually
selectable, without any network I/O.

Playbook context: ARP hwlen/protolen were hardcoded 6/4 and never mutated, and
the sender/target address fields were never truncated. The two new requests
close both gaps:
  * Ethernet_ARP_HwLen_ProtoLen_Mutation -> node ARP_HwLen_ProtoLen_Mutation
  * Ethernet_ARP_Truncated_Fields        -> node ARP_Truncated_Fields
"""

import pytest

from boofuzz.mutation_context import MutationContext

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core

# Advertised RequestInfo name -> connected boofuzz Request node name.
NEW_REQUESTS = {
    "Ethernet_ARP_HwLen_ProtoLen_Mutation": "ARP_HwLen_ProtoLen_Mutation",
    "Ethernet_ARP_Truncated_Fields": "ARP_Truncated_Fields",
}

# Byte offset of the ARP hardware-length field in a rendered
# ARP_HwLen_ProtoLen_Mutation frame:
#   dst_mac(6) + src_mac(6) + ethertype(2) + htype(2) + ptype(2) = 18
HWLEN_OFFSET = 18


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
    fuzzer_class = PROTOCOL_FUZZERS["ethernet"]
    if fuzzer_class is None:
        pytest.skip("ethernet fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of Request nodes actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["ethernet"].get_request_definitions()}


def _node(fuzzer, node_name):
    for node in fuzzer.session.nodes.values():
        if node.name == node_name:
            return node
    raise AssertionError(f"node {node_name!r} not connected")


def test_new_arp_requests_are_advertised():
    """Both new techniques appear in --list-requests."""
    assert set(NEW_REQUESTS) <= _advertised()


@pytest.mark.parametrize("advertised,node_name", sorted(NEW_REQUESTS.items()))
def test_each_new_request_is_selectable(advertised, node_name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[advertised])))
    assert connected == {node_name}


@pytest.mark.parametrize("advertised,node_name", sorted(NEW_REQUESTS.items()))
def test_each_new_request_is_disableable(advertised, node_name):
    """--disable <name> removes it while leaving other ARP requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[advertised])))
    assert node_name not in connected
    # Sanity: the pre-existing ARP spoofing request survives the disable.
    assert "ARP_Spoofing_Attack" in connected


def test_hwlen_mutations_are_never_6():
    """Rendered hwlen bytes cover the mutated set and never the hardcoded 6."""
    fuzzer = _build(_make_config(enabled_requests=["Ethernet_ARP_HwLen_ProtoLen_Mutation"]))
    req = _node(fuzzer, "ARP_HwLen_ProtoLen_Mutation")

    # The un-mutated frame already carries a non-6 hwlen (Group default != 6).
    assert req.render()[HWLEN_OFFSET] != 6

    seen = {req.render(MutationContext(m))[HWLEN_OFFSET] for m in req.mutations(None)}
    assert 6 not in seen
    # The full mutated hwlen set is exercised.
    assert {0x00, 0x01, 0x07, 0x08, 0xFF} <= seen


def test_truncated_frames_are_short():
    """ARP_Truncated_Fields renders frames cut mid address field.

    A complete ARP-over-Ethernet frame is 14 (Ethernet) + 28 (ARP) = 42 bytes
    before padding; every truncation variant renders shorter than that, and the
    shortest variant stops right after the opcode (no address bytes).
    """
    fuzzer = _build(_make_config(enabled_requests=["Ethernet_ARP_Truncated_Fields"]))
    req = _node(fuzzer, "ARP_Truncated_Fields")

    # The Group's first value is the "original" (rendered by default); the rest
    # are yielded as mutations. Both are truncated frames.
    lengths = {len(req.render())}
    lengths |= {len(req.render(MutationContext(m))) for m in req.mutations(None)}
    assert lengths, "no truncation frames rendered"
    assert max(lengths) < 42
    # Shortest variant = Ethernet(14) + ARP header up to opcode(8) = 22 bytes
    # (no address bytes at all).
    assert min(lengths) == 22
