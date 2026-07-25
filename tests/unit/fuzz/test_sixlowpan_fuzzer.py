"""
Offline tests for the 6LoWPAN adaptation-layer fuzzer.

SixLoWPANFuzzer wraps fuzzed 6LoWPAN dispatch/payload bytes in a static
ZEP(v2) + IEEE 802.15.4 MAC prefix over UDP/17754. Its _define_protocol()
gates every session.connect() behind is_request_enabled("<name>") with a
STRICT 1:1 name convention, so --enable / --disable select exactly one
request. These tests build the boofuzz session offline (MockConnectionFactory,
no network I/O) and inspect session.nodes plus rendered bytes.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.sixlowpan import SixLoWPANFuzzer

pytestmark = pytest.mark.core

ALL_REQUESTS = {
    "SixLoWPAN_Baseline",
    "SixLoWPAN_IPHC_Truncated",
    "SixLoWPAN_NHC_UDP_Underflow",
    "SixLoWPAN_FRAG1_DispatchOnly",
    "SixLoWPAN_FRAGN_DispatchOnly",
    "SixLoWPAN_Frag_Overlap",
    "SixLoWPAN_HighBit_ShiftUB",
    "SixLoWPAN_802154_LongAddr_Short",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=17754,
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


def _build(config):
    return SixLoWPANFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in SixLoWPANFuzzer.get_request_definitions()}


def _request_node(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node
    raise AssertionError(f"request {name} not connected")


def test_all_eight_requests_advertised():
    """(a) all 8 names appear in get_request_definitions()."""
    assert _advertised() == ALL_REQUESTS
    assert len(SixLoWPANFuzzer.get_request_definitions()) == 8


def test_default_advertised_equals_connected():
    """(b) advertised == connected under default flags (nothing gated off)."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_individually_selectable(name):
    """(c) --enable <name> connects exactly that one request (STRICT 1:1)."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_individually_disableable(name):
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "SixLoWPAN_Baseline" in connected or name == "SixLoWPAN_Baseline"


def test_categories_present():
    """RequestInfo categories are drawn from the intended set."""
    cats = {d.category for d in SixLoWPANFuzzer.get_request_definitions()}
    assert cats <= {"baseline", "overflow", "boundary", "malformed"}


def _rendered_variants(node, limit=6):
    """Default render plus a handful of mutation renders."""
    from boofuzz.mutation_context import MutationContext

    out = [node.render()]
    for i, mutation in enumerate(node.mutations(None)):
        if i >= limit:
            break
        out.append(node.render(MutationContext(mutation)))
    return out


def test_iphc_truncated_dispatch_bytes_appear():
    """(d) a truncated-IPHC mutation carries the 0x60.. dispatch and is short.

    The frame must end right after the 2 IPHC dispatch bytes (no inline
    address bytes), which is the over-read trigger.
    """
    fuzzer = _build(_make_config(enabled_requests=["SixLoWPAN_IPHC_Truncated"]))
    node = _request_node(fuzzer, "SixLoWPAN_IPHC_Truncated")
    variants = _rendered_variants(node)
    # ZEP+MAC prefix is 32 + 9 = 41 bytes; a truncated frame is prefix + 2.
    assert any(len(v) == 43 for v in variants), [len(v) for v in variants]
    # The IPHC dispatch byte (0b011xxxxx, i.e. 0x60-0x7F) sits right after prefix.
    for v in variants:
        assert 0x60 <= v[41] <= 0x7F


def test_frag_dispatch_bytes_appear():
    """(d) FRAG1/FRAGN dispatch-only renders carry the 0xC0/0xE0 dispatch byte."""
    for name, lo, hi in (
        ("SixLoWPAN_FRAG1_DispatchOnly", 0xC0, 0xC7),
        ("SixLoWPAN_FRAGN_DispatchOnly", 0xE0, 0xE7),
    ):
        fuzzer = _build(_make_config(enabled_requests=[name]))
        node = _request_node(fuzzer, name)
        rendered = node.render()
        # prefix (41 bytes) + a single dispatch byte only.
        assert len(rendered) == 42, (name, len(rendered))
        assert lo <= rendered[41] <= hi, (name, hex(rendered[41]))


def test_longaddr_short_claims_ext_addressing():
    """(d) the 802.15.4 malformed frame sets the ext-addressing FCF nibble."""
    fuzzer = _build(_make_config(enabled_requests=["SixLoWPAN_802154_LongAddr_Short"]))
    node = _request_node(fuzzer, "SixLoWPAN_802154_LongAddr_Short")
    rendered = node.render()
    # ZEP header only is 32 bytes; MAC bytes follow. FCF wire low byte 0x41.
    assert rendered[32] == 0x41
    # High FCF byte carries the dst/src ext-addressing mode bits (0xC*).
    assert rendered[33] & 0xC0
