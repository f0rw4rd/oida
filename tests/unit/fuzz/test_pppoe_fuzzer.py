"""Offline tests for the PPP/PPPoE (with EAP) fuzzer.

PPPoEFuzzer wires every session.connect() under
`self.is_request_enabled("<RegisteredName>")` using a strict 1:1 convention
(RequestInfo.name == Request node name), so --enable / --disable (which
populate config.enabled_requests / disabled_requests) actually take effect.

These build the boofuzz session offline via MockConnectionFactory and inspect
session.nodes -- no network I/O. Mirrors test_ipv6_request_gating's
_make_config flags and ProtocolType.RAW (same raw L2 type the Ethernet fuzzer
uses).

The class is imported directly (central registration in protocols/__init__.py
is handled separately) so these tests do not depend on PROTOCOL_FUZZERS.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.pppoe import PPPoEFuzzer

pytestmark = pytest.mark.core

# All seven advertised requests build unconditionally under default flags,
# so advertised == connected with nothing extra.
ALL_REQUESTS = {
    "PPPoE_Baseline",
    "PPPoE_EAP_MD5_Name_Overflow",
    "PPPoE_EAP_TLS_Len_Underflow",
    "PPPoE_LCP_Option_ZeroLen",
    "PPPoE_IPCP_Option_Len",
    "PPPoE_Discovery_Tag_Len",
    "PPPoE_Session_Length_Lie",
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
    return PPPoEFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in PPPoEFuzzer.get_request_definitions()}


def _render(fuzzer, name):
    """Render the (non-mutated) bytes of a connected request node by name."""
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node.render()
    raise AssertionError(f"request {name!r} not connected in session")


def test_uses_raw_protocol_type():
    """The fuzzer forces ProtocolType.RAW like the Ethernet L2 fuzzer."""
    fuzzer = _build(_make_config())
    assert fuzzer.config.protocol_type == ProtocolType.RAW


def test_all_seven_requests_advertised():
    """--list-requests exposes exactly the seven PPPoE requests."""
    assert _advertised() == ALL_REQUESTS


def test_request_categories():
    """Each advertised request carries the expected category."""
    cats = {d.name: d.category for d in PPPoEFuzzer.get_request_definitions()}
    assert cats == {
        "PPPoE_Baseline": "baseline",
        "PPPoE_EAP_MD5_Name_Overflow": "overflow",
        "PPPoE_EAP_TLS_Len_Underflow": "malformed",
        "PPPoE_LCP_Option_ZeroLen": "malformed",
        "PPPoE_IPCP_Option_Len": "boundary",
        "PPPoE_Discovery_Tag_Len": "malformed",
        "PPPoE_Session_Length_Lie": "boundary",
    }


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags; nothing extra."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ALL_REQUESTS


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that one request (proves gating)."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> drops it while the rest stay connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "PPPoE_Baseline" in connected or name == "PPPoE_Baseline"


def test_eap_md5_overflow_renders_long_a_run():
    """CVE-2020-8597: the EAP-Request/MD5 request carries a long 'A' peer-name.

    The first Group mutant renders the 64-byte name; assert a long contiguous
    run of 0x41 is present (the stack-overflow write primitive) along with the
    EAP MD5 type byte (0x04) and EAP protocol field (0xC227).
    """
    fuzzer = _build(_make_config(enabled_requests=["PPPoE_EAP_MD5_Name_Overflow"]))
    rendered = _render(fuzzer, "PPPoE_EAP_MD5_Name_Overflow")
    assert b"A" * 64 in rendered
    assert b"\xc2\x27" in rendered  # PPP protocol = EAP
    assert b"\x04" in rendered  # EAP type = MD5-Challenge


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
