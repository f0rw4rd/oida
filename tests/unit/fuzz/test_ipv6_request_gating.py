"""
Offline tests for IPv6 per-request enable/disable gating.

The IPv6 fuzzer's _define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable (which
populate config.enabled_requests / disabled_requests) actually take effect.
These tests build the boofuzz session offline and inspect session.nodes to
verify which requests were connected, without any network I/O.

Regression guard for the finding "three requests connected but never
registered in get_request_definitions (invisible to --list-requests, two
ungated)": IPv6_Quick_Coverage, IPv6_Quick_ICMPv6_Types and
IPv6_Incorrect_Length must be advertised AND individually selectable.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from oida.fuzz.core.connections import MockConnectionFactory

pytestmark = pytest.mark.core

# Advertised requests that have no backing connect() under default flags
# (they only build when include_extensions / dhcpv6_mode are enabled).
DEFAULT_UNCONNECTED = {
    "IPv6_Hop_by_Hop",
    "IPv6_Routing",
    "IPv6_Extension_Chain",
    "IPv6_Fragment",
    "IPv6_DHCPv6_Solicit",
}

# The three previously-invisible requests this finding is about.
PREVIOUSLY_INVISIBLE = {
    "IPv6_Quick_Coverage",
    "IPv6_Quick_ICMPv6_Types",
    "IPv6_Incorrect_Length",
}

# Black-box malformation techniques (AMNESIA:33 / RFC 6946 classes). These
# build unconditionally, so they are advertised, individually gated, AND
# connected under default flags.
BLACKBOX_TECHNIQUES = {
    "IPv6_HBH_ZeroLen_Option_Loop",
    "IPv6_HBH_Option_Len_OverRead",
    "IPv6_Atomic_Fragment",
    "IPv6_ND_Option_ZeroLen",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="::1",
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


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _build(config):
    fuzzer_class = PROTOCOL_FUZZERS["ipv6"]
    if fuzzer_class is None:
        pytest.skip("ipv6 fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["ipv6"].get_request_definitions()}


def test_three_previously_invisible_requests_are_advertised():
    """The three connected-but-unregistered requests now appear in --list-requests."""
    assert PREVIOUSLY_INVISIBLE <= _advertised()


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags.

    Every advertised request that has a backing connect() under default flags
    is wired up, and nothing is connected that is not advertised. Requests that
    only build under include_extensions / dhcpv6_mode are excluded.
    """
    connected = _connected_names(_build(_make_config()))
    expected = _advertised() - DEFAULT_UNCONNECTED

    assert connected == expected
    # No request is connected without being advertised (the original bug).
    assert connected <= _advertised()


@pytest.mark.parametrize("name", sorted(PREVIOUSLY_INVISIBLE))
def test_each_previously_invisible_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(PREVIOUSLY_INVISIBLE))
def test_each_previously_invisible_request_is_disableable(name):
    """--disable <name> removes it while leaving other default requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    # Sanity: other default-connected requests survive the disable.
    assert "IPv6_Basic" in connected


def test_blackbox_techniques_are_advertised():
    """The four AMNESIA:33 / RFC 6946 techniques appear in --list-requests."""
    assert BLACKBOX_TECHNIQUES <= _advertised()


def test_blackbox_techniques_connected_by_default():
    """All four black-box techniques are wired up under default flags."""
    connected = _connected_names(_build(_make_config()))
    assert BLACKBOX_TECHNIQUES <= connected


@pytest.mark.parametrize("name", sorted(BLACKBOX_TECHNIQUES))
def test_each_blackbox_technique_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(BLACKBOX_TECHNIQUES))
def test_each_blackbox_technique_is_disableable(name):
    """--disable <name> removes it while leaving other default requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "IPv6_Basic" in connected
