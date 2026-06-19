"""
Offline tests for ICMPv6 per-request enable/disable gating.

The ICMPv6 fuzzer's _define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable (which
populate config.enabled_requests / disabled_requests) actually take effect.
These tests build the boofuzz session offline and inspect session.nodes to
verify which requests were connected, without any network I/O.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="::1",
        target_port=0,
        protocol_type=ProtocolType.ICMPV6,
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
    fuzzer_class = PROTOCOL_FUZZERS["icmpv6"]
    if fuzzer_class is None:
        pytest.skip("icmpv6 fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def test_enable_whitelists_single_request():
    """--enable ICMPv6_Echo_Request connects only that request."""
    config = _make_config(enabled_requests=["ICMPv6_Echo_Request"])
    connected = _connected_names(_build(config))

    assert connected == {"ICMPv6_Echo_Request"}


def test_disable_removes_named_request():
    """--disable ICMPv6_Smurf_Echo connects everything except that request."""
    config = _make_config(disabled_requests=["ICMPv6_Smurf_Echo"])
    connected = _connected_names(_build(config))

    assert "ICMPv6_Smurf_Echo" not in connected
    # A non-disabled request from the default run is still present.
    assert "ICMPv6_Quick_Coverage" in connected


def test_default_run_connects_everything():
    """No --enable/--disable: all advertised requests connect under default flags.

    enable_cve_tests defaults True and attack_mode defaults "normal", so every
    request in get_request_definitions() must have a backing Request that is
    wired up. This asserts advertised == connected with no phantom: every name
    in --list-requests resolves to a real connected Request and vice versa.
    """
    config = _make_config()
    connected = _connected_names(_build(config))

    advertised = {d.name for d in PROTOCOL_FUZZERS["icmpv6"].get_request_definitions()}

    # No advertised-but-never-built phantom (regression: ICMPv6_Hop_Limit_Boundary).
    assert advertised - connected == set(), f"advertised but not connected: {advertised - connected}"
    # No connected request that was never advertised.
    assert connected - advertised == set(), f"connected but not advertised: {connected - advertised}"
    assert connected == advertised


def test_hop_limit_boundary_is_connected():
    """ICMPv6_Hop_Limit_Boundary is advertised AND builds/connects a real Request."""
    config = _make_config(enabled_requests=["ICMPv6_Hop_Limit_Boundary"])
    connected = _connected_names(_build(config))

    assert connected == {"ICMPv6_Hop_Limit_Boundary"}
