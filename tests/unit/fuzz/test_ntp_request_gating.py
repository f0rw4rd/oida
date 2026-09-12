"""
Offline tests for NTP per-request enable/disable gating.

The NTP fuzzer's _define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable (which
populate config.enabled_requests / disabled_requests) actually take effect.
These tests build the boofuzz session offline and inspect session.nodes to
verify which requests were connected, without any network I/O.

They also assert the advertised set (get_request_definitions, surfaced by
--list-requests) matches the connected set, so every fuzzable request is both
visible and individually selectable.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

# NTP_Auth_Request is advertised but only connected when enable_auth=True,
# so it is excluded from the default-run connected expectation.
AUTH_ONLY = {"NTP_Auth_Request"}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=123,
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
    fuzzer_class = PROTOCOL_FUZZERS["ntp"]
    if fuzzer_class is None:
        require_service("ntp fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["ntp"].get_request_definitions()}


def test_advertised_matches_connected_default():
    """Every advertised request (minus auth-only) is connected on a default run.

    This is the core of the finding: --list-requests must reflect the real fuzz
    surface, with no connected-but-hidden requests and no advertised-but-dead
    requests.
    """
    config = _make_config()
    connected = _connected_names(_build(config))

    expected = _advertised() - AUTH_ONLY
    assert connected == expected


def test_no_connected_request_is_unadvertised():
    """No request reachable by connect() is missing from get_request_definitions()."""
    config = _make_config()
    connected = _connected_names(_build(config))

    assert connected <= _advertised()


def test_enable_whitelists_single_request():
    """--enable NTP_Monlist_Attack connects only that request (CVE-2013-5211 scoping)."""
    config = _make_config(enabled_requests=["NTP_Monlist_Attack"])
    connected = _connected_names(_build(config))

    assert connected == {"NTP_Monlist_Attack"}


def test_disable_removes_named_request():
    """--disable NTP_Quick_Coverage connects everything except that request."""
    config = _make_config(disabled_requests=["NTP_Quick_Coverage"])
    connected = _connected_names(_build(config))

    assert "NTP_Quick_Coverage" not in connected
    # A non-disabled request from the default run is still present.
    assert "NTP_Monlist_Attack" in connected


def test_newly_registered_requests_are_selectable():
    """The 7 previously-hidden requests are now advertised and individually enableable."""
    newly_registered = {
        "NTP_Quick_Coverage",
        "NTP_Extension_Overflow",
        "NTP_Crypto_NAK_Attack",
        "NTP_Monlist_Attack",
        "NTP_Trap_Attack",
        "NTP_Reference_ID_Boundary",
        "NTP_Timestamp_Fraction_Boundary",
    }
    assert newly_registered <= _advertised()

    for name in newly_registered:
        config = _make_config(enabled_requests=[name])
        connected = _connected_names(_build(config))
        assert connected == {name}, f"{name} not individually selectable"
