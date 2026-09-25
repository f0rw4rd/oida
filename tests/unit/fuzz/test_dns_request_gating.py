"""
Offline tests for DNS request advertise-vs-connect parity and gating.

The DNS fuzzer's get_request_definitions() advertises 68 named requests for
--list-requests / --enable. Every advertised name must be backed by a
session.connect() gated under is_request_enabled("<name>"), otherwise
--list-requests lies and --enable/--disable have no effect.

Regression guard: _define_protocol() connected all 64
requests unconditionally (no is_request_enabled gates), so a user asking to run
only DNS_A_QUERY still got all 64 requests.

The session is built offline (no live device) via the lazy `.session` property,
which calls _define_protocol() and wires the boofuzz nodes.
"""

import inspect
import re

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=0,
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
    fuzzer_class = PROTOCOL_FUZZERS["dns"]
    if fuzzer_class is None:
        require_service("dns fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["dns"].get_request_definitions()}


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _gated_names():
    """Names passed to is_request_enabled() inside _define_protocol()."""
    source = inspect.getsource(PROTOCOL_FUZZERS["dns"]._define_protocol)
    return set(re.findall(r'is_request_enabled\(\s*"([^"]+)"\s*\)', source))


def test_advertised_matches_connected_by_default():
    """Under default (no --enable/--disable) every advertised request connects,
    and nothing connects that is not advertised."""
    advertised = _advertised_names()
    connected = _connected_names(_build(_make_config()))
    assert connected == advertised


def test_every_advertised_request_is_gated():
    """Every advertised name must gate its connect() via is_request_enabled().

    Regression guard: _define_protocol() previously connected all 64 requests
    unconditionally, so --enable/--disable had no effect.
    """
    advertised = _advertised_names()
    gated = _gated_names()
    ungated = advertised - gated
    assert not ungated, f"Advertised requests not gated by is_request_enabled: {sorted(ungated)}"


def test_enable_whitelists_single_request():
    """--enable DNS_A_QUERY connects only that request (the flag actually works)."""
    connected = _connected_names(_build(_make_config(enabled_requests=["DNS_A_QUERY"])))
    assert connected == {"DNS_A_QUERY"}


def test_disable_suppresses_single_request():
    """--disable DNS_CACHE_POISONING removes it from the otherwise-full run."""
    full = _connected_names(_build(_make_config()))
    assert "DNS_CACHE_POISONING" in full

    disabled = _connected_names(_build(_make_config(disabled_requests=["DNS_CACHE_POISONING"])))
    assert "DNS_CACHE_POISONING" not in disabled
    assert disabled == full - {"DNS_CACHE_POISONING"}


# NAME:WRECK-class techniques added on top of the original 64.
NAMEWRECK_REQUESTS = [
    "DNS_RDLength_Underflow",
    "DNS_Pointer_Forward",
    "DNS_Pointer_Past_Packet",
    "DNS_Name_Over_255",
]


@pytest.mark.parametrize("name", NAMEWRECK_REQUESTS)
def test_namewreck_request_advertised(name):
    """Each NAME:WRECK technique is advertised via get_request_definitions()."""
    assert name in _advertised_names()


@pytest.mark.parametrize("name", NAMEWRECK_REQUESTS)
def test_namewreck_request_gated(name):
    """Each NAME:WRECK technique gates its connect() via is_request_enabled()."""
    assert name in _gated_names()


@pytest.mark.parametrize("name", NAMEWRECK_REQUESTS)
def test_namewreck_request_individually_selectable(name):
    """--enable <name> connects only that NAME:WRECK request."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}
