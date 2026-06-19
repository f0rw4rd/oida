"""
Offline tests for CoAP request advertise-vs-connect parity and gating.

The CoAP fuzzer's get_request_definitions() advertises a set of named requests
for --list-requests / --enable. Every advertised name must be backed by a
session.connect() gated under is_request_enabled("<name>"), otherwise
--list-requests lies and --enable/--disable have no effect.

Regression guard for CODE_REVIEW.md:
  src/oida/fuzz/protocols/coap.py:159-714 - _define_protocol() connected all 21
  requests unconditionally (no is_request_enabled gates, so --enable/--disable
  were ignored), and the connected "CoAP_Cache_Control" request was missing from
  get_request_definitions() (invisible to --list-requests).

The session is built offline (no live device) via the lazy `.session` property,
which calls _define_protocol() and wires the boofuzz nodes.
"""

import inspect
import re

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

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
    fuzzer_class = PROTOCOL_FUZZERS["coap"]
    if fuzzer_class is None:
        pytest.skip("coap fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["coap"].get_request_definitions()}


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _gated_names():
    """Names passed to is_request_enabled() inside _define_protocol()."""
    source = inspect.getsource(PROTOCOL_FUZZERS["coap"]._define_protocol)
    return set(re.findall(r'is_request_enabled\(\s*"([^"]+)"\s*\)', source))


def test_cache_control_is_advertised():
    """CoAP_Cache_Control is connected and must also be advertised.

    Regression guard: it was connected at the tail of _define_protocol but
    absent from get_request_definitions(), so --list-requests showed 20 of 21.
    """
    assert "CoAP_Cache_Control" in _advertised_names()


def test_advertised_matches_connected_by_default():
    """Under default (no --enable/--disable) every advertised request connects,
    and nothing connects that is not advertised."""
    advertised = _advertised_names()
    connected = _connected_names(_build(_make_config()))
    assert connected == advertised


def test_every_advertised_request_is_gated():
    """Every advertised name must gate its connect() via is_request_enabled().

    Regression guard: _define_protocol() previously connected all requests
    unconditionally, so --enable/--disable had no effect.
    """
    advertised = _advertised_names()
    gated = _gated_names()
    ungated = advertised - gated
    assert not ungated, f"Advertised requests not gated by is_request_enabled: {sorted(ungated)}"


def test_enable_whitelists_single_request():
    """--enable CoAP_GET connects only that request."""
    connected = _connected_names(_build(_make_config(enabled_requests=["CoAP_GET"])))
    assert connected == {"CoAP_GET"}


def test_disable_suppresses_single_request():
    """--disable CoAP_Cache_Control removes it from the otherwise-full run."""
    full = _connected_names(_build(_make_config()))
    assert "CoAP_Cache_Control" in full

    disabled = _connected_names(
        _build(_make_config(disabled_requests=["CoAP_Cache_Control"]))
    )
    assert "CoAP_Cache_Control" not in disabled
    assert disabled == full - {"CoAP_Cache_Control"}
