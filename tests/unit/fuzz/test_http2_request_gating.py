"""
Offline tests for HTTP/2 request advertise-vs-connect parity.

The HTTP/2 fuzzer's get_request_definitions() advertises a set of named
request groups for --list-requests / --enable / --disable. Every request the
fuzzer wires into the boofuzz session (apart from the mandatory connection
preface) must be gated by is_request_enabled("<advertised-name>"); otherwise
--enable/--disable cannot reach it.

Regression guard for CODE_REVIEW.md:
  src/oida/fuzz/protocols/http2.py:1196,1208,1232,1264,1275 - the ping,
  window_update, rst_stream, settings_variations and settings_ack requests
  were connected unconditionally (no is_request_enabled gate), so they ran on
  every campaign regardless of --enable/--disable and could not be turned off.
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
        protocol_type=ProtocolType.TCP,
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
    fuzzer_class = PROTOCOL_FUZZERS.get("http2")
    if fuzzer_class is None:
        pytest.skip("http2 fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["http2"].get_request_definitions()}


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _gated_names():
    """Names passed to is_request_enabled() across the request-defining methods.

    Content-payload groups are gated in _define_content_payloads(), which
    _define_protocol() dispatches to, so both sources must be scanned.
    """
    cls = PROTOCOL_FUZZERS["http2"]
    source = inspect.getsource(cls._define_protocol)
    source += inspect.getsource(cls._define_content_payloads)
    return set(re.findall(r'is_request_enabled\(\s*"([^"]+)"\s*\)', source))


# Frame requests that the fix moved behind a gate; their boofuzz node names
# (lowercase) and the advertised group that now controls them.
_FORMERLY_UNGATED = {
    "http2_ping": "HTTP2_Ping",
    "http2_window_update": "HTTP2_Window_Attack",
    "http2_rst_stream": "HTTP2_Rst_Stream",
    "http2_settings_variations": "HTTP2_Settings_Attack",
    "http2_settings_ack": "HTTP2_Settings_Attack",
}


def test_advertised_groups_are_all_gated():
    """Every advertised group is reachable via an is_request_enabled() gate."""
    advertised = _advertised_names()
    gated = _gated_names()
    ungated = advertised - gated
    assert not ungated, f"Advertised groups never gated: {sorted(ungated)}"


def test_ping_and_rst_stream_are_advertised():
    """The two new standalone groups appear in --list-requests."""
    advertised = _advertised_names()
    assert "HTTP2_Ping" in advertised
    assert "HTTP2_Rst_Stream" in advertised


def test_formerly_ungated_requests_are_disableable():
    """--disable <group> now suppresses each previously-unconditional request.

    Regression guard: before the fix these five requests were connected with no
    gate, so disabling their group left them running.
    """
    full = _connected_names(_build(_make_config()))
    for node_name, group in _FORMERLY_UNGATED.items():
        assert node_name in full, f"{node_name} missing from default run"

    for node_name, group in _FORMERLY_UNGATED.items():
        disabled = _connected_names(_build(_make_config(disabled_requests=[group])))
        assert node_name not in disabled, f"--disable {group} failed to suppress {node_name}"


def test_enable_scopes_out_formerly_ungated_requests():
    """--enable a narrow group must not drag in the five formerly-ungated frames."""
    connected = _connected_names(_build(_make_config(enabled_requests=["HTTP2_Quick_Coverage"])))
    for node_name in _FORMERLY_UNGATED:
        assert node_name not in connected, (
            f"{node_name} leaked into --enable HTTP2_Quick_Coverage run"
        )
