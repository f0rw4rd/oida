"""
Offline tests for VNC request advertise-vs-connect parity and gating.

The VNC fuzzer's get_request_definitions() advertises 15 named requests for
--list-requests / --enable. Every advertised name must be backed by a
session.connect() gated under is_request_enabled("<name>"), otherwise
--list-requests lies and --enable/--disable have no effect.

Regression guard for CODE_REVIEW.md:
  src/oida/fuzz/protocols/vnc.py:698-704,878-886 - _define_preauth_protocol() and
  _define_postauth_protocol() connected every request unconditionally (no
  is_request_enabled gates), so --enable/--disable were silently ignored.

VNC splits its advertised requests across two mutually exclusive flows selected
by the use_auth option:
  * use_auth=False -> _define_preauth_protocol() (version/security handshake)
  * use_auth=True  -> _define_postauth_protocol() (post-auth client messages)
Both flows are chains: a downstream request can only be reached through its
prerequisite path nodes, so enabling a leaf also connects its prerequisites
(the same pattern smtp.py uses for its HELO prerequisite).

The session is built offline (no live device) via the lazy `.session` property.
"""

import inspect
import re

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

# Advertised names that belong to each flow (split by requires_state lifecycle).
PREAUTH_NAMES = {
    "StaticProtocolVersion",
    "ProtocolVersionDynVersion",
    "ProtocolVersionDynAll",
    "SecurityTypeSelection",
    "SecurityTypeResponse",
    "VNCAuth",
    "MalformedMessages",
}
POSTAUTH_NAMES = {
    "ClientInit",
    "SetPixelFormat",
    "SetEncodings",
    "FramebufferUpdateRequest",
    "KeyEvent",
    "PointerEvent",
    "VNC_Overflow",
    "VNC_Boundary",
}


def _make_config(use_auth, **overrides):
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
    config.protocol_options = {"use_auth": use_auth}
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build(config):
    fuzzer_class = PROTOCOL_FUZZERS["vnc"]
    if fuzzer_class is None:
        require_service("vnc fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["vnc"].get_request_definitions()}


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _gated_names():
    """Names passed to is_request_enabled() across both flow definitions."""
    cls = PROTOCOL_FUZZERS["vnc"]
    source = "".join(
        inspect.getsource(getattr(cls, method))
        for method in ("_define_preauth_protocol", "_define_postauth_protocol")
    )
    return set(re.findall(r'is_request_enabled\(\s*"([^"]+)"\s*\)', source))


def test_advertised_split_covers_all_requests():
    """The preauth/postauth name split accounts for every advertised request."""
    assert PREAUTH_NAMES | POSTAUTH_NAMES == _advertised_names()
    assert PREAUTH_NAMES.isdisjoint(POSTAUTH_NAMES)


def test_every_advertised_request_is_gated():
    """Every advertised name must gate its connect() via is_request_enabled().

    Regression guard: both flows previously connected all requests
    unconditionally, so --enable/--disable had no effect.
    """
    ungated = _advertised_names() - _gated_names()
    assert not ungated, f"Advertised requests not gated by is_request_enabled: {sorted(ungated)}"


def test_postauth_default_connects_postauth_flow():
    """use_auth=True default run connects exactly the post-auth requests."""
    connected = _connected_names(_build(_make_config(use_auth=True)))
    assert connected == POSTAUTH_NAMES


def test_preauth_default_connects_preauth_flow():
    """use_auth=False default run connects exactly the pre-auth requests."""
    connected = _connected_names(_build(_make_config(use_auth=False)))
    assert connected == PREAUTH_NAMES


def test_enable_leaf_pulls_in_prerequisites_only():
    """--enable KeyEvent connects KeyEvent plus its prerequisite path, nothing else.

    Regression guard: previously --enable was ignored and all 8 post-auth
    requests connected. The leaf is only reachable through SetPixelFormat ->
    SetEncodings, so those prerequisites connect too, but no sibling leaves.
    """
    connected = _connected_names(_build(_make_config(use_auth=True, enabled_requests=["KeyEvent"])))
    assert connected == {"ClientInit", "SetPixelFormat", "SetEncodings", "KeyEvent"}


def test_enable_root_connects_only_root():
    """--enable ClientInit connects only the chain root."""
    connected = _connected_names(
        _build(_make_config(use_auth=True, enabled_requests=["ClientInit"]))
    )
    assert connected == {"ClientInit"}


def test_disable_leaf_removes_only_that_leaf():
    """--disable KeyEvent drops only KeyEvent from the otherwise-full post-auth run."""
    full = _connected_names(_build(_make_config(use_auth=True)))
    disabled = _connected_names(_build(_make_config(use_auth=True, disabled_requests=["KeyEvent"])))
    assert disabled == full - {"KeyEvent"}


def test_preauth_enable_independent_root():
    """--enable ProtocolVersionDynAll (an independent pre-auth root) connects only it."""
    connected = _connected_names(
        _build(_make_config(use_auth=False, enabled_requests=["ProtocolVersionDynAll"]))
    )
    assert connected == {"ProtocolVersionDynAll"}
