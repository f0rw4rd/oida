"""
Offline tests for EtherNet/IP request advertise-vs-connect parity.

The EtherNet/IP fuzzer's get_request_definitions() advertises a set of named
requests for --list-requests / --enable. Every advertised name must be backed
by something the fuzzer actually wires into the boofuzz session under
is_request_enabled("<name>") - otherwise --list-requests lies and
--enable <name> fuzzes nothing (a "phantom" request).

These tests build the boofuzz session offline (no live device; the
RegisterSession handshake in _define_state_machine fails fast and falls through)
and inspect which advertised names are live.

Regression guard for CODE_REVIEW.md:
  src/oida/fuzz/protocols/ethernetip.py:179 - EIP_CIP_Boundary was advertised
  but never built or connected.
"""

import inspect

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
    # Enable the option-gated request groups so every advertised group
    # connects under default --enable/--disable (no whitelist/blacklist).
    config.protocol_options = {"enable_write": True, "enable_auth": True}
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build(config):
    fuzzer_class = PROTOCOL_FUZZERS["ethernetip"]
    if fuzzer_class is None:
        pytest.skip("ethernetip fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["ethernetip"].get_request_definitions()}


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _gated_names():
    """Names passed to is_request_enabled() inside _define_protocol()."""
    import re

    source = inspect.getsource(PROTOCOL_FUZZERS["ethernetip"]._define_protocol)
    return set(re.findall(r'is_request_enabled\(\s*"([^"]+)"\s*\)', source))


def test_no_phantom_request_definitions():
    """Every advertised request must be live: it either gates a session.connect()
    via is_request_enabled("<name>"), or is itself a connected boofuzz Request.

    EIP_CIP_Boundary regressed here: advertised, but neither gated nor connected.
    """
    advertised = _advertised_names()
    connected = _connected_names(_build(_make_config()))
    gated = _gated_names()

    live = gated | connected
    phantoms = advertised - live

    assert not phantoms, (
        f"Phantom request(s) advertised but never gated or connected: {sorted(phantoms)}"
    )


def test_eip_cip_boundary_is_gone():
    """Explicit regression guard for the removed phantom."""
    assert "EIP_CIP_Boundary" not in _advertised_names()


def test_enable_whitelists_single_request():
    """--enable EIP_Baseline connects only that group's requests (no phantom leaks)."""
    config = _make_config(enabled_requests=["EIP_Baseline"])
    connected = _connected_names(_build(config))

    # EIP_Baseline wires the quick-coverage requests. CIP_Class_Enumeration is
    # its own advertised group and must NOT ride along under EIP_Baseline.
    assert connected == {
        "Quick_EIP_Coverage",
        "Quick_CIP_Coverage",
    }


def test_cip_class_enumeration_independently_selectable():
    """CIP_Class_Enumeration has its own gate, decoupled from EIP_Baseline.

    Regression guard for CODE_REVIEW.md ethernetip.py:210-215: the
    cip_class_enumeration request was connected inside the EIP_Baseline gate,
    so --enable CIP_Class_Enumeration ran nothing and --disable
    CIP_Class_Enumeration could not suppress it.
    """
    # --enable CIP_Class_Enumeration alone connects exactly that request.
    enabled = _connected_names(_build(_make_config(enabled_requests=["CIP_Class_Enumeration"])))
    assert enabled == {"CIP_Class_Enumeration"}

    # --enable EIP_Baseline alone must NOT pull in CIP_Class_Enumeration.
    baseline = _connected_names(_build(_make_config(enabled_requests=["EIP_Baseline"])))
    assert "CIP_Class_Enumeration" not in baseline

    # --disable CIP_Class_Enumeration suppresses it from the full default run.
    not_disabled = _connected_names(_build(_make_config()))
    assert "CIP_Class_Enumeration" in not_disabled
    disabled = _connected_names(_build(_make_config(disabled_requests=["CIP_Class_Enumeration"])))
    assert "CIP_Class_Enumeration" not in disabled
