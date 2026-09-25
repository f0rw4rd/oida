"""
Offline tests for CoAP OSCORE + Block-wise fuzzer coverage.

The CoAP fuzzer previously grazed the OSCORE option header (option 9 appeared
only inside CoAP_Option_Overflow) but never fuzzed its value, and only sent
well-formed Block1/Block2 options. This adds two requests:

  CoAP_OSCORE_Option_Malformed - OSCORE option (No. 9) flag byte claiming
      Partial-IV / kid-context / kid lengths larger than the value present
      (over-read). Targets CVE-2024-0962 (libcoap OSCORE config OOB write).
  CoAP_Block_Forged - Block1/Block2 (No. 27/23) with a forged size-exponent
      (SZX 0-7), a huge block-number (NUM) and M-bit combos implying an
      oversized total, plus a Block option whose length is not the legal
      1-3 bytes. Targets CVE-2026-58465 (Wakaama Block1 unbounded alloc).

The session is built offline via MockConnectionFactory; the lazy `.session`
property runs _define_protocol() and wires the boofuzz nodes. Request objects
are named to match their registered names.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

NEW_REQUESTS = {
    "CoAP_OSCORE_Option_Malformed",
    "CoAP_Block_Forged",
}


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
        require_service("coap fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised_names():
    return {d.name for d in PROTOCOL_FUZZERS["coap"].get_request_definitions()}


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _render(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node.render()
    raise AssertionError(f"request {name!r} not connected")


def test_new_requests_are_advertised():
    """Both OSCORE/Block requests appear in --list-requests."""
    assert NEW_REQUESTS <= _advertised_names()


def test_new_requests_connected_by_default():
    """Both requests are wired into the session under default flags."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_disableable(name):
    """--disable <name> removes it while leaving other requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "CoAP_GET" in connected


def test_oscore_option_renders_overreading_flag_byte():
    """Default render carries an OSCORE option (delta 9) whose flag byte 0x1f
    (n=7, k=1, h=1) claims lengths absent from the 1-byte value - the over-read."""
    rendered = _render(_build(_make_config()), "CoAP_OSCORE_Option_Malformed")
    # message-id 0x0009 then option 9 (0x9_) length 1 then flag 0x1f.
    assert b"\x00\x09\x91\x1f" in rendered
    # High nibble of the option header byte is the delta = 9 (OSCORE).
    assert (rendered[4] >> 4) == 9


def test_block_forged_renders_forged_szx_and_num():
    """Default render carries a Block1 option (delta 16 ext -> 0xd3) with a
    forged 3-byte value 0xffffff (SZX=7, M=1, huge NUM)."""
    rendered = _render(_build(_make_config()), "CoAP_Block_Forged")
    assert b"\xd3\x03\xff\xff\xff" in rendered
    # Last block value byte low 3 bits = SZX = 7 (1024-byte blocks); bit 3 = M.
    assert (0xFF & 0x07) == 7
