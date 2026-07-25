"""Offline tests for the TASE.2 / ICCP (IEC 60870-6) fuzzer.

TASE.2 rides ISO 9506 MMS over the OSI stack on TCP/102, so the TASE2Fuzzer
reuses the shared MMS codec and OSI/COTP/BER framing and layers ICCP-specific
named-object malformations (Bilateral Table, Transfer-Set objects) on top of
the MMS/BER decode paths (CVE-2014-2357 ICCP parser DoS class).

Like the IPv6 gating regression guard, the fuzzer wraps every session.connect()
behind ``self.is_request_enabled("<Name>")`` where the advertised RequestInfo
name equals the connected boofuzz Request node name (strict 1:1). These tests
build the boofuzz session offline with MockConnectionFactory and inspect
session.nodes - no network I/O.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.tase2 import TASE2Fuzzer

pytestmark = pytest.mark.core

ALL_REQUESTS = {
    "TASE2_Baseline",
    "TASE2_BER_Length_Attack",
    "TASE2_ObjectName_Overflow",
    "TASE2_TransferSet_Malformed",
    "TASE2_InvokeID_Boundary",
    "TASE2_BilateralTable_Malformed",
    "TASE2_MMS_Service_Boundary",
}

EXPECTED_CATEGORIES = {
    "TASE2_Baseline": "baseline",
    "TASE2_BER_Length_Attack": "malformed",
    "TASE2_ObjectName_Overflow": "overflow",
    "TASE2_TransferSet_Malformed": "malformed",
    "TASE2_InvokeID_Boundary": "boundary",
    "TASE2_BilateralTable_Malformed": "malformed",
    "TASE2_MMS_Service_Boundary": "boundary",
}


def _make_config(**overrides):
    # Mirror test_ipv6_request_gating._make_config; TASE.2 is a TCP protocol.
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=102,
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
    return TASE2Fuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of Request nodes actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in TASE2Fuzzer.get_request_definitions()}


def _node(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node
    raise AssertionError(f"request node {name!r} not connected")


# ---------------------------------------------------------------------------
# Advertising / categories
# ---------------------------------------------------------------------------
def test_seven_requests_advertised():
    """All seven TASE.2 requests appear in --list-requests."""
    assert _advertised() == ALL_REQUESTS
    assert len(TASE2Fuzzer.get_request_definitions()) == 7


def test_categories_are_the_four_expected_buckets():
    """Categories are drawn only from {baseline, overflow, boundary, malformed}."""
    cats = {d.name: d.category for d in TASE2Fuzzer.get_request_definitions()}
    assert cats == EXPECTED_CATEGORIES
    assert set(cats.values()) == {"baseline", "overflow", "boundary", "malformed"}


def test_default_monitors_mirror_mms():
    """DEFAULT_MONITORS mirrors the MMS fuzzer (mms identify probe every 10 cases)."""
    assert TASE2Fuzzer.DEFAULT_MONITORS == "mms:10"


def test_tcp_protocol_and_port_102():
    """TASE.2 forces TCP and targets ISO-TSAP port 102."""
    fuzzer = _build(_make_config())
    assert fuzzer.config.protocol_type == ProtocolType.TCP
    assert fuzzer.config.target_port == 102


# ---------------------------------------------------------------------------
# Strict 1:1 gating
# ---------------------------------------------------------------------------
def test_default_run_advertised_equals_connected():
    """Under default flags every advertised request is connected, and nothing else is."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ALL_REQUESTS


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_individually_selectable(name):
    """--enable <name> connects exactly that one request (proves it is gated 1:1)."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes exactly that request, leaving the rest connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == ALL_REQUESTS - {name}


# ---------------------------------------------------------------------------
# Rendering / malformation content
# ---------------------------------------------------------------------------
def test_all_requests_render_without_error():
    """Every connected request renders to a non-empty payload."""
    fuzzer = _build(_make_config())
    for name in ALL_REQUESTS:
        assert len(_node(fuzzer, name).render()) > 0


def test_ber_length_attack_has_long_form_length_octet():
    """The BER length attack renders a long-form BER length octet (0x81/0x82/0x84).

    Long-form length (top bit set in the length octet) is the crux of the
    CVE-2014-2357 ICCP-parser-DoS class: an over-declared / truncated length
    drives the MMS/BER decoder past the buffer.
    """
    fuzzer = _build(_make_config())
    rendered = _node(fuzzer, "TASE2_BER_Length_Attack").render()
    assert any(octet in rendered for octet in (0x81, 0x82, 0x83, 0x84)), rendered.hex()
    # Default render selects the first Group value: 0xA0 0x84 0xFF 0xFF 0xFF 0xFF.
    assert b"\xa0\x84\xff\xff\xff\xff" in rendered


def test_baseline_carries_mms_initiate_and_cotp_framing():
    """Baseline reuses the MMS codec/OSI stack: TPKT header + MMS Initiate tag present."""
    fuzzer = _build(_make_config())
    rendered = _node(fuzzer, "TASE2_Baseline").render()
    # TPKT version 0x03 0x00 at the very front (OSI framing reused from MMS).
    assert rendered[:2] == b"\x03\x00"
    # MMS Initiate-RequestPDU tag [8] = 0xA8 appears inside the association packet.
    assert b"\xa8" in rendered
