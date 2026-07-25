"""Offline tests for the KNXnet/IP fuzzer (UDP/3671).

Mirrors test_ipv6_request_gating: builds the boofuzz session offline via
MockConnectionFactory and inspects session.nodes to verify strict 1:1
per-request enable/disable gating without any network I/O.

Motivating CVEs:
  - CVE-2021-37740: KNXnet/IP Secure SESSION_REQUEST TotalLength-lie DoS.
  - CVE-2019-6840: KNX server malformed CONNECT_REQUEST / cEMI handling (RCE).
"""

import struct

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.knx import KNXFuzzer

pytestmark = pytest.mark.core

ALL_REQUESTS = {
    "KNX_Baseline",
    "KNX_TotalLength_Lie",
    "KNX_HPAI_StructLen_Overflow",
    "KNX_ServiceType_Boundary",
    "KNX_Connect_CRI_Malformed",
    "KNX_cEMI_Truncated",
    "KNX_HeaderLength_Boundary",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=3671,
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
    return KNXFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in KNXFuzzer.get_request_definitions()}


def _node(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node
    raise KeyError(name)


def test_default_monitor_is_ping():
    assert KNXFuzzer.DEFAULT_MONITORS == "ping"


def test_seven_requests_advertised():
    assert _advertised() == ALL_REQUESTS
    assert len(KNXFuzzer.get_request_definitions()) == 7


def test_request_categories():
    cats = {d.name: d.category for d in KNXFuzzer.get_request_definitions()}
    assert cats == {
        "KNX_Baseline": "baseline",
        "KNX_TotalLength_Lie": "malformed",
        "KNX_HPAI_StructLen_Overflow": "overflow",
        "KNX_ServiceType_Boundary": "boundary",
        "KNX_Connect_CRI_Malformed": "malformed",
        "KNX_cEMI_Truncated": "malformed",
        "KNX_HeaderLength_Boundary": "boundary",
    }


def test_default_run_advertised_equals_connected():
    """Under default flags every advertised request is wired, nothing extra."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ALL_REQUESTS


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request (strict 1:1 gating)."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes it, others survive."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "KNX_Baseline" in connected or name == "KNX_Baseline"
    assert connected == ALL_REQUESTS - {name}


def test_baseline_is_well_formed_search_request():
    """Baseline renders a valid SEARCH_REQUEST with consistent TotalLength."""
    fuzzer = _build(_make_config())
    data = _node(fuzzer, "KNX_Baseline").render()
    assert data[0] == 0x06  # HeaderLength
    assert data[1] == 0x10  # ProtocolVersion
    assert data[2:4] == b"\x02\x01"  # SEARCH_REQUEST
    total_length = struct.unpack_from(">H", data, 4)[0]
    assert total_length == len(data) == 14  # header(6) + HPAI(8)


def test_total_length_lie_present_in_render():
    """The rendered SESSION_REQUEST carries a TotalLength that lies about the
    real datagram length (CVE-2021-37740 length-inconsistency DoS class)."""
    fuzzer = _build(_make_config())
    data = _node(fuzzer, "KNX_TotalLength_Lie").render()

    assert data[2:4] == b"\x09\x51"  # SESSION_REQUEST (KNXnet/IP Secure)
    declared = struct.unpack_from(">H", data, 4)[0]
    actual = len(data)
    # Default render uses the first Group value (0x0000): declared != actual.
    assert declared == 0x0000
    assert actual != declared
    # Real datagram: header(6) + HPAI(8) + DH(32) = 46 bytes.
    assert actual == 46
