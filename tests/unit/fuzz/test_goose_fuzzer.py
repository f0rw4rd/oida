"""Offline tests for the IEC 61850 GOOSE Layer-2 fuzzer.

GOOSEFuzzer publishes crafted GOOSE frames (EtherType 0x88B8) whose goosePdu
lies about BER lengths, dataset-entry counts, and Data-element value tags.
Like the ethernet/ipv6 raw-L2 fuzzers it wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable take
effect. These tests build the boofuzz session offline (MockConnectionFactory)
and inspect session.nodes -- no network I/O.

Covers CVE-2018-18957 (prepareGooseBuffer overflow), CVE-2022-22723/22725
(Schneider CWE-120), and CVE-2023-4518 (Relion out-of-range reboot).
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.goose import GOOSEFuzzer

pytestmark = pytest.mark.core

# All seven advertised requests build unconditionally, so advertised ==
# connected under default flags.
ALL_REQUESTS = {
    "GOOSE_Baseline",
    "GOOSE_Length_Overflow",
    "GOOSE_NumDatSetEntries_Lie",
    "GOOSE_AllData_TypeConfusion",
    "GOOSE_Header_Length_Lie",
    "GOOSE_StNum_SqNum_Boundary",
    "GOOSE_BER_TagLen_Underflow",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="00:00:00:00:00:00",
        target_port=0,
        protocol_type=ProtocolType.RAW,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    # Deterministic MACs so no interface auto-detection happens offline.
    config.protocol_options = {
        "dst_mac": "01:0c:cd:01:00:01",
        "src_mac": "aa:bb:cc:dd:ee:ff",
    }
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build(config):
    return GOOSEFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in GOOSEFuzzer.get_request_definitions()}


def test_all_seven_requests_advertised():
    """--list-requests exposes all seven GOOSE requests."""
    assert _advertised() == ALL_REQUESTS


def test_advertised_categories():
    """Each request carries its intended category."""
    cats = {d.name: d.category for d in GOOSEFuzzer.get_request_definitions()}
    assert cats["GOOSE_Baseline"] == "baseline"
    assert cats["GOOSE_Length_Overflow"] == "overflow"
    assert cats["GOOSE_NumDatSetEntries_Lie"] == "malformed"
    assert cats["GOOSE_AllData_TypeConfusion"] == "malformed"
    assert cats["GOOSE_Header_Length_Lie"] == "boundary"
    assert cats["GOOSE_StNum_SqNum_Boundary"] == "boundary"
    assert cats["GOOSE_BER_TagLen_Underflow"] == "malformed"


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ALL_REQUESTS


def test_protocol_type_is_raw():
    """GOOSE is a raw Layer-2 fuzzer (mirrors ethernet.py)."""
    fuzzer = _build(_make_config())
    assert fuzzer.config.protocol_type == ProtocolType.RAW


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_enable_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving the others connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == ALL_REQUESTS - {name}


def _render(fuzzer, request_name):
    """Render a single request to its default wire bytes."""
    request = fuzzer.session.nodes[
        next(node_id for node_id, node in fuzzer.session.nodes.items() if node.name == request_name)
    ]
    return request.render()


def test_length_overflow_renders_oversized_length_byte():
    """GOOSE_Length_Overflow renders a BER length far larger than bytes present.

    The gocbRef octet-string only carries 4 bytes ('IED1') but the length
    field claims 0x7F (127) -- the prepareGooseBuffer / CWE-120 pattern.
    """
    fuzzer = _build(_make_config(enabled_requests=["GOOSE_Length_Overflow"]))
    rendered = bytes(_render(fuzzer, "GOOSE_Length_Overflow"))

    # EtherType 0x88B8 is present (this really is a GOOSE frame).
    assert b"\x88\xb8" in rendered
    # The oversized 0x7F length byte is emitted (goosePdu + gocbRef lengths).
    assert b"\x7f" in rendered
    # gocbRef claims 127 bytes but only the 4-byte 'IED1' payload follows it.
    idx = rendered.index(b"\x80\x7f")  # gocbRef tag 0x80 + length 0x7F
    payload_after = rendered[idx + 2 :]
    assert len(payload_after) < 0x7F
    assert b"IED1" in rendered
