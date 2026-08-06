"""Offline tests for the IEC 61850 GOOSE Layer-2 fuzzer.

GOOSEFuzzer publishes crafted GOOSE frames (EtherType 0x88B8) whose goosePdu
lies about BER lengths, dataset-entry counts, and Data-element value tags.
Like the other raw-L2 fuzzers it wraps every session.connect() in
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

# All advertised requests build unconditionally, so advertised ==
# connected under default flags.
ALL_REQUESTS = {
    "GOOSE_Baseline",
    "GOOSE_Length_Overflow",
    "GOOSE_NumDatSetEntries_Lie",
    "GOOSE_AllData_TypeConfusion",
    "GOOSE_Header_Length_Lie",
    "GOOSE_StNum_SqNum_Boundary",
    "GOOSE_BER_TagLen_Underflow",
    "GOOSE_Ref_Identifier_Injection",
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


def test_all_requests_advertised():
    """--list-requests exposes every GOOSE request."""
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
    assert cats["GOOSE_Ref_Identifier_Injection"] == "malformed"


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ALL_REQUESTS


def test_protocol_type_is_raw():
    """GOOSE is a raw Layer-2 fuzzer (ProtocolType.RAW)."""
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


def _parse_ber_len(buf, i):
    """Return (length_value, index_after_length) for a BER length at buf[i]."""
    lb = buf[i]
    if lb < 0x80:
        return lb, i + 1
    n = lb & 0x7F
    return int.from_bytes(buf[i + 1 : i + 1 + n], "big"), i + 1 + n


def test_ref_identifier_injection_frame_is_valid():
    """GOOSE_Ref_Identifier_Injection renders a length-consistent baseline frame.

    All three enclosing lengths must agree with the actual bytes: the GOOSE
    header Length Word (8 + goosePdu), the goosePdu BER length, and the
    gocbRef octet-string length. A malformed baseline that a subscriber
    rejects outright would be worse than an unfuzzed identifier.
    """
    fuzzer = _build(_make_config(enabled_requests=["GOOSE_Ref_Identifier_Injection"]))
    raw = bytes(_render(fuzzer, "GOOSE_Ref_Identifier_Injection"))

    assert b"\x88\xb8" in raw  # really a GOOSE frame
    # GOOSE header Length Word (after 14B Ethernet + 2B APPID) = 8 + goosePdu.
    goose_len = int.from_bytes(raw[16:18], "big")
    pdu = raw[22:]  # 14 Ethernet + 8 GOOSE header
    assert goose_len == 8 + len(pdu)
    # goosePdu BER length covers exactly the remaining field bytes.
    assert raw[22] == 0x61
    pdu_len, i = _parse_ber_len(raw, 23)
    assert pdu_len == len(raw) - i
    # gocbRef[0] octet-string length matches the identifier bytes present.
    assert raw[i] == 0x80
    gocbref_len, j = _parse_ber_len(raw, i + 1)
    assert raw[j : j + gocbref_len] == b"IEDGENGGIO1/LLN0$GO$gcb01"


def test_ref_identifier_injection_fuzzes_the_identifier():
    """The gocbRef/datSet/goID SmartStrings actually produce mutations."""
    fuzzer = _build(_make_config(enabled_requests=["GOOSE_Ref_Identifier_Injection"]))
    request = fuzzer.session.nodes[
        next(
            nid
            for nid, node in fuzzer.session.nodes.items()
            if node.name == "GOOSE_Ref_Identifier_Injection"
        )
    ]
    # Far more than a fixed Group would give -- the identifiers are fuzzed.
    assert request.num_mutations() > 500
