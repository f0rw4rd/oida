"""Offline tests for the EtherCAT-over-Ethernet (0x88A4) raw-L2 fuzzer.

The EtherCATFuzzer gates every session.connect() behind
`self.is_request_enabled("<Name>")`, where the advertised RequestInfo name
equals the connected boofuzz Request node name. These tests build the boofuzz
session offline with MockConnectionFactory and inspect session.nodes to verify
the seven requests are advertised, connected-by-default, and individually
selectable, without any network I/O.

Closes the gap: only scanner-side SDO/PDO fuzzing existed for EtherCAT; there
was no fuzz-framework fuzzer covering the datagram / mailbox length-lie OOB
classes (CVE-2023-7242/7243/7244, CVE-2012-4293). EtherCAT is LITTLE-ENDIAN.
"""

import struct

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.ethercat import EtherCATFuzzer

pytestmark = pytest.mark.core

ALL_REQUESTS = {
    "EtherCAT_Baseline",
    "EtherCAT_Datagram_Length_Overflow",
    "EtherCAT_Header_Length_Lie",
    "EtherCAT_Mailbox_Length_Overflow",
    "EtherCAT_Cmd_Boundary",
    "EtherCAT_More_Datagrams_Lie",
    "EtherCAT_Datagram_ZeroLen",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=0,
        protocol_type=ProtocolType.RAW,
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
    return EtherCATFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of Request nodes actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in EtherCATFuzzer.get_request_definitions()}


def _node(fuzzer, node_name):
    for node in fuzzer.session.nodes.values():
        if node.name == node_name:
            return node
    raise AssertionError(f"node {node_name!r} not connected")


def test_seven_requests_advertised():
    """--list-requests advertises exactly the seven EtherCAT requests."""
    assert _advertised() == ALL_REQUESTS
    assert len(EtherCATFuzzer.get_request_definitions()) == 7


def test_categories_are_covered():
    """Every request carries one of the four expected categories."""
    cats = {d.name: d.category for d in EtherCATFuzzer.get_request_definitions()}
    assert cats["EtherCAT_Baseline"] == "baseline"
    assert cats["EtherCAT_Datagram_Length_Overflow"] == "overflow"
    assert cats["EtherCAT_Mailbox_Length_Overflow"] == "overflow"
    assert cats["EtherCAT_Header_Length_Lie"] == "boundary"
    assert cats["EtherCAT_Cmd_Boundary"] == "boundary"
    assert cats["EtherCAT_More_Datagrams_Lie"] == "malformed"
    assert cats["EtherCAT_Datagram_ZeroLen"] == "malformed"
    assert set(cats.values()) == {"baseline", "overflow", "boundary", "malformed"}


def test_default_run_advertised_equals_connected():
    """Under default flags, advertised set == connected set (strict 1:1)."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ALL_REQUESTS


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ALL_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving the rest connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == ALL_REQUESTS - {name}


def test_ethertype_is_ecat_and_little_endian_header():
    """Baseline frame carries EtherType 0x88A4 (big-endian on wire) then a
    little-endian EtherCAT header with Type nibble = 1."""
    fuzzer = _build(_make_config(enabled_requests=["EtherCAT_Baseline"]))
    frame = _node(fuzzer, "EtherCAT_Baseline").render()
    # EtherType at offset 12 is network byte order.
    assert frame[12:14] == struct.pack(">H", 0x88A4)
    # EtherCAT header Word is little-endian; Type nibble (top 4 bits) == 1.
    hdr = struct.unpack("<H", frame[14:16])[0]
    assert (hdr >> 12) & 0xF == 1


def test_datagram_length_overflow_oversized_len_present():
    """The oversized LenBits is present on the wire while only 4 data bytes
    follow -> a length-trusting parser walks past the buffer (CVE-2023-7244)."""
    fuzzer = _build(_make_config(enabled_requests=["EtherCAT_Datagram_Length_Overflow"]))
    req = _node(fuzzer, "EtherCAT_Datagram_Length_Overflow")

    frame = req.render()  # default render uses the first Group value (0x7FF)
    # Flags word sits after eth(14) + ecat_hdr(2) + cmd(1) + index(1)
    #   + adp(2) + ado(2) = 22.
    flags_off = 14 + 2 + 1 + 1 + 2 + 2
    flags = struct.unpack("<H", frame[flags_off : flags_off + 2])[0]
    len_bits = flags & 0x7FF
    assert len_bits == 0x7FF
    # Only 4 data bytes are actually present -> advertised length dwarfs them.
    assert len_bits > 4
    # The little-endian 0x07FF must appear literally in the rendered bytes.
    assert struct.pack("<H", 0x07FF) in frame


def test_more_bit_set_with_no_following_datagram():
    """More (M) bit set but the frame ends right after the single datagram."""
    fuzzer = _build(_make_config(enabled_requests=["EtherCAT_More_Datagrams_Lie"]))
    frame = _node(fuzzer, "EtherCAT_More_Datagrams_Lie").render()
    flags_off = 14 + 2 + 1 + 1 + 2 + 2
    flags = struct.unpack("<H", frame[flags_off : flags_off + 2])[0]
    assert (flags >> 15) & 1 == 1  # More bit set
    # Single datagram only: eth(14)+ecat(2)+dgram(10 hdr + 4 data + 2 wkc = 16).
    assert len(frame) == 14 + 2 + 16
