"""Offline tests for the ADS-Discovery (UDP/48899) request family.

The ADS fuzzer historically only reached the TCP/48898 AMS channel, leaving the
entire ADS/AMS router-discovery attack surface on UDP/48899 unreachable. Two
known bugs live there:

  ADS_Discovery_Malformed    - bad magic cookie / truncated discovery datagram
                               (CVE-2019-5636, CWE-404 service shutdown)
  ADS_Discovery_TLV_Overflow - TLV length Word > value bytes / oversized value
                               (CVE-2011-3486, CWE-125 OOB read)
  ADS_Discovery_Count_Lie    - TLV-block count DWord disagrees with blocks present

Each must be advertised in --list-requests AND individually enable-selectable
(proving the connect() is 1:1 gated). One is rendered to prove the discovery
magic cookie and the oversized TLV length claim are really on the wire. The
discovery datagram is UDP port 48899; the session is built offline with
MockConnectionFactory (no I/O).
"""

import struct

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

# The three new UDP/48899 discovery requests.
NEW_REQUESTS = {
    "ADS_Discovery_Malformed",
    "ADS_Discovery_TLV_Overflow",
    "ADS_Discovery_Count_Lie",
}

# On-the-wire discovery cookie 0x71146603 (little-endian) == 03 66 14 71.
DISCOVERY_MAGIC = struct.pack("<I", 0x71146603)


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=48899,  # ADS/AMS router discovery, UDP
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
    fuzzer_class = PROTOCOL_FUZZERS["ads"]
    if fuzzer_class is None:
        require_service("ads fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _connected_nodes(fuzzer):
    session = fuzzer.session
    return {node.name: node for node in session.nodes.values()}


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["ads"].get_request_definitions()}


def test_new_requests_are_advertised():
    """All three discovery requests appear in --list-requests."""
    assert NEW_REQUESTS <= _advertised()


def test_discovery_requests_connected_by_default():
    """Default build wires all three discovery requests plus the baseline."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected
    # Existing TCP requests are untouched.
    assert "ADS_Quick_Coverage" in connected


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_discovery_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving 1:1 gating."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_discovery_request_is_disableable(name):
    """--disable <name> removes it while leaving other defaults connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "ADS_Quick_Coverage" in connected


def test_tlv_overflow_carries_magic_and_oversized_length():
    """ADS_Discovery_TLV_Overflow renders the discovery cookie and a TLV length
    Word that overclaims relative to the value bytes actually present (the
    CVE-2011-3486 OOB-read shape)."""
    fuzzer = _build(_make_config(enabled_requests=["ADS_Discovery_TLV_Overflow"]))
    node = _connected_nodes(fuzzer)["ADS_Discovery_TLV_Overflow"]
    rendered = node.render()

    # Header starts with the AMS router discovery magic cookie.
    assert rendered[:4] == DISCOVERY_MAGIC

    # Layout: magic(4) type(4) netid(6) port(2) count(4) tag(2) len(2) value...
    # -> declared TLV length Word lives at bytes [22:24], value follows at [24:].
    declared_len = int.from_bytes(rendered[22:24], "little")
    value_bytes = rendered[24:]
    assert declared_len == 0xFFFF  # baseline renders the max overclaim
    assert declared_len > len(value_bytes)  # length lies beyond the datagram

    # The oversized claim is present in the TLV_Length group (boofuzz Group
    # keeps the first value as the baseline _default_value, the rest as .values).
    length_group = node.names["ADS_Discovery_TLV_Overflow.Discovery_TLV_Overflow.TLV_Length"]
    length_values = {length_group._default_value, *length_group.values}
    assert struct.pack("<H", 0xFFFF) in length_values


def test_count_lie_carries_magic_and_lying_count():
    """ADS_Discovery_Count_Lie renders the magic cookie and offers count values
    (0, 0xFFFFFFFF) that disagree with the single TLV block present."""
    fuzzer = _build(_make_config(enabled_requests=["ADS_Discovery_Count_Lie"]))
    node = _connected_nodes(fuzzer)["ADS_Discovery_Count_Lie"]
    rendered = node.render()
    assert rendered[:4] == DISCOVERY_MAGIC

    count_group = node.names["ADS_Discovery_Count_Lie.Discovery_Count_Lie.TLV_Count"]
    count_values = {count_group._default_value, *count_group.values}
    assert struct.pack("<I", 0) in count_values
    assert struct.pack("<I", 0xFFFFFFFF) in count_values
