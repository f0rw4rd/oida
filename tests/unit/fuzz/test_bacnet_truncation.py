"""Offline tests for the BACnet length-desync / truncation request family.

bacnet-stack's crown-jewel OOB reads all share one shape: the decoder trusts a
declared BVLL/NPDU length and walks ASN.1 tags past the delivered buffer. This
suite guards the five requests added to close that gap:

  BACnet_APDU_Truncated        - RPM/WPM body truncated below declared length
                                 (CVE-2026-41503, CVE-2026-41475)
  BACnet_APDU_Length_Underflow - tiny WriteProperty + 2-byte NPDU underflow
                                 (CVE-2026-26264, CVE-2025-66624)
  BACnet_BVLC_Forwarded_NPDU   - BVLC Forwarded-NPDU (0x04) mismatched length
                                 (CVE-2018-10238)
  BACnet_AtomicFile_Payload    - AtomicReadFile/WriteFile + traversal filename
                                 (CVE-2019-12480)
  BACnet_BVLL_Length_Desync    - the BVLL Length field itself made fuzzable

Each must be advertised in --list-requests AND individually enable-selectable
(proving the connect() is 1:1 gated). Two are rendered to prove the desynced
length / Forwarded-NPDU function byte are really on the wire. BACnet/IP is UDP
port 47808; the session is built offline with MockConnectionFactory (no I/O).
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

# The five new length-desync / truncation requests.
NEW_REQUESTS = {
    "BACnet_APDU_Truncated",
    "BACnet_APDU_Length_Underflow",
    "BACnet_BVLC_Forwarded_NPDU",
    "BACnet_AtomicFile_Payload",
    "BACnet_BVLL_Length_Desync",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=47808,  # BACnet/IP, UDP 0xBAC0
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
    fuzzer_class = PROTOCOL_FUZZERS["bacnet"]
    if fuzzer_class is None:
        require_service("bacnet fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _connected_nodes(fuzzer):
    session = fuzzer.session
    return {node.name: node for node in session.nodes.values()}


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["bacnet"].get_request_definitions()}


def test_new_requests_are_advertised():
    """All five new requests appear in --list-requests."""
    assert NEW_REQUESTS <= _advertised()


def test_fuzzer_instantiates_and_baseline_survives():
    """Default build still wires the baseline plus every new request.

    (bacnet advertises coarse group names, e.g. BACnet_Write_Operations, while
    connecting finer Request objects, so a strict connected <= advertised check
    is intentionally not asserted here.)
    """
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected
    # Existing requests are untouched.
    assert "BACnet_Quick_Coverage" in connected


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving 1:1 gating."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_disableable(name):
    """--disable <name> removes it while leaving other defaults connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert "BACnet_Quick_Coverage" in connected


def test_apdu_truncated_declares_more_than_it_delivers():
    """BACnet_APDU_Truncated: BVLL Length claims more bytes than are rendered.

    This is the RPM/WPM OOB-read shape - a declared property/tag runs past the
    end of the actual frame (declared length > actual content).
    """
    fuzzer = _build(_make_config(enabled_requests=["BACnet_APDU_Truncated"]))
    node = _connected_nodes(fuzzer)["BACnet_APDU_Truncated"]
    rendered = node.render()
    # BVLC: type(1) function(1) length(2) -> length word at bytes [2:4].
    declared_len = int.from_bytes(rendered[2:4], "big")
    assert rendered[0] == 0x81  # BACnet/IP
    assert declared_len == 0x0013  # static full-frame claim (19 bytes)
    # The rendered frame is shorter than what the length field promises.
    assert len(rendered) < declared_len


def test_bvlc_forwarded_npdu_function_byte_present():
    """BACnet_BVLC_Forwarded_NPDU renders BVLC function 0x04 (Forwarded-NPDU).

    Guards the CVE-2018-10238 bvlc_encode_forwarded_npdu stack-copy surface and
    verifies the declared length is desynced from the delivered frame.
    """
    fuzzer = _build(_make_config(enabled_requests=["BACnet_BVLC_Forwarded_NPDU"]))
    node = _connected_nodes(fuzzer)["BACnet_BVLC_Forwarded_NPDU"]
    rendered = node.render()
    assert rendered[0] == 0x81  # BACnet/IP
    assert rendered[1] == 0x04  # Forwarded-NPDU function (CVE-2018-10238 surface)
    # 6-octet Originating B/IP address follows the 4-byte BVLC header.
    assert rendered[4:10] == b"\xc0\xa8\x01\x01\xba\xc0"  # 192.168.1.1:47808
    # The oversized/mismatched length values that drive the stack copy are in
    # the fuzzable BVLL_Length_FWD group (baseline renders the clean length).
    length_group = node.names["BACnet_BVLC_Forwarded_NPDU.BVLC_Header_FWD.BVLL_Length_FWD"]
    assert b"\xff\xff" in length_group.values  # oversized claim is fuzzed
