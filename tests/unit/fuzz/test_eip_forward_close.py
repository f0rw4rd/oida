"""
Offline tests for the dedicated EtherNet/IP CIP connection-management
malformation requests.

Adds coverage for the three requests that close proven gaps in the EtherNet/IP
fuzzer:

  * EIP_ForwardClose_Malformed - a CIP Forward_Close (service 0x4E) whose
    connection-path-size byte disagrees with the EPATH bytes actually present.
    Confirmed fault: CVE-2025-7693 (malformed CIP Forward_Close faults Rockwell
    Micro850).
  * EIP_ForwardOpen_Malformed - a Forward_Open (service 0x54) with a
    connection-path-size larger than the EPATH present and oversized network
    connection params.
  * EIP_ConnMgr_Path_Overflow - a Connection Manager request with an oversized,
    looping EPATH that ends mid logical segment.

The session is built offline with MockConnectionFactory (no live device; the
RegisterSession handshake in _define_state_machine fails fast and falls
through), mirroring test_ethernetip_request_gating and
test_ipv6_request_gating.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core

NEW_CONNMGMT_REQUESTS = {
    "EIP_ForwardClose_Malformed",
    "EIP_ForwardOpen_Malformed",
    "EIP_ConnMgr_Path_Overflow",
}


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
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _find(block, name):
    if getattr(block, "name", None) == name:
        return block
    for child in getattr(block, "stack", []) or []:
        found = _find(child, name)
        if found is not None:
            return found
    return None


def _node(fuzzer, name):
    return next(n for n in fuzzer.session.nodes.values() if n.name == name)


def test_new_connmgmt_requests_are_advertised():
    """All three requests appear in --list-requests."""
    assert NEW_CONNMGMT_REQUESTS <= _advertised_names()


def test_new_connmgmt_requests_connected_by_default():
    """All three are wired into the session under default flags (no enable_write
    needed - they are malformed crash tests, not real writes)."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_CONNMGMT_REQUESTS <= connected


@pytest.mark.parametrize("name", sorted(NEW_CONNMGMT_REQUESTS))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(NEW_CONNMGMT_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while other default requests survive."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    # Sanity: an unrelated default-connected request survives the disable.
    assert "EIP_Malformed_Packet" in connected


def test_forward_close_malformed_service_and_bad_path_size():
    """ForwardClose_Malformed renders CIP service 0x4E and carries a
    connection-path-size that disagrees with the EPATH present (CVE-2025-7693)."""
    node = _node(_build(_make_config()), "EIP_ForwardClose_Malformed")

    # CIP Forward_Close service byte.
    service = _find(node, "Forward_Close_Service")
    assert service is not None
    assert service.render() == b"\x4e"

    # The malformed connection-path-size byte. boofuzz Group excludes the first
    # value (the default) from .values, so the full emitted set is default +
    # values. All three (0x00, 0xFF, 0x08) are wrong: the EPATH present is a
    # single 2-word logical path, so none of the declared sizes match it.
    path_size = _find(node, "Connection_Path_Size")
    assert path_size is not None
    emitted = {b[0] for b in list(path_size.values) + [path_size._default_value]}
    assert {0x00, 0xFF, 0x08} <= emitted
    assert 2 not in emitted  # the real EPATH word-count is never advertised

    # EPATH bytes are actually present regardless of the declared size.
    for seg in ("Conn_Path_Class_Seg", "Conn_Path_Class", "Conn_Path_Inst_Seg", "Conn_Path_Inst"):
        assert _find(node, seg) is not None

    # The full request renders, and the service byte is in the wire bytes.
    rendered = node.render()
    assert b"\x4e" in rendered


def test_forward_open_malformed_oversized_path_size():
    """ForwardOpen_Malformed renders service 0x54 and declares a
    connection-path-size larger than the single word of path present."""
    node = _node(_build(_make_config()), "EIP_ForwardOpen_Malformed")

    service = _find(node, "Forward_Open_Service")
    assert service is not None
    assert service.render() == b"\x54"

    path_size = _find(node, "Connection_Path_Size")
    assert path_size is not None
    emitted = {b[0] for b in list(path_size.values) + [path_size._default_value]}
    # Only one path word (Port_Segment + Link_Address) is present, so every
    # declared size (0xFF / 0x40 / 0x7F) massively overstates it.
    assert {0xFF, 0x40, 0x7F} <= emitted
    assert min(emitted) > 1


def test_connmgr_path_overflow_ends_mid_segment():
    """ConnMgr_Path_Overflow declares an oversized path size and carries an
    EPATH that ends on a lone logical-segment opener (mid-segment)."""
    node = _node(_build(_make_config()), "EIP_ConnMgr_Path_Overflow")

    path_size = _find(node, "Path_Size_Overflow")
    assert path_size is not None
    emitted = {b[0] for b in list(path_size.values) + [path_size._default_value]}
    assert {0x40, 0x7F, 0x80, 0xFF} <= emitted

    path_data = _find(node, "Path_Data")
    assert path_data is not None
    rendered = path_data.render()
    # Looping Connection Manager EPATH (0x20 0x06 0x24 0x01) that ends mid
    # logical segment: a trailing 0x20 opener with no class byte after it.
    assert rendered.endswith(b"\x20")
    assert rendered.count(b"\x20\x06\x24\x01") >= 2
