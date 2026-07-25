"""Offline tests for the PROFINET-DCP fuzzer's per-request enable/disable gating.

PN-DCP is the L2 discovery/config channel of PROFINET IO (EtherType 0x8892, no
IP). The fuzzer targets classic DCP parser bugs unreachable by any prior OIDA
fuzzer:

- CVE-2012-1800 - Scalance S PROFINET-DCP stack-based buffer overflow
  (oversized DCPDataLength / block length).
- CVE-2017-2680 / CVE-2017-2681 - SIMATIC / PROFINET IO DoS across a large
  Siemens fleet, driven by crafted PN-DCP packets.

Every session.connect() in _define_protocol() is wrapped in
is_request_enabled("<RegisteredName>"), so --enable / --disable take effect.
These tests build the boofuzz session offline with MockConnectionFactory and
inspect session.nodes - no network I/O. The fuzzer is imported directly
(central registration in protocols/__init__.py is intentionally out of scope).
"""

import pytest

from boofuzz.mutation_context import MutationContext

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.profinet import ProfinetDCPFuzzer

pytestmark = pytest.mark.core

EXPECTED_NAMES = {
    "ProfinetDCP_Baseline",
    "ProfinetDCP_DataLength_Overflow",
    "ProfinetDCP_BlockLength_Lie",
    "ProfinetDCP_Set_NameOfStation_Overflow",
    "ProfinetDCP_Option_Suboption_Boundary",
    "ProfinetDCP_FrameID_Boundary",
    "ProfinetDCP_Block_ZeroLen_Loop",
}

# Byte offset of the DCPDataLength Word in a rendered frame:
#   dst(6) + src(6) + ethertype(2) + FrameID(2) + ServiceID(1) + ServiceType(1)
#   + Xid(4) + ResponseDelay(2) = 24
DCPDATALENGTH_OFFSET = 24


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
    return ProfinetDCPFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of Request nodes actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in ProfinetDCPFuzzer.get_request_definitions()}


def _node(fuzzer, node_name):
    for node in fuzzer.session.nodes.values():
        if node.name == node_name:
            return node
    raise AssertionError(f"node {node_name!r} not connected")


def test_all_seven_requests_are_advertised():
    """--list-requests exposes exactly the seven documented requests."""
    assert _advertised() == EXPECTED_NAMES
    assert len(ProfinetDCPFuzzer.get_request_definitions()) == 7


def test_request_categories_are_valid():
    """Every request declares a category from the allowed set."""
    allowed = {"baseline", "overflow", "boundary", "malformed"}
    cats = {d.category for d in ProfinetDCPFuzzer.get_request_definitions()}
    assert cats <= allowed


def test_category_assignment():
    """Each request maps to its documented category."""
    by_name = {d.name: d.category for d in ProfinetDCPFuzzer.get_request_definitions()}
    assert by_name["ProfinetDCP_Baseline"] == "baseline"
    assert by_name["ProfinetDCP_DataLength_Overflow"] == "overflow"
    assert by_name["ProfinetDCP_BlockLength_Lie"] == "malformed"
    assert by_name["ProfinetDCP_Set_NameOfStation_Overflow"] == "overflow"
    assert by_name["ProfinetDCP_Option_Suboption_Boundary"] == "boundary"
    assert by_name["ProfinetDCP_FrameID_Boundary"] == "boundary"
    assert by_name["ProfinetDCP_Block_ZeroLen_Loop"] == "malformed"


def test_default_run_advertised_equals_connected():
    """Advertised set == connected set under default flags (all build unconditionally)."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == EXPECTED_NAMES


@pytest.mark.parametrize("name", sorted(EXPECTED_NAMES))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(EXPECTED_NAMES))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving the other requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == EXPECTED_NAMES - {name}


def test_baseline_is_valid_identify_all():
    """Baseline renders a well-formed Identify-All frame.

    EtherType 0x8892, FrameID 0xFEFE, ServiceID 5 (Identify), an All-selector
    block (0xFF/0xFF, len 0), and a DCPDataLength that exactly matches the 4
    block bytes present.
    """
    fuzzer = _build(_make_config(enabled_requests=["ProfinetDCP_Baseline"]))
    rendered = _node(fuzzer, "ProfinetDCP_Baseline").render()

    assert rendered[12:14] == b"\x88\x92"  # EtherType PROFINET
    assert rendered[14:16] == b"\xfe\xfe"  # FrameID Identify-Req
    assert rendered[16] == 0x05  # ServiceID Identify
    # DCPDataLength == 4 == the four trailing block bytes (0xFF 0xFF 0x00 0x00).
    assert rendered[DCPDATALENGTH_OFFSET : DCPDATALENGTH_OFFSET + 2] == b"\x00\x04"
    assert rendered.endswith(b"\xff\xff\x00\x00")
    assert len(rendered) == 30


def test_datalength_overflow_declares_oversized_length():
    """DataLength_Overflow renders an oversized DCPDataLength vs the block bytes.

    The default Group value declares 0xFFFF (65535) block bytes while only the
    4-byte All-selector block is present (CVE-2012-1800 stack-overflow class).
    """
    fuzzer = _build(_make_config(enabled_requests=["ProfinetDCP_DataLength_Overflow"]))
    req = _node(fuzzer, "ProfinetDCP_DataLength_Overflow")
    rendered = req.render()

    declared = rendered[DCPDATALENGTH_OFFSET : DCPDATALENGTH_OFFSET + 2]
    assert declared == b"\xff\xff"  # oversized length bytes present
    # Actual block bytes after the length field are far fewer than declared.
    actual_block_bytes = len(rendered) - (DCPDATALENGTH_OFFSET + 2)
    assert int.from_bytes(declared, "big") > actual_block_bytes
    assert actual_block_bytes == 4

    # The full oversized-length sweep is exercised (default render + mutations).
    seen = {declared}
    seen |= {
        req.render(MutationContext(m))[DCPDATALENGTH_OFFSET : DCPDATALENGTH_OFFSET + 2]
        for m in req.mutations(None)
    }
    assert {b"\xff\xff", b"\x7f\xff", b"\x0f\xff", b"\x01\x00"} <= seen


def test_blocklength_lie_covers_zero_and_max():
    """BlockLength_Lie sweeps {0, 0xFFFF, >frame} against a 2-byte value tail."""
    fuzzer = _build(_make_config(enabled_requests=["ProfinetDCP_BlockLength_Lie"]))
    req = _node(fuzzer, "ProfinetDCP_BlockLength_Lie")

    # BlockLength offset: header(24) + DCPDataLength(2) + Option(1) + Suboption(1) = 28
    bl_off = 28
    rendered = req.render()
    seen = {rendered[bl_off : bl_off + 2]}
    seen |= {req.render(MutationContext(m))[bl_off : bl_off + 2] for m in req.mutations(None)}
    assert {b"\x00\x00", b"\xff\xff", b"\x04\x00"} <= seen
    # Only two value bytes are actually present after the block header.
    assert rendered.endswith(b"AB")


def test_set_nameofstation_is_oversized():
    """Set Name-of-Station renders a ServiceID-4 Set frame with an oversized name."""
    fuzzer = _build(_make_config(enabled_requests=["ProfinetDCP_Set_NameOfStation_Overflow"]))
    rendered = _node(fuzzer, "ProfinetDCP_Set_NameOfStation_Overflow").render()

    assert rendered[14:16] == b"\xfe\xfd"  # FrameID Get/Set
    assert rendered[16] == 0x04  # ServiceID Set
    assert rendered[26] == 0x02  # Block Option: device properties
    assert rendered[27] == 0x02  # Block Suboption: name of station
    # Oversized station name value present (default 512-byte 'A' run).
    assert b"A" * 512 in rendered


def test_frameid_boundary_sweep():
    """FrameID_Boundary walks the documented FrameID set at the frame head."""
    fuzzer = _build(_make_config(enabled_requests=["ProfinetDCP_FrameID_Boundary"]))
    req = _node(fuzzer, "ProfinetDCP_FrameID_Boundary")

    seen = {req.render()[14:16]}
    seen |= {req.render(MutationContext(m))[14:16] for m in req.mutations(None)}
    assert {b"\xfe\xfe", b"\xfe\xfd", b"\xfe\xfc", b"\x00\x00", b"\xff\xff"} <= seen


def test_zerolen_loop_has_zero_block_lengths():
    """Block_ZeroLen_Loop renders three zero-length blocks under an inflated
    DCPDataLength (non-advancing block-walk / PNIO DoS)."""
    fuzzer = _build(_make_config(enabled_requests=["ProfinetDCP_Block_ZeroLen_Loop"]))
    rendered = _node(fuzzer, "ProfinetDCP_Block_ZeroLen_Loop").render()

    # DCPDataLength claims 12 block bytes (three 4-byte zero-length blocks).
    assert rendered[DCPDATALENGTH_OFFSET : DCPDATALENGTH_OFFSET + 2] == b"\x00\x0c"
    # The three block-length Words are all zero (offsets 28, 32, 36).
    assert rendered[28:30] == b"\x00\x00"
    assert rendered[32:34] == b"\x00\x00"
    assert rendered[36:38] == b"\x00\x00"
