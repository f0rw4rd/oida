"""Offline tests for the ASTM E1381/E1394 clinical-lab (LIS) fuzzer.

ASTMFuzzer._define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")` with a strict 1:1 mapping
(RequestInfo.name == Request node name), so --enable / --disable each select
exactly one request. These tests build the boofuzz session offline via
MockConnectionFactory and inspect session.nodes -- no network I/O.

They also render two requests to prove the framing shape:
  - ASTM_Checksum_Corrupt carries the E1381 control bytes STX (0x02) and
    ETX (0x03) around the record body.
  - ASTM_Oversized_Record emits a long run of 'A' to overflow fixed
    instrument parse buffers.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.astm import (
    DEFAULT_PORT,
    ETX,
    STX,
    ASTMFuzzer,
    astm_checksum,
    astm_frame,
)

pytestmark = pytest.mark.core

EXPECTED_REQUESTS = {
    "ASTM_Baseline",
    "ASTM_Checksum_Corrupt",
    "ASTM_Oversized_Record",
    "ASTM_Delimiter_Injection",
    "ASTM_Frame_Number_Boundary",
    "ASTM_Missing_Terminator",
    "ASTM_Record_Type_Boundary",
}

EXPECTED_CATEGORIES = {
    "ASTM_Baseline": "baseline",
    "ASTM_Checksum_Corrupt": "malformed",
    "ASTM_Oversized_Record": "overflow",
    "ASTM_Delimiter_Injection": "malformed",
    "ASTM_Frame_Number_Boundary": "boundary",
    "ASTM_Missing_Terminator": "malformed",
    "ASTM_Record_Type_Boundary": "boundary",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=DEFAULT_PORT,
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
    return ASTMFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in ASTMFuzzer.get_request_definitions()}


def _node(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node
    return None


# ---------------------------------------------------------------------------
# Advertisement / gating
# ---------------------------------------------------------------------------
def test_all_seven_requests_advertised():
    """--list-requests advertises exactly the seven ASTM requests."""
    assert _advertised() == EXPECTED_REQUESTS
    assert len(ASTMFuzzer.get_request_definitions()) == 7


def test_request_categories():
    """Each request carries its documented {baseline,overflow,boundary,malformed} category."""
    categories = {d.name: d.category for d in ASTMFuzzer.get_request_definitions()}
    assert categories == EXPECTED_CATEGORIES
    assert set(categories.values()) == {"baseline", "overflow", "boundary", "malformed"}


def test_default_monitors_mirror_hl7():
    """DEFAULT_MONITORS mirrors the HL7 framing fuzzer's monitor cadence."""
    from oida.fuzz.protocols.hl7 import HL7Fuzzer

    assert ASTMFuzzer.DEFAULT_MONITORS == HL7Fuzzer.DEFAULT_MONITORS


def test_default_tcp_port():
    assert DEFAULT_PORT == 12000


def test_default_run_advertised_equals_connected():
    """Under default flags every advertised request is wired, and nothing extra."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == EXPECTED_REQUESTS


@pytest.mark.parametrize("name", sorted(EXPECTED_REQUESTS))
def test_each_request_is_enable_selectable(name):
    """--enable <name> connects exactly that request, proving 1:1 gating."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(EXPECTED_REQUESTS))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving the other requests connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == EXPECTED_REQUESTS - {name}


# ---------------------------------------------------------------------------
# Framing helpers
# ---------------------------------------------------------------------------
def test_astm_checksum_is_mod256_upper_hex():
    """Checksum is the mod-256 sum of the body as two uppercase-hex ASCII bytes."""
    # sum(b"1H") = 0x31 + 0x48 = 0x79
    assert astm_checksum(b"1H") == b"79"
    # Wrap-around past 256 keeps only the low byte.
    assert astm_checksum(b"\xff\x02") == b"01"
    assert len(astm_checksum(b"anything here")) == 2


def test_astm_frame_is_well_formed():
    """astm_frame wraps STX/body/ETX/checksum/CRLF with a matching checksum."""
    frame = astm_frame(b"1", b"H|\\^&", ETX)
    assert frame[:1] == STX
    assert frame.endswith(b"\x0d\x0a")
    body = b"1" + b"H|\\^&" + ETX
    assert astm_checksum(body) in frame
    assert ETX in frame


# ---------------------------------------------------------------------------
# Render assertions
# ---------------------------------------------------------------------------
def test_checksum_corrupt_frame_contains_stx_and_etx():
    """The corrupt-checksum frame is a real E1381 frame: STX ... ETX present."""
    fuzzer = _build(_make_config())
    node = _node(fuzzer, "ASTM_Checksum_Corrupt")
    assert node is not None, "ASTM_Checksum_Corrupt not connected"

    rendered = node.render()
    assert STX in rendered
    assert ETX in rendered
    # STX must precede the ETX terminator in the frame.
    assert rendered.index(STX) < rendered.index(ETX)
    assert rendered.endswith(b"\x0d\x0a")


def test_oversized_record_has_long_a_run():
    """The overflow request emits a long run of 'A' to overflow fixed buffers."""
    fuzzer = _build(_make_config())
    node = _node(fuzzer, "ASTM_Oversized_Record")
    assert node is not None, "ASTM_Oversized_Record not connected"

    rendered = node.render()
    # Default render selects the first Group value: 256 * 'A'.
    assert b"A" * 256 in rendered
    assert STX in rendered
    assert ETX in rendered


def test_baseline_frame_checksum_is_correct():
    """The baseline request renders a frame whose embedded checksum is valid."""
    fuzzer = _build(_make_config())
    node = _node(fuzzer, "ASTM_Baseline")
    assert node is not None
    rendered = node.render()

    # ENQ ... <STX>frame#..ETX C1C2 CRLF ... EOT
    assert rendered.startswith(b"\x05")  # ENQ handshake
    assert rendered.endswith(b"\x04")  # EOT
    stx_idx = rendered.index(STX)
    etx_idx = rendered.index(ETX, stx_idx)
    body = rendered[stx_idx + 1 : etx_idx + 1]  # frame#..ETX inclusive
    embedded_checksum = rendered[etx_idx + 1 : etx_idx + 3]
    assert embedded_checksum == astm_checksum(body)
