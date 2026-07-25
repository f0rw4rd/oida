"""Offline tests for the NetBIOS Name Service (NBNS, UDP 137) fuzzer.

NetBIOSFuzzer._define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")` with a strict 1:1 mapping
(RequestInfo.name == Request node name), so --enable / --disable select
exactly one request each. These tests build the boofuzz session offline via
MockConnectionFactory and inspect session.nodes -- no network I/O.

They also render the NetBIOS_Name_Unterminated request to prove the classic
name-decode over-read shape: the 32-byte first-level-encoded label is followed
directly by QTYPE with no 0x00 label terminator in between (Samba nmbd
CVE-2007-5398 / Windows NBNS CVE-2003-0661).
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.netbios import NetBIOSFuzzer

pytestmark = pytest.mark.core

EXPECTED_REQUESTS = {
    "NetBIOS_Baseline",
    "NetBIOS_Name_Unterminated",
    "NetBIOS_Label_Length_Boundary",
    "NetBIOS_Name_Oversized",
    "NetBIOS_SecondLevel_Length_Lie",
    "NetBIOS_Count_Lies",
    "NetBIOS_NBSTAT_Wildcard",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=137,
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
    return NetBIOSFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in NetBIOSFuzzer.get_request_definitions()}


def _node(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node
    return None


def test_all_seven_requests_advertised():
    """--list-requests advertises exactly the seven NBNS requests."""
    assert _advertised() == EXPECTED_REQUESTS


def test_default_monitor_is_ping():
    assert NetBIOSFuzzer.DEFAULT_MONITORS == "ping"


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


def test_unterminated_name_has_no_null_terminator_before_qtype():
    """The over-read request: 32-byte encoded label runs straight into QTYPE.

    A well-formed NBNS question ends the owner name with a 0x00 label
    terminator before QTYPE. The over-read case omits it, so the two bytes
    following the encoded label must be QTYPE itself (NB == 0x0020), not a
    0x00 terminator label.
    """
    fuzzer = _build(_make_config())
    node = _node(fuzzer, "NetBIOS_Name_Unterminated")
    assert node is not None, "NetBIOS_Name_Unterminated not connected"

    rendered = node.render()
    name_bytes = b"ABCDEFGHIJKLMNOP" * 2
    idx = rendered.index(name_bytes)
    after_name = rendered[idx + len(name_bytes) : idx + len(name_bytes) + 2]

    # QTYPE NB immediately follows the label -> no 0x00 terminator label present.
    assert after_name == b"\x00\x20"
    # And no stray 0x00 terminator byte sits between the label and QTYPE.
    assert rendered[idx + len(name_bytes) - 1] != 0x00


def test_baseline_by_contrast_has_null_terminator():
    """Sanity contrast: the baseline request DOES terminate the name with 0x00."""
    fuzzer = _build(_make_config())
    node = _node(fuzzer, "NetBIOS_Baseline")
    assert node is not None
    rendered = node.render()
    # wildcard first-level label
    name_bytes = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    idx = rendered.index(name_bytes)
    # byte right after the 32-byte label is the 0x00 terminator, then QTYPE NBSTAT.
    assert rendered[idx + len(name_bytes)] == 0x00
    assert rendered[idx + len(name_bytes) + 1 : idx + len(name_bytes) + 3] == b"\x00\x21"
