"""Offline tests for the S7comm fuzzer request gating and framing.

The S7comm fuzzer's _define_protocol() wraps every session.connect() in
`self.is_request_enabled("<RegisteredName>")` with strict 1:1 gating (the
boofuzz Request node name equals the advertised RequestInfo name), so
--enable / --disable take effect per-request. These tests build the boofuzz
session offline (MockConnectionFactory) and inspect session.nodes without any
network I/O.

Bug classes covered by the eight requests:
- CVE-2017-1000230  ItemCount DoS      (S7Comm_ItemCount_Lie)
- CVE-2026-51218    WriteVar heap overflow (S7Comm_WriteVar_DataLen_Overflow)
- CVE-2020-22552    COTP last-data-unit crash (S7Comm_COTP_LastDataUnit)
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.s7comm import S7CommFuzzer

pytestmark = pytest.mark.core

ADVERTISED = {
    "S7Comm_Baseline",
    "S7Comm_ItemCount_Lie",
    "S7Comm_WriteVar_DataLen_Overflow",
    "S7Comm_COTP_LastDataUnit",
    "S7Comm_ParamLen_DataLen_Lie",
    "S7Comm_TPKT_Length_Lie",
    "S7Comm_ROSCTR_Boundary",
    "S7Comm_Userdata_Malformed",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=102,
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
    return S7CommFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in S7CommFuzzer.get_request_definitions()}


def _render(fuzzer, name):
    """Render a connected request node to its default bytes."""
    session = fuzzer.session
    for node in session.nodes.values():
        if node.name == name:
            return node.render()
    raise AssertionError(f"request {name} not connected")


def test_eight_requests_advertised():
    """--list-requests advertises exactly the eight S7comm requests."""
    assert _advertised() == ADVERTISED
    assert len(S7CommFuzzer.get_request_definitions()) == 8


def test_categories_are_expected():
    """Each request carries the expected {baseline, overflow, boundary, malformed} category."""
    cats = {d.name: d.category for d in S7CommFuzzer.get_request_definitions()}
    assert cats["S7Comm_Baseline"] == "baseline"
    assert cats["S7Comm_ItemCount_Lie"] == "malformed"
    assert cats["S7Comm_WriteVar_DataLen_Overflow"] == "overflow"
    assert cats["S7Comm_COTP_LastDataUnit"] == "malformed"
    assert cats["S7Comm_ParamLen_DataLen_Lie"] == "boundary"
    assert cats["S7Comm_TPKT_Length_Lie"] == "boundary"
    assert cats["S7Comm_ROSCTR_Boundary"] == "boundary"
    assert cats["S7Comm_Userdata_Malformed"] == "malformed"
    assert {d.category for d in S7CommFuzzer.get_request_definitions()} == {
        "baseline",
        "overflow",
        "boundary",
        "malformed",
    }


def test_default_run_advertised_equals_connected():
    """Under default flags every advertised request is connected, and nothing else."""
    connected = _connected_names(_build(_make_config()))
    assert connected == _advertised()
    assert connected == ADVERTISED
    # No request is connected without being advertised.
    assert connected <= _advertised()


@pytest.mark.parametrize("name", sorted(ADVERTISED))
def test_each_request_is_selectable(name):
    """--enable <name> connects exactly that request, proving 1:1 gating."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected == {name}


@pytest.mark.parametrize("name", sorted(ADVERTISED))
def test_each_request_is_disableable(name):
    """--disable <name> removes it while leaving the other seven connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected
    assert connected == ADVERTISED - {name}


def test_item_count_lie_renders_inflated_count(name="S7Comm_ItemCount_Lie"):
    """The ItemCount_Lie default render carries an inflated count byte with one item.

    S7comm framing: TPKT(4) + COTP(3) + S7 header(10) + param. The parameter is
    ReadVar (func 0x04), item-count byte, then a single 12-byte ANY item. The
    count byte lies (0xFF) about how many items follow (CVE-2017-1000230).
    """
    data = _render(_build(_make_config(enabled_requests=[name])), name)

    # TPKT + COTP DT header
    assert data[0] == 0x03  # TPKT version
    assert data[4:7] == b"\x02\xf0\x80"  # COTP length, DT, EOT set

    # S7comm header
    assert data[7] == 0x32  # protocol id
    assert data[8] == 0x01  # ROSCTR Job

    # parameter: function byte then the inflated item-count byte
    read_func_idx = 17  # 4 (TPKT) + 3 (COTP) + 10 (S7 header)
    assert data[read_func_idx] == 0x04  # ReadVar function
    item_count = data[read_func_idx + 1]
    assert item_count == 0xFF  # the lie: claims 255 items

    # ...while exactly one 12-byte ANY item actually follows.
    item = data[read_func_idx + 2 :]
    assert len(item) == 12
    assert item[0] == 0x12  # ANY-item spec type
    assert item_count > 1  # count byte inflated past the single item present


def test_writevar_overflow_datalen_exceeds_payload(name="S7Comm_WriteVar_DataLen_Overflow"):
    """WriteVar default render declares a data-length far larger than the bytes present."""
    data = _render(_build(_make_config(enabled_requests=[name])), name)
    assert data[7] == 0x32  # S7 protocol id
    # S7 header data-length word (offset 15-16) is the inflated 0xFFFF lie.
    assert data[15:17] == b"\xff\xff"
    # WriteVar function byte present.
    assert data[17] == 0x05


def test_cotp_last_data_unit_clears_eot(name="S7Comm_COTP_LastDataUnit"):
    """COTP DT default render clears the EOT (last-data-unit) bit (0x00, not 0x80)."""
    data = _render(_build(_make_config(enabled_requests=[name])), name)
    assert data[4] == 0x02  # COTP length
    assert data[5] == 0xF0  # COTP DT PDU-type
    assert data[6] == 0x00  # EOT cleared -> fragment continuation
