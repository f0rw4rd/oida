"""
Offline tests for the TFTP runt / unterminated malformed request groups.

TFTP groups several boofuzz Requests under a single RequestInfo and a single
`is_request_enabled("<RequestInfo>")` gate. These tests build the boofuzz
session offline via MockConnectionFactory (no network I/O) and verify that the
two new malformed groups are advertised via get_request_definitions() and each
is individually selectable via enabled_requests.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core

NEW_GROUPS = {"TFTP_Short_Datagram", "TFTP_Unterminated"}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=69,
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
    fuzzer_class = PROTOCOL_FUZZERS["tftp"]
    if fuzzer_class is None:
        pytest.skip("tftp fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["tftp"].get_request_definitions()}


def test_new_malformed_groups_are_advertised():
    assert NEW_GROUPS <= _advertised()


@pytest.mark.parametrize("name", sorted(NEW_GROUPS))
def test_each_group_is_individually_selectable(name):
    """--enable <group> connects only that group's requests, proving it is gated."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert connected, f"enabling {name} connected no requests"
    # No other advertised group's request leaks in. TFTP_Short_Datagram's node
    # shares the group name; TFTP_Unterminated's nodes are its two RRQ variants.
    if name == "TFTP_Short_Datagram":
        assert connected == {"TFTP_Short_Datagram"}
    else:
        assert connected == {
            "TFTP_Malformed_Unterminated_Filename_RRQ",
            "TFTP_Malformed_Unterminated_Mode_RRQ",
        }


def test_short_datagram_renders_below_header_length():
    """At least one short-datagram mutation renders to fewer than 4 bytes."""
    fuzzer = _build(_make_config(enabled_requests=["TFTP_Short_Datagram"]))
    request = fuzzer.session.nodes[
        next(n for n, node in fuzzer.session.nodes.items() if node.name == "TFTP_Short_Datagram")
    ]
    rendered = request.render()
    assert len(rendered) < 4, f"default render was {len(rendered)} bytes: {rendered!r}"
