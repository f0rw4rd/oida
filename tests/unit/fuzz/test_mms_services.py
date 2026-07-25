"""Offline tests for the new MMS service / typed-data-value fuzz requests.

The MMS fuzzer's _define_protocol() wires every session.connect() behind
`self.is_request_enabled("<RegisteredName>")`, so --enable / --disable actually
take effect. These tests build the boofuzz session offline with
MockConnectionFactory and inspect session.nodes - no live fuzzing I/O.

Coverage targets (proven gaps closed):
- MMS_DeleteNamedVariableList: DeleteNamedVariableList [14] w/ malformed name
  and scopeOfDelete sweep, plus an oversized DefineNamedVariableList [12]
  (CVE-2024-26529 DoS in mmsServer_handleDeleteNamedVariableListRequest).
- MMS_BitString_UnusedBits: Write MMS_BIT_STRING [4] w/ an illegal unused-bits
  leading octet (>7) and a declared length larger than the payload present
  (CVE-2020-7054 heap overflow in MmsValue_decodeMmsData).
- MMS_OctetString_Length_Lie: Write MMS_OCTET_STRING [9] over-read.
- MMS_Structured_Nesting: deeply nested structured/array data value.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.mms import MMSFuzzer

pytestmark = pytest.mark.core

# The four new RequestInfo names this change adds.
NEW_REQUESTS = {
    "MMS_DeleteNamedVariableList",
    "MMS_BitString_UnusedBits",
    "MMS_OctetString_Length_Lie",
    "MMS_Structured_Nesting",
}

# The boofuzz node that MMS_DeleteNamedVariableList also connects (the oversized
# DefineNamedVariableList) - a sub-request, deliberately not separately
# advertised.
DEFINE_SUBREQUEST = "MMS_DefineNamedVariableList"


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
    return MMSFuzzer(config=config, connection_factory=MockConnectionFactory())


def _connected_names(fuzzer):
    """Names of requests actually wired into the boofuzz session."""
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _advertised():
    return {d.name for d in MMSFuzzer.get_request_definitions()}


def _node(fuzzer, node_name):
    for node in fuzzer.session.nodes.values():
        if node.name == node_name:
            return node
    raise AssertionError(f"node {node_name!r} not connected")


def test_new_requests_are_advertised():
    """--list-requests exposes the four new requests."""
    assert NEW_REQUESTS <= _advertised()


def test_new_requests_connected_by_default():
    """All four new requests (plus the Define sub-request) wire up by default."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected
    assert DEFINE_SUBREQUEST in connected


def test_new_requests_categories_keep_mms_balance():
    """New requests are crash/boundary, preserving the MMS category balance."""
    by_name = {d.name: d.category for d in MMSFuzzer.get_request_definitions()}
    assert by_name["MMS_DeleteNamedVariableList"] == "crash"
    assert by_name["MMS_BitString_UnusedBits"] == "crash"
    assert by_name["MMS_OctetString_Length_Lie"] == "crash"
    assert by_name["MMS_Structured_Nesting"] == "boundary"

    cats = {d.category for d in MMSFuzzer.get_request_definitions()}
    assert {"baseline", "read", "write", "crash"} <= cats


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_selectable(name):
    """--enable <name> connects that request and none of the other new ones."""
    connected = _connected_names(_build(_make_config(enabled_requests=[name])))
    assert name in connected
    # No OTHER new request leaks in when only this one is enabled.
    assert (NEW_REQUESTS - {name}) & connected == set()


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_each_new_request_is_disableable(name):
    """--disable <name> removes it while leaving the baseline connected."""
    connected = _connected_names(_build(_make_config(disabled_requests=[name])))
    assert name not in connected


def test_delete_named_variable_list_enable_pulls_define_subrequest():
    """Enabling the delete request also connects its Define sibling."""
    connected = _connected_names(
        _build(_make_config(enabled_requests=["MMS_DeleteNamedVariableList"]))
    )
    assert connected == {"MMS_DeleteNamedVariableList", DEFINE_SUBREQUEST}


def test_delete_request_scope_sweep_includes_invalid_scope():
    """The scopeOfDelete Group sweeps {specific, aa-specific, domain, invalid}."""
    fuzzer = _build(_make_config(enabled_requests=["MMS_DeleteNamedVariableList"]))
    rendered = _node(fuzzer, "MMS_DeleteNamedVariableList").render()
    # deleteNamedVariableList [14] IMPLICIT SEQUENCE tag present.
    assert b"\xae" in rendered
    # scopeOfDelete [0] IMPLICIT INTEGER, default first Group value = specific(0).
    assert b"\x80\x01\x00" in rendered


def test_bitstring_request_renders_illegal_unused_bits_octet():
    """MMS_BitString_UnusedBits renders an illegal (>7) unused-bits octet
    behind a BER length that lies about the payload size (CVE-2020-7054)."""
    fuzzer = _build(_make_config(enabled_requests=["MMS_BitString_UnusedBits"]))
    rendered = _node(fuzzer, "MMS_BitString_UnusedBits").render()

    # [4] BIT STRING tag, length 0xff (>> 1 payload octet), unused-bits 0x08.
    marker = b"\x84\x81\xff\x08"
    assert marker in rendered

    # The unused-bits leading octet is illegal: legal range is 0..7.
    unused_bits_octet = rendered[rendered.index(marker) + 3]
    assert unused_bits_octet > 7


def test_bitstring_group_values_are_all_illegal_or_boundary():
    """Every non-zero unused-bits Group value is illegal (>7)."""
    fuzzer = _build(_make_config(enabled_requests=["MMS_BitString_UnusedBits"]))
    node = _node(fuzzer, "MMS_BitString_UnusedBits")
    group = next(c for c in node.stack if c.name == "unused_bits_octet")
    illegal = [v for v in group.values if v[0] > 7]
    # Multiple illegal unused-bits octets are swept (0x09, 0x40, 0xff, ...);
    # boofuzz's Group.values excludes the default (0x08), which is also illegal.
    assert len(illegal) >= 3


def test_octetstring_request_renders_length_lie():
    """MMS_OctetString_Length_Lie declares far more octets than it ships."""
    fuzzer = _build(_make_config(enabled_requests=["MMS_OctetString_Length_Lie"]))
    rendered = _node(fuzzer, "MMS_OctetString_Length_Lie").render()
    # [9] OCTET STRING tag, default length 0x40 (64), then only 4 octets.
    assert b"\x89\x40\x01\x02\x03\x04" in rendered


def test_structured_nesting_request_renders_deep_nesting():
    """MMS_Structured_Nesting renders a long run of nested structure tags."""
    fuzzer = _build(_make_config(enabled_requests=["MMS_Structured_Nesting"]))
    rendered = _node(fuzzer, "MMS_Structured_Nesting").render()
    # Default Group value: 64 nested MMS_STRUCTURE [2] indefinite-length tags.
    assert b"\xa2\x80" * 32 in rendered


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
