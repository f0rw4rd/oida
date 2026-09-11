"""Regression tests for confirmed BACnet fuzzer bugs: BVLL_Length desync
across 12 requests, and three inner tag-length lies (MAC_Length, two
password tags).

These assert on the RENDERED BYTES of the real boofuzz Request objects
produced by the BACnet fuzzer, never on source text.
"""

from __future__ import annotations

import struct

import pytest
from boofuzz.mutation_context import MutationContext

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

# These five requests intentionally lie about BVLL_Length as the point of the
# test case (self-advertised malformed-length attacks). They must NOT be
# "fixed" -- the mismatch IS the test.
SELF_ADVERTISED_LIES = {
    "BACnet_Malformed_APDU",
    "BACnet_BVLC_Overflow",
    "BACnet_APDU_Truncated",
    "BACnet_APDU_Length_Underflow",
    "BACnet_BVLL_Length_Desync",
}


def _make_fuzzer():
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=47808,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    config.protocol_options = getattr(config, "protocol_options", {}) or {}
    config.protocol_options["enable_reinit"] = True
    config.protocol_options["enable_auth"] = True
    return PROTOCOL_FUZZERS["bacnet"](config=config, connection_factory=MockConnectionFactory())


@pytest.fixture(scope="module")
def nodes():
    fz = _make_fuzzer()
    return {n.name: n for n in fz.session.nodes.values() if hasattr(n, "render")}


def _find_primitive(request, name):
    for n in request.walk():
        if getattr(n, "name", None) == name:
            return n
    raise AssertionError(f"primitive {name!r} not found in request {request.name!r}")


def _bvll_length_ok(data: bytes) -> bool:
    if len(data) < 4:
        return False
    declared = struct.unpack(">H", data[2:4])[0]
    return declared == len(data)


# ---------------------------------------------------------------------------
# Bug 4: BVLL_Length must cover the whole BVLL message including its 4-byte
# BVLC header, for every request except the five self-advertised liars.
# ---------------------------------------------------------------------------


def test_bvll_length_matches_frame_size_baseline(nodes):
    checked = 0
    for name, request in nodes.items():
        if name in SELF_ADVERTISED_LIES:
            continue
        data = request.render()
        declared = struct.unpack(">H", data[2:4])[0]
        assert declared == len(data), (
            f"{name}: BVLL_Length={declared} but rendered frame is {len(data)} bytes"
        )
        checked += 1
    assert checked > 0


@pytest.mark.parametrize(
    "req_name,fuzzable_field",
    [
        ("BACnet_Object_ID_Boundary", "Object_ID_Boundary"),
        ("BACnet_Property_ID_Boundary", "Property_ID_Boundary"),
        ("BACnet_Read_Property", "Property_Value"),
        ("BACnet_Read_Object_List", "Object_List_Property"),
        ("BACnet_I_Am", "Vendor_ID"),
        ("BACnet_Confirmed_Event_Notification", "Notification_Class"),
        ("BACnet_NPDU_Control_Fuzz", "NPDU_Control_Fuzz"),
        ("BACnet_Authenticate", "Operator_Name"),
        ("BACnet_Request_Key", "MAC_Address"),
        ("BACnet_Reinitialize_With_Password", "Device_Password"),
        ("BACnet_DCC_With_Password", "DCC_Password"),
        ("BACnet_AtomicFile_Payload", "Traversal_Filename"),
    ],
)
def test_bvll_length_tracks_mutations(nodes, req_name, fuzzable_field):
    """BVLL_Length must stay correct even as the body's fuzzable fields
    mutate (in particular AtomicFile_Payload's variable-length filename
    tail, which a hardcoded constant can never track)."""
    request = nodes[req_name]
    primitive = _find_primitive(request, fuzzable_field)

    checked = 0
    for mutation_list in primitive.get_mutations():
        ctx = MutationContext(mutation_list)
        data = request.render(mutation_context=ctx)
        assert _bvll_length_ok(data), (
            f"{req_name}: BVLL_Length wrong under mutation #{checked} of {fuzzable_field}"
        )
        checked += 1
        if checked >= 25:  # bound runtime; we only need to prove it tracks, not exhaust it
            break
    assert checked > 0, f"no mutations were generated for {fuzzable_field} on {req_name}"


def test_self_advertised_lies_are_left_alone(nodes):
    """The five malformed-length attack requests must keep lying -- this is
    the whole point of the test case, not a bug."""
    expected_mismatches = {
        "BACnet_Malformed_APDU": (255, 210),
        "BACnet_BVLC_Overflow": (65535, 259),
        "BACnet_APDU_Truncated": (19, 13),
        "BACnet_APDU_Length_Underflow": (23, 5),
        "BACnet_BVLL_Length_Desync": (65535, 16),
    }
    for name, (declared_expected, actual_expected) in expected_mismatches.items():
        data = nodes[name].render()
        declared = struct.unpack(">H", data[2:4])[0]
        assert declared == declared_expected
        assert len(data) == actual_expected
        assert declared != len(data), f"{name} unexpectedly has a consistent BVLL_Length"


# ---------------------------------------------------------------------------
# Bug 5: inner tag lengths must match their actual rendered value bytes.
# ---------------------------------------------------------------------------


def test_mac_length_matches_mac_address_bytes(nodes):
    """Request_Key: MAC_Length must declare the actual length of the
    MAC_Address ASCII string ("010203040506" = 12 bytes), not 6."""
    request = nodes["BACnet_Request_Key"]
    data = request.render()

    # Walk: ... MAC_Tag(0x75) MAC_Length(1 byte) MAC_Address(N bytes) Req_Addr_Close(0x1F) ...
    idx = data.index(b"\x75")
    mac_length = data[idx + 1]
    mac_address = b"010203040506"
    assert data[idx + 2 : idx + 2 + mac_length] == mac_address[:mac_length]
    assert mac_length == len(mac_address), (
        f"MAC_Length declares {mac_length} but MAC_Address is {len(mac_address)} bytes"
    )


def test_reinitialize_password_tag_length_matches_value(nodes):
    """Reinitialize_With_Password: the password opening tag must declare
    the actual length of the rendered password ("password" = 8 bytes)."""
    request = nodes["BACnet_Reinitialize_With_Password"]
    data = request.render()
    password = b"password"

    idx = data.index(password)
    tag_byte = data[idx - 1]
    declared_len = tag_byte & 0x0F
    assert declared_len == len(password), (
        f"password tag declares length {declared_len} but value is {len(password)} bytes "
        f"(tag byte {tag_byte:#x})"
    )


def test_dcc_password_tag_length_matches_value(nodes):
    """DCC_With_Password: the password tag must declare the actual length
    of the rendered password ("password" = 8 bytes), not 13 (which would
    make a target honouring the tag length read 5 bytes past the frame)."""
    request = nodes["BACnet_DCC_With_Password"]
    data = request.render()
    password = b"password"

    idx = data.index(password)
    tag_byte = data[idx - 1]
    declared_len = tag_byte & 0x0F
    assert declared_len == len(password), (
        f"password tag declares length {declared_len} but value is {len(password)} bytes "
        f"(tag byte {tag_byte:#x})"
    )
