"""Regression tests for confirmed NTP fuzzer bugs (mode-7 header layout,
extension-field lengths, and Count/DataSize desync).

These assert on the RENDERED BYTES of the real boofuzz Request objects
produced by the NTP fuzzer, never on source text.
"""

from __future__ import annotations

import struct

import pytest
from boofuzz.mutation_context import MutationContext

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS


def _make_fuzzer():
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=123,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    config.protocol_options = getattr(config, "protocol_options", {}) or {}
    config.protocol_options["enable_auth"] = True
    return PROTOCOL_FUZZERS["ntp"](config=config, connection_factory=MockConnectionFactory())


@pytest.fixture(scope="module")
def nodes():
    fz = _make_fuzzer()
    return {n.name: n for n in fz.session.nodes.values() if hasattr(n, "render")}


def _find_primitive(request, name):
    for n in request.walk():
        if getattr(n, "name", None) == name:
            return n
    raise AssertionError(f"primitive {name!r} not found in request {request.name!r}")


# ---------------------------------------------------------------------------
# Bug 1: mode-7 header fields shifted one octet; monlist never sent
# ---------------------------------------------------------------------------


def test_monlist_attack_implementation_and_reqcode_octets(nodes):
    """NTP_Monlist_Attack must place IMPL_XNTPD at octet 2 and
    MON_GETLIST_1 (0x2A) at octet 3, per the real req_pkt layout
    (rm_vn_mode, auth_seq, implementation, request)."""
    data = nodes["NTP_Monlist_Attack"].render()
    assert data[2] == 0x03, f"expected implementation=0x03 (IMPL_XNTPD) at octet 2, got {data[2]:#x}"
    assert data[3] == 0x2A, f"expected request code=0x2A (MON_GETLIST_1) at octet 3, got {data[3]:#x}"


def test_private_request_implementation_and_reqcode_octets(nodes):
    data = nodes["NTP_Private_Request"].render()
    assert data[2] == 0x03, f"expected implementation=0x03 at octet 2, got {data[2]:#x}"


# ---------------------------------------------------------------------------
# Bug 2: extension-field lengths must include the 4-byte header, be 4-byte
# aligned, and never run past the end of the packet.
# ---------------------------------------------------------------------------


def _walk_extension_chain(data: bytes, start: int = 48):
    """Yield (offset, declared_length) for every extension in the chain,
    walking from the fixed 48-byte NTP header."""
    offset = start
    chain = []
    while offset < len(data):
        assert offset + 4 <= len(data), f"truncated extension header at offset {offset}"
        _ext_type, declared = struct.unpack(">HH", data[offset : offset + 4])
        chain.append((offset, declared))
        assert declared >= 4, f"ext@{offset} declared length {declared} < 4-byte header"
        assert declared % 4 == 0, f"ext@{offset} declared length {declared} is not 4-byte aligned"
        assert offset + declared <= len(data), (
            f"ext@{offset} declared length {declared} overruns packet "
            f"(only {len(data) - offset} bytes remain)"
        )
        offset += declared
    return chain


@pytest.mark.parametrize(
    "req_name",
    ["NTP_Extension_Request", "NTP_Autokey_Request", "NTP_Multi_Extension_Request"],
)
def test_extension_chain_lengths_are_sane(nodes, req_name):
    data = nodes[req_name].render()
    chain = _walk_extension_chain(data)
    assert chain, f"{req_name} produced no extensions to walk"


# ---------------------------------------------------------------------------
# Bug 3: Count/DataSize must track the actual data payload, including under
# mutation of the data field.
# ---------------------------------------------------------------------------


def test_control_message_count_tracks_control_data_mutations(nodes):
    request = nodes["NTP_Control_Message"]
    control_data = _find_primitive(request, "Control_Data")

    checked = 0
    for mutation_list in control_data.get_mutations():
        ctx = MutationContext(mutation_list)
        data = request.render(mutation_context=ctx)
        count_field = struct.unpack(">H", data[10:12])[0]
        actual_data_bytes = len(data) - 12
        assert count_field == actual_data_bytes, (
            f"Count={count_field} but Control_Data is {actual_data_bytes} bytes "
            f"(mutation #{checked})"
        )
        checked += 1
    assert checked > 0, "no Control_Data mutations were generated"


def test_private_request_datasize_tracks_private_data_mutations(nodes):
    request = nodes["NTP_Private_Request"]
    private_data = _find_primitive(request, "Private_Data")

    checked = 0
    for mutation_list in private_data.get_mutations():
        ctx = MutationContext(mutation_list)
        data = request.render(mutation_context=ctx)
        # Private_Header: LI_VN_Mode(1) AuthSeq(1) Implementation(1) RequestCode(1)
        # Flags(1) Sequence(2) Status(2) DataSize(2) Reserved(4) = 15 bytes header
        data_size_field = struct.unpack(">H", data[9:11])[0]
        actual_data_bytes = len(data) - 15
        assert data_size_field == actual_data_bytes, (
            f"DataSize={data_size_field} but Private_Data is {actual_data_bytes} bytes "
            f"(mutation #{checked})"
        )
        checked += 1
    assert checked > 0, "no Private_Data mutations were generated"
