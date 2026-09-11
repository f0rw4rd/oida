"""Regression tests for tase2.py hardcoded TPKT length bug.

Six TASE.2 requests declared a fixed 12-byte TPKT+COTP header
(b"\\x03\\x00\\x00\\x0c\\x02\\xf0\\x80") while their actual rendered payload was
13-49 bytes. RFC 1006 requires the TPKT length field (bytes 2:4) to cover the
whole TPKT -- the 4-byte header plus everything after it -- so the declared
0x000c truncated every one of these messages on the wire.

The fix binds a boofuzz Size() (offset=4, big-endian, 2 bytes) to the payload
block so the length recomputes from the actual rendered bytes, including under
mutation.

TASE2_Baseline is intentionally excluded from these checks: it is two
concatenated TPKT messages (Initiate + GetNameList), so its total rendered
length legitimately differs from the length declared in its first TPKT header.
"""

import struct

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

# Requests that previously hardcoded TPKT length 0x000c.
FIXED_REQUESTS = [
    "TASE2_BER_Length_Attack",
    "TASE2_ObjectName_Overflow",
    "TASE2_TransferSet_Malformed",
    "TASE2_InvokeID_Boundary",
    "TASE2_BilateralTable_Malformed",
    "TASE2_MMS_Service_Boundary",
]


def _build_tase2_fuzzer():
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
    return PROTOCOL_FUZZERS["tase2"](config=config, connection_factory=MockConnectionFactory())


def _node(fz, name):
    return next(n for n in fz.session.nodes.values() if getattr(n, "name", "") == name)


def _tpkt_ok(data: bytes) -> bool:
    """True if the first TPKT header's declared length equals the rendered length."""
    if len(data) < 4:
        return False
    return struct.unpack(">H", data[2:4])[0] == len(data)


def test_tase2_baseline_tpkt_header_covers_first_message():
    """Sanity on the excluded baseline: first TPKT length field must still point at
    a message boundary within the render (two concatenated TPKTs)."""
    fz = _build_tase2_fuzzer()
    data = _node(fz, "TASE2_Baseline").render()
    declared = struct.unpack(">H", data[2:4])[0]
    assert 4 <= declared <= len(data)
    assert declared != 12  # the old bogus constant must not reappear


def test_all_fixed_requests_tpkt_length_matches_rendered_bytes():
    fz = _build_tase2_fuzzer()
    bad = []
    for name in FIXED_REQUESTS:
        data = _node(fz, name).render()
        if not _tpkt_ok(data):
            declared = struct.unpack(">H", data[2:4])[0]
            bad.append((name, declared, len(data)))
    assert not bad, f"TPKT length mismatch: {bad}"


def test_tpkt_length_tracks_mutated_payload():
    """The Size-bound length must recompute when a fuzzable payload mutates."""
    from boofuzz.mutation_context import MutationContext

    fz = _build_tase2_fuzzer()
    node = _node(fz, "TASE2_MMS_Service_Boundary")
    checked = 0
    for mutation in node.get_mutations():
        data = node.render(MutationContext(mutation))
        assert _tpkt_ok(data), f"TPKT length wrong under mutation {mutation}: {data!r}"
        checked += 1
    assert checked > 0
