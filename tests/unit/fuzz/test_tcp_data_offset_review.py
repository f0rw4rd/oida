"""Correctness tests for TCPDataOffsetByte (bug-hunt review).

Two defects are covered here:

1. ``encode()`` ignored its ``value`` argument.  boofuzz's ``Fuzzable.render()``
   calls ``encode(value=self.get_value(mutation_context), ...)``, so an encode
   that recomputes from scratch renders the *same* byte for every declared
   mutation -- the field reports 25 test cases but is never actually fuzzed.

2. ``_find_options_block()`` looked the options block up by its *bare* name in
   ``request.names``, which boofuzz keys by *qualified* name ("req.block").
   ``dict.get`` never raises ``KeyError``, so the recursive fallback was dead
   code and the options size was always 0 -- Data_Offset was pinned at 5 words
   (0x50) no matter how many option bytes followed it.
"""

import pytest

boofuzz = pytest.importorskip("boofuzz")

from boofuzz import Block, Bytes, Request  # noqa: E402
from boofuzz.mutation_context import MutationContext  # noqa: E402

from oida.fuzz.primitives.tcp_data_offset import TCPDataOffsetByte  # noqa: E402


def _build(option_bytes: bytes):
    primitive = TCPDataOffsetByte(options_block_name="opts", name="do")
    request = Request(
        "tcp",
        children=(
            primitive,
            Block("opts", children=(Bytes("o", option_bytes, fuzzable=False),)),
        ),
    )
    return primitive, request


def _render_all(request):
    return [request.render(MutationContext(mutations=m)) for m in request.get_mutations()]


def test_every_declared_mutation_reaches_the_wire():
    """Bug 1: all 25 mutations used to render as the identical byte 0x50."""
    primitive, request = _build(b"\x01\x01\x01\x01")

    renders = _render_all(request)

    assert len(renders) == primitive.num_mutations()
    produced = {r[:1] for r in renders}
    # The generator yields 23 distinct byte values across its 25 cases
    # (0x50 and 0xF0 are repeated by the explicit boundary cases).
    assert len(produced) == 23, sorted(b.hex() for b in produced)


def test_mutations_cover_the_documented_data_offset_space():
    """The 4-bit Data_Offset nibble must be exercised across 5..15 plus the
    invalid 0x00/0xFF boundaries and the reserved/NS bit variants."""
    _, request = _build(b"")

    produced = {r[0] for r in _render_all(request)}

    for offset in range(5, 16):
        assert (offset << 4) in produced, f"data offset {offset} never rendered"
    assert 0x00 in produced, "invalid zero-length header never rendered"
    assert 0xFF in produced, "all-bits-set boundary never rendered"
    for reserved in range(1, 8):
        assert (5 << 4) | (reserved << 1) in produced, f"reserved={reserved} never rendered"
    for offset in (5, 10, 15):
        assert (offset << 4) | 1 in produced, f"NS flag with offset={offset} never rendered"


@pytest.mark.parametrize(
    ("option_bytes", "expected_words"),
    [
        (b"", 5),  # 20 byte header, no options
        (b"\x01\x01\x01\x01", 6),  # +4 bytes of options
        (b"\x02\x04\x05\xb4" * 2, 7),  # +8 bytes
        (b"\x00" * 40, 15),  # maximum options -> 60 byte header
        (b"\x00" * 64, 15),  # over-long options clamp at 15 words
    ],
)
def test_data_offset_tracks_the_options_block_size(option_bytes, expected_words):
    """Bug 2: the options block was never found, so this was always 5 words."""
    primitive, _request = _build(option_bytes)

    assert primitive._get_options_size() == len(option_bytes)
    assert primitive.encode(None, None) == bytes([expected_words << 4])


def test_unmutated_render_still_reflects_the_options_block():
    """The non-fuzzed render must carry the calculated offset, not a mutation."""
    _, request = _build(b"\x01\x01\x01\x01")

    rendered = request.render()

    assert rendered[0] == 0x60  # (20 + 4) / 4 == 6 words


def test_reserved_and_ns_flags_are_placed_in_the_low_bits():
    primitive = TCPDataOffsetByte(options_block_name="opts", ns_flag=1, reserved=0b101, name="do")
    Request("tcp", children=(primitive, Block("opts", children=(Bytes("o", b"", fuzzable=False),))))

    # DDDD RRR N  ->  0101 101 1
    assert primitive.encode(None, None) == bytes([(5 << 4) | (0b101 << 1) | 1])
