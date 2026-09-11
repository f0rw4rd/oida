"""Regression tests for ReducedString byte-fidelity of Latin-1-range payloads.

boofuzz's ``String.encode()`` does ``value.encode(self.encoding, "replace")`` and
``String``'s default encoding is ``"utf-8"``. ``ReducedString`` (and its subclass
``SmartStringPrimitive``) ship curated payload literals like ``"\\xde\\xad\\xbe\\xef"``
and ``"\\xc0\\x80"`` whose characters in the U+0080-U+00FF range are meant to render
as the RAW BYTES 0xDE 0xAD 0xBE 0xEF / 0xC0 0x80, not as UTF-8-re-encoded multi-byte
sequences. Re-encoding via UTF-8 mangles every such payload and doubles the byte
length of every non-ASCII long-string boundary probe.
"""

from oida.fuzz.primitives.reduced_string import ReducedString


def _all_mutation_bytes(prim, default_value="A"):
    return [prim.encode(m, None) for m in prim.mutations(default_value)]


class TestReducedStringByteFidelity:
    def test_deadbeef_bytes_present(self):
        prim = ReducedString(name="f", default_value="A")
        outs = _all_mutation_bytes(prim)
        assert any(b"\xde\xad\xbe\xef" in o for o in outs), (
            "no mutation contains the literal bytes b'\\xde\\xad\\xbe\\xef'"
        )

    def test_pure_ff_bytes_present(self):
        prim = ReducedString(name="f", default_value="A")
        outs = _all_mutation_bytes(prim)
        assert any(o == b"\xff" * len(o) and len(o) > 0 for o in outs), (
            "no mutation is pure 0xff bytes"
        )

    def test_malformed_utf8_present(self):
        prim = ReducedString(name="f", default_value="A")
        outs = _all_mutation_bytes(prim)
        malformed = []
        for o in outs:
            try:
                o.decode("utf-8")
            except UnicodeDecodeError:
                malformed.append(o)
        assert malformed, "no mutation is genuinely malformed UTF-8"

    def test_ff_long_string_boundary_lengths(self):
        prim = ReducedString(name="f", default_value="A")
        outs = _all_mutation_bytes(prim)
        ff_lengths = {len(o) for o in outs if len(o) > 0 and o == b"\xff" * len(o)}
        for expected in (255, 256, 257):
            assert expected in ff_lengths, (
                f"expected a pure-0xff mutation of exactly {expected} bytes, "
                f"got lengths: {sorted(ff_lengths)}"
            )

    def test_ascii_payload_byte_for_byte_unchanged(self):
        prim = ReducedString(name="f", default_value="A")
        # "A" * 10 + "\x00" is one of the curated ASCII-range fuzz_library entries.
        ascii_payload = "A" * 10 + "\x00"
        assert prim.encode(ascii_payload, None) == ascii_payload.encode("utf-8")
