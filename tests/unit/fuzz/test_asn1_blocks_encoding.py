"""Encoding/mutation coverage for ASN.1 boofuzz block primitives.

Complements ``test_asn1_primitives.py`` / ``test_asn1_blocks_render.py`` by
driving the byte-construction branches that those files leave uncovered:

- ``encode_length`` long-form (3- and 4-byte) branches
- ``BERSize`` BER length emission via ``_length_to_bytes``
- ``ASN1BitString`` (the whole class was untested)
- value-mutation branches of OID / Null / VisibleString
- the ``encode()`` mutation-context dispatch and non-fuzzable paths

All assertions are on concrete byte output / mutation structure.
"""

from oida.fuzz.primitives.asn1_blocks import (
    ASN1BitString,
    ASN1Boolean,
    ASN1Integer,
    ASN1Null,
    ASN1OctetString,
    ASN1OID,
    ASN1Primitive,
    ASN1Sequence,
    ASN1Tag,
    ASN1VisibleString,
    BERSize,
    encode_length,
    encode_integer_content,
    encode_oid_content,
)


# ---------------------------------------------------------------------------
# Minimal boofuzz mutation_context stand-in (a plain value holder, not a patch
# of the code under test). encode() reads .mutation_index off whatever it gets.
# ---------------------------------------------------------------------------
class _Ctx:
    def __init__(self, idx):
        self.mutation_index = idx


# ---------------------------------------------------------------------------
# encode_length long-form branches
# ---------------------------------------------------------------------------
class TestEncodeLengthLongForm:
    def test_three_byte_form(self):
        # 0x10000 .. 0xFFFFFF -> 0x83 prefix, 3 length octets
        assert encode_length(0x10000) == b"\x83\x01\x00\x00"
        assert encode_length(0xFFFFFF) == b"\x83\xff\xff\xff"

    def test_four_byte_form(self):
        # > 0xFFFFFF -> 0x84 prefix, 4 length octets
        assert encode_length(0x1000000) == b"\x84\x01\x00\x00\x00"
        assert encode_length(0x12345678) == b"\x84\x12\x34\x56\x78"

    def test_two_byte_boundary(self):
        assert encode_length(0x100) == b"\x82\x01\x00"
        assert encode_length(0xFFFF) == b"\x82\xff\xff"


# ---------------------------------------------------------------------------
# BERSize: BER definite-form length field
# ---------------------------------------------------------------------------
class TestBERSize:
    def test_short_form_length(self):
        sz = BERSize("len", "blk", fuzzable=False)
        # math(length) returns the length unchanged by default -> short form
        assert sz._length_to_bytes(5) == b"\x05"
        assert sz._length_to_bytes(0x7F) == b"\x7f"

    def test_long_form_length(self):
        sz = BERSize("len", "blk", fuzzable=False)
        # 128 must not collapse to raw 0x80 (BER indefinite marker)
        assert sz._length_to_bytes(128) == b"\x81\x80"
        assert sz._length_to_bytes(256) == b"\x82\x01\x00"

    def test_constructor_strips_conflicting_kwargs(self):
        # length/endian/output_format are force-overridden; passing them must
        # not raise and BER emission must still be correct.
        sz = BERSize("len", "blk", length=1, endian="<", output_format="binary", fuzzable=False)
        assert sz._length_to_bytes(200) == b"\x81\xc8"


# ---------------------------------------------------------------------------
# ASN1BitString: previously entirely uncovered
# ---------------------------------------------------------------------------
class TestASN1BitString:
    def test_original_value_prepends_unused_bits(self):
        # content = unused-bits octet (0x00) + data
        field = ASN1BitString("flags", b"\xde\xad", unused_bits=0)
        result = field.original_value()
        assert result == b"\x03\x03\x00\xde\xad"  # tag 0x03, len 3, 00 de ad

    def test_unused_bits_value_is_encoded(self):
        field = ASN1BitString("flags", b"\xff", unused_bits=3)
        result = field.original_value()
        assert result == b"\x03\x02\x03\xff"

    def test_context_tag(self):
        field = ASN1BitString("flags", b"\x01", context_tag=2)
        # CONTEXT (0x80) | 2 = 0x82
        assert field.original_value()[0] == 0x82

    def test_value_mutations_invalid_unused_bits(self):
        field = ASN1BitString("flags", b"\xaa")
        muts = list(field.mutations(None))
        # invalid unused-bit counts 8 / 9 / 255 appear as the value's first
        # content octet (right after tag+length).
        invalid_unused_present = any(
            len(m) >= 3 and m[0] == 0x03 and m[2] in (8, 9, 255) for m in muts
        )
        assert invalid_unused_present
        # all-ones and all-zeros bit string mutations
        assert (b"\x03\x02\x00\xff") in muts
        assert (b"\x03\x02\x00\x00") in muts

    def test_non_fuzzable_has_only_valid_encoding(self):
        field = ASN1BitString("flags", b"\x01", fuzzable=False)
        assert field.num_mutations() == 0
        assert field.original_value() == b"\x03\x02\x00\x01"


# ---------------------------------------------------------------------------
# ASN1OID value mutations
# ---------------------------------------------------------------------------
class TestASN1OIDMutations:
    def test_common_oid_mutations_present(self):
        field = ASN1OID("oid", "1.2.3")
        muts = list(field.mutations(None))
        # RSA OID 1.2.840.113549.1.1.1 content must appear in some mutation
        rsa_content = encode_oid_content("1.2.840.113549.1.1.1")
        assert any(rsa_content in m for m in muts)

    def test_empty_and_single_byte_oid(self):
        field = ASN1OID("oid", "1.2.3")
        muts = list(field.mutations(None))
        assert b"\x06\x00" in muts  # empty OID
        assert b"\x06\x01\x00" in muts  # single byte OID

    def test_default_oid_excluded_from_common_list(self):
        # When the default IS one of the common OIDs, it must not be re-emitted
        # as a value mutation duplicate.
        field = ASN1OID("oid", "1.0.9506.2.3")
        muts = list(field.mutations(None))
        own_content = encode_oid_content("1.0.9506.2.3")
        own_tlv = b"\x06" + encode_length(len(own_content)) + own_content
        # the valid encoding is skipped by mutations(); it should not reappear
        assert muts.count(own_tlv) == 0


# ---------------------------------------------------------------------------
# ASN1Null length mutations (override path)
# ---------------------------------------------------------------------------
class TestASN1NullLengthMutations:
    def test_null_with_content_is_a_mutation(self):
        field = ASN1Null("n")
        muts = list(field.mutations(None))
        # NULL carrying content (invalid) - tag 0x05 with non-zero length
        assert b"\x05\x01\x00" in muts
        assert b"\x05\x02\x00\x00" in muts

    def test_null_value_mutations_disabled(self):
        # ASN1Null constructs with fuzz_value=False; value mutations absent but
        # tag + length mutations still present.
        field = ASN1Null("n")
        assert field.num_mutations() > 0


# ---------------------------------------------------------------------------
# ASN1VisibleString value mutations
# ---------------------------------------------------------------------------
class TestASN1VisibleStringMutations:
    def test_format_string_and_jndi_payloads(self):
        field = ASN1VisibleString("s", "x", max_len=2048)
        muts = list(field.mutations(None))
        joined = b" ".join(muts)
        assert b"%s%s%s%s" in joined
        assert b"${jndi:ldap://x}" in joined

    def test_non_ascii_payload(self):
        field = ASN1VisibleString("s", "x")
        muts = list(field.mutations(None))
        assert b"\x80\x81\xff\xfe" in b"".join(muts)

    def test_max_len_caps_long_strings(self):
        # With a tiny max_len, the 128/256/1024 long-string mutations are skipped
        small = ASN1VisibleString("s", "x", max_len=16)
        big = ASN1VisibleString("s", "x", max_len=2048)
        assert small.num_mutations() < big.num_mutations()


# ---------------------------------------------------------------------------
# encode() dispatch via mutation_context
# ---------------------------------------------------------------------------
class TestEncodeDispatch:
    def test_encode_returns_indexed_mutation(self):
        field = ASN1Integer("i", 42)
        # index 0 is the valid encoding
        assert field.encode(None, _Ctx(0)) == b"\x02\x01\x2a"
        # a later index returns the corresponding stored mutation
        assert field.encode(None, _Ctx(1)) == list(field._mutations)[1]

    def test_encode_out_of_range_falls_back_to_valid(self):
        field = ASN1Integer("i", 42)
        huge = _Ctx(10_000)
        assert field.encode(None, huge) == b"\x02\x01\x2a"

    def test_encode_without_context_returns_valid(self):
        field = ASN1Integer("i", 7)
        assert field.encode(None, None) == b"\x02\x01\x07"


# ---------------------------------------------------------------------------
# ASN1Sequence non-fuzzable + encode + empty original_value branch
# ---------------------------------------------------------------------------
class TestASN1SequenceBranches:
    def test_non_fuzzable_sequence_only_valid(self):
        child = ASN1Integer("c", 5, fuzzable=False)
        seq = ASN1Sequence("seq", children=[child], fuzzable=False)
        assert seq.num_mutations() == 0
        assert seq.original_value() == b"\x30\x03\x02\x01\x05"

    def test_sequence_encode_dispatch(self):
        child = ASN1Integer("c", 1, fuzzable=False)
        seq = ASN1Sequence("seq", children=[child])
        assert seq.encode(None, _Ctx(0)) == seq.original_value()
        assert seq.encode(None, _Ctx(99999)) == seq.original_value()

    def test_tag_only_fuzz_skips_length_mutations(self):
        child = ASN1Integer("c", 1, fuzzable=False)
        only_tag = ASN1Sequence("seq", children=[child], fuzz_tag=True, fuzz_length=False)
        both = ASN1Sequence("seq", children=[child], fuzz_tag=True, fuzz_length=True)
        assert only_tag.num_mutations() < both.num_mutations()


# ---------------------------------------------------------------------------
# encode_integer_content negative two's-complement boundaries
# ---------------------------------------------------------------------------
class TestEncodeIntegerContentNegative:
    def test_negative_multibyte_boundaries(self):
        # -129 needs two octets (0xFF 0x7F), -128 fits one (0x80)
        assert encode_integer_content(-128) == b"\x80"
        assert encode_integer_content(-129) == b"\xff\x7f"
        assert encode_integer_content(-256) == b"\xff\x00"

    def test_negative_loop_terminates_on_positive_msb(self):
        # -200: low octet 0x38, then n becomes -1 with msb set -> break.
        # Exercises the n == -1 termination branch.
        assert encode_integer_content(-200) == b"\xff\x38"

    def test_positive_requires_padding(self):
        assert encode_integer_content(255) == b"\x00\xff"
        assert encode_integer_content(256) == b"\x01\x00"


# ---------------------------------------------------------------------------
# encode_oid_content: zero-valued sub-identifier branch
# ---------------------------------------------------------------------------
class TestEncodeOIDContentZeroComponent:
    def test_zero_component_emits_single_zero_octet(self):
        # 1.2.0.5 -> first octet 40*1+2=42, then 0x00 for the zero component,
        # then 0x05.
        assert encode_oid_content("1.2.0.5") == bytes([42, 0x00, 0x05])

    def test_multibyte_component_high_bit_continuation(self):
        # component 9506 spans two base-128 groups with continuation bits.
        result = encode_oid_content("1.0.9506.2.3")
        assert result[0] == 40  # 40*1 + 0
        assert len(result) >= 4


# ---------------------------------------------------------------------------
# context_tag constructor branches across primitive types
# ---------------------------------------------------------------------------
class TestContextTagBranches:
    def test_boolean_context_tag(self):
        field = ASN1Boolean("b", True, context_tag=1)
        # CONTEXT (0x80) | 1
        assert field.original_value()[0] == 0x81

    def test_octet_string_context_tag(self):
        field = ASN1OctetString("o", b"hi", context_tag=3)
        assert field.original_value()[0] == 0x83
        assert field.original_value()[2:] == b"hi"

    def test_oid_context_tag(self):
        field = ASN1OID("oid", "1.2.3", context_tag=5)
        assert field.original_value()[0] == ASN1Tag.CONTEXT | 5

    def test_null_context_tag(self):
        field = ASN1Null("n", context_tag=0)
        assert field.original_value()[0] == ASN1Tag.CONTEXT  # 0x80 | 0
        assert field.original_value()[1] == 0x00

    def test_visible_string_context_tag(self):
        field = ASN1VisibleString("s", "ab", context_tag=4)
        assert field.original_value()[0] == ASN1Tag.CONTEXT | 4
        assert b"ab" in field.original_value()


# ---------------------------------------------------------------------------
# Base ASN1Primitive with no value-mutation override
# ---------------------------------------------------------------------------
class TestBasePrimitiveNoValueMutations:
    def test_base_value_mutations_empty_but_tag_length_present(self):
        # ASN1Primitive itself returns [] from _generate_value_mutations,
        # but tag + length mutations are still generated when fuzzable.
        prim = ASN1Primitive("raw", ASN1Tag.OCTET_STRING, b"\x01\x02")
        muts = list(prim.mutations(None))
        assert prim.original_value() == b"\x04\x02\x01\x02"
        assert len(muts) > 0
        # a tag mutation flipping to SEQUENCE (0x30) should be present
        assert any(m[0] == 0x30 for m in muts)

    def test_base_primitive_empty_original_value(self):
        # original_value returns b"" only when there are no mutations; with a
        # real default the valid encoding is returned.
        prim = ASN1Primitive("raw", ASN1Tag.NULL, b"", fuzzable=False, fuzz_value=False)
        assert prim.original_value() == b"\x05\x00"
