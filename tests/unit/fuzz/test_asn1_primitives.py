"""
Comprehensive tests for ASN.1 primitives and encoding.

Tests cover:
- BER encoding correctness (ITU-T X.690)
- ASN.1 primitive types (Integer, Boolean, OctetString, etc.)
- ASN.1 block primitives for boofuzz (ASN1Integer, ASN1Sequence, etc.)
- Mutation generation and fuzzing capabilities
- MMS-specific encoding helpers
"""

import pytest


# =============================================================================
# Test ASN.1 BER Encoding Functions (primitives/asn1.py)
# =============================================================================


class TestBERLengthEncoding:
    """Tests for BER length field encoding."""

    def test_encode_short_form_zero(self):
        """Length 0 encodes to single byte 0x00."""
        from oida.fuzz.primitives.asn1 import encode_ber_length

        assert encode_ber_length(0) == b"\x00"

    def test_encode_short_form_max(self):
        """Length 127 encodes to single byte 0x7F."""
        from oida.fuzz.primitives.asn1 import encode_ber_length

        assert encode_ber_length(127) == b"\x7f"

    def test_encode_long_form_one_byte(self):
        """Length 128-255 encodes with 0x81 prefix."""
        from oida.fuzz.primitives.asn1 import encode_ber_length

        assert encode_ber_length(128) == b"\x81\x80"
        assert encode_ber_length(200) == b"\x81\xc8"
        assert encode_ber_length(255) == b"\x81\xff"

    def test_encode_long_form_two_bytes(self):
        """Length 256-65535 encodes with 0x82 prefix."""
        from oida.fuzz.primitives.asn1 import encode_ber_length

        assert encode_ber_length(256) == b"\x82\x01\x00"
        assert encode_ber_length(1000) == b"\x82\x03\xe8"
        assert encode_ber_length(65535) == b"\x82\xff\xff"

    def test_encode_long_form_three_bytes(self):
        """Length 65536-16777215 encodes with 0x83 prefix."""
        from oida.fuzz.primitives.asn1 import encode_ber_length

        assert encode_ber_length(65536) == b"\x83\x01\x00\x00"

    def test_encode_long_form_four_bytes(self):
        """Length > 16777215 encodes with 0x84 prefix."""
        from oida.fuzz.primitives.asn1 import encode_ber_length

        result = encode_ber_length(16777216)
        assert result[0] == 0x84


class TestBERIntegerEncoding:
    """Tests for BER integer encoding."""

    def test_encode_zero(self):
        """Integer 0 encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_integer

        result = encode_ber_integer(0)
        assert result == b"\x02\x01\x00"

    def test_encode_positive_small(self):
        """Small positive integers encode correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_integer

        # 42 = 0x2a
        result = encode_ber_integer(42)
        assert result == b"\x02\x01\x2a"

    def test_encode_positive_boundary_127(self):
        """127 encodes as single byte without padding."""
        from oida.fuzz.primitives.asn1 import encode_ber_integer

        result = encode_ber_integer(127)
        assert result == b"\x02\x01\x7f"

    def test_encode_positive_boundary_128(self):
        """128 requires leading zero (high bit set)."""
        from oida.fuzz.primitives.asn1 import encode_ber_integer

        result = encode_ber_integer(128)
        assert result == b"\x02\x02\x00\x80"

    def test_encode_positive_large(self):
        """Large positive integers encode correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_integer

        # 1000 = 0x03e8
        result = encode_ber_integer(1000)
        assert result == b"\x02\x02\x03\xe8"

    def test_encode_custom_tag(self):
        """Custom tag is used when specified."""
        from oida.fuzz.primitives.asn1 import encode_ber_integer

        result = encode_ber_integer(42, tag_value=0x82)
        assert result[0] == 0x82


class TestBERBooleanEncoding:
    """Tests for BER boolean encoding."""

    def test_encode_true(self):
        """True encodes as 0xFF."""
        from oida.fuzz.primitives.asn1 import encode_ber_boolean

        result = encode_ber_boolean(True)
        assert result == b"\x01\x01\xff"

    def test_encode_false(self):
        """False encodes as 0x00."""
        from oida.fuzz.primitives.asn1 import encode_ber_boolean

        result = encode_ber_boolean(False)
        assert result == b"\x01\x01\x00"


class TestBEROctetStringEncoding:
    """Tests for BER octet string encoding."""

    def test_encode_empty(self):
        """Empty octet string encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_octet_string

        result = encode_ber_octet_string(b"")
        assert result == b"\x04\x00"

    def test_encode_data(self):
        """Data is preserved in encoding."""
        from oida.fuzz.primitives.asn1 import encode_ber_octet_string

        result = encode_ber_octet_string(b"\x01\x02\x03")
        assert result == b"\x04\x03\x01\x02\x03"


class TestBERVisibleStringEncoding:
    """Tests for BER visible string encoding."""

    def test_encode_ascii(self):
        """ASCII string encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_visible_string

        result = encode_ber_visible_string("test")
        assert result == b"\x1a\x04test"

    def test_encode_empty(self):
        """Empty string encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_visible_string

        result = encode_ber_visible_string("")
        assert result == b"\x1a\x00"


class TestBERObjectIdentifierEncoding:
    """Tests for BER OID encoding."""

    def test_encode_simple_oid(self):
        """Simple OID encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_object_identifier

        # OID 1.2.3 -> first byte = 40*1 + 2 = 42, then 3
        result = encode_ber_object_identifier("1.2.3")
        assert result[0] == 0x06  # OID tag
        assert result[2] == 42  # 40*1 + 2

    def test_encode_mms_oid(self):
        """MMS OID 1.0.9506.2.3 encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_object_identifier

        result = encode_ber_object_identifier("1.0.9506.2.3")
        assert result[0] == 0x06  # OID tag


class TestBERSequenceEncoding:
    """Tests for BER sequence encoding."""

    def test_encode_empty_sequence(self):
        """Empty sequence encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_sequence

        result = encode_ber_sequence(b"")
        assert result == b"\x30\x00"

    def test_encode_sequence_with_contents(self):
        """Sequence wraps contents correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_sequence

        result = encode_ber_sequence(b"\x02\x01\x2a")  # INTEGER 42
        assert result == b"\x30\x03\x02\x01\x2a"


class TestBERContextTagEncoding:
    """Tests for BER context-specific tag encoding."""

    def test_encode_primitive_context_tag(self):
        """Primitive context tag encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_context_tag

        result = encode_ber_context_tag(0, b"\x01", False)
        assert result[0] == 0x80  # Context[0] primitive

    def test_encode_constructed_context_tag(self):
        """Constructed context tag encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_ber_context_tag

        result = encode_ber_context_tag(1, b"\x02\x01\x2a", True)
        assert result[0] == 0xA1  # Context[1] constructed

    def test_high_tag_number_raises(self):
        """Tag numbers > 30 raise ValueError."""
        from oida.fuzz.primitives.asn1 import encode_ber_context_tag

        with pytest.raises(ValueError):
            encode_ber_context_tag(31, b"\x01", False)


class TestMMSHelpers:
    """Tests for MMS-specific encoding helpers."""

    def test_encode_mms_oid(self):
        """MMS OID helper encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_mms_oid

        result = encode_mms_oid()
        assert result[0] == 0x06  # OID tag

    def test_encode_mms_integer(self):
        """MMS integer helper encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_mms_integer

        result = encode_mms_integer(42)
        assert result == b"\x02\x01\x2a"

    def test_encode_mms_integer_with_context_tag(self):
        """MMS integer with context tag encodes correctly."""
        from oida.fuzz.primitives.asn1 import encode_mms_integer

        result = encode_mms_integer(42, context_tag=0)
        # Context[0] explicit (constructed) = 0xa0, contains integer TLV
        assert result[0] == 0xA0  # Context[0] constructed/explicit
        assert b"\x02\x01\x2a" in result  # Contains integer encoding


# =============================================================================
# Test ASN.1 Builder Class (core/codecs/asn1.py)
# =============================================================================


class TestASN1Builder:
    """Tests for ASN1Builder class."""

    def test_builder_instantiation(self):
        """ASN1Builder can be instantiated."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        assert builder is not None

    def test_build_integer_zero(self):
        """Builder encodes integer 0."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_integer(0)
        assert result == b"\x02\x01\x00"

    def test_build_integer_negative(self):
        """Builder encodes negative integers correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_integer(-1)
        assert result == b"\x02\x01\xff"

    def test_build_boolean(self):
        """Builder encodes booleans correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        assert builder.build_boolean(True) == b"\x01\x01\xff"
        assert builder.build_boolean(False) == b"\x01\x01\x00"

    def test_build_null(self):
        """Builder encodes NULL correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_null()
        assert result == b"\x05\x00"

    def test_build_octet_string(self):
        """Builder encodes octet string correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_octet_string(b"test")
        assert result == b"\x04\x04test"

    def test_build_sequence(self):
        """Builder encodes sequence correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        inner = builder.build_integer(42)
        result = builder.build_sequence(inner)
        assert result[0] == 0x30  # SEQUENCE tag
        assert inner in result

    def test_build_context_specific(self):
        """Builder encodes context-specific tags correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        inner = builder.build_integer(42)
        result = builder.build_context_specific(0, inner)
        assert result[0] == 0xA0  # Context[0] constructed

    def test_build_tlv(self):
        """Builder builds TLV structures correctly."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_tlv(0x04, b"test")
        assert result == b"\x04\x04test"


class TestASN1BuilderFuzzing:
    """Tests for ASN1Builder fuzzing helpers."""

    def test_fuzz_length_variants(self):
        """Fuzzing generates length field variants."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        variants = builder.fuzz_length_variants(b"test")
        assert len(variants) > 0
        # Should include zero length, truncated, oversized
        assert any(v.startswith(b"\x00") for v in variants)

    def test_fuzz_tag_variants(self):
        """Fuzzing generates tag field variants."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        variants = builder.fuzz_tag_variants(0x02, b"\x01\x2a")
        assert len(variants) > 0
        # Should include invalid tags
        assert any(v[0] == 0xFF for v in variants)

    def test_build_with_overflow(self):
        """Overflow helper adds extra bytes."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_with_overflow(0x04, b"test", overflow_size=10)
        assert len(result) > 10

    def test_build_truncated(self):
        """Truncation helper creates mismatched length."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_truncated(0x04, b"test", truncate_by=1)
        # Length says 4 but only 3 bytes of content
        assert result[1] == 4  # Length field says 4
        assert len(result) - 2 == 3  # But only 3 bytes of content

    def test_build_nested_depth(self):
        """Deep nesting helper creates nested structures."""
        from oida.fuzz.core.codecs.asn1 import ASN1Builder

        builder = ASN1Builder()
        result = builder.build_nested_depth(0x30, b"\x02\x01\x2a", depth=5)
        # Count SEQUENCE tags
        seq_count = result.count(b"\x30")
        assert seq_count >= 5


# =============================================================================
# Test ASN.1 Boofuzz Blocks (primitives/asn1_blocks.py)
# =============================================================================


class TestASN1TagConstants:
    """Tests for ASN1Tag constants."""

    def test_universal_tags(self):
        """Universal tag constants are correct."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Tag

        assert ASN1Tag.BOOLEAN == 0x01
        assert ASN1Tag.INTEGER == 0x02
        assert ASN1Tag.BIT_STRING == 0x03
        assert ASN1Tag.OCTET_STRING == 0x04
        assert ASN1Tag.NULL == 0x05
        assert ASN1Tag.OID == 0x06
        assert ASN1Tag.SEQUENCE == 0x30
        assert ASN1Tag.SET == 0x31

    def test_tag_classes(self):
        """Tag class constants are correct."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Tag

        assert ASN1Tag.UNIVERSAL == 0x00
        assert ASN1Tag.APPLICATION == 0x40
        assert ASN1Tag.CONTEXT == 0x80
        assert ASN1Tag.PRIVATE == 0xC0


class TestASN1Integer:
    """Tests for ASN1Integer boofuzz primitive."""

    def test_creation(self):
        """ASN1Integer can be created."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test_int", 42)
        assert field is not None

    def test_original_value(self):
        """Original value is valid ASN.1 encoding."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test_int", 42)
        result = field.original_value()
        assert result[0] == 0x02  # INTEGER tag
        assert result[-1] == 42

    def test_num_mutations(self):
        """ASN1Integer generates mutations."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test_int", 42)
        assert field.num_mutations() > 0

    def test_mutations_include_boundary_values(self):
        """Mutations include integer boundary values."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test_int", 42)
        mutations = list(field.mutations(None))
        # Should have mutations for boundaries like 0, -1, 127, 128, etc.
        assert len(mutations) > 10

    def test_context_tag(self):
        """Context tag overrides default tag."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test_int", 42, context_tag=0)
        result = field.original_value()
        assert result[0] == 0x80  # Context[0]

    def test_non_fuzzable(self):
        """Non-fuzzable field has no mutations."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test_int", 42, fuzzable=False)
        assert field.num_mutations() == 0


class TestASN1Boolean:
    """Tests for ASN1Boolean boofuzz primitive."""

    def test_creation_true(self):
        """ASN1Boolean(True) encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Boolean

        field = ASN1Boolean("test_bool", True)
        result = field.original_value()
        assert result == b"\x01\x01\xff"

    def test_creation_false(self):
        """ASN1Boolean(False) encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Boolean

        field = ASN1Boolean("test_bool", False)
        result = field.original_value()
        assert result == b"\x01\x01\x00"

    def test_mutations_include_invalid_values(self):
        """Mutations include invalid boolean encodings."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Boolean

        field = ASN1Boolean("test_bool", True)
        mutations = list(field.mutations(None))
        # Should have mutations with invalid byte values like 0x01, 0x7F
        assert len(mutations) > 0


class TestASN1OctetString:
    """Tests for ASN1OctetString boofuzz primitive."""

    def test_creation_empty(self):
        """Empty octet string encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1OctetString

        field = ASN1OctetString("test_bytes", b"")
        result = field.original_value()
        assert result == b"\x04\x00"

    def test_creation_with_data(self):
        """Octet string with data encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1OctetString

        field = ASN1OctetString("test_bytes", b"hello")
        result = field.original_value()
        assert result == b"\x04\x05hello"

    def test_mutations_include_long_strings(self):
        """Mutations include oversized strings."""
        from oida.fuzz.primitives.asn1_blocks import ASN1OctetString

        field = ASN1OctetString("test_bytes", b"test", max_len=4096)
        mutations = list(field.mutations(None))
        # Should include long strings
        assert any(len(m) > 100 for m in mutations)


class TestASN1OID:
    """Tests for ASN1OID boofuzz primitive."""

    def test_creation(self):
        """OID primitive encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1OID

        field = ASN1OID("test_oid", "1.2.3")
        result = field.original_value()
        assert result[0] == 0x06  # OID tag

    def test_mutations_include_common_oids(self):
        """Mutations include common OID values."""
        from oida.fuzz.primitives.asn1_blocks import ASN1OID

        field = ASN1OID("test_oid", "1.2.3")
        mutations = list(field.mutations(None))
        assert len(mutations) > 0


class TestASN1Null:
    """Tests for ASN1Null boofuzz primitive."""

    def test_creation(self):
        """NULL primitive encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Null

        field = ASN1Null("test_null")
        result = field.original_value()
        assert result[0] == 0x05  # NULL tag
        assert result[1] == 0x00  # Zero length

    def test_mutations_include_invalid_null(self):
        """Mutations include NULL with content (invalid)."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Null

        field = ASN1Null("test_null")
        mutations = list(field.mutations(None))
        # Should include NULL with unexpected content
        assert any(len(m) > 2 for m in mutations)


class TestASN1VisibleString:
    """Tests for ASN1VisibleString boofuzz primitive."""

    def test_creation(self):
        """VisibleString encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1VisibleString

        field = ASN1VisibleString("test_str", "hello")
        result = field.original_value()
        assert result[0] == 0x1A  # VisibleString tag
        assert b"hello" in result

    def test_mutations_include_format_strings(self):
        """Mutations include format string attacks."""
        from oida.fuzz.primitives.asn1_blocks import ASN1VisibleString

        field = ASN1VisibleString("test_str", "test")
        mutations = list(field.mutations(None))
        # Should include format strings like %s, %n
        assert any(b"%" in m for m in mutations)


class TestASN1Sequence:
    """Tests for ASN1Sequence boofuzz primitive."""

    def test_creation_empty(self):
        """Empty sequence encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Sequence

        field = ASN1Sequence("test_seq")
        result = field.original_value()
        assert result[0] == 0x30  # SEQUENCE tag
        assert result[1] == 0x00  # Zero length

    def test_creation_with_children(self):
        """Sequence with children encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Sequence, ASN1Integer

        child = ASN1Integer("int_child", 42, fuzzable=False)
        field = ASN1Sequence("test_seq", children=[child])
        result = field.original_value()
        assert result[0] == 0x30  # SEQUENCE tag
        assert b"\x02\x01\x2a" in result  # Contains INTEGER 42

    def test_mutations_include_missing_children(self):
        """Mutations include sequences with missing children."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Sequence, ASN1Integer

        child1 = ASN1Integer("int1", 1, fuzzable=False)
        child2 = ASN1Integer("int2", 2, fuzzable=False)
        field = ASN1Sequence("test_seq", children=[child1, child2])
        mutations = list(field.mutations(None))
        # Should include mutations with one child missing
        assert any(b"\x02\x01\x01" not in m or b"\x02\x01\x02" not in m for m in mutations)

    def test_mutations_include_deep_nesting(self):
        """Mutations include deeply nested structures."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Sequence, ASN1Integer

        child = ASN1Integer("int_child", 42, fuzzable=False)
        field = ASN1Sequence("test_seq", children=[child])
        mutations = list(field.mutations(None))
        # Should include deep nesting
        assert any(m.count(b"\x30") > 10 for m in mutations)

    def test_context_tag(self):
        """Context tag on sequence works correctly."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Sequence

        field = ASN1Sequence("test_seq", context_tag=1)
        result = field.original_value()
        assert result[0] == 0xA1  # Context[1] constructed


# =============================================================================
# Test Helper Functions
# =============================================================================


class TestEncodeLengthHelper:
    """Tests for encode_length helper function."""

    def test_encode_length_short(self):
        """Short form length encoding."""
        from oida.fuzz.primitives.asn1_blocks import encode_length

        assert encode_length(0) == b"\x00"
        assert encode_length(127) == b"\x7f"

    def test_encode_length_long(self):
        """Long form length encoding."""
        from oida.fuzz.primitives.asn1_blocks import encode_length

        assert encode_length(128) == b"\x81\x80"
        assert encode_length(256) == b"\x82\x01\x00"


class TestEncodeIntegerContentHelper:
    """Tests for encode_integer_content helper function."""

    def test_encode_zero(self):
        """Zero encodes as single 0x00 byte."""
        from oida.fuzz.primitives.asn1_blocks import encode_integer_content

        assert encode_integer_content(0) == b"\x00"

    def test_encode_positive(self):
        """Positive integers encode correctly."""
        from oida.fuzz.primitives.asn1_blocks import encode_integer_content

        assert encode_integer_content(42) == b"\x2a"
        assert encode_integer_content(128) == b"\x00\x80"  # Needs padding

    def test_encode_negative(self):
        """Negative integers encode correctly (two's complement)."""
        from oida.fuzz.primitives.asn1_blocks import encode_integer_content

        assert encode_integer_content(-1) == b"\xff"
        assert encode_integer_content(-128) == b"\x80"


class TestEncodeOIDContentHelper:
    """Tests for encode_oid_content helper function."""

    def test_encode_simple_oid(self):
        """Simple OID encodes correctly."""
        from oida.fuzz.primitives.asn1_blocks import encode_oid_content

        result = encode_oid_content("1.2.3")
        assert result[0] == 42  # 40*1 + 2

    def test_invalid_oid_raises(self):
        """OID with less than 2 components raises."""
        from oida.fuzz.primitives.asn1_blocks import encode_oid_content

        with pytest.raises(ValueError):
            encode_oid_content("1")


# =============================================================================
# Test Valid ASN.1 Types (pyasn1 re-exports)
# =============================================================================


class TestValidASN1Types:
    """Tests for valid (non-mutated) ASN.1 type re-exports."""

    def test_valid_encode_integer(self):
        """valid_encode produces correct BER."""
        from oida.fuzz.primitives.asn1 import ValidInteger, valid_encode

        obj = ValidInteger(42)
        result = valid_encode(obj)
        assert result == b"\x02\x01\x2a"

    def test_valid_encode_sequence(self):
        """valid_encode produces correct sequence BER."""
        from oida.fuzz.primitives.asn1 import ValidSequence, ValidInteger, valid_encode

        seq = ValidSequence()
        seq.setComponentByPosition(0, ValidInteger(42))
        result = valid_encode(seq)
        assert result[0] == 0x30  # SEQUENCE tag

    def test_valid_decode_roundtrip(self):
        """Encode then decode produces same value."""
        from oida.fuzz.primitives.asn1 import ValidInteger, valid_encode, valid_decode

        original = ValidInteger(42)
        encoded = valid_encode(original)
        decoded, remainder = valid_decode(encoded)
        assert int(decoded) == 42


# =============================================================================
# Test Mutation Quality
# =============================================================================


class TestMutationQuality:
    """Tests for mutation quality and coverage."""

    def test_integer_mutations_diverse(self):
        """Integer mutations are diverse (not all similar)."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test", 0)
        mutations = list(field.mutations(None))
        # Check that mutations have different lengths
        lengths = set(len(m) for m in mutations)
        assert len(lengths) > 1

    def test_mutations_include_tag_fuzz(self):
        """Mutations include tag field fuzzing."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test", 42, fuzz_tag=True)
        mutations = list(field.mutations(None))
        # Should include mutations with different tags
        tags = set(m[0] for m in mutations if len(m) > 0)
        assert len(tags) > 1

    def test_mutations_include_length_fuzz(self):
        """Mutations include length field fuzzing."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        field = ASN1Integer("test", 42, fuzz_length=True)
        mutations = list(field.mutations(None))
        # Should include mutations with invalid lengths
        # Look for oversized length indicator 0x82
        assert any(len(m) > 1 and m[1] == 0x82 for m in mutations)

    def test_fuzz_flags_respected(self):
        """Disabling fuzz flags reduces mutations."""
        from oida.fuzz.primitives.asn1_blocks import ASN1Integer

        full = ASN1Integer("test", 42, fuzz_tag=True, fuzz_length=True, fuzz_value=True)
        no_tag = ASN1Integer("test", 42, fuzz_tag=False, fuzz_length=True, fuzz_value=True)
        assert no_tag.num_mutations() < full.num_mutations()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
