#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive tests for the Modbus decoder module.

Tests all 12 data types, endian variants, word orders, and edge cases.
"""

import math
import struct
import pytest

# Check for pymodbus availability
try:
    from pymodbus.client.mixin import ModbusClientMixin

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

# Skip all tests if pymodbus is not available
pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")

from oida.protocols.modbus.decoder import (
    ModbusDecoder,
    ModbusEncoder,
    DataType,
    TYPE_ALIASES,
    REGISTERS_PER_TYPE,
    get_endian,
    decode_with_map,
    load_register_map,
    list_register_maps,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def decoder_big():
    """Decoder with big-endian byte and word order (default)."""
    return ModbusDecoder(byte_order="big", word_order="big")


@pytest.fixture
def decoder_little():
    """Decoder with little-endian byte and word order."""
    return ModbusDecoder(byte_order="little", word_order="little")


@pytest.fixture
def decoder_big_little():
    """Decoder with big-endian bytes, little-endian words."""
    return ModbusDecoder(byte_order="big", word_order="little")


@pytest.fixture
def decoder_little_big():
    """Decoder with little-endian bytes, big-endian words."""
    return ModbusDecoder(byte_order="little", word_order="big")


# =============================================================================
# Test Constants and Data Type Metadata
# =============================================================================


class TestDataTypeEnum:
    """Tests for DataType enum."""

    def test_all_types_defined(self):
        """Verify all 12 data types are defined in enum."""
        expected_types = [
            "f32",
            "f64",
            "i16",
            "i32",
            "i64",
            "u16",
            "u32",
            "u64",
            "str",
            "hex",
            "bits",
            "bcd",
        ]
        enum_values = [dt.value for dt in DataType]
        for expected in expected_types:
            assert expected in enum_values, f"Missing type: {expected}"

    def test_enum_count(self):
        """Verify exactly 12 data types."""
        assert len(DataType) == 12


class TestTypeAliases:
    """Tests for type alias mappings."""

    @pytest.mark.parametrize(
        "alias,canonical",
        [
            # Float aliases
            ("float", "f32"),
            ("float32", "f32"),
            ("f32", "f32"),
            ("double", "f64"),
            ("float64", "f64"),
            ("f64", "f64"),
            # Signed integer aliases
            ("int", "i16"),
            ("int16", "i16"),
            ("i16", "i16"),
            ("int32", "i32"),
            ("i32", "i32"),
            ("int64", "i64"),
            ("i64", "i64"),
            # Unsigned integer aliases
            ("uint", "u16"),
            ("uint16", "u16"),
            ("u16", "u16"),
            ("uint32", "u32"),
            ("u32", "u32"),
            ("uint64", "u64"),
            ("u64", "u64"),
            # String aliases
            ("string", "str"),
            ("text", "str"),
            ("str", "str"),
            ("ascii", "str"),
            # Hex aliases
            ("hex", "hex"),
            ("binary", "hex"),
            ("raw", "hex"),
            # Bits aliases
            ("bits", "bits"),
            ("bit", "bits"),
            # BCD
            ("bcd", "bcd"),
        ],
    )
    def test_alias_mapping(self, alias, canonical):
        """Test that type aliases resolve to canonical names."""
        assert TYPE_ALIASES[alias] == canonical


class TestRegistersPerType:
    """Tests for register count per type."""

    @pytest.mark.parametrize(
        "dtype,expected",
        [
            ("f32", 2),
            ("f64", 4),
            ("i16", 1),
            ("i32", 2),
            ("i64", 4),
            ("u16", 1),
            ("u32", 2),
            ("u64", 4),
            ("str", None),  # Variable
            ("hex", None),  # Variable
            ("bits", 1),
            ("bcd", 1),
        ],
    )
    def test_register_counts(self, dtype, expected):
        """Verify register counts for each type."""
        assert REGISTERS_PER_TYPE[dtype] == expected


# =============================================================================
# Test get_endian() Function
# =============================================================================


class TestGetEndian:
    """Tests for get_endian() helper function."""

    @pytest.mark.parametrize(
        "endian_str,expected",
        [
            ("big", "big"),
            ("little", "little"),
            (">", "big"),
            ("<", "little"),
            ("be", "big"),
            ("le", "little"),
            ("big-swap", "big"),
            ("little-swap", "little"),
            ("BIG", "big"),  # Case insensitive
            ("LITTLE", "little"),
        ],
    )
    def test_endian_mapping(self, endian_str, expected):
        """Test endian string to constant mapping."""
        assert get_endian(endian_str) == expected

    def test_unknown_defaults_to_big(self):
        """Unknown endian string defaults to big."""
        assert get_endian("unknown") == "big"


# =============================================================================
# Test UINT16 (u16) Decoding
# =============================================================================


class TestDecodeUint16:
    """Tests for 16-bit unsigned integer decoding."""

    def test_u16_zero(self, decoder_big):
        """Decode u16 value of 0."""
        result = decoder_big.decode([0], "u16")
        assert len(result) == 1
        assert result[0]["value"] == 0
        assert result[0]["type"] == "u16"
        assert result[0]["registers"] == [0]
        assert result[0]["offset"] == 0

    def test_u16_max_value(self, decoder_big):
        """Decode u16 max value (65535)."""
        result = decoder_big.decode([65535], "u16")
        assert result[0]["value"] == 65535

    def test_u16_mid_value(self, decoder_big):
        """Decode u16 mid-range value."""
        result = decoder_big.decode([32768], "u16")
        assert result[0]["value"] == 32768

    def test_u16_multiple_values(self, decoder_big):
        """Decode multiple u16 values."""
        result = decoder_big.decode([100, 200, 300], "u16")
        assert len(result) == 3
        assert result[0]["value"] == 100
        assert result[1]["value"] == 200
        assert result[2]["value"] == 300
        assert result[0]["offset"] == 0
        assert result[1]["offset"] == 1
        assert result[2]["offset"] == 2

    def test_u16_with_count_limit(self, decoder_big):
        """Decode u16 with count limit."""
        result = decoder_big.decode([100, 200, 300], "u16", count=2)
        assert len(result) == 2
        assert result[0]["value"] == 100
        assert result[1]["value"] == 200

    @pytest.mark.parametrize("alias", ["uint", "uint16", "u16"])
    def test_u16_aliases(self, decoder_big, alias):
        """Test u16 type aliases."""
        result = decoder_big.decode([1234], alias)
        assert result[0]["value"] == 1234
        assert result[0]["type"] == "u16"


# =============================================================================
# Test INT16 (i16) Decoding
# =============================================================================


class TestDecodeInt16:
    """Tests for 16-bit signed integer decoding."""

    def test_i16_zero(self, decoder_big):
        """Decode i16 value of 0."""
        result = decoder_big.decode([0], "i16")
        assert result[0]["value"] == 0
        assert result[0]["type"] == "i16"

    def test_i16_positive(self, decoder_big):
        """Decode positive i16 value."""
        result = decoder_big.decode([32767], "i16")
        assert result[0]["value"] == 32767

    def test_i16_negative_one(self, decoder_big):
        """Decode i16 value of -1 (0xFFFF)."""
        result = decoder_big.decode([0xFFFF], "i16")
        assert result[0]["value"] == -1

    def test_i16_min_value(self, decoder_big):
        """Decode i16 min value (-32768)."""
        result = decoder_big.decode([0x8000], "i16")
        assert result[0]["value"] == -32768

    def test_i16_negative_value(self, decoder_big):
        """Decode negative i16 value."""
        # -100 in two's complement 16-bit
        result = decoder_big.decode([0xFF9C], "i16")
        assert result[0]["value"] == -100

    @pytest.mark.parametrize("alias", ["int", "int16", "i16"])
    def test_i16_aliases(self, decoder_big, alias):
        """Test i16 type aliases."""
        result = decoder_big.decode([100], alias)
        assert result[0]["value"] == 100
        assert result[0]["type"] == "i16"


# =============================================================================
# Test UINT32 (u32) Decoding
# =============================================================================


class TestDecodeUint32:
    """Tests for 32-bit unsigned integer decoding."""

    def test_u32_zero(self, decoder_big):
        """Decode u32 value of 0."""
        result = decoder_big.decode([0, 0], "u32")
        assert result[0]["value"] == 0
        assert result[0]["type"] == "u32"
        assert result[0]["registers"] == [0, 0]

    def test_u32_max_value(self, decoder_big):
        """Decode u32 max value (4294967295)."""
        result = decoder_big.decode([0xFFFF, 0xFFFF], "u32")
        assert result[0]["value"] == 4294967295

    def test_u32_specific_value(self, decoder_big):
        """Decode specific u32 value."""
        # 0x00010002 = 65538
        result = decoder_big.decode([0x0001, 0x0002], "u32")
        assert result[0]["value"] == 65538

    def test_u32_word_order_little(self, decoder_big_little):
        """Test u32 with little-endian word order."""
        # With little word order, LSW comes first
        # Value 0x00010002 with little word order: [0x0002, 0x0001]
        result = decoder_big_little.decode([0x0002, 0x0001], "u32")
        assert result[0]["value"] == 65538

    def test_u32_multiple_values(self, decoder_big):
        """Decode multiple u32 values."""
        result = decoder_big.decode([0, 100, 0, 200], "u32")
        assert len(result) == 2
        assert result[0]["value"] == 100
        assert result[1]["value"] == 200

    @pytest.mark.parametrize("alias", ["uint32", "u32"])
    def test_u32_aliases(self, decoder_big, alias):
        """Test u32 type aliases."""
        result = decoder_big.decode([0, 1000], alias)
        assert result[0]["value"] == 1000
        assert result[0]["type"] == "u32"


# =============================================================================
# Test INT32 (i32) Decoding
# =============================================================================


class TestDecodeInt32:
    """Tests for 32-bit signed integer decoding."""

    def test_i32_zero(self, decoder_big):
        """Decode i32 value of 0."""
        result = decoder_big.decode([0, 0], "i32")
        assert result[0]["value"] == 0
        assert result[0]["type"] == "i32"

    def test_i32_positive(self, decoder_big):
        """Decode positive i32 value."""
        # 0x7FFFFFFF = 2147483647
        result = decoder_big.decode([0x7FFF, 0xFFFF], "i32")
        assert result[0]["value"] == 2147483647

    def test_i32_negative_one(self, decoder_big):
        """Decode i32 value of -1."""
        result = decoder_big.decode([0xFFFF, 0xFFFF], "i32")
        assert result[0]["value"] == -1

    def test_i32_min_value(self, decoder_big):
        """Decode i32 min value (-2147483648)."""
        result = decoder_big.decode([0x8000, 0x0000], "i32")
        assert result[0]["value"] == -2147483648

    def test_i32_negative_value(self, decoder_big):
        """Decode specific negative i32 value."""
        # -1000 = 0xFFFFFC18
        result = decoder_big.decode([0xFFFF, 0xFC18], "i32")
        assert result[0]["value"] == -1000

    @pytest.mark.parametrize("alias", ["int32", "i32"])
    def test_i32_aliases(self, decoder_big, alias):
        """Test i32 type aliases."""
        result = decoder_big.decode([0, 100], alias)
        assert result[0]["value"] == 100
        assert result[0]["type"] == "i32"


# =============================================================================
# Test UINT64 (u64) Decoding
# =============================================================================


class TestDecodeUint64:
    """Tests for 64-bit unsigned integer decoding."""

    def test_u64_zero(self, decoder_big):
        """Decode u64 value of 0."""
        result = decoder_big.decode([0, 0, 0, 0], "u64")
        assert result[0]["value"] == 0
        assert result[0]["type"] == "u64"
        assert len(result[0]["registers"]) == 4

    def test_u64_max_value(self, decoder_big):
        """Decode u64 max value (18446744073709551615)."""
        result = decoder_big.decode([0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF], "u64")
        assert result[0]["value"] == 18446744073709551615

    def test_u64_specific_value(self, decoder_big):
        """Decode specific u64 value."""
        # 0x0000000100000002 = 4294967298
        result = decoder_big.decode([0x0000, 0x0001, 0x0000, 0x0002], "u64")
        assert result[0]["value"] == 4294967298

    @pytest.mark.parametrize("alias", ["uint64", "u64"])
    def test_u64_aliases(self, decoder_big, alias):
        """Test u64 type aliases."""
        result = decoder_big.decode([0, 0, 0, 1], alias)
        assert result[0]["value"] == 1
        assert result[0]["type"] == "u64"


# =============================================================================
# Test INT64 (i64) Decoding
# =============================================================================


class TestDecodeInt64:
    """Tests for 64-bit signed integer decoding."""

    def test_i64_zero(self, decoder_big):
        """Decode i64 value of 0."""
        result = decoder_big.decode([0, 0, 0, 0], "i64")
        assert result[0]["value"] == 0
        assert result[0]["type"] == "i64"

    def test_i64_positive_max(self, decoder_big):
        """Decode i64 max positive value."""
        result = decoder_big.decode([0x7FFF, 0xFFFF, 0xFFFF, 0xFFFF], "i64")
        assert result[0]["value"] == 9223372036854775807

    def test_i64_negative_one(self, decoder_big):
        """Decode i64 value of -1."""
        result = decoder_big.decode([0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF], "i64")
        assert result[0]["value"] == -1

    def test_i64_min_value(self, decoder_big):
        """Decode i64 min value."""
        result = decoder_big.decode([0x8000, 0x0000, 0x0000, 0x0000], "i64")
        assert result[0]["value"] == -9223372036854775808

    @pytest.mark.parametrize("alias", ["int64", "i64"])
    def test_i64_aliases(self, decoder_big, alias):
        """Test i64 type aliases."""
        result = decoder_big.decode([0, 0, 0, 100], alias)
        assert result[0]["value"] == 100
        assert result[0]["type"] == "i64"


# =============================================================================
# Test FLOAT32 (f32) Decoding
# =============================================================================


class TestDecodeFloat32:
    """Tests for 32-bit float decoding."""

    def test_f32_zero(self, decoder_big):
        """Decode f32 value of 0.0."""
        result = decoder_big.decode([0x0000, 0x0000], "f32")
        assert result[0]["value"] == 0.0
        assert result[0]["type"] == "f32"

    def test_f32_one(self, decoder_big):
        """Decode f32 value of 1.0."""
        # IEEE 754: 1.0 = 0x3F800000
        result = decoder_big.decode([0x3F80, 0x0000], "f32")
        assert result[0]["value"] == 1.0

    def test_f32_pi(self, decoder_big):
        """Decode f32 value of pi (approximately)."""
        # IEEE 754: pi = 0x40490FDB
        result = decoder_big.decode([0x4049, 0x0FDB], "f32")
        assert abs(result[0]["value"] - 3.14159265) < 0.0001

    def test_f32_negative(self, decoder_big):
        """Decode negative f32 value."""
        # IEEE 754: -1.0 = 0xBF800000
        result = decoder_big.decode([0xBF80, 0x0000], "f32")
        assert result[0]["value"] == -1.0

    def test_f32_small_value(self, decoder_big):
        """Decode small f32 value."""
        # IEEE 754: 0.001 = 0x3A83126F
        result = decoder_big.decode([0x3A83, 0x126F], "f32")
        assert abs(result[0]["value"] - 0.001) < 0.0001

    def test_f32_large_value(self, decoder_big):
        """Decode large f32 value."""
        # IEEE 754: 1000000.0 = 0x49742400
        result = decoder_big.decode([0x4974, 0x2400], "f32")
        assert abs(result[0]["value"] - 1000000.0) < 1.0

    def test_f32_nan(self, decoder_big):
        """Decode f32 NaN value."""
        # IEEE 754: NaN = 0x7FC00000
        result = decoder_big.decode([0x7FC0, 0x0000], "f32")
        assert math.isnan(result[0]["value"])

    def test_f32_positive_infinity(self, decoder_big):
        """Decode f32 positive infinity."""
        # IEEE 754: +Inf = 0x7F800000
        result = decoder_big.decode([0x7F80, 0x0000], "f32")
        assert math.isinf(result[0]["value"])
        assert result[0]["value"] > 0

    def test_f32_negative_infinity(self, decoder_big):
        """Decode f32 negative infinity."""
        # IEEE 754: -Inf = 0xFF800000
        result = decoder_big.decode([0xFF80, 0x0000], "f32")
        assert math.isinf(result[0]["value"])
        assert result[0]["value"] < 0

    def test_f32_negative_zero(self, decoder_big):
        """Decode f32 negative zero."""
        # IEEE 754: -0.0 = 0x80000000
        result = decoder_big.decode([0x8000, 0x0000], "f32")
        assert result[0]["value"] == 0.0
        # Check if it's actually negative zero
        assert str(result[0]["value"]) == "-0.0" or result[0]["value"] == 0.0

    @pytest.mark.parametrize("alias", ["float", "float32", "f32"])
    def test_f32_aliases(self, decoder_big, alias):
        """Test f32 type aliases."""
        result = decoder_big.decode([0x3F80, 0x0000], alias)
        assert result[0]["value"] == 1.0
        assert result[0]["type"] == "f32"

    def test_f32_word_order_little(self, decoder_big_little):
        """Test f32 with little-endian word order."""
        # 1.0 with swapped words: [0x0000, 0x3F80]
        result = decoder_big_little.decode([0x0000, 0x3F80], "f32")
        assert result[0]["value"] == 1.0


# =============================================================================
# Test FLOAT64 (f64) Decoding
# =============================================================================


class TestDecodeFloat64:
    """Tests for 64-bit float (double) decoding."""

    def test_f64_zero(self, decoder_big):
        """Decode f64 value of 0.0."""
        result = decoder_big.decode([0, 0, 0, 0], "f64")
        assert result[0]["value"] == 0.0
        assert result[0]["type"] == "f64"
        assert len(result[0]["registers"]) == 4

    def test_f64_one(self, decoder_big):
        """Decode f64 value of 1.0."""
        # IEEE 754: 1.0 = 0x3FF0000000000000
        result = decoder_big.decode([0x3FF0, 0x0000, 0x0000, 0x0000], "f64")
        assert result[0]["value"] == 1.0

    def test_f64_pi(self, decoder_big):
        """Decode f64 value of pi."""
        # IEEE 754: pi = 0x400921FB54442D18
        result = decoder_big.decode([0x4009, 0x21FB, 0x5444, 0x2D18], "f64")
        assert abs(result[0]["value"] - 3.141592653589793) < 1e-10

    def test_f64_negative(self, decoder_big):
        """Decode negative f64 value."""
        # IEEE 754: -1.0 = 0xBFF0000000000000
        result = decoder_big.decode([0xBFF0, 0x0000, 0x0000, 0x0000], "f64")
        assert result[0]["value"] == -1.0

    def test_f64_nan(self, decoder_big):
        """Decode f64 NaN value."""
        # IEEE 754: NaN = 0x7FF8000000000000
        result = decoder_big.decode([0x7FF8, 0x0000, 0x0000, 0x0000], "f64")
        assert math.isnan(result[0]["value"])

    def test_f64_positive_infinity(self, decoder_big):
        """Decode f64 positive infinity."""
        # IEEE 754: +Inf = 0x7FF0000000000000
        result = decoder_big.decode([0x7FF0, 0x0000, 0x0000, 0x0000], "f64")
        assert math.isinf(result[0]["value"])
        assert result[0]["value"] > 0

    def test_f64_negative_infinity(self, decoder_big):
        """Decode f64 negative infinity."""
        # IEEE 754: -Inf = 0xFFF0000000000000
        result = decoder_big.decode([0xFFF0, 0x0000, 0x0000, 0x0000], "f64")
        assert math.isinf(result[0]["value"])
        assert result[0]["value"] < 0

    @pytest.mark.parametrize("alias", ["double", "float64", "f64"])
    def test_f64_aliases(self, decoder_big, alias):
        """Test f64 type aliases."""
        result = decoder_big.decode([0x3FF0, 0x0000, 0x0000, 0x0000], alias)
        assert result[0]["value"] == 1.0
        assert result[0]["type"] == "f64"


# =============================================================================
# Test STRING (str) Decoding
# =============================================================================


class TestDecodeString:
    """Tests for string decoding."""

    def test_str_hello(self, decoder_big):
        """Decode 'Hello' string."""
        # 'He' = 0x4865, 'l' = 0x6C, 'lo' = 0x6C6F
        result = decoder_big.decode([0x4865, 0x6C6C, 0x6F00], "str")
        assert result[0]["value"] == "Hello"
        assert result[0]["type"] == "str"
        assert "length" in result[0]

    def test_str_empty_registers(self, decoder_big):
        """Decode empty registers as string."""
        result = decoder_big.decode([0x0000], "str")
        assert result[0]["value"] == ""

    def test_str_with_null_terminator(self, decoder_big):
        """String stops at null terminator."""
        # 'AB\x00CD' should decode as 'AB'
        result = decoder_big.decode([0x4142, 0x0043, 0x4445], "str")
        assert result[0]["value"] == "AB"

    def test_str_max_length(self, decoder_big):
        """Test string with max_length limit."""
        # 'Hello World'
        regs = [0x4865, 0x6C6C, 0x6F20, 0x576F, 0x726C, 0x6400]
        result = decoder_big.decode(regs, "str", string_length=5)
        assert result[0]["value"] == "Hello"

    def test_str_non_ascii_replacement(self, decoder_big):
        """Non-ASCII bytes are replaced."""
        # Register with non-ASCII high byte
        result = decoder_big.decode([0xFF41], "str")
        # The 0xFF byte should be replaced with Unicode replacement char
        assert len(result[0]["value"]) > 0

    def test_str_full_words(self, decoder_big):
        """Decode full word string without null terminator."""
        # 'TEST' = [0x5445, 0x5354]
        result = decoder_big.decode([0x5445, 0x5354], "str")
        assert result[0]["value"] == "TEST"

    @pytest.mark.parametrize("alias", ["string", "text", "str", "ascii"])
    def test_str_aliases(self, decoder_big, alias):
        """Test string type aliases."""
        result = decoder_big.decode([0x4142], alias)
        assert result[0]["value"] == "AB"
        assert result[0]["type"] == "str"


# =============================================================================
# Test HEX Decoding
# =============================================================================


class TestDecodeHex:
    """Tests for hexadecimal representation decoding."""

    def test_hex_single_register(self, decoder_big):
        """Decode single register as hex."""
        result = decoder_big.decode([0xABCD], "hex")
        assert result[0]["value"] == "ABCD"
        assert result[0]["type"] == "hex"

    def test_hex_multiple_registers(self, decoder_big):
        """Decode multiple registers as hex."""
        result = decoder_big.decode([0x1234, 0x5678, 0x9ABC], "hex")
        assert result[0]["value"] == "1234 5678 9ABC"

    def test_hex_zero_padding(self, decoder_big):
        """Verify zero padding in hex output."""
        result = decoder_big.decode([0x0001, 0x00FF], "hex")
        assert result[0]["value"] == "0001 00FF"

    def test_hex_all_zeros(self, decoder_big):
        """Decode all-zero registers."""
        result = decoder_big.decode([0x0000, 0x0000], "hex")
        assert result[0]["value"] == "0000 0000"

    def test_hex_all_ones(self, decoder_big):
        """Decode all-ones registers."""
        result = decoder_big.decode([0xFFFF, 0xFFFF], "hex")
        assert result[0]["value"] == "FFFF FFFF"

    @pytest.mark.parametrize("alias", ["hex", "binary", "raw"])
    def test_hex_aliases(self, decoder_big, alias):
        """Test hex type aliases."""
        result = decoder_big.decode([0x1234], alias)
        assert result[0]["value"] == "1234"
        assert result[0]["type"] == "hex"


# =============================================================================
# Test BITS Decoding
# =============================================================================


class TestDecodeBits:
    """Tests for binary bit representation decoding."""

    def test_bits_zero(self, decoder_big):
        """Decode zero register as bits."""
        result = decoder_big.decode([0x0000], "bits")
        assert result[0]["value"] == "0000000000000000"
        assert result[0]["type"] == "bits"
        assert result[0]["bit_list"] == [0] * 16

    def test_bits_all_ones(self, decoder_big):
        """Decode all-ones register as bits."""
        result = decoder_big.decode([0xFFFF], "bits")
        assert result[0]["value"] == "1111111111111111"
        assert result[0]["bit_list"] == [1] * 16

    def test_bits_alternating(self, decoder_big):
        """Decode alternating pattern."""
        # 0xAAAA = 1010101010101010
        result = decoder_big.decode([0xAAAA], "bits")
        assert result[0]["value"] == "1010101010101010"

    def test_bits_single_bit(self, decoder_big):
        """Decode single bit set."""
        # 0x0001 = bit 0 set
        result = decoder_big.decode([0x0001], "bits")
        assert result[0]["value"] == "0000000000000001"
        assert result[0]["bit_list"][-1] == 1  # LSB
        assert sum(result[0]["bit_list"]) == 1

    def test_bits_multiple_registers(self, decoder_big):
        """Decode multiple registers as bits."""
        result = decoder_big.decode([0x00FF, 0xFF00], "bits")
        assert len(result) == 2
        assert result[0]["value"] == "0000000011111111"
        assert result[1]["value"] == "1111111100000000"

    def test_bits_with_count(self, decoder_big):
        """Decode bits with count limit."""
        result = decoder_big.decode([0x0001, 0x0002, 0x0003], "bits", count=2)
        assert len(result) == 2

    @pytest.mark.parametrize("alias", ["bits", "bit"])
    def test_bits_aliases(self, decoder_big, alias):
        """Test bits type aliases."""
        result = decoder_big.decode([0x0001], alias)
        assert result[0]["value"] == "0000000000000001"
        assert result[0]["type"] == "bits"


# =============================================================================
# Test BCD Decoding
# =============================================================================


class TestDecodeBcd:
    """Tests for BCD (Binary Coded Decimal) decoding."""

    def test_bcd_zero(self, decoder_big):
        """Decode BCD value of 0."""
        result = decoder_big.decode([0x0000], "bcd")
        assert result[0]["value"] == 0
        assert result[0]["type"] == "bcd"
        assert result[0]["hex"] == "0000"

    def test_bcd_simple_value(self, decoder_big):
        """Decode simple BCD value."""
        # 0x1234 -> BCD 1234
        result = decoder_big.decode([0x1234], "bcd")
        assert result[0]["value"] == 1234

    def test_bcd_max_value(self, decoder_big):
        """Decode max valid BCD value (9999)."""
        result = decoder_big.decode([0x9999], "bcd")
        assert result[0]["value"] == 9999

    def test_bcd_with_zeros(self, decoder_big):
        """Decode BCD with leading zeros."""
        result = decoder_big.decode([0x0099], "bcd")
        assert result[0]["value"] == 99

    def test_bcd_multiple_registers(self, decoder_big):
        """Decode multiple BCD values."""
        result = decoder_big.decode([0x1234, 0x5678], "bcd")
        assert len(result) == 2
        assert result[0]["value"] == 1234
        assert result[1]["value"] == 5678

    def test_bcd_invalid_digit(self, decoder_big):
        """BCD with invalid digit (A-F) returns None with error."""
        # 0x123A has invalid digit 'A'
        result = decoder_big.decode([0x123A], "bcd")
        assert result[0]["value"] is None
        assert result[0]["error"] == "invalid_bcd"

    def test_bcd_all_invalid(self, decoder_big):
        """BCD with all invalid digits."""
        result = decoder_big.decode([0xABCD], "bcd")
        assert result[0]["value"] is None
        assert result[0]["error"] == "invalid_bcd"

    def test_bcd_with_count(self, decoder_big):
        """Decode BCD with count limit."""
        result = decoder_big.decode([0x1111, 0x2222, 0x3333], "bcd", count=2)
        assert len(result) == 2


# =============================================================================
# Test Endian Variations
# =============================================================================


class TestEndianVariations:
    """Tests for different byte order and word order combinations."""

    def test_u32_big_endian(self, decoder_big):
        """u32 with big-endian byte and word order."""
        # 0x00010002 = 65538, stored as [0x0001, 0x0002]
        result = decoder_big.decode([0x0001, 0x0002], "u32")
        assert result[0]["value"] == 65538

    def test_u32_little_word_order(self, decoder_big_little):
        """u32 with big bytes but little word order (word swap)."""
        # Same value but words swapped: [0x0002, 0x0001]
        result = decoder_big_little.decode([0x0002, 0x0001], "u32")
        assert result[0]["value"] == 65538

    def test_u32_little_endian(self, decoder_little):
        """u32 with little-endian byte and word order."""
        # Full little endian: bytes swapped within words, words swapped
        result = decoder_little.decode([0x0200, 0x0100], "u32")
        assert result[0]["value"] == 65538

    def test_u32_little_byte_big_word(self, decoder_little_big):
        """u32 with little bytes but big word order."""
        result = decoder_little_big.decode([0x0100, 0x0200], "u32")
        assert result[0]["value"] == 65538

    def test_f32_endian_consistency(self):
        """Float value decoded correctly with different endian settings."""
        # Create register values for 1.0 in big endian
        value = 1.0
        packed = struct.pack(">f", value)  # Big endian
        reg1 = struct.unpack(">H", packed[0:2])[0]
        reg2 = struct.unpack(">H", packed[2:4])[0]

        # Decode with matching endian settings
        decoder = ModbusDecoder(byte_order="big", word_order="big")
        result = decoder.decode([reg1, reg2], "f32")
        assert result[0]["value"] == value

    @pytest.mark.parametrize(
        "byte_order,word_order",
        [
            ("big", "big"),
            ("big", "little"),
            ("little", "big"),
            ("little", "little"),
        ],
    )
    def test_i64_all_endian_combinations(self, byte_order, word_order):
        """Test i64 decoding with all endian combinations."""
        decoder = ModbusDecoder(byte_order=byte_order, word_order=word_order)
        # Just verify it doesn't crash
        result = decoder.decode([0x0001, 0x0002, 0x0003, 0x0004], "i64")
        assert len(result) == 1
        assert result[0]["type"] == "i64"


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_register_list(self, decoder_big):
        """Empty register list returns empty results."""
        result = decoder_big.decode([], "u16")
        assert result == []

    def test_insufficient_registers_u32(self, decoder_big):
        """Insufficient registers for u32."""
        result = decoder_big.decode([0x1234], "u32")  # Needs 2, got 1
        assert result == []

    def test_insufficient_registers_f64(self, decoder_big):
        """Insufficient registers for f64."""
        result = decoder_big.decode([0x1234, 0x5678], "f64")  # Needs 4
        assert result == []

    def test_partial_decode(self, decoder_big):
        """Partial decode when not enough registers for all values."""
        # 3 registers can give 1 u32 with 1 leftover
        result = decoder_big.decode([0x0001, 0x0002, 0x0003], "u32")
        assert len(result) == 1

    def test_unknown_data_type(self, decoder_big):
        """Unknown data type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown data type"):
            decoder_big.decode([0x1234], "unknown_type")

    def test_large_register_count(self, decoder_big):
        """Handle large register count."""
        registers = list(range(1000))
        result = decoder_big.decode(registers, "u16")
        assert len(result) == 1000

    def test_string_empty_after_strip(self, decoder_big):
        """String that's empty after stripping whitespace."""
        # All spaces and nulls
        result = decoder_big.decode([0x2020, 0x0000], "str")
        assert result[0]["value"] == ""

    def test_max_uint16_value_as_i16(self, decoder_big):
        """0xFFFF interpreted as i16 is -1."""
        result = decoder_big.decode([0xFFFF], "i16")
        assert result[0]["value"] == -1

    def test_value_just_over_half_range_i16(self, decoder_big):
        """Value just over half range for signed interpretation."""
        # 0x8001 = 32769 unsigned, -32767 signed
        result_unsigned = decoder_big.decode([0x8001], "u16")
        result_signed = decoder_big.decode([0x8001], "i16")
        assert result_unsigned[0]["value"] == 32769
        assert result_signed[0]["value"] == -32767


# =============================================================================
# Test decode_with_map Function
# =============================================================================


class TestDecodeWithMap:
    """Tests for decode_with_map function."""

    def test_basic_register_map(self):
        """Test basic register map decoding."""
        registers = {100: 1000, 101: 2000}
        register_map = {
            "byte_order": "big",
            "word_order": "big",
            "registers": {
                "temperature": {
                    "address": 100,
                    "type": "u16",
                    "unit": "C",
                    "description": "Temperature sensor",
                },
                "pressure": {"address": 101, "type": "u16", "unit": "bar"},
            },
        }
        result = decode_with_map(registers, register_map)
        assert "temperature" in result
        assert result["temperature"]["value"] == 1000
        assert result["temperature"]["unit"] == "C"
        assert result["pressure"]["value"] == 2000

    def test_register_map_with_scale(self):
        """Test register map with scale and offset."""
        registers = {100: 1000}
        register_map = {
            "registers": {
                "temperature": {
                    "address": 100,
                    "type": "u16",
                    "scale": 0.1,
                    "offset": -273.15,
                }
            }
        }
        result = decode_with_map(registers, register_map)
        # 1000 * 0.1 - 273.15 = -173.15
        assert abs(result["temperature"]["value"] - (-173.15)) < 0.01

    def test_register_map_missing_registers(self):
        """Test register map with missing registers."""
        registers = {}
        register_map = {
            "registers": {
                "temperature": {
                    "address": 100,
                    "type": "u16",
                }
            }
        }
        result = decode_with_map(registers, register_map)
        assert result["temperature"]["error"] == "missing_registers"

    def test_register_map_32bit_type(self):
        """Test register map with 32-bit type."""
        registers = {100: 0x0001, 101: 0x0002}
        register_map = {
            "registers": {
                "counter": {
                    "address": 100,
                    "type": "u32",
                }
            }
        }
        result = decode_with_map(registers, register_map)
        assert result["counter"]["value"] == 65538


# =============================================================================
# Test ModbusDecoder Initialization
# =============================================================================


class TestModbusDecoderInit:
    """Tests for ModbusDecoder initialization."""

    def test_default_initialization(self):
        """Default initialization uses big endian."""
        decoder = ModbusDecoder()
        # Should work without errors
        result = decoder.decode([1234], "u16")
        assert result[0]["value"] == 1234

    def test_custom_byte_order(self):
        """Custom byte order initialization."""
        decoder = ModbusDecoder(byte_order="little")
        result = decoder.decode([1234], "u16")
        assert len(result) == 1

    def test_custom_word_order(self):
        """Custom word order initialization."""
        decoder = ModbusDecoder(word_order="little")
        result = decoder.decode([0, 1], "u32")
        assert len(result) == 1


# =============================================================================
# Test Result Structure
# =============================================================================


class TestResultStructure:
    """Tests for result dictionary structure."""

    def test_numeric_result_structure(self, decoder_big):
        """Verify numeric result has all expected keys."""
        result = decoder_big.decode([0x1234], "u16")
        r = result[0]
        assert "value" in r
        assert "type" in r
        assert "registers" in r
        assert "offset" in r

    def test_string_result_structure(self, decoder_big):
        """Verify string result has additional keys."""
        result = decoder_big.decode([0x4142], "str")
        r = result[0]
        assert "value" in r
        assert "type" in r
        assert "registers" in r
        assert "length" in r or "error" in r

    def test_hex_result_structure(self, decoder_big):
        """Verify hex result structure."""
        result = decoder_big.decode([0x1234], "hex")
        r = result[0]
        assert r["value"] == "1234"
        assert r["type"] == "hex"

    def test_bits_result_structure(self, decoder_big):
        """Verify bits result has bit_list."""
        result = decoder_big.decode([0x000F], "bits")
        r = result[0]
        assert "bit_list" in r
        assert len(r["bit_list"]) == 16

    def test_bcd_result_structure(self, decoder_big):
        """Verify BCD result has hex field."""
        result = decoder_big.decode([0x1234], "bcd")
        r = result[0]
        assert "hex" in r
        assert r["hex"] == "1234"


# =============================================================================
# Test Multiple Value Decoding
# =============================================================================


class TestMultipleValues:
    """Tests for decoding multiple values from register arrays."""

    def test_multiple_u16(self, decoder_big):
        """Decode array of u16 values."""
        registers = [100, 200, 300, 400, 500]
        result = decoder_big.decode(registers, "u16")
        assert len(result) == 5
        for i, r in enumerate(result):
            assert r["offset"] == i
            assert r["value"] == registers[i]

    def test_multiple_u32(self, decoder_big):
        """Decode array of u32 values."""
        # Two u32 values: 65538, 131076
        registers = [0x0001, 0x0002, 0x0002, 0x0004]
        result = decoder_big.decode(registers, "u32")
        assert len(result) == 2
        assert result[0]["value"] == 65538
        assert result[1]["value"] == 131076
        assert result[0]["offset"] == 0
        assert result[1]["offset"] == 2

    def test_multiple_f32(self, decoder_big):
        """Decode array of f32 values."""
        # 1.0 and 2.0
        registers = [0x3F80, 0x0000, 0x4000, 0x0000]
        result = decoder_big.decode(registers, "f32")
        assert len(result) == 2
        assert result[0]["value"] == 1.0
        assert result[1]["value"] == 2.0

    def test_count_limit(self, decoder_big):
        """Count parameter limits decoded values."""
        registers = list(range(100))
        result = decoder_big.decode(registers, "u16", count=10)
        assert len(result) == 10


# =============================================================================
# Test Case Insensitivity
# =============================================================================


class TestCaseInsensitivity:
    """Tests for case-insensitive type handling."""

    @pytest.mark.parametrize(
        "dtype",
        [
            "U16",
            "u16",
            "U32",
            "u32",
            "I16",
            "i16",
            "I32",
            "i32",
            "F32",
            "f32",
            "F64",
            "f64",
            "STR",
            "str",
            "HEX",
            "hex",
            "BITS",
            "bits",
            "BCD",
            "bcd",
            "FLOAT",
            "Float",
            "INT",
            "Int",
        ],
    )
    def test_type_case_insensitive(self, decoder_big, dtype):
        """Data type strings are case-insensitive."""
        # Provide enough registers for any type
        registers = [0x3F80, 0x0000, 0x0000, 0x0000]
        result = decoder_big.decode(registers, dtype)
        assert len(result) >= 1


# =============================================================================
# Performance-Related Tests
# =============================================================================


class TestPerformance:
    """Performance-related tests."""

    def test_large_array_u16(self, decoder_big):
        """Decode large array of u16 values."""
        registers = list(range(10000))
        result = decoder_big.decode(registers, "u16")
        assert len(result) == 10000

    def test_large_array_f32(self, decoder_big):
        """Decode large array of f32 values."""
        # 1000 f32 values = 2000 registers
        registers = [0x3F80, 0x0000] * 1000
        result = decoder_big.decode(registers, "f32")
        assert len(result) == 1000

    def test_repeated_decode_calls(self, decoder_big):
        """Multiple decode calls on same decoder instance."""
        for _ in range(100):
            result = decoder_big.decode([0x1234], "u16")
            assert result[0]["value"] == 0x1234


# =============================================================================
# Test Data Integrity
# =============================================================================


class TestDataIntegrity:
    """Tests for data integrity and consistency."""

    def test_u16_i16_relationship(self, decoder_big):
        """u16 and i16 decode same bits differently."""
        register = [0x8001]
        u16_result = decoder_big.decode(register, "u16")
        i16_result = decoder_big.decode(register, "i16")
        # Same bits, different interpretation
        assert u16_result[0]["value"] == 32769
        assert i16_result[0]["value"] == -32767
        # They should convert back to same raw value
        assert (u16_result[0]["value"] & 0xFFFF) == (i16_result[0]["value"] & 0xFFFF)

    def test_u32_i32_relationship(self, decoder_big):
        """u32 and i32 decode same bits differently."""
        registers = [0x8000, 0x0001]
        u32_result = decoder_big.decode(registers, "u32")
        i32_result = decoder_big.decode(registers, "i32")
        # u32: 0x80000001 = 2147483649
        # i32: 0x80000001 = -2147483647
        assert u32_result[0]["value"] == 2147483649
        assert i32_result[0]["value"] == -2147483647

    def test_registers_not_modified(self, decoder_big):
        """Original register list is not modified."""
        registers = [0x1234, 0x5678]
        original = registers.copy()
        decoder_big.decode(registers, "u32")
        assert registers == original

    def test_f32_roundtrip_known_values(self, decoder_big):
        """Known float values decode correctly."""
        test_values = [
            ([0x3F80, 0x0000], 1.0),
            ([0x4000, 0x0000], 2.0),
            ([0xC000, 0x0000], -2.0),
            ([0x4120, 0x0000], 10.0),
            ([0x447A, 0x0000], 1000.0),
        ]
        for regs, expected in test_values:
            result = decoder_big.decode(regs, "f32")
            assert result[0]["value"] == expected, f"Failed for {expected}"


# =============================================================================
# Encoder Test Fixtures
# =============================================================================


@pytest.fixture
def encoder_big():
    """Encoder with big-endian byte and word order."""
    return ModbusEncoder(byte_order="big", word_order="big")


@pytest.fixture
def encoder_little():
    """Encoder with little-endian byte and word order."""
    return ModbusEncoder(byte_order="little", word_order="little")


@pytest.fixture
def encoder_big_little():
    """Encoder with big bytes, little words."""
    return ModbusEncoder(byte_order="big", word_order="little")


@pytest.fixture
def encoder_little_big():
    """Encoder with little bytes, big words."""
    return ModbusEncoder(byte_order="little", word_order="big")


# =============================================================================
# Test ModbusEncoder Initialization
# =============================================================================


class TestModbusEncoderInit:
    """Tests for ModbusEncoder initialization."""

    def test_default_initialization(self):
        """Default initialization uses big endian."""
        encoder = ModbusEncoder()
        # Should work without errors
        result = encoder.encode_uint16(1234)
        assert len(result) == 1

    def test_custom_byte_order(self):
        """Custom byte order initialization."""
        encoder = ModbusEncoder(byte_order="little")
        result = encoder.encode_uint16(1234)
        assert len(result) == 1

    def test_custom_word_order(self):
        """Custom word order initialization."""
        encoder = ModbusEncoder(word_order="little")
        result = encoder.encode_uint32(65538)
        assert len(result) == 2

    def test_both_custom_orders(self):
        """Both byte and word order custom."""
        encoder = ModbusEncoder(byte_order="little", word_order="little")
        result = encoder.encode_uint32(65538)
        assert len(result) == 2


# =============================================================================
# Test FLOAT32 (f32) Encoding
# =============================================================================


class TestEncodeFloat32:
    """Tests for 32-bit float encoding."""

    def test_f32_zero(self, encoder_big):
        """Encode f32 value of 0.0."""
        result = encoder_big.encode_float32(0.0)
        assert result == [0x0000, 0x0000]

    def test_f32_one(self, encoder_big):
        """Encode f32 value of 1.0."""
        result = encoder_big.encode_float32(1.0)
        assert result == [0x3F80, 0x0000]

    def test_f32_negative_one(self, encoder_big):
        """Encode f32 value of -1.0."""
        result = encoder_big.encode_float32(-1.0)
        assert result == [0xBF80, 0x0000]

    def test_f32_pi(self, encoder_big, decoder_big):
        """Encode f32 value of pi with round-trip verification."""
        pi_value = 3.14159265
        result = encoder_big.encode_float32(pi_value)
        decoded = decoder_big.decode(result, "f32")
        assert abs(decoded[0]["value"] - pi_value) < 0.0001

    def test_f32_large_value(self, encoder_big, decoder_big):
        """Encode large f32 value."""
        large_value = 1e10
        result = encoder_big.encode_float32(large_value)
        decoded = decoder_big.decode(result, "f32")
        assert abs(decoded[0]["value"] - large_value) / large_value < 0.0001

    def test_f32_small_value(self, encoder_big, decoder_big):
        """Encode small f32 value."""
        small_value = 1e-10
        result = encoder_big.encode_float32(small_value)
        decoded = decoder_big.decode(result, "f32")
        assert abs(decoded[0]["value"] - small_value) / small_value < 0.0001

    def test_f32_nan(self, encoder_big, decoder_big):
        """Encode f32 NaN value."""
        result = encoder_big.encode_float32(float("nan"))
        decoded = decoder_big.decode(result, "f32")
        assert math.isnan(decoded[0]["value"])

    def test_f32_positive_infinity(self, encoder_big, decoder_big):
        """Encode f32 positive infinity."""
        result = encoder_big.encode_float32(float("inf"))
        decoded = decoder_big.decode(result, "f32")
        assert math.isinf(decoded[0]["value"])
        assert decoded[0]["value"] > 0

    def test_f32_negative_infinity(self, encoder_big, decoder_big):
        """Encode f32 negative infinity."""
        result = encoder_big.encode_float32(float("-inf"))
        decoded = decoder_big.decode(result, "f32")
        assert math.isinf(decoded[0]["value"])
        assert decoded[0]["value"] < 0

    def test_f32_negative_zero(self, encoder_big, decoder_big):
        """Encode f32 negative zero."""
        result = encoder_big.encode_float32(-0.0)
        decoded = decoder_big.decode(result, "f32")
        # Negative zero should decode to zero
        assert decoded[0]["value"] == 0.0


# =============================================================================
# Test FLOAT64 (f64) Encoding
# =============================================================================


class TestEncodeFloat64:
    """Tests for 64-bit float encoding."""

    def test_f64_zero(self, encoder_big):
        """Encode f64 value of 0.0."""
        result = encoder_big.encode_float64(0.0)
        assert result == [0x0000, 0x0000, 0x0000, 0x0000]

    def test_f64_one(self, encoder_big):
        """Encode f64 value of 1.0."""
        result = encoder_big.encode_float64(1.0)
        assert result == [0x3FF0, 0x0000, 0x0000, 0x0000]

    def test_f64_negative_one(self, encoder_big):
        """Encode f64 value of -1.0."""
        result = encoder_big.encode_float64(-1.0)
        assert result == [0xBFF0, 0x0000, 0x0000, 0x0000]

    def test_f64_pi(self, encoder_big, decoder_big):
        """Encode f64 value of pi with round-trip verification."""
        pi_value = 3.141592653589793
        result = encoder_big.encode_float64(pi_value)
        decoded = decoder_big.decode(result, "f64")
        assert abs(decoded[0]["value"] - pi_value) < 1e-15

    def test_f64_nan(self, encoder_big, decoder_big):
        """Encode f64 NaN value."""
        result = encoder_big.encode_float64(float("nan"))
        decoded = decoder_big.decode(result, "f64")
        assert math.isnan(decoded[0]["value"])

    def test_f64_positive_infinity(self, encoder_big, decoder_big):
        """Encode f64 positive infinity."""
        result = encoder_big.encode_float64(float("inf"))
        decoded = decoder_big.decode(result, "f64")
        assert math.isinf(decoded[0]["value"])
        assert decoded[0]["value"] > 0

    def test_f64_negative_infinity(self, encoder_big, decoder_big):
        """Encode f64 negative infinity."""
        result = encoder_big.encode_float64(float("-inf"))
        decoded = decoder_big.decode(result, "f64")
        assert math.isinf(decoded[0]["value"])
        assert decoded[0]["value"] < 0

    def test_f64_large_value(self, encoder_big, decoder_big):
        """Encode large f64 value."""
        large_value = 1e100
        result = encoder_big.encode_float64(large_value)
        decoded = decoder_big.decode(result, "f64")
        assert abs(decoded[0]["value"] - large_value) / large_value < 1e-10


# =============================================================================
# Test INT16 (i16) Encoding
# =============================================================================


class TestEncodeInt16:
    """Tests for 16-bit signed integer encoding."""

    def test_i16_zero(self, encoder_big):
        """Encode i16 value of 0."""
        result = encoder_big.encode_int16(0)
        assert result == [0x0000]

    def test_i16_one(self, encoder_big):
        """Encode i16 value of 1."""
        result = encoder_big.encode_int16(1)
        assert result == [0x0001]

    def test_i16_negative_one(self, encoder_big):
        """Encode i16 value of -1."""
        result = encoder_big.encode_int16(-1)
        assert result == [0xFFFF]

    def test_i16_max_value(self, encoder_big):
        """Encode i16 max value (32767)."""
        result = encoder_big.encode_int16(32767)
        assert result == [0x7FFF]

    def test_i16_min_value(self, encoder_big):
        """Encode i16 min value (-32768)."""
        result = encoder_big.encode_int16(-32768)
        assert result == [0x8000]

    def test_i16_mid_negative(self, encoder_big, decoder_big):
        """Encode i16 mid-range negative value."""
        result = encoder_big.encode_int16(-100)
        decoded = decoder_big.decode(result, "i16")
        assert decoded[0]["value"] == -100


# =============================================================================
# Test INT32 (i32) Encoding
# =============================================================================


class TestEncodeInt32:
    """Tests for 32-bit signed integer encoding."""

    def test_i32_zero(self, encoder_big):
        """Encode i32 value of 0."""
        result = encoder_big.encode_int32(0)
        assert result == [0x0000, 0x0000]

    def test_i32_one(self, encoder_big):
        """Encode i32 value of 1."""
        result = encoder_big.encode_int32(1)
        assert result == [0x0000, 0x0001]

    def test_i32_negative_one(self, encoder_big):
        """Encode i32 value of -1."""
        result = encoder_big.encode_int32(-1)
        assert result == [0xFFFF, 0xFFFF]

    def test_i32_max_value(self, encoder_big):
        """Encode i32 max value (2147483647)."""
        result = encoder_big.encode_int32(2147483647)
        assert result == [0x7FFF, 0xFFFF]

    def test_i32_min_value(self, encoder_big):
        """Encode i32 min value (-2147483648)."""
        result = encoder_big.encode_int32(-2147483648)
        assert result == [0x8000, 0x0000]

    def test_i32_large_negative(self, encoder_big, decoder_big):
        """Encode i32 large negative value with round-trip."""
        value = -1000000
        result = encoder_big.encode_int32(value)
        decoded = decoder_big.decode(result, "i32")
        assert decoded[0]["value"] == value


# =============================================================================
# Test INT64 (i64) Encoding
# =============================================================================


class TestEncodeInt64:
    """Tests for 64-bit signed integer encoding."""

    def test_i64_zero(self, encoder_big):
        """Encode i64 value of 0."""
        result = encoder_big.encode_int64(0)
        assert result == [0x0000, 0x0000, 0x0000, 0x0000]

    def test_i64_max_value(self, encoder_big):
        """Encode i64 max value."""
        result = encoder_big.encode_int64(9223372036854775807)
        assert result == [0x7FFF, 0xFFFF, 0xFFFF, 0xFFFF]

    def test_i64_min_value(self, encoder_big):
        """Encode i64 min value."""
        result = encoder_big.encode_int64(-9223372036854775808)
        assert result == [0x8000, 0x0000, 0x0000, 0x0000]

    def test_i64_negative_one(self, encoder_big):
        """Encode i64 value of -1."""
        result = encoder_big.encode_int64(-1)
        assert result == [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]

    def test_i64_large_value(self, encoder_big, decoder_big):
        """Encode i64 large value with round-trip."""
        value = 123456789012345
        result = encoder_big.encode_int64(value)
        decoded = decoder_big.decode(result, "i64")
        assert decoded[0]["value"] == value


# =============================================================================
# Test UINT16 (u16) Encoding
# =============================================================================


class TestEncodeUint16:
    """Tests for 16-bit unsigned integer encoding."""

    def test_u16_zero(self, encoder_big):
        """Encode u16 value of 0."""
        result = encoder_big.encode_uint16(0)
        assert result == [0x0000]

    def test_u16_one(self, encoder_big):
        """Encode u16 value of 1."""
        result = encoder_big.encode_uint16(1)
        assert result == [0x0001]

    def test_u16_max_value(self, encoder_big):
        """Encode u16 max value (65535)."""
        result = encoder_big.encode_uint16(65535)
        assert result == [0xFFFF]

    def test_u16_mid_value(self, encoder_big):
        """Encode u16 mid-range value."""
        result = encoder_big.encode_uint16(32768)
        assert result == [0x8000]

    def test_u16_roundtrip(self, encoder_big, decoder_big):
        """Encode u16 with round-trip verification."""
        value = 12345
        result = encoder_big.encode_uint16(value)
        decoded = decoder_big.decode(result, "u16")
        assert decoded[0]["value"] == value


# =============================================================================
# Test UINT32 (u32) Encoding
# =============================================================================


class TestEncodeUint32:
    """Tests for 32-bit unsigned integer encoding."""

    def test_u32_zero(self, encoder_big):
        """Encode u32 value of 0."""
        result = encoder_big.encode_uint32(0)
        assert result == [0x0000, 0x0000]

    def test_u32_one(self, encoder_big):
        """Encode u32 value of 1."""
        result = encoder_big.encode_uint32(1)
        assert result == [0x0000, 0x0001]

    def test_u32_max_value(self, encoder_big):
        """Encode u32 max value (4294967295)."""
        result = encoder_big.encode_uint32(4294967295)
        assert result == [0xFFFF, 0xFFFF]

    def test_u32_specific_value(self, encoder_big):
        """Encode specific u32 value (65538)."""
        result = encoder_big.encode_uint32(65538)
        assert result == [0x0001, 0x0002]

    def test_u32_roundtrip(self, encoder_big, decoder_big):
        """Encode u32 with round-trip verification."""
        value = 123456789
        result = encoder_big.encode_uint32(value)
        decoded = decoder_big.decode(result, "u32")
        assert decoded[0]["value"] == value


# =============================================================================
# Test UINT64 (u64) Encoding
# =============================================================================


class TestEncodeUint64:
    """Tests for 64-bit unsigned integer encoding."""

    def test_u64_zero(self, encoder_big):
        """Encode u64 value of 0."""
        result = encoder_big.encode_uint64(0)
        assert result == [0x0000, 0x0000, 0x0000, 0x0000]

    def test_u64_one(self, encoder_big):
        """Encode u64 value of 1."""
        result = encoder_big.encode_uint64(1)
        assert result == [0x0000, 0x0000, 0x0000, 0x0001]

    def test_u64_max_value(self, encoder_big):
        """Encode u64 max value."""
        result = encoder_big.encode_uint64(18446744073709551615)
        assert result == [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]

    def test_u64_roundtrip(self, encoder_big, decoder_big):
        """Encode u64 with round-trip verification."""
        value = 9876543210123456789
        result = encoder_big.encode_uint64(value)
        decoded = decoder_big.decode(result, "u64")
        assert decoded[0]["value"] == value


# =============================================================================
# Test STRING (str) Encoding
# =============================================================================


class TestEncodeString:
    """Tests for string encoding."""

    def test_str_hello(self, encoder_big):
        """Encode 'Hello' string."""
        result = encoder_big.encode_string("Hello", 6)
        # 'He' = 0x4865, 'll' = 0x6C6C, 'o\x00' = 0x6F00
        assert result == [0x4865, 0x6C6C, 0x6F00]

    def test_str_padding(self, encoder_big):
        """Encode string with padding."""
        result = encoder_big.encode_string("AB", 4)
        # 'AB' = 0x4142, '\x00\x00' = 0x0000
        assert result == [0x4142, 0x0000]

    def test_str_truncation(self, encoder_big):
        """Encode string with truncation."""
        result = encoder_big.encode_string("Hello World", 4)
        # 'He' = 0x4865, 'll' = 0x6C6C
        assert result == [0x4865, 0x6C6C]

    def test_str_odd_length(self, encoder_big):
        """Encode string with odd length (rounds up)."""
        result = encoder_big.encode_string("ABC", 3)
        # 'AB' = 0x4142, 'C\x00' = 0x4300
        assert result == [0x4142, 0x4300]

    def test_str_empty(self, encoder_big):
        """Encode empty string with length."""
        result = encoder_big.encode_string("", 2)
        assert result == [0x0000]

    def test_str_roundtrip(self, encoder_big, decoder_big):
        """Encode string with round-trip verification."""
        value = "TEST"
        result = encoder_big.encode_string(value, len(value))
        decoded = decoder_big.decode(result, "str")
        assert decoded[0]["value"] == value

    def test_str_with_spaces(self, encoder_big, decoder_big):
        """Encode string with spaces."""
        value = "A B"
        result = encoder_big.encode_string(value, 4)
        decoded = decoder_big.decode(result, "str")
        assert decoded[0]["value"] == value

    def test_str_single_char(self, encoder_big):
        """Encode single character string."""
        result = encoder_big.encode_string("X", 2)
        # 'X\x00' = 0x5800
        assert result == [0x5800]


# =============================================================================
# Test HEX Encoding
# =============================================================================


class TestEncodeHex:
    """Tests for hexadecimal encoding."""

    def test_hex_dead(self, encoder_big):
        """Encode hex string 'DEAD'."""
        result = encoder_big.encode_hex("DEAD")
        assert result == [0xDEAD]

    def test_hex_deadbeef(self, encoder_big):
        """Encode hex string 'DEADBEEF'."""
        result = encoder_big.encode_hex("DEADBEEF")
        assert result == [0xDEAD, 0xBEEF]

    def test_hex_with_spaces(self, encoder_big):
        """Encode hex string with spaces."""
        result = encoder_big.encode_hex("DE AD BE EF")
        assert result == [0xDEAD, 0xBEEF]

    def test_hex_lowercase(self, encoder_big):
        """Encode lowercase hex string."""
        result = encoder_big.encode_hex("deadbeef")
        assert result == [0xDEAD, 0xBEEF]

    def test_hex_padding(self, encoder_big):
        """Encode hex string requiring padding."""
        result = encoder_big.encode_hex("ABC")
        # Padded to 4 digits: 0ABC
        assert result == [0x0ABC]

    def test_hex_invalid_chars(self, encoder_big):
        """Encode hex string with invalid characters raises ValueError."""
        with pytest.raises(ValueError, match="Invalid hex string"):
            encoder_big.encode_hex("GHIJ")


# =============================================================================
# Test BITS Encoding
# =============================================================================


class TestEncodeBits:
    """Tests for binary bit encoding."""

    def test_bits_all_zeros(self, encoder_big):
        """Encode all zeros bit string."""
        result = encoder_big.encode_bits("0000000000000000")
        assert result == [0x0000]

    def test_bits_all_ones(self, encoder_big):
        """Encode all ones bit string."""
        result = encoder_big.encode_bits("1111111111111111")
        assert result == [0xFFFF]

    def test_bits_alternating(self, encoder_big):
        """Encode alternating bit pattern."""
        result = encoder_big.encode_bits("1010101010101010")
        assert result == [0xAAAA]

    def test_bits_truncation(self, encoder_big):
        """Encode bit string longer than 16 bits (truncates)."""
        result = encoder_big.encode_bits("11111111111111110000")
        # Truncated to first 16 bits
        assert result == [0xFFFF]

    def test_bits_padding(self, encoder_big):
        """Encode short bit string (pads with zeros)."""
        result = encoder_big.encode_bits("1111")
        # Padded to 16 bits: 0000000000001111 = 0x000F
        assert result == [0x000F]

    def test_bits_invalid_chars(self, encoder_big):
        """Encode bit string with invalid characters raises ValueError."""
        with pytest.raises(ValueError, match="Invalid bit string"):
            encoder_big.encode_bits("1012")


# =============================================================================
# Test BCD Encoding
# =============================================================================


class TestEncodeBcd:
    """Tests for BCD (Binary Coded Decimal) encoding."""

    def test_bcd_zero(self, encoder_big):
        """Encode BCD value of 0."""
        result = encoder_big.encode_bcd(0)
        assert result == [0x0000]

    def test_bcd_1234(self, encoder_big):
        """Encode BCD value of 1234."""
        result = encoder_big.encode_bcd(1234)
        assert result == [0x1234]

    def test_bcd_9999(self, encoder_big):
        """Encode BCD max value (9999)."""
        result = encoder_big.encode_bcd(9999)
        assert result == [0x9999]

    def test_bcd_out_of_range(self, encoder_big):
        """Encode BCD value > 9999 raises ValueError."""
        with pytest.raises(ValueError, match="BCD value must be 0-9999"):
            encoder_big.encode_bcd(10000)

    def test_bcd_negative(self, encoder_big):
        """Encode negative BCD value raises ValueError."""
        with pytest.raises(ValueError, match="BCD value must be 0-9999"):
            encoder_big.encode_bcd(-1)


# =============================================================================
# Test Encode Dispatch Method
# =============================================================================


class TestEncodeDispatch:
    """Tests for the main encode() dispatch method."""

    def test_encode_float_alias(self, encoder_big, decoder_big):
        """Encode using 'float' alias."""
        result = encoder_big.encode("3.14159", "float")
        decoded = decoder_big.decode(result, "f32")
        assert abs(decoded[0]["value"] - 3.14159) < 0.0001

    def test_encode_int32_alias(self, encoder_big, decoder_big):
        """Encode using 'int32' alias."""
        result = encoder_big.encode("-1000", "int32")
        decoded = decoder_big.decode(result, "i32")
        assert decoded[0]["value"] == -1000

    def test_encode_uint_alias(self, encoder_big, decoder_big):
        """Encode using 'uint' alias (u16)."""
        result = encoder_big.encode("12345", "uint")
        decoded = decoder_big.decode(result, "u16")
        assert decoded[0]["value"] == 12345

    def test_encode_string_alias(self, encoder_big, decoder_big):
        """Encode using 'string' alias."""
        result = encoder_big.encode("Test", "string", length=4)
        decoded = decoder_big.decode(result, "str")
        assert decoded[0]["value"] == "Test"

    def test_encode_double_alias(self, encoder_big, decoder_big):
        """Encode using 'double' alias (f64)."""
        result = encoder_big.encode("2.718281828", "double")
        decoded = decoder_big.decode(result, "f64")
        assert abs(decoded[0]["value"] - 2.718281828) < 1e-8

    def test_encode_case_insensitive(self, encoder_big):
        """Encode with case-insensitive type."""
        result1 = encoder_big.encode("100", "U16")
        result2 = encoder_big.encode("100", "u16")
        result3 = encoder_big.encode("100", "UINT16")
        assert result1 == result2 == result3

    def test_encode_unknown_type(self, encoder_big):
        """Encode with unknown type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown data type"):
            encoder_big.encode("100", "unknown")

    def test_encode_bcd_via_dispatch(self, encoder_big):
        """Encode BCD via dispatch method."""
        result = encoder_big.encode("1234", "bcd")
        assert result == [0x1234]


# =============================================================================
# Test Encoder Endian Variations
# =============================================================================


class TestEncoderEndianVariations:
    """Tests for different endian combinations in encoder."""

    def test_u32_big_endian(self, encoder_big, decoder_big):
        """u32 with big-endian byte and word order."""
        value = 65538
        encoded = encoder_big.encode_uint32(value)
        decoded = decoder_big.decode(encoded, "u32")
        assert decoded[0]["value"] == value

    def test_u32_little_word_order(self, encoder_big_little, decoder_big_little):
        """u32 with big bytes but little word order."""
        value = 65538
        encoded = encoder_big_little.encode_uint32(value)
        decoded = decoder_big_little.decode(encoded, "u32")
        assert decoded[0]["value"] == value

    def test_u32_little_endian(self, encoder_little, decoder_little):
        """u32 with little-endian byte and word order."""
        value = 65538
        encoded = encoder_little.encode_uint32(value)
        decoded = decoder_little.decode(encoded, "u32")
        assert decoded[0]["value"] == value

    def test_u32_little_byte_big_word(self, encoder_little_big, decoder_little_big):
        """u32 with little bytes but big word order."""
        value = 65538
        encoded = encoder_little_big.encode_uint32(value)
        decoded = decoder_little_big.decode(encoded, "u32")
        assert decoded[0]["value"] == value


# =============================================================================
# Test Encode/Decode Round-Trip
# =============================================================================


class TestEncodeDecodeRoundTrip:
    """Tests for encode->decode round-trip verification."""

    @pytest.mark.parametrize("value", [0.0, 1.0, -1.0, 3.14159, 1e10, -1e-5])
    def test_roundtrip_f32(self, encoder_big, decoder_big, value):
        """Round-trip test for f32 values."""
        encoded = encoder_big.encode_float32(value)
        decoded = decoder_big.decode(encoded, "f32")
        if value == 0.0:
            assert decoded[0]["value"] == 0.0
        else:
            assert abs(decoded[0]["value"] - value) / abs(value) < 1e-6

    @pytest.mark.parametrize("value", [0, 1, -1, 2147483647, -2147483648, -1000000])
    def test_roundtrip_i32(self, encoder_big, decoder_big, value):
        """Round-trip test for i32 values."""
        encoded = encoder_big.encode_int32(value)
        decoded = decoder_big.decode(encoded, "i32")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1, 4294967295, 123456789, 65535])
    def test_roundtrip_u32(self, encoder_big, decoder_big, value):
        """Round-trip test for u32 values."""
        encoded = encoder_big.encode_uint32(value)
        decoded = decoder_big.decode(encoded, "u32")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1, -1, 32767, -32768, 100])
    def test_roundtrip_i16(self, encoder_big, decoder_big, value):
        """Round-trip test for i16 values."""
        encoded = encoder_big.encode_int16(value)
        decoded = decoder_big.decode(encoded, "i16")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1, 65535, 32768, 12345])
    def test_roundtrip_u16(self, encoder_big, decoder_big, value):
        """Round-trip test for u16 values."""
        encoded = encoder_big.encode_uint16(value)
        decoded = decoder_big.decode(encoded, "u16")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1, -1, 9223372036854775807, -9223372036854775808])
    def test_roundtrip_i64(self, encoder_big, decoder_big, value):
        """Round-trip test for i64 values."""
        encoded = encoder_big.encode_int64(value)
        decoded = decoder_big.decode(encoded, "i64")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1, 18446744073709551615, 9876543210])
    def test_roundtrip_u64(self, encoder_big, decoder_big, value):
        """Round-trip test for u64 values."""
        encoded = encoder_big.encode_uint64(value)
        decoded = decoder_big.decode(encoded, "u64")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", ["TEST", "AB", "Hello", "1234"])
    def test_roundtrip_str(self, encoder_big, decoder_big, value):
        """Round-trip test for string values."""
        encoded = encoder_big.encode_string(value, len(value))
        decoded = decoder_big.decode(encoded, "str")
        assert decoded[0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1234, 9999, 99, 1])
    def test_roundtrip_bcd(self, encoder_big, decoder_big, value):
        """Round-trip test for BCD values."""
        encoded = encoder_big.encode_bcd(value)
        decoded = decoder_big.decode(encoded, "bcd")
        assert decoded[0]["value"] == value

    def test_roundtrip_f64(self, encoder_big, decoder_big):
        """Round-trip test for f64 values."""
        for value in [0.0, 1.0, -1.0, 3.141592653589793, 1e100]:
            encoded = encoder_big.encode_float64(value)
            decoded = decoder_big.decode(encoded, "f64")
            if value == 0.0:
                assert decoded[0]["value"] == 0.0
            else:
                assert abs(decoded[0]["value"] - value) / abs(value) < 1e-15

    def test_roundtrip_hex(self, encoder_big, decoder_big):
        """Round-trip test for hex values."""
        encoded = encoder_big.encode_hex("DEADBEEF")
        decoded = decoder_big.decode(encoded, "hex")
        assert decoded[0]["value"] == "DEAD BEEF"


# =============================================================================
# Test Encoder Edge Cases
# =============================================================================


class TestEncoderEdgeCases:
    """Tests for encoder edge cases."""

    def test_encode_invalid_type(self, encoder_big):
        """Encoding with invalid type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown data type"):
            encoder_big.encode("100", "invalid_type")

    def test_encode_float_from_int_string(self, encoder_big, decoder_big):
        """Encoding float from integer string."""
        result = encoder_big.encode("100", "f32")
        decoded = decoder_big.decode(result, "f32")
        assert decoded[0]["value"] == 100.0

    def test_encode_int_with_leading_zeros(self, encoder_big, decoder_big):
        """Encoding int with leading zeros in string."""
        result = encoder_big.encode("0042", "u16")
        decoded = decoder_big.decode(result, "u16")
        assert decoded[0]["value"] == 42

    def test_encode_hex_short_string(self, encoder_big):
        """Encoding short hex string pads correctly."""
        result = encoder_big.encode_hex("F")
        assert result == [0x000F]

    def test_encode_bits_with_spaces(self, encoder_big):
        """Encoding bits with spaces."""
        result = encoder_big.encode_bits("1111 1111 0000 0000")
        assert result == [0xFF00]


# =============================================================================
# Test load_register_map Function
# =============================================================================


class TestLoadRegisterMap:
    """Tests for load_register_map function."""

    def test_load_by_name(self):
        """Load register map by name without extension."""
        result = load_register_map("generic")
        assert result is not None
        assert result["vendor"] == "Generic"
        assert result["model"] == "Template"
        assert "registers" in result

    def test_load_by_name_with_extension(self):
        """Load register map by name with .json extension."""
        result = load_register_map("generic.json")
        assert result is not None
        assert result["vendor"] == "Generic"

    def test_load_nested_path(self):
        """Load register map from subdirectory."""
        result = load_register_map("sunspec/sunspec-common")
        assert result is not None
        assert "registers" in result

    def test_load_nonexistent_map(self):
        """Loading non-existent map returns None."""
        result = load_register_map("nonexistent-device-xyz")
        assert result is None

    def test_load_vendor_specific(self):
        """Load vendor-specific register map."""
        result = load_register_map("schneider-m340")
        assert result is not None
        assert "Schneider" in result.get("vendor", "")

    def test_loaded_map_has_byte_order(self):
        """Loaded map includes byte order configuration."""
        result = load_register_map("generic")
        assert result is not None
        assert "byte_order" in result
        assert result["byte_order"] in ("big", "little")

    def test_loaded_map_registers_have_address(self):
        """All registers in loaded map have address field."""
        result = load_register_map("generic")
        assert result is not None
        for name, reg in result.get("registers", {}).items():
            assert "address" in reg, f"Register {name} missing address"


# =============================================================================
# Test list_register_maps Function
# =============================================================================


class TestListRegisterMaps:
    """Tests for list_register_maps function."""

    def test_list_returns_list(self):
        """list_register_maps returns a list."""
        result = list_register_maps()
        assert isinstance(result, list)

    def test_list_not_empty(self):
        """list_register_maps returns non-empty list."""
        result = list_register_maps()
        assert len(result) > 0

    def test_list_entry_structure(self):
        """Each entry has expected fields."""
        result = list_register_maps()
        assert len(result) > 0
        entry = result[0]
        assert "name" in entry
        assert "vendor" in entry
        assert "model" in entry
        assert "path" in entry

    def test_list_contains_generic(self):
        """List includes the generic template map."""
        result = list_register_maps()
        names = [m["name"] for m in result]
        assert any("generic" in name.lower() for name in names)

    def test_list_contains_subcategories(self):
        """List includes maps from subdirectories."""
        result = list_register_maps()
        categories = [m.get("category", "") for m in result]
        # Should have some categorized maps (solar, battery, sunspec, meters)
        assert any(cat for cat in categories if cat)

    def test_list_paths_exist(self):
        """All paths in list actually exist."""
        import os

        result = list_register_maps()
        for entry in result[:5]:  # Check first 5 to keep test fast
            assert os.path.exists(entry["path"]), f"Path not found: {entry['path']}"


# =============================================================================
# Test Register Map Integration
# =============================================================================


class TestRegisterMapIntegration:
    """Integration tests for register map loading and decoding."""

    def test_load_and_decode(self):
        """Load map and decode registers with it."""
        reg_map = load_register_map("generic")
        assert reg_map is not None

        # Simulate reading device_status and firmware_version
        registers = {0: 0x0001, 1: 0x0102}
        result = decode_with_map(registers, reg_map)

        assert "device_status" in result
        assert result["device_status"]["value"] == 1
        assert "firmware_version" in result
        assert result["firmware_version"]["value"] == 258  # 0x0102

    def test_load_and_decode_float(self):
        """Load map and decode float32 register."""
        reg_map = load_register_map("generic")
        assert reg_map is not None

        # analog_input_1 at address 100, type f32 (2 registers)
        # IEEE 754: 1.0 = 0x3F800000 -> [0x3F80, 0x0000]
        registers = {100: 0x3F80, 101: 0x0000}
        result = decode_with_map(registers, reg_map)

        assert "analog_input_1" in result
        assert result["analog_input_1"]["value"] == 1.0

    def test_decode_with_missing_registers(self):
        """Decode with missing registers returns error."""
        reg_map = load_register_map("generic")
        assert reg_map is not None

        # Only provide one register for f32 (needs 2)
        registers = {100: 0x3F80}
        result = decode_with_map(registers, reg_map)

        assert "analog_input_1" in result
        assert result["analog_input_1"]["error"] == "missing_registers"

    def test_all_maps_load_successfully(self):
        """All listed maps can be loaded without error."""
        maps = list_register_maps()
        for entry in maps:
            loaded = load_register_map(entry["path"])
            assert loaded is not None, f"Failed to load: {entry['name']}"
            # Maps should have registers, coils, or holding_registers structure
            has_data = (
                "registers" in loaded
                or "coils" in loaded
                or "holding_registers" in loaded
                or "input_registers" in loaded
                or any(k.startswith("default_") for k in loaded)
            )
            assert has_data, f"Map {entry['name']} has no recognized register/coil keys"
